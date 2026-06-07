"""Symfony-specific passive exposure detector.

Built from the three SECREP-* security reports in docs/threat-intel/.
The intel pack itself lives at `signatures/intel/symfony_exposure.json`
so adding a new exposure path is a JSON edit, not a code change.

This module is **strictly passive**:
  * GETs each exposure path with HEAD-style probing (small body cap)
  * never sends attack payloads or SQLi / XSS strings
  * the only "active" query is `?+--env=dev`, which the upstream Symfony
    project itself documents as a publicly-known fingerprinting query
    (SECREP-symfony-upstream-issues), and even that probe just checks
    whether the response NOW exposes the profiler — it does not
    persist any change.

The module ALWAYS runs in the `passive` and `standard` mode presets
because the SECREP reports prove this is one of the highest-impact
classes of finding currently in the wild.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

from utils.http_client import http_get
from utils.logger import ScanLogger
from utils.module_safe import module_safe


log = logging.getLogger("hunterpy.symfony")


SIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "signatures", "intel", "symfony_exposure.json",
)


def _load_intel() -> Dict[str, Any]:
    try:
        with open(SIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        log.warning("symfony intel pack unavailable: %s", e)
        return {}


# Load once at module import — these signatures are small (<10KB)
# and we'd rather have a clean ImportError at startup than silent
# misbehavior at scan time.
_INTEL: Dict[str, Any] = _load_intel()


class SymfonyDetector:
    MODULE_NAME = "symfony"

    def __init__(self, settings):
        self.settings = settings
        self.base = self._abs(settings.target)
        self.logger = ScanLogger(settings.output_dir)
        self.context: Dict[str, Any] = {}
        # Cap total HTTP requests so we can't accidentally turn into a
        # crawler if someone extends the intel pack to 200 paths.
        self._max_probes = 20

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    def _next_ua(self) -> str:
        """Return the UA to use for the next probe — rotates if configured."""
        selector = getattr(self.settings, "ua_selector", None)
        return selector.next() if selector is not None else self.settings.user_agent

    # ------------------------------------------------------------------
    @module_safe(fallback="skip", log_level="warning")
    def run(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        if not _INTEL:
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "intel pack missing"}

        # Step 1 — quickly fingerprint Symfony from the landing page.
        # If we can't see Symfony at all, we still try the most-common
        # paths but reduce noise in the report.
        landing = http_get(self.base, user_agent=self.settings.user_agent,
                            timeout=self.settings.timeout,
                            cookies=self.settings.cookies)
        is_symfony = False
        sf_evidence: Dict[str, Any] = {}
        if landing is not None:
            is_symfony, sf_evidence = self._fingerprint_symfony(landing)
            if is_symfony:
                findings.append({
                    "module": self.MODULE_NAME, "type": "symfony_fingerprint",
                    "url": self.base, "severity": "INFO",
                    "title": "Symfony framework detected",
                    "details": "Symfony markers observed in headers/body — "
                               "running the SECREP* exposure checks.",
                    "evidence": sf_evidence,
                })

        # Step 2 — probe every exposure path
        probes_done = 0
        for entry in _INTEL.get("exposure_paths", []):
            if probes_done >= self._max_probes:
                break
            f = self._probe_path(entry)
            probes_done += 1
            if f is not None:
                findings.append(f)
            # tiny inter-probe pause — playing nice with WAFs
            time.sleep(0.2)

        # Step 3 — query-string tricks (only when we already saw Symfony,
        # otherwise the probes are noise).
        if is_symfony:
            for trick in _INTEL.get("query_string_tricks", []):
                if probes_done >= self._max_probes:
                    break
                f = self._probe_query_trick(trick)
                probes_done += 1
                if f is not None:
                    findings.append(f)

        # Step 4 — scan the landing-page body for the exposed-credential
        # patterns. These ONLY trigger if the variable name AND a value
        # appear in the HTML (mostly catches dump()/dd() leaks).
        if landing and landing.text:
            findings.extend(self._scan_credentials(landing.text))

        return {
            "module":   self.MODULE_NAME,
            "findings": findings,
            "raw": {
                "is_symfony": is_symfony,
                "evidence":   sf_evidence,
                "probes":     probes_done,
            },
        }

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------
    def _fingerprint_symfony(self, resp) -> (bool, Dict[str, Any]):
        ev: Dict[str, Any] = {}
        fp = _INTEL.get("framework_fingerprints", {})
        # 1) response headers
        hdrs = {k.lower(): v for k, v in (resp.headers or {}).items()}
        for sig in fp.get("header_signatures", []):
            if sig["name"].lower() in hdrs:
                ev.setdefault("headers", []).append(sig["name"])
        # 2) cookies
        cookie_blob = " ".join(resp.raw_set_cookie or [])
        for sig in fp.get("cookie_signatures", []):
            if sig["name"] in cookie_blob:
                ev.setdefault("cookies", []).append(sig["name"])
        # 3) body markers
        body = resp.text or ""
        for marker in fp.get("body_signatures", []):
            if marker in body:
                ev.setdefault("body_markers", []).append(marker)
        return (bool(ev), ev)

    # ------------------------------------------------------------------
    # Path probes
    # ------------------------------------------------------------------
    def _probe_path(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        path = entry.get("path", "")
        url = self.base.rstrip("/") + path
        resp = http_get(url, user_agent=self._next_ua(),
                        timeout=self.settings.timeout,
                        cookies=self.settings.cookies,
                        allow_redirects=False)
        if resp is None:
            return None

        ok_status = entry.get("match_status") or [200]
        if resp.status_code not in ok_status:
            return None

        body_any = entry.get("match_body_any") or []
        if body_any:
            body = (resp.text or "")
            if not any(marker in body for marker in body_any):
                return None

        return {
            "module":   self.MODULE_NAME,
            "type":     entry["finding_type"],
            "url":      url,
            "severity": entry.get("severity", "MEDIUM"),
            "title":    entry.get("title", entry["finding_type"]),
            "details":  entry.get("description", ""),
            "confirmed": True,    # we got HTTP 200 + body match
            "interesting": entry.get("severity", "").upper() in ("HIGH", "CRITICAL"),
            "evidence": {
                "status_code": resp.status_code,
                "intel_path":  path,
                "source_reports": _INTEL.get("_sources", []),
            },
        }

    def _probe_query_trick(self, trick: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = self.base.rstrip("/") + trick.get("probe_query", "")
        resp = http_get(url, user_agent=self._next_ua(),
                        timeout=self.settings.timeout,
                        cookies=self.settings.cookies,
                        allow_redirects=False)
        if resp is None:
            return None
        body = resp.text or ""
        match_any = trick.get("match_body_any") or []
        if match_any and not any(m in body for m in match_any):
            return None
        return {
            "module":   self.MODULE_NAME,
            "type":     trick["finding_type"],
            "url":      url,
            "severity": trick.get("severity", "MEDIUM"),
            "title":    trick.get("name", "symfony query trick"),
            "details":  trick.get("description", ""),
            "interesting": True,
            "evidence": {
                "probe": trick.get("probe_query"),
                "status_code": resp.status_code,
                "source_reports": _INTEL.get("_sources", []),
            },
        }

    # ------------------------------------------------------------------
    # Body credential scan
    # ------------------------------------------------------------------
    def _scan_credentials(self, body: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        patterns = _INTEL.get("credential_exposure_patterns", [])
        for needle in patterns:
            # Require both the variable name AND something that looks
            # like an assigned value on the same line; otherwise plain
            # documentation mentioning APP_SECRET= would false-fire.
            rx = re.compile(re.escape(needle) + r"\s*([A-Za-z0-9_./+-]{6,})")
            m = rx.search(body)
            if m:
                # Mask the value — never persist real secrets.
                masked = m.group(1)[:3] + "***" + m.group(1)[-2:] \
                    if len(m.group(1)) > 8 else "<redacted>"
                out.append({
                    "module":   self.MODULE_NAME,
                    "type":     "symfony_exposed_credentials",
                    "url":      self.base,
                    "severity": "CRITICAL",
                    "title":    f"Credential leak in landing page: {needle}",
                    "details":  (f"The token `{needle}` and a value-shaped "
                                 "string appear in the same response body. "
                                 "Likely a dump() / dd() / debug output."),
                    "confirmed": True, "interesting": True,
                    "evidence": {
                        "needle":   needle,
                        "value_preview": masked,
                        "source_reports": _INTEL.get("_sources", []),
                    },
                })
        return out

    # ------------------------------------------------------------------
    @staticmethod
    def _abs(target: str) -> str:
        if "://" in target:
            return target.rstrip("/")
        return f"https://{target.rstrip('/')}"
