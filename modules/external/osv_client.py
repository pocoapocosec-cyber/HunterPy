"""OSV.dev client — vulnerabilities for JS packages discovered in source.

OSV (https://osv.dev) aggregates vulnerability data for open-source
packages (npm, PyPI, Maven, Go, …) under a stable, free, well-documented
JSON API. No API key required.

We use it to enrich JS package versions extracted from `<script>` src
URLs (e.g. /jquery-3.4.1.min.js → query npm for jquery@3.4.1).
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


log = logging.getLogger("hunterpy.osv")


OSV_URL = "https://api.osv.dev/v1/query"

# Patterns to extract (lib, version) from common CDN/script URLs
PACKAGE_PATTERNS = [
    # /jquery-3.4.1.min.js, /jquery@3.4.1/dist/jquery.min.js
    re.compile(r"/(?P<name>[a-z][\w.-]*?)[-@](?P<ver>\d+\.\d+(?:\.\d+)?)"
               r"(?:[./-]|$)", re.I),
    # /js/react.production.min.js?v=18.2.0
    re.compile(r"(?P<name>[a-z][\w.-]*?)\.(?:min|production|development)\.js"
               r"\?v=(?P<ver>\d+\.\d+(?:\.\d+)?)", re.I),
]


class OSVClient:
    """Tiny stdlib OSV.dev client. Caches lookups in-process per scan."""

    def __init__(self, timeout: int = 6):
        self.timeout = timeout
        self._cache: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}

    # ---------- public ----------
    def lookup(self, ecosystem: str, package: str,
               version: str) -> List[Dict[str, Any]]:
        key = (ecosystem, package.lower(), version)
        if key in self._cache:
            return self._cache[key]
        try:
            payload = {
                "version": version,
                "package": {"name": package, "ecosystem": ecosystem},
            }
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                OSV_URL, data=body,
                headers={"Content-Type": "application/json",
                         "User-Agent": "HunterPy/2.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            log.warning("OSV HTTP %s for %s %s", e.code, package, version)
            self._cache[key] = []
            return []
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            log.warning("OSV lookup failed for %s@%s: %s", package, version, e)
            self._cache[key] = []
            return []

        vulns = data.get("vulns", []) or []
        self._cache[key] = vulns
        return vulns

    # ---------- helpers ----------
    @staticmethod
    def extract_packages_from_urls(urls: List[str]
                                   ) -> List[Tuple[str, str, str]]:
        """Return de-duplicated [(name, version, source_url), …]."""
        out: List[Tuple[str, str, str]] = []
        seen = set()
        for url in urls:
            for rx in PACKAGE_PATTERNS:
                m = rx.search(url)
                if not m:
                    continue
                name = m.group("name").lower()
                ver  = m.group("ver")
                key = (name, ver)
                if key in seen:
                    continue
                seen.add(key)
                out.append((name, ver, url))
                break
        return out

    @staticmethod
    def vuln_to_finding(vuln: Dict[str, Any], package: str,
                        version: str, source_url: str) -> Dict[str, Any]:
        aliases = vuln.get("aliases") or []
        cve = next((a for a in aliases if a.startswith("CVE-")), None)

        # OSV's `severity` array contains entries like
        #   {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/..."}
        # The `score` field is the CVSS *vector string*, NOT a numeric
        # base score. We can't compute the real base score without a
        # full CVSS calculator, so we estimate severity from the
        # qualitative label in `database_specific.severity` first
        # (HIGH / MEDIUM / LOW / CRITICAL — provided by GitHub for
        # GHSA entries), and only fall back to a coarse heuristic.
        db_specific_sev = ((vuln.get("database_specific") or {})
                           .get("severity") or "").upper().strip()
        sev = db_specific_sev or "UNKNOWN"

        # Pull the CVSS vector for evidence, but DO NOT pretend it is
        # a base score.
        cvss_vector = ""
        for s in (vuln.get("severity") or []):
            score_str = (s.get("score") or "")
            if score_str.startswith("CVSS:"):
                cvss_vector = score_str
                break

        # Map qualitative label to an approximate numeric for sorting.
        cvss = _label_to_approx_cvss(sev)
        if sev == "UNKNOWN":
            sev = _cvss_to_label(cvss)

        title = vuln.get("summary") or vuln.get("id") or "OSV vulnerability"
        return {
            "module": "osv",
            "type": "cve",
            "url": source_url,
            "title": f"{vuln.get('id')} — {package}@{version}: {title[:80]}",
            "severity": sev,
            "details": (vuln.get("details") or "")[:500],
            "cvss": cvss,
            "confirmed": True,
            "interesting": sev in ("HIGH", "CRITICAL"),
            "evidence": {
                "osv_id": vuln.get("id"),
                "cve_id": cve,
                "package": package,
                "version": version,
                "ecosystem": "npm",
                "cvss_vector": cvss_vector,
                "references": [r.get("url") for r in (vuln.get("references") or [])][:5],
                "fixed_versions": _extract_fixed_versions(vuln),
            },
        }


def _cvss_to_label(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >= 0.1: return "LOW"
    return "INFO"


def _label_to_approx_cvss(label: str) -> float:
    """Approximate numeric CVSS for a qualitative label. We only need
    this for ranking/sorting — never present it as an authoritative
    base score. The real base score is in the CVSS vector string."""
    return {
        "CRITICAL": 9.5,
        "HIGH":     8.0,
        "MEDIUM":   5.5,
        "LOW":      3.0,
        "INFO":     1.0,
        "UNKNOWN":  0.0,
    }.get((label or "").upper(), 0.0)


def _extract_fixed_versions(vuln: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for aff in (vuln.get("affected") or []):
        for r in (aff.get("ranges") or []):
            for ev in (r.get("events") or []):
                if "fixed" in ev:
                    out.append(ev["fixed"])
    return sorted(set(out))


class JSPackageVulnScan:
    """A module-shaped wrapper so the orchestrator can call this like any other."""

    MODULE_NAME = "js_vulns"

    def __init__(self, settings, client: Optional[OSVClient] = None):
        self.settings = settings
        self.client = client or OSVClient()
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    def run(self) -> Dict[str, Any]:
        # Pull first-party JS URLs from the js analyzer's artifact (if it ran)
        js_artifact = (self.context.get("js") or {}).get("javascript") or {}
        urls = (js_artifact.get("first_party_scripts") or []) + \
               (js_artifact.get("third_party_scripts") or [])
        if not urls:
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "no JS files discovered yet"}

        packages = OSVClient.extract_packages_from_urls(urls)
        if not packages:
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "no recognizable JS packages in script URLs"}

        findings: List[Dict[str, Any]] = []
        for pkg, ver, src in packages:
            vulns = self.client.lookup("npm", pkg, ver)
            for v in vulns[:5]:    # cap output noise
                findings.append(OSVClient.vuln_to_finding(v, pkg, ver, src))
        return {"module": self.MODULE_NAME, "findings": findings,
                "packages_checked": [{"name": p, "version": v} for p, v, _ in packages]}
