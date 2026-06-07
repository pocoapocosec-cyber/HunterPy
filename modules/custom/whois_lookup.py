"""Passive WHOIS lookup. Only reports fields that are reliably present."""
from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, List, Optional

from utils.logger import ScanLogger


log = logging.getLogger("hunterpy.whois")


SAFE_FIELDS = (
    "registrar", "creation_date", "expiration_date", "updated_date",
    "name_servers", "status", "emails", "org", "country",
)


try:
    import whois as _whois        # type: ignore
    _HAVE_WHOIS = True
except ImportError:
    _whois = None
    _HAVE_WHOIS = False


class WhoisLookup:
    MODULE_NAME = "whois_lookup"

    def __init__(self, settings):
        self.settings = settings
        self.target = self._host(settings.target)
        self.logger = ScanLogger(settings.output_dir)
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    def run(self) -> Dict[str, Any]:
        if not _HAVE_WHOIS:
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "python-whois not installed"}

        try:
            raw = _whois.whois(self.target)
        except Exception as e:
            self.logger.log_error(f"[whois] lookup failed: {e}")
            return {"module": self.MODULE_NAME, "findings": [],
                    "error": str(e)}

        cleaned = self._extract(raw)
        findings = self._findings_from(cleaned)
        return {
            "module": self.MODULE_NAME,
            "findings": findings,
            "whois": cleaned,
        }

    # ------------------------------------------------------------------
    def _extract(self, raw) -> Dict[str, Any]:
        out: Dict[str, Any] = {f: None for f in SAFE_FIELDS}
        for field in SAFE_FIELDS:
            try:
                val = getattr(raw, field, None)
            except Exception:
                val = None
            if val is None:
                continue
            if isinstance(val, list):
                val = val[0] if val else None
            if isinstance(val, datetime.datetime):
                val = val.isoformat()
            elif isinstance(val, datetime.date):
                val = val.isoformat()
            out[field] = val
        return out

    def _findings_from(self, w: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if w.get("registrar"):
            findings.append({
                "module": self.MODULE_NAME, "type": "whois_summary",
                "url": self.target, "severity": "INFO",
                "title": f"Registered via {w['registrar']}",
                "details": f"{self.target} (org: {w.get('org') or 'n/a'})",
                "evidence": w,
            })

        exp = self._parse_iso(w.get("expiration_date"))
        if exp:
            days = (exp - datetime.datetime.utcnow()).days
            if days < 30:
                findings.append({
                    "module": self.MODULE_NAME, "type": "domain_expiring",
                    "url": self.target,
                    "severity": "HIGH" if days < 7 else "MEDIUM",
                    "title": f"Domain expires in {days} day(s)",
                    "details": f"Expiration: {w['expiration_date']}",
                    "interesting": True,
                })

        created = self._parse_iso(w.get("creation_date"))
        if created and (datetime.datetime.utcnow() - created).days < 30:
            findings.append({
                "module": self.MODULE_NAME, "type": "recently_registered",
                "url": self.target, "severity": "LOW",
                "title": "Recently registered domain",
                "details": f"Created: {w['creation_date']}",
            })
        return findings

    @staticmethod
    def _parse_iso(value) -> Optional[datetime.datetime]:
        if not value:
            return None
        try:
            return datetime.datetime.fromisoformat(str(value).split("+")[0].split(".")[0])
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _host(target: str) -> str:
        if "://" in target:
            from urllib.parse import urlparse
            return urlparse(target).netloc or target
        return target.rstrip("/")
