"""CORS misconfiguration tester."""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from utils.logger import ScanLogger


class CORSTester:
    MODULE_NAME = "cors"

    TEST_ORIGINS = (
        "https://evil.com",
        "https://attacker.example",
        "null",
        "https://evil.{domain}",
        "https://{domain}.evil.com",
    )

    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target if "://" in settings.target \
                      else f"https://{settings.target}"
        self.logger = ScanLogger(settings.output_dir)
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    def run(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        domain = urlparse(self.target).netloc
        for tmpl in self.TEST_ORIGINS:
            origin = tmpl.format(domain=domain)
            f = self._probe(origin)
            if f:
                findings.append(f)
        return {"module": self.MODULE_NAME, "findings": findings}

    def _probe(self, origin: str) -> Optional[Dict[str, Any]]:
        try:
            req = urllib.request.Request(self.target, headers={
                "Origin": origin,
                "User-Agent": self.settings.user_agent,
            })
            if self.settings.cookies:
                req.add_header("Cookie", self.settings.cookies)
            with urllib.request.urlopen(req, timeout=self.settings.timeout) as r:
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
        except urllib.error.HTTPError as e:
            acao = e.headers.get("Access-Control-Allow-Origin", "") if e.headers else ""
            acac = e.headers.get("Access-Control-Allow-Credentials", "") if e.headers else ""
        except Exception as e:
            self.logger.log_error(f"cors probe failed for {origin}: {e}")
            return None

        if acao == origin and acac.lower() == "true":
            return {
                "module": self.MODULE_NAME, "type": "cors_with_credentials",
                "url": self.target, "severity": "CRITICAL",
                "title": f"CORS allows origin '{origin}' WITH credentials",
                "details": "Server reflects arbitrary origins AND allows credentials. "
                           "An attacker can read authenticated responses.",
                "raw": f"ACAO: {acao}\nACAC: {acac}",
                "confirmed": True, "interesting": True,
            }
        if acao == origin:
            return {
                "module": self.MODULE_NAME, "type": "cors_reflection",
                "url": self.target, "severity": "MEDIUM",
                "title": f"CORS reflects arbitrary origin: {origin}",
                "details": "Server reflects origin (no credentials).",
                "raw": f"ACAO: {acao}", "interesting": True,
            }
        if origin == "null" and acao == "null":
            return {
                "module": self.MODULE_NAME, "type": "cors_null_origin",
                "url": self.target, "severity": "HIGH",
                "title": "CORS accepts null origin",
                "details": "Null origin acceptance can enable sandbox bypass",
                "raw": f"ACAO: {acao}", "interesting": True,
            }
        return None
