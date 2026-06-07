"""Passive DNS enumeration — A, MX, NS, TXT, CNAME.

Uses dnspython when available; falls back to stdlib socket for A-records
so the module still works without the dep.
"""
from __future__ import annotations

import logging
import socket
from typing import Any, Dict, List, Optional

from utils.logger import ScanLogger


log = logging.getLogger("hunterpy.dns")


try:
    import dns.resolver         # type: ignore
    import dns.exception        # type: ignore
    _HAVE_DNS = True
except ImportError:
    dns = None                  # type: ignore
    _HAVE_DNS = False


class DNSEnum:
    MODULE_NAME = "dns_enum"

    def __init__(self, settings):
        self.settings = settings
        self.target = self._host(settings.target)
        self.logger = ScanLogger(settings.output_dir)
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        records = {
            "a":     self.a_records(),
            "mx":    self.mx_records(),
            "ns":    self.ns_records(),
            "txt":   self.txt_records(),
            "cname": self.cname_record(),
        }
        findings: List[Dict[str, Any]] = []

        if records["a"]:
            findings.append({
                "module": self.MODULE_NAME, "type": "dns_a",
                "url": self.target, "severity": "INFO",
                "title": f"A record(s): {', '.join(records['a'])}",
                "details": f"{self.target} resolves to {', '.join(records['a'])}",
                "evidence": {"records": records["a"]},
            })

        for mx in records["mx"]:
            findings.append({
                "module": self.MODULE_NAME, "type": "dns_mx",
                "url": self.target, "severity": "INFO",
                "title": f"MX: {mx['mail_server']} (pri={mx['priority']})",
                "details": str(mx), "evidence": mx,
            })

        for txt in records["txt"]:
            low = txt.lower()
            if "v=spf1" in low or "v=dmarc1" in low or "v=dkim1" in low:
                findings.append({
                    "module": self.MODULE_NAME, "type": "email_policy",
                    "url": self.target, "severity": "INFO",
                    "title": f"Email policy TXT: {txt[:60]}",
                    "details": txt, "evidence": {"txt": txt},
                })

        # Missing SPF is a passive-safe interesting finding
        if records["txt"] and not any("v=spf1" in t.lower() for t in records["txt"]):
            findings.append({
                "module": self.MODULE_NAME, "type": "missing_spf",
                "url": self.target, "severity": "MEDIUM",
                "title": "No SPF record found",
                "details": "Domain has no SPF TXT record — may be spoofable",
                "interesting": True,
            })

        return {
            "module": self.MODULE_NAME,
            "findings": findings,
            "records": records,
        }

    # ------------------------------------------------------------------
    def a_records(self) -> List[str]:
        if _HAVE_DNS:
            return self._query("A", lambda r: r.to_text())
        try:
            infos = socket.getaddrinfo(self.target, None)
            return sorted({a[4][0] for a in infos})
        except OSError as e:
            self.logger.log_error(f"[dns] A lookup failed: {e}")
            return []

    def mx_records(self) -> List[Dict[str, Any]]:
        if not _HAVE_DNS:
            return []
        try:
            answers = dns.resolver.resolve(self.target, "MX", lifetime=5)
            out = [{"priority": int(a.preference),
                    "mail_server": str(a.exchange).rstrip(".")}
                   for a in answers]
            out.sort(key=lambda x: x["priority"])
            return out
        except Exception as e:
            self._log_dns_error("MX", e)
            return []

    def ns_records(self) -> List[str]:
        return self._query("NS", lambda r: str(r).rstrip("."))

    def txt_records(self) -> List[str]:
        # dnspython returns TXT as bytes joined inside quoted segments
        if not _HAVE_DNS:
            return []
        try:
            answers = dns.resolver.resolve(self.target, "TXT", lifetime=5)
            out = []
            for rdata in answers:
                joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
                out.append(joined)
            return out
        except Exception as e:
            self._log_dns_error("TXT", e)
            return []

    def cname_record(self) -> Optional[str]:
        if not _HAVE_DNS:
            return None
        try:
            answers = dns.resolver.resolve(self.target, "CNAME", lifetime=5)
            for a in answers:
                return str(a.target).rstrip(".")
        except Exception as e:
            self._log_dns_error("CNAME", e)
        return None

    # ------------------------------------------------------------------
    def _query(self, rtype: str, fmt) -> List[str]:
        if not _HAVE_DNS:
            return []
        try:
            answers = dns.resolver.resolve(self.target, rtype, lifetime=5)
            return [fmt(a) for a in answers]
        except Exception as e:
            self._log_dns_error(rtype, e)
            return []

    def _log_dns_error(self, rtype: str, e: Exception) -> None:
        if _HAVE_DNS:
            if isinstance(e, dns.resolver.NXDOMAIN):
                self.logger.log_info(f"[dns] {rtype}: NXDOMAIN")
                return
            if isinstance(e, dns.resolver.NoAnswer):
                self.logger.log_info(f"[dns] {rtype}: no answer")
                return
            if isinstance(e, dns.exception.Timeout):
                self.logger.log_error(f"[dns] {rtype}: timeout")
                return
        self.logger.log_error(f"[dns] {rtype}: {e}")

    @staticmethod
    def _host(target: str) -> str:
        if "://" in target:
            from urllib.parse import urlparse
            return urlparse(target).netloc or target
        return target.rstrip("/")
