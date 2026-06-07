"""HTTP security header analyzer (pure-Python, no CLI tools needed)."""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any, Dict, List
from urllib.parse import urlparse

from utils.logger import ScanLogger


SECURITY_HEADERS = {
    "content-security-policy":   {"desc": "Content Security Policy", "severity": "HIGH",
                                  "msg": "No CSP header — XSS attacks possible"},
    "x-frame-options":           {"desc": "Clickjacking Protection", "severity": "MEDIUM",
                                  "msg": "Missing X-Frame-Options — clickjacking possible"},
    "x-content-type-options":    {"desc": "MIME Sniffing Protection", "severity": "LOW",
                                  "msg": "Missing X-Content-Type-Options"},
    "strict-transport-security": {"desc": "HSTS", "severity": "HIGH",
                                  "msg": "Missing HSTS — HTTPS not enforced"},
    "x-xss-protection":          {"desc": "XSS Protection (legacy)", "severity": "LOW",
                                  "msg": "Missing X-XSS-Protection"},
    "referrer-policy":           {"desc": "Referrer Policy", "severity": "LOW",
                                  "msg": "Missing Referrer-Policy"},
    "permissions-policy":        {"desc": "Permissions Policy", "severity": "LOW",
                                  "msg": "Missing Permissions-Policy"},
}

INFO_DISCLOSURE_HEADERS = {
    "server":               "Server version disclosed",
    "x-powered-by":         "Technology stack exposed",
    "x-aspnet-version":     "ASP.NET version exposed",
    "x-aspnetmvc-version":  "ASP.NET MVC version exposed",
    "x-generator":          "Generator disclosed",
}


class HeaderAnalyzer:
    MODULE_NAME = "headers"

    def __init__(self, settings):
        self.settings = settings
        self.target = self._normalize(settings.target)
        self.logger = ScanLogger(settings.output_dir)
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    # ---------- main entry ----------
    def run(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        headers: Dict[str, str] = {}
        cookies: List[Dict[str, Any]] = []
        try:
            status, headers, raw_cookies, _ = self._fetch(self.target)
            if status is None:
                raise RuntimeError("could not reach target")
            findings.extend(self._missing_headers(headers))
            findings.extend(self._info_disclosure(headers))
            findings.extend(self._interesting_values(headers))
            if "content-security-policy" in headers:
                findings.extend(self._analyze_csp(headers["content-security-policy"]))
            if "strict-transport-security" in headers:
                findings.extend(self._analyze_hsts(headers["strict-transport-security"]))
            cookies = self._analyze_cookies(raw_cookies)
            findings.extend(self._cookie_findings(cookies))
        except Exception as e:
            self.logger.log_error(f"header analysis failed: {e}")
        return {
            "module": self.MODULE_NAME,
            "findings": findings,
            "headers": headers,
            "cookies": cookies,
        }

    # ---------- cookie analysis ----------
    @staticmethod
    def _analyze_cookies(raw_set_cookies: List[str]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for raw in raw_set_cookies or []:
            try:
                first, *attrs = [p.strip() for p in raw.split(";") if p.strip()]
                if "=" not in first:
                    continue
                name = first.split("=", 1)[0].strip()
                attr_lower = [a.lower() for a in attrs]
                samesite = None
                for a in attrs:
                    if "=" in a and a.lower().startswith("samesite"):
                        samesite = a.split("=", 1)[1].strip()
                out.append({
                    "name": name,
                    "httponly": any(a == "httponly" for a in attr_lower),
                    "secure":   any(a == "secure"   for a in attr_lower),
                    "samesite": samesite,
                    "raw_attrs": attrs,
                })
            except Exception:
                continue
        return out

    def _cookie_findings(self, cookies) -> List[Dict[str, Any]]:
        out = []
        for c in cookies:
            missing = []
            if not c["httponly"]: missing.append("HttpOnly")
            if not c["secure"]:   missing.append("Secure")
            if not c["samesite"]: missing.append("SameSite")
            if missing:
                out.append({
                    "module": self.MODULE_NAME, "type": "weak_cookie",
                    "url": self.target,
                    "severity": "MEDIUM" if "Secure" in missing else "LOW",
                    "title": f"Cookie '{c['name']}' missing {' + '.join(missing)}",
                    "details": f"Cookie attributes: {', '.join(c['raw_attrs']) or '(none)'}",
                    "evidence": {"name": c["name"], "missing_flags": missing},
                })
        return out

    # ---------- checks ----------
    def _missing_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        out = []
        for h, info in SECURITY_HEADERS.items():
            if h not in headers:
                out.append({
                    "module": self.MODULE_NAME,
                    "type": "missing_security_header",
                    "url": self.target,
                    "title": f"Missing security header: {info['desc']}",
                    "severity": info["severity"],
                    "details": info["msg"],
                    "header_name": h,
                    "raw": f"header '{h}' not present",
                    "common_finding": True,
                })
        return out

    def _info_disclosure(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        out = []
        for h, desc in INFO_DISCLOSURE_HEADERS.items():
            if h not in headers:
                continue
            val = headers[h]
            out.append({
                "module": self.MODULE_NAME,
                "type": "info_disclosure_header",
                "url": self.target,
                "title": f"Information disclosure: {h}",
                "severity": "LOW",
                "details": f"{desc}: {val}",
                "header_name": h,
                "header_value": val,
                "raw": f"{h}: {val}",
                "interesting_if_version": any(c.isdigit() for c in val),
            })
        return out

    def _interesting_values(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        out = []
        if headers.get("access-control-allow-origin") == "*":
            out.append({
                "module": self.MODULE_NAME,
                "type": "cors_wildcard",
                "url": self.target,
                "title": "CORS wildcard origin allowed",
                "severity": "MEDIUM",
                "details": "Access-Control-Allow-Origin: * allows any origin",
                "raw": "access-control-allow-origin: *",
                "interesting": True,
            })
        return out

    def _analyze_csp(self, csp: str) -> List[Dict[str, Any]]:
        weak = {
            "unsafe-inline": ("HIGH", "CSP allows unsafe-inline scripts — XSS risk"),
            "unsafe-eval":   ("HIGH", "CSP allows unsafe-eval — XSS risk"),
            "data:":         ("MEDIUM", "CSP allows data: URIs"),
            "*":             ("HIGH", "CSP wildcard source allows any domain"),
        }
        out = []
        for needle, (sev, msg) in weak.items():
            if needle in csp:
                out.append({
                    "module": self.MODULE_NAME,
                    "type": "weak_csp",
                    "url": self.target,
                    "title": f"Weak CSP directive: {needle}",
                    "severity": sev,
                    "details": msg,
                    "raw": f"Content-Security-Policy: {csp}",
                    "interesting": True,
                })
        return out

    def _analyze_hsts(self, hsts: str) -> List[Dict[str, Any]]:
        out = []
        if "max-age=" in hsts:
            try:
                age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                if age < 15_768_000:
                    out.append({
                        "module": self.MODULE_NAME,
                        "type": "weak_hsts",
                        "url": self.target,
                        "title": "Short HSTS max-age",
                        "severity": "LOW",
                        "details": f"HSTS max-age={age} (recommended ≥ 31536000)",
                        "raw": f"Strict-Transport-Security: {hsts}",
                    })
            except ValueError:
                pass
        if "includesubdomains" not in hsts.lower():
            out.append({
                "module": self.MODULE_NAME,
                "type": "hsts_no_subdomains",
                "url": self.target,
                "title": "HSTS missing includeSubDomains",
                "severity": "LOW",
                "details": "HSTS policy does not cover subdomains",
                "raw": f"Strict-Transport-Security: {hsts}",
            })
        return out

    # ---------- HTTP ----------
    @staticmethod
    def _normalize(target: str) -> str:
        if target.startswith(("http://", "https://")):
            return target.rstrip("/")
        return f"https://{target.rstrip('/')}"

    def _fetch(self, url: str):
        # Use the shared HTTP helper so we get a uniform Set-Cookie list
        from utils.http_client import http_get
        merged = dict(self.settings.custom_headers or {})
        r = http_get(url,
                     headers=merged,
                     cookies=self.settings.cookies,
                     user_agent=self.settings.user_agent,
                     timeout=self.settings.timeout)
        if not r:
            return None, {}, [], ""
        lower = {k.lower(): v for k, v in (r.headers or {}).items()}
        return r.status_code, lower, list(r.raw_set_cookie or []), r.text or ""
