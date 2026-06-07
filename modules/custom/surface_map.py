"""Passive surface mapping.

Extracts from the landing page (and nothing more aggressive):
  * internal / external links
  * subdomains mentioned in the source
  * forms (action, method, field names, hidden fields)
  * URL parameter names found across links
  * status of a small fixed list of common sensitive paths
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from utils.http_client import http_get
from utils.logger import ScanLogger


log = logging.getLogger("hunterpy.surface")


# Strict allow-list — do not extend at runtime
COMMON_SENSITIVE_PATHS = (
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD",
    "/backup/", "/admin/", "/phpinfo.php", "/.htaccess",
    "/wp-config.php", "/config.php",
)

LINK_RE   = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\']', re.I)
FORM_OPEN_RE  = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.I | re.S)
ATTR_RE       = re.compile(r'(\w+)=["\']([^"\']*)["\']')
INPUT_RE      = re.compile(r'<input\b[^>]*?>', re.I)


try:
    from bs4 import BeautifulSoup    # type: ignore
    _HAVE_BS = True
except ImportError:
    BeautifulSoup = None             # type: ignore
    _HAVE_BS = False


class SurfaceMap:
    MODULE_NAME = "surface_map"

    def __init__(self, settings):
        self.settings = settings
        self.target = self._abs(settings.target)
        self.host   = urlparse(self.target).netloc
        self.logger = ScanLogger(settings.output_dir)
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        resp = http_get(self.target, user_agent=self.settings.user_agent,
                        cookies=self.settings.cookies,
                        timeout=self.settings.timeout)
        html = resp.text if resp else ""

        links_int, links_ext = self.extract_links(html, self.target)
        subdomains = self.extract_subdomains(html)
        forms      = self.extract_forms(html)
        params     = self.extract_url_params(links_int + links_ext)
        paths      = self.check_common_paths()

        findings: List[Dict[str, Any]] = []
        for p in paths:
            if p["status_code"] and 200 <= p["status_code"] < 300 and p["has_content"]:
                ftype = ("git_exposed" if ".git" in p["url"] else
                         "env_exposed" if ".env" in p["url"] else
                         "admin_panel" if "admin" in p["url"] else
                         "config_exposed" if "config" in p["url"] else
                         "sensitive_path")
                findings.append({
                    "module": self.MODULE_NAME, "type": ftype,
                    "url": p["url"],
                    "severity": "CRITICAL" if ftype in (
                        "git_exposed", "env_exposed", "config_exposed")
                        else "HIGH",
                    "title": f"Sensitive path reachable: {p['url']}",
                    "details": f"HTTP {p['status_code']} with non-empty body",
                    "status_code": p["status_code"],
                    "interesting": True,
                })

        for form in forms:
            if any(i.get("type") == "password" for i in form["fields"]):
                findings.append({
                    "module": self.MODULE_NAME, "type": "login_form",
                    "url": form.get("action") or self.target,
                    "severity": "INFO",
                    "title": "Login form discovered",
                    "details": f"{form['method']} {form.get('action') or '(self)'}",
                    "evidence": form,
                })

        return {
            "module":     self.MODULE_NAME,
            "findings":   findings,
            "endpoints":  links_int,
            "surface": {
                "internal_links": links_int,
                "external_links": links_ext,
                "subdomains":     subdomains,
                "forms":          forms,
                "url_params":     params,
                "sensitive_paths": paths,
            },
        }

    # ------------------------------------------------------------------
    def extract_links(self, html: str, base: str):
        if not html:
            return [], []
        internal: Set[str] = set()
        external: Set[str] = set()

        if _HAVE_BS:
            try:
                soup = BeautifulSoup(html, "html.parser")
                hrefs = [a.get("href") for a in soup.find_all("a", href=True)]
            except Exception as e:
                self.logger.log_error(f"[surface] bs4 parse failed: {e}")
                hrefs = LINK_RE.findall(html)
        else:
            hrefs = LINK_RE.findall(html)

        for href in hrefs:
            if not href:
                continue
            try:
                absu = urljoin(base, href.strip())
            except Exception:
                continue
            netloc = urlparse(absu).netloc
            if not netloc:
                continue
            if netloc == self.host or netloc.endswith("." + self.host):
                internal.add(absu)
            else:
                external.add(absu)
        return sorted(internal), sorted(external)

    def extract_subdomains(self, html: str) -> List[str]:
        if not html:
            return []
        # NOTE: str.lstrip takes a *set of characters*, not a prefix.
        # "www.example.com".lstrip("www.") happens to work but
        # "web.example.com".lstrip("www.") returns "eb.example.com" — bug.
        base = self.host
        if base.startswith("www."):
            base = base[4:]
        # Match `sub[.sub2].<base>` where each label is 1-63 chars.
        rx = re.compile(
            r"\b([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})*\.)"
            + re.escape(base) + r"\b", re.I
        )
        out: Set[str] = set()
        for m in rx.finditer(html):
            full = m.group(0).lower()
            if full and full != self.host and full != base:
                out.add(full)
        return sorted(out)

    def extract_forms(self, html: str) -> List[Dict[str, Any]]:
        if not html:
            return []
        forms: List[Dict[str, Any]] = []
        if _HAVE_BS:
            try:
                soup = BeautifulSoup(html, "html.parser")
                for f in soup.find_all("form"):
                    fields = []
                    for inp in f.find_all("input"):
                        fields.append({
                            "name":  inp.get("name"),
                            "type":  (inp.get("type") or "text").lower(),
                            "value": inp.get("value"),
                            "hidden": (inp.get("type") or "").lower() == "hidden",
                        })
                    forms.append({
                        "action": urljoin(self.target, f.get("action") or ""),
                        "method": (f.get("method") or "GET").upper(),
                        "fields": fields,
                    })
                return forms
            except Exception as e:
                self.logger.log_error(f"[surface] bs4 form parse failed: {e}")

        # FORM_OPEN_RE captures (attrs_string, inner_html) — far cleaner
        # than the previous approach of re-wrapping the body.
        for attrs_str, body in FORM_OPEN_RE.findall(html):
            attrs = dict(ATTR_RE.findall(attrs_str))
            fields = []
            for inp_html in INPUT_RE.findall(body):
                inp_attrs = dict(ATTR_RE.findall(inp_html))
                fields.append({
                    "name":  inp_attrs.get("name"),
                    "type":  (inp_attrs.get("type") or "text").lower(),
                    "value": inp_attrs.get("value"),
                    "hidden": (inp_attrs.get("type") or "").lower() == "hidden",
                })
            forms.append({
                "action": urljoin(self.target, attrs.get("action", "")),
                "method": (attrs.get("method") or "GET").upper(),
                "fields": fields,
            })
        return forms

    @staticmethod
    def extract_url_params(urls: List[str]) -> List[str]:
        out: Set[str] = set()
        for url in urls:
            try:
                qs = urlparse(url).query
            except Exception:
                continue
            if not qs:
                continue
            for pair in qs.split("&"):
                name = pair.split("=", 1)[0].strip()
                if name:
                    out.add(name)
        return sorted(out)

    def check_common_paths(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        base = self.target.rstrip("/")
        # Per-path UA rotation when the operator opted into it. Many
        # paths in one tight loop is exactly where rotation matters
        # (WAF rate-limit by UA, cache-busting per UA, etc.).
        selector = getattr(self.settings, "ua_selector", None)
        for path in COMMON_SENSITIVE_PATHS:
            full = base + path
            ua = (selector.next() if selector is not None
                  else self.settings.user_agent)
            r = http_get(full, user_agent=ua,
                         timeout=self.settings.timeout,
                         allow_redirects=False)
            if r is None:
                out.append({"url": full, "status_code": None, "has_content": False})
                continue
            out.append({
                "url": full,
                "status_code": r.status_code,
                "has_content": bool(r.text and r.text.strip()),
            })
        return out

    @staticmethod
    def _abs(target: str) -> str:
        if "://" in target:
            return target.rstrip("/")
        return f"https://{target.rstrip('/')}"
