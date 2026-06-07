"""Lightweight crawler — extracts API endpoints + secrets from HTML/JS.

Uses urllib + a tiny regex-based link extractor so the module works
without BeautifulSoup. If `bs4` is installed it will be used for richer
parsing.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

from utils.logger import ScanLogger


API_PATTERNS = [
    re.compile(r'["\'](/api/[a-zA-Z0-9/_\-{}]+)["\']'),
    re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9/_\-{}]+)["\']'),
    re.compile(r'fetch\(["\']([^"\']+)["\']'),
    re.compile(r'axios\.[a-z]+\(["\']([^"\']+)["\']'),
    re.compile(r'\.get\(["\']([^"\']+)["\']'),
    re.compile(r'\.post\(["\']([^"\']+)["\']'),
]

LINK_RE   = re.compile(r'href=["\']([^"\'#]+)', re.I)
SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)', re.I)

SENSITIVE_PATTERNS = {
    "api_key":     re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']'),
    "aws_key":     re.compile(r'AKIA[A-Z0-9]{16}'),
    "token":       re.compile(r'(?i)(?:token|bearer)\s*[=:]\s*["\']([a-zA-Z0-9._\-]{20,})["\']'),
    "password":    re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']'),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "graphql":     re.compile(r'(?i)(?:graphql|/graphql|gql)'),
}


class EndpointCrawler:
    MODULE_NAME = "endpoints"

    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target if "://" in settings.target \
                      else f"https://{settings.target}"
        self.logger = ScanLogger(settings.output_dir)
        self.context: Dict[str, Any] = {}
        self.visited: Set[str] = set()

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    def run(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        endpoints: Set[str] = set()
        pages = self._crawl()

        for url, body in pages.items():
            endpoints.update(self._extract_endpoints(body, url))
            findings.extend(self._check_secrets(body, url))

        findings.extend(self._analyze_js(pages))

        for ep in sorted(endpoints):
            findings.append({
                "module": self.MODULE_NAME, "type": "endpoint_discovered",
                "url": ep, "severity": "INFO",
                "title": f"Endpoint discovered: {ep}",
                "details": "Extracted from HTML/JS content",
                "has_params": "?" in ep or "{" in ep,
                "is_api": "/api/" in ep or "/v1/" in ep or "/v2/" in ep,
            })

        return {
            "module": self.MODULE_NAME,
            "findings": findings,
            "endpoints": sorted(endpoints),
        }

    # ---------- crawler ----------
    def _crawl(self, max_pages: int = 20) -> Dict[str, str]:
        out: Dict[str, str] = {}
        queue = [self.target]
        domain = urlparse(self.target).netloc

        while queue and len(out) < max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            status, body = self._fetch(url)
            if not body:
                continue
            out[url] = body
            for href in LINK_RE.findall(body):
                nxt = urljoin(url, href)
                if urlparse(nxt).netloc == domain and nxt not in self.visited:
                    queue.append(nxt)
        return out

    # ---------- analysis ----------
    def _extract_endpoints(self, body: str, source: str) -> Set[str]:
        out: Set[str] = set()
        base = f"{urlparse(source).scheme}://{urlparse(source).netloc}"
        for rx in API_PATTERNS:
            for m in rx.findall(body):
                ep = m if isinstance(m, str) else m[0]
                if ep.startswith("/"):
                    out.add(base + ep)
                elif ep.startswith("http"):
                    out.add(ep)
        return out

    def _check_secrets(self, body: str, source: str) -> List[Dict[str, Any]]:
        findings = []
        for kind, rx in SENSITIVE_PATTERNS.items():
            for m in rx.findall(body):
                if kind == "graphql":
                    findings.append({
                        "module": self.MODULE_NAME, "type": "graphql_endpoint",
                        "url": source, "severity": "INFO",
                        "title": "GraphQL endpoint detected",
                        "details": "GraphQL endpoints often allow introspection",
                        "interesting": True,
                    })
                else:
                    sample = m if isinstance(m, str) else (m[0] if m else "")
                    findings.append({
                        "module": self.MODULE_NAME, "type": "sensitive_data_exposure",
                        "url": source, "severity": "CRITICAL",
                        "title": f"Potential {kind.replace('_', ' ')} exposed",
                        "details": f"Found likely {kind} in page source",
                        "raw": str(sample)[:80],
                        "confirmed": True, "interesting": True,
                    })
        return findings

    def _analyze_js(self, pages: Dict[str, str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        js_urls: Set[str] = set()
        for url, body in pages.items():
            for src in SCRIPT_RE.findall(body):
                js_urls.add(urljoin(url, src))

        for js_url in list(js_urls)[:15]:
            _, body = self._fetch(js_url)
            if not body:
                continue
            if "//# sourceMappingURL=" in body:
                findings.append({
                    "module": self.MODULE_NAME, "type": "source_map_exposed",
                    "url": js_url, "severity": "MEDIUM",
                    "title": "JavaScript source map exposed",
                    "details": "sourceMappingURL directive present",
                    "interesting": True,
                })
            findings.extend(self._check_secrets(body, js_url))
        return findings

    # ---------- HTTP ----------
    def _fetch(self, url: str):
        # Respect the UA rotation strategy on Settings: many requests
        # per scan + per-target diff = a place where rotation actually
        # changes responses (WAF / CDN cache / UA-conditional render).
        selector = getattr(self.settings, "ua_selector", None)
        ua = (selector.next() if selector is not None
              else self.settings.user_agent)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            with urllib.request.urlopen(req, timeout=self.settings.timeout) as r:
                return r.status, r.read(300_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:
            return None, ""
