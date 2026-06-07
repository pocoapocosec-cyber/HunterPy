"""Passive JavaScript analyzer.

Downloads first-party JS files referenced by the landing page, then
flags (does NOT log) sensitive-looking keywords and extracts likely API
endpoints. Concurrent fetching via ThreadPoolExecutor.
"""
from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse

from utils.http_client import http_get
from utils.logger import ScanLogger


log = logging.getLogger("hunterpy.js")


SCRIPT_SRC_RE = re.compile(r'<script[^>]*\bsrc=["\']([^"\']+)["\']', re.I)

# Sensitive keywords to flag (we never log surrounding values verbatim
# for the secret itself — only a short generic context window).
SENSITIVE_KEYWORDS = (
    "api_key", "apikey", "api-key",
    "secret", "secret_key",
    "token", "access_token", "auth_token",
    "password", "passwd", "pwd",
    "admin", "debug", "private_key",
    "aws_access", "aws_secret", "bearer",
)
KEYWORD_RE = re.compile(
    r"(" + "|".join(re.escape(k) for k in SENSITIVE_KEYWORDS) + r")",
    re.I,
)

# Endpoint pattern strictly per the brief
ENDPOINT_RE = re.compile(
    r'["\'](/(?:api|v\d+|graphql)/[^"\'?\s]{1,100})["\']'
)


class JSAnalyzer:
    MODULE_NAME = "js_analyzer"

    def __init__(self, settings):
        self.settings = settings
        self.target = self._abs(settings.target)
        self.host   = urlparse(self.target).netloc
        self.logger = ScanLogger(settings.output_dir)
        self.context: Dict[str, Any] = {}
        self.threads = max(1, min(int(getattr(settings, "threads", 5)), 16))

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        page = http_get(self.target, user_agent=self.settings.user_agent,
                        cookies=self.settings.cookies,
                        timeout=self.settings.timeout)
        if not page or not page.text:
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "could not fetch landing page"}

        first, third = self._discover(page.text)
        contents = self._download_many(first[:25])
        keyword_hits, endpoints = self._analyze(contents)

        findings: List[Dict[str, Any]] = []
        for hit in keyword_hits:
            findings.append({
                "module": self.MODULE_NAME, "type": "sensitive_keyword_in_js",
                "url": hit["file"], "severity": "MEDIUM",
                "title": f"Sensitive keyword '{hit['keyword']}' in JS",
                "details": (f"{hit['file']} line {hit['line']}: "
                            f"...{hit['context']}..."),
                "evidence": hit,
                "interesting": True,
            })
        for ep in endpoints:
            findings.append({
                "module": self.MODULE_NAME, "type": "endpoint_discovered",
                "url": urljoin(self.target, ep),
                "severity": "INFO",
                "title": f"Endpoint referenced in JS: {ep}",
                "details": "Discovered via JS source scanning",
                "is_api": "/api/" in ep or "/v" in ep,
                "evidence": {"path": ep},
            })

        return {
            "module": self.MODULE_NAME,
            "findings": findings,
            "javascript": {
                "first_party_scripts": first,
                "third_party_scripts": third,
                "sensitive_keyword_hits": keyword_hits,
                "endpoints": sorted(endpoints),
            },
            "endpoints": [urljoin(self.target, ep) for ep in endpoints],
        }

    # ------------------------------------------------------------------
    def _discover(self, html: str) -> Tuple[List[str], List[str]]:
        first: Set[str] = set()
        third: Set[str] = set()
        for src in SCRIPT_SRC_RE.findall(html):
            try:
                absu = urljoin(self.target, src.strip())
            except Exception:
                continue
            netloc = urlparse(absu).netloc
            if netloc == self.host or netloc.endswith("." + self.host):
                first.add(absu)
            else:
                third.add(absu)
        return sorted(first), sorted(third)

    def _download_many(self, urls: List[str]) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        if not urls:
            return out
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._fetch_one, u): u for u in urls}
            for fut in as_completed(futures):
                url = futures[fut]
                try:
                    body = fut.result()
                    if body:
                        out.append((url, body))
                except Exception as e:
                    self.logger.log_error(f"[js] download error {url}: {e}")
        return out

    def _fetch_one(self, url: str) -> str:
        r = http_get(url, user_agent=self.settings.user_agent,
                     timeout=self.settings.timeout)
        if not r:
            return ""
        return r.text or ""

    def _analyze(self, files: List[Tuple[str, str]]):
        hits: List[Dict[str, Any]] = []
        endpoints: Set[str] = set()

        for url, body in files:
            try:
                lines = body.splitlines()
                line_starts = [0]
                cum = 0
                for ln in lines:
                    cum += len(ln) + 1
                    line_starts.append(cum)

                for m in KEYWORD_RE.finditer(body):
                    pos = m.start()
                    # find line number via binary search
                    lo, hi = 0, len(line_starts) - 1
                    while lo < hi:
                        mid = (lo + hi) // 2
                        if line_starts[mid + 1] <= pos:
                            lo = mid + 1
                        else:
                            hi = mid
                    line_no = lo + 1
                    start = max(0, pos - 40)
                    end   = min(len(body), pos + 40)
                    snippet = body[start:end].replace("\n", " ").replace("\r", " ")
                    snippet = re.sub(r"\s+", " ", snippet)
                    # Mask anything that looks like a long token
                    snippet = re.sub(r"[A-Za-z0-9_\-]{20,}", "<redacted>", snippet)
                    hits.append({
                        "file":     url,
                        "keyword":  m.group(1).lower(),
                        "line":     line_no,
                        "context":  snippet,
                    })

                for m in ENDPOINT_RE.finditer(body):
                    endpoints.add(m.group(1))
            except Exception as e:
                self.logger.log_error(f"[js] analysis failed for {url}: {e}")

        return hits, endpoints

    @staticmethod
    def _abs(target: str) -> str:
        if "://" in target:
            return target.rstrip("/")
        return f"https://{target.rstrip('/')}"
