"""NVD 2.0 CVE feed client with on-disk caching and rate limiting.

Falls back to the local static `vulnerability_db.json` when NVD is
unreachable, returns an empty list when nothing matches, and never
crashes a scan if the network is down.

NVD rate limits (per https://nvd.nist.gov/developers/start-here):
  * Without API key: 5 requests / 30 seconds
  * With API key:    50 requests / 30 seconds

To use a key:  export NVD_API_KEY=xxxxxxxx
              or pass api_key=... to NVDClient(...)
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone


def _utcnow() -> datetime:
    """Return naive UTC now (kept naive for sqlite TEXT-column compatibility)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
from typing import Any, Deque, Dict, List, Optional


SIG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "signatures",
)


def _load_static_db() -> Dict[str, Any]:
    try:
        with open(os.path.join(SIG_DIR, "vulnerability_db.json"),
                  "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"cves": [], "eol_software": []}


log = logging.getLogger("hunterpy.nvd")

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_TTL = timedelta(days=1)
USER_AGENT = "HunterPy/1.0 (+https://example.local/legal)"


# ---------- data model ----------
@dataclass
class CVE:
    """Normalized CVE record used downstream by HunterPy modules."""
    cve_id: str
    description: str = ""
    cvss: float = 0.0
    severity: str = "UNKNOWN"          # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    vector: str = ""
    published: Optional[str] = None
    last_modified: Optional[str] = None
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    exploit: str = "moderate"          # heuristic: trivial | moderate | difficult
    source: str = "nvd"                # nvd | static

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------- rate limiter ----------
class _RateLimiter:
    """Sliding-window limiter, thread-safe, blocks until quota available."""

    def __init__(self, max_calls: int, period_sec: float):
        self.max = max_calls
        self.period = period_sec
        self.events: Deque[float] = deque()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        with self.lock:
            now = time.monotonic()
            while self.events and now - self.events[0] >= self.period:
                self.events.popleft()
            if len(self.events) >= self.max:
                sleep_for = self.period - (now - self.events[0]) + 0.05
                log.debug("NVD rate limit: sleeping %.2fs", sleep_for)
                time.sleep(max(0.0, sleep_for))
                # purge again post-sleep
                now = time.monotonic()
                while self.events and now - self.events[0] >= self.period:
                    self.events.popleft()
            self.events.append(time.monotonic())


# ---------- main client ----------
class NVDClient:
    """Tiny stdlib NVD 2.0 client with SQLite cache + offline fallback."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        db_path: Optional[str] = None,
        cache_ttl: timedelta = DEFAULT_CACHE_TTL,
        timeout: int = 10,
        offline: bool = False,
    ):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.offline = offline
        max_calls = 50 if self.api_key else 5
        self.limiter = _RateLimiter(max_calls=max_calls, period_sec=30.0)

        # Independent connection so we don't fight the orchestrator's DB handle
        self.db_path = db_path or "hunterpy.db"
        self._init_cache()
        self._static_db = _load_static_db()

    # ---------- cache plumbing ----------
    def _conn(self) -> sqlite3.Connection:
        # Per-call connection keeps us thread-safe & avoids cross-thread errors
        return sqlite3.connect(self.db_path, timeout=5)

    def _init_cache(self) -> None:
        with self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS nvd_cache (
                    query_key  TEXT PRIMARY KEY,
                    payload    TEXT NOT NULL,
                    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def _cache_get(self, key: str) -> Optional[List[CVE]]:
        with self._conn() as c:
            row = c.execute(
                "SELECT payload, fetched_at FROM nvd_cache WHERE query_key=?",
                (key,),
            ).fetchone()
        if not row:
            return None
        payload, fetched_at = row
        try:
            fetched_dt = datetime.fromisoformat(fetched_at)
        except ValueError:
            fetched_dt = _utcnow() - self.cache_ttl - timedelta(seconds=1)
        if _utcnow() - fetched_dt > self.cache_ttl:
            return None
        try:
            return [CVE(**c) for c in json.loads(payload)]
        except (ValueError, TypeError):
            return None

    def _cache_put(self, key: str, cves: List[CVE]) -> None:
        with self._conn() as c:
            c.execute(
                "REPLACE INTO nvd_cache (query_key, payload, fetched_at) VALUES (?,?,?)",
                (key, json.dumps([cve.to_dict() for cve in cves]),
                 _utcnow().isoformat()),
            )

    def clear_cache(self) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM nvd_cache")

    # ---------- public API ----------
    def search_by_keyword(
        self,
        keyword: str,
        limit: int = 20,
        min_cvss: float = 0.0,
    ) -> List[CVE]:
        """Find CVEs matching a keyword (e.g. 'apache 2.4.41')."""
        if not keyword.strip():
            return []
        key = f"kw:{keyword.lower()}:{limit}:{min_cvss}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        if self.offline:
            return self._static_fallback(keyword, min_cvss)

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 50),
        }
        try:
            data = self._request(params)
            cves = self._parse_nvd_response(data)
            cves = [c for c in cves if c.cvss >= min_cvss][:limit]
            self._cache_put(key, cves)
            return cves
        except Exception as e:
            log.warning("NVD query failed (%s); falling back to static DB", e)
            return self._static_fallback(keyword, min_cvss)

    def get_cve(self, cve_id: str) -> Optional[CVE]:
        """Fetch a single CVE record by ID."""
        cve_id = cve_id.upper().strip()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
            raise ValueError(f"Invalid CVE id: {cve_id!r}")
        key = f"id:{cve_id}"
        cached = self._cache_get(key)
        if cached:
            return cached[0]
        if self.offline:
            return None
        try:
            data = self._request({"cveId": cve_id})
            cves = self._parse_nvd_response(data)
            if cves:
                self._cache_put(key, cves[:1])
                return cves[0]
            return None
        except Exception as e:
            log.warning("NVD get_cve(%s) failed: %s", cve_id, e)
            return None

    def lookup_product(
        self,
        product: str,
        version: Optional[str] = None,
        limit: int = 20,
        min_cvss: float = 0.0,
    ) -> List[CVE]:
        """Convenience helper used by tech_detector."""
        kw = f"{product} {version}".strip() if version else product
        return self.search_by_keyword(kw, limit=limit, min_cvss=min_cvss)

    # ---------- HTTP ----------
    def _request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self.limiter.acquire()
        url = f"{NVD_ENDPOINT}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        if self.api_key:
            req.add_header("apiKey", self.api_key)
        log.debug("NVD GET %s", url)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 429:                       # rate-limited despite limiter
                time.sleep(6.0)
                return self._request(params)
            raise
        try:
            return json.loads(body)
        except ValueError as e:
            raise RuntimeError(f"NVD returned non-JSON: {e}")

    # ---------- parsing ----------
    @staticmethod
    def _parse_nvd_response(data: Dict[str, Any]) -> List[CVE]:
        out: List[CVE] = []
        for item in (data.get("vulnerabilities") or []):
            c = item.get("cve") or {}
            cve_id = c.get("id", "")
            if not cve_id:
                continue

            descriptions = c.get("descriptions") or []
            desc = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                "",
            )

            cvss, severity, vector = NVDClient._extract_metrics(c.get("metrics") or {})

            refs = [r.get("url", "") for r in (c.get("references") or [])][:5]
            cwes: List[str] = []
            for w in (c.get("weaknesses") or []):
                for d in (w.get("description") or []):
                    val = d.get("value", "")
                    if val.startswith("CWE-"):
                        cwes.append(val)

            out.append(CVE(
                cve_id=cve_id,
                description=desc,
                cvss=cvss,
                severity=severity,
                vector=vector,
                published=c.get("published"),
                last_modified=c.get("lastModified"),
                references=refs,
                cwe_ids=sorted(set(cwes)),
                exploit=NVDClient._guess_exploit(cvss, vector),
                source="nvd",
            ))
        # Sort by CVSS descending so callers get the worst first
        out.sort(key=lambda x: x.cvss, reverse=True)
        return out

    @staticmethod
    def _extract_metrics(metrics: Dict[str, Any]):
        """Prefer CVSS v3.1 > v3.0 > v2.0."""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if not arr:
                continue
            entry = arr[0].get("cvssData") or {}
            return (
                float(entry.get("baseScore", 0.0)),
                str(arr[0].get("baseSeverity")
                    or entry.get("baseSeverity")
                    or "UNKNOWN").upper(),
                str(entry.get("vectorString", "")),
            )
        return 0.0, "UNKNOWN", ""

    @staticmethod
    def _guess_exploit(cvss: float, vector: str) -> str:
        """Cheap heuristic for the scorer's exploit_level field."""
        v = (vector or "").upper()
        network    = "AV:N" in v
        no_priv    = "PR:N" in v
        no_user    = "UI:N" in v
        if network and no_priv and no_user and cvss >= 7.0:
            return "trivial"
        if cvss >= 6.0:
            return "moderate"
        return "difficult"

    # ---------- static fallback ----------
    def _static_fallback(self, keyword: str, min_cvss: float) -> List[CVE]:
        kw = keyword.lower()
        out: List[CVE] = []
        for entry in self._static_db.get("cves", []):
            if entry["product"] in kw and entry["cvss"] >= min_cvss:
                out.append(CVE(
                    cve_id=entry["cve"],
                    description=f"{entry['product']} <{entry['version_lt']}",
                    cvss=float(entry["cvss"]),
                    severity=NVDClient._severity_label(entry["cvss"]),
                    exploit=entry.get("exploit", "moderate"),
                    source="static",
                ))
        return out

    @staticmethod
    def _severity_label(cvss: float) -> str:
        if cvss >= 9.0: return "CRITICAL"
        if cvss >= 7.0: return "HIGH"
        if cvss >= 4.0: return "MEDIUM"
        if cvss >= 0.1: return "LOW"
        return "UNKNOWN"
