"""Behavioral baseline analyzer.

Profiles a target's "normal" behavior so later findings can be scored as
*deviations* rather than absolute checks. This is heuristic statistics,
NOT machine learning — we measure response-length / status-code / latency
distributions and detect when something falls outside that envelope.

Why it matters for HunterPy:
  * A 200 OK on /admin means nothing if every random path returns 200.
  * A 50 KB response is "interesting" only if everything else is ~3 KB.
  * Response latency that spikes by 5x on a single endpoint is signal.
"""
from __future__ import annotations

import logging
import statistics
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from utils.http_client import http_get


log = logging.getLogger("hunterpy.baseline")


@dataclass
class Baseline:
    """Snapshot of what 'normal' looks like on this target."""
    samples: int = 0
    status_distribution: Dict[int, int] = field(default_factory=dict)
    length_mean: float = 0.0
    length_stdev: float = 0.0
    length_p95: float = 0.0
    latency_mean_ms: float = 0.0
    latency_stdev_ms: float = 0.0
    common_404_bodies: List[int] = field(default_factory=list)   # body sizes
    server_header: Optional[str] = None
    waf_signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BehaviorAnalyzer:
    """Build + query a baseline for a target."""

    # Random-looking paths to probe — anything that 404s gives us a "baseline
    # 404" signature (length + content type). Anything that 200s on a path
    # this random tells us the app uses wildcard routing.
    PROBE_PATHS = (
        "/", "/hunterpy_baseline_probe_aaa",
        "/_hpy_random_xyz", "/__nonexistent__/",
        "/api/__not_real_endpoint__",
    )

    def __init__(self, settings):
        self.settings = settings
        self.target = self._abs(settings.target)
        self.baseline: Optional[Baseline] = None

    # ---------- public ----------
    def establish(self) -> Baseline:
        """Probe a small set of URLs and compute distribution stats."""
        lengths: List[int] = []
        latencies: List[float] = []
        status_counts: Dict[int, int] = {}
        not_found_lengths: List[int] = []
        server: Optional[str] = None

        probes = [self._probe(p) for p in self.PROBE_PATHS]
        # add 3 random paths to detect wildcard routing
        for _ in range(3):
            probes.append(self._probe(f"/__hpy_{uuid.uuid4().hex[:8]}"))

        for p in probes:
            if not p:
                continue
            status_counts[p["status"]] = status_counts.get(p["status"], 0) + 1
            lengths.append(p["length"])
            latencies.append(p["latency_ms"])
            if p["status"] == 404:
                not_found_lengths.append(p["length"])
            server = server or p.get("server")

        baseline = Baseline(
            samples=len(probes),
            status_distribution=status_counts,
            length_mean=statistics.fmean(lengths) if lengths else 0.0,
            length_stdev=statistics.stdev(lengths) if len(lengths) > 1 else 0.0,
            length_p95=sorted(lengths)[int(len(lengths) * 0.95)] if lengths else 0.0,
            latency_mean_ms=statistics.fmean(latencies) if latencies else 0.0,
            latency_stdev_ms=statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
            common_404_bodies=sorted(set(not_found_lengths)),
            server_header=server,
        )
        self.baseline = baseline
        return baseline

    def score_response(self, status: int, length: int,
                       latency_ms: float = 0.0) -> Dict[str, Any]:
        """Score a single response against the baseline. Returns:
            {anomaly: 0..1, reasons: [...], soft_404: bool, deviation: str}
        """
        if self.baseline is None:
            return {"anomaly": 0.0, "reasons": [], "soft_404": False,
                    "deviation": "no baseline"}

        b = self.baseline
        reasons: List[str] = []
        anomaly = 0.0

        # 1) Soft-404 detection: status 200 but body matches a known 404 size
        soft_404 = False
        if status in (200, 301, 302) and length in b.common_404_bodies:
            soft_404 = True
            reasons.append("body size matches baseline 404 — likely soft-404")
            anomaly = max(anomaly, 0.6)

        # 2) Length deviation (z-score, clipped)
        if b.length_stdev > 0:
            z = abs(length - b.length_mean) / b.length_stdev
            if z >= 3.0:
                reasons.append(f"response length {length} is {z:.1f}σ from baseline")
                anomaly = max(anomaly, min(0.9, z / 5.0))

        # 3) Latency spike
        if latency_ms and b.latency_stdev_ms > 0:
            lz = (latency_ms - b.latency_mean_ms) / b.latency_stdev_ms
            if lz >= 3.0:
                reasons.append(f"latency {latency_ms:.0f}ms is {lz:.1f}σ above baseline")
                anomaly = max(anomaly, 0.5)

        # 4) Unusual status code (rare in baseline)
        total = sum(b.status_distribution.values()) or 1
        seen = b.status_distribution.get(status, 0)
        if seen / total < 0.1 and status >= 400:
            reasons.append(f"status {status} unseen during baseline")
            anomaly = max(anomaly, 0.4)

        deviation = "normal"
        if anomaly >= 0.7:
            deviation = "high"
        elif anomaly >= 0.4:
            deviation = "medium"
        elif anomaly > 0:
            deviation = "low"

        return {"anomaly": round(anomaly, 2), "reasons": reasons,
                "soft_404": soft_404, "deviation": deviation}

    # ---------- helpers ----------
    def _probe(self, path: str) -> Optional[Dict[str, Any]]:
        url = self.target.rstrip("/") + path
        start = time.monotonic()
        r = http_get(url, user_agent=self.settings.user_agent,
                     timeout=self.settings.timeout,
                     allow_redirects=False)
        elapsed_ms = (time.monotonic() - start) * 1000.0
        if r is None:
            return None
        return {
            "url": url,
            "status": r.status_code,
            "length": len(r.text or ""),
            "latency_ms": elapsed_ms,
            "server": r.headers.get("Server") or r.headers.get("server"),
        }

    @staticmethod
    def _abs(target: str) -> str:
        if "://" in target:
            return target.rstrip("/")
        return f"https://{target.rstrip('/')}"
