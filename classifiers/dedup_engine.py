"""Deduplicate findings produced by multiple modules.

Two findings are considered duplicates when they share a normalized
(module, type, url, title) signature. The first one wins; subsequent
duplicates increment a `duplicate_count`.
"""
from __future__ import annotations

from typing import Any, Dict, List


class DedupEngine:
    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Dict[tuple, Dict[str, Any]] = {}
        for f in findings:
            sig = self._signature(f)
            if sig in seen:
                seen[sig]["duplicate_count"] = seen[sig].get("duplicate_count", 1) + 1
                # preserve the higher severity if duplicate has stronger signal
                if self._sev_rank(f.get("severity")) > self._sev_rank(seen[sig].get("severity")):
                    seen[sig]["severity"] = f["severity"]
            else:
                f.setdefault("duplicate_count", 1)
                seen[sig] = f
        return list(seen.values())

    @staticmethod
    def _signature(f: Dict[str, Any]) -> tuple:
        return (
            (f.get("module") or "").lower(),
            (f.get("type") or "").lower(),
            (f.get("url") or "").lower().rstrip("/"),
            (f.get("title") or "").lower()[:120],
        )

    _SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    @classmethod
    def _sev_rank(cls, sev) -> int:
        return cls._SEV_ORDER.get((sev or "INFO").upper(), 0)
