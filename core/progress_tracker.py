"""Per-scan progress + module-completion tracker.

Lives outside ``ScannerEngine`` so:
  * the engine doesn't grow a fifth concern (orchestration, DB writes,
    progress, error handling, AND report dispatch was the old shape)
  * the API layer's ``ScanManager`` can poll the same object instead of
    duplicating module-completion counters
  * tests can introspect "what completed?" without spinning up the
    whole engine
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class ProgressTracker:
    """Thread-safe counters + module-completion set.

    `started` and `completed` are independent: a module that ran but
    returned ``{"skipped": ...}`` is `started` but not `completed`.
    Downstream modules consult `completed_modules` via
    ``unmet_module_requirements`` to decide whether to skip.
    """
    total_modules: int = 0
    _started: Set[str] = field(default_factory=set)
    _completed: Set[str] = field(default_factory=set)
    _failed: Dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ---- mutation ----
    def mark_started(self, module: str) -> None:
        with self._lock:
            self._started.add(module)

    def mark_completed(self, module: str) -> None:
        with self._lock:
            self._completed.add(module)

    def mark_failed(self, module: str, reason: str) -> None:
        with self._lock:
            self._failed[module] = reason

    # ---- queries ----
    @property
    def completed_modules(self) -> List[str]:
        with self._lock:
            return sorted(self._completed)

    @property
    def failed_modules(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._failed)

    @property
    def started_count(self) -> int:
        with self._lock:
            return len(self._started)

    @property
    def completed_count(self) -> int:
        with self._lock:
            return len(self._completed)

    @property
    def percent(self) -> int:
        if self.total_modules <= 0:
            return 0
        with self._lock:
            return self._percent_locked()

    def _percent_locked(self) -> int:
        """Compute percent assuming the lock is already held."""
        if self.total_modules <= 0:
            return 0
        return min(100, int(100 * len(self._completed) / self.total_modules))

    # ---- snapshot for API responses / reports ----
    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            return {
                "total_modules":   self.total_modules,
                "started_count":   len(self._started),
                "completed_count": len(self._completed),
                "failed_count":    len(self._failed),
                "percent":         self._percent_locked(),
                "completed":       sorted(self._completed),
                "failed":          dict(self._failed),
            }
