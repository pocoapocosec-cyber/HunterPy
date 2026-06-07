"""Sliding-window rate limiter (thread-safe)."""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque


class RateLimiter:
    """Block calls until quota is available within the rolling window."""

    def __init__(self, max_calls: int, period_sec: float = 1.0):
        self.max = max(1, int(max_calls))
        self.period = float(period_sec)
        self.events: Deque[float] = deque()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        with self.lock:
            now = time.monotonic()
            self._purge(now)
            if len(self.events) >= self.max:
                wait = self.period - (now - self.events[0]) + 0.01
                if wait > 0:
                    time.sleep(wait)
                self._purge(time.monotonic())
            self.events.append(time.monotonic())

    def _purge(self, now: float) -> None:
        while self.events and now - self.events[0] >= self.period:
            self.events.popleft()
