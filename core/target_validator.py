"""Target validation & scope checking.

Re-exports TargetValidator from utils.validators (kept for backwards
compatibility) and adds optional scope-file enforcement.
"""
from __future__ import annotations

import os
from typing import List, Optional
from urllib.parse import urlparse

from utils.validators import TargetValidator as _BaseValidator


class TargetValidator:
    """Wraps the base validator with optional scope-file restrictions."""

    def __init__(self, scope_file: Optional[str] = None):
        self._base = _BaseValidator()
        self.scope_domains: List[str] = []
        if scope_file and os.path.exists(scope_file):
            with open(scope_file, "r", encoding="utf-8") as fh:
                self.scope_domains = [
                    ln.strip().lower()
                    for ln in fh
                    if ln.strip() and not ln.startswith("#")
                ]

    def validate(self, target: str) -> bool:
        """Return True if target passes safety + scope checks."""
        try:
            cleaned = self._base.validate(self._strip_scheme(target))
        except ValueError:
            return False
        return self._in_scope(cleaned)

    def validate_and_normalize(self, target: str) -> str:
        """Validate and return the normalized hostname. Raises ValueError."""
        cleaned = self._base.validate(self._strip_scheme(target))
        if not self._in_scope(cleaned):
            raise ValueError(f"Target {cleaned!r} is out of scope.")
        return cleaned

    # ---------- helpers ----------
    @staticmethod
    def _strip_scheme(target: str) -> str:
        if "://" in target:
            return urlparse(target).netloc or target
        return target

    def _in_scope(self, target: str) -> bool:
        if not self.scope_domains:
            return True
        return any(target == d or target.endswith("." + d)
                   for d in self.scope_domains)
