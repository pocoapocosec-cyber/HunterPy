"""SQLite persistence wrapper for the scan engine.

Pre-v2.6 the engine called ``self.session.db.save_checkpoint(...)`` and
caught the exception inline. That entangled "did the scan complete?"
logic with "did the checkpoint write?" logic. Pull DB operations into a
thin layer so the engine's `_safe_run` stops being half-orchestration,
half-persistence.

The wrapper is intentionally narrow — only the operations the engine
actually performs. Other DB callers (the CLI's ``--list-scans``,
the API's ``ScanManager``) still use ``utils.database.Database``
directly.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional


log = logging.getLogger("hunterpy.persistence")


class ScanPersistence:
    """Persistence operations the engine needs at scan time."""

    def __init__(self, db, logger=None):
        self.db = db
        self.logger = logger    # optional ScanLogger for log_error()

    def save_checkpoint(self, scan_id: Optional[int], module_name: str,
                        status: str, payload: Dict[str, Any]) -> bool:
        """Persist a module checkpoint. Returns True on success; False on
        failure (logged but never raised — checkpoint failures must not
        abort the scan)."""
        if scan_id is None:
            return False
        try:
            self.db.save_checkpoint(scan_id, module_name, status, payload or {})
            return True
        except Exception as e:
            msg = f"checkpoint failed for {module_name}: {e}"
            log.warning(msg)
            if self.logger is not None:
                try:
                    self.logger.log_error(msg)
                except Exception:
                    log.debug("scan logger also unavailable", exc_info=True)
            return False
