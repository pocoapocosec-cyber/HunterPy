"""Scan session bookkeeping (start/end times, scan_id, target metadata)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.database import Database


class SessionManager:
    """Tracks one scan run from start to finish."""

    def __init__(self, settings, db: Optional[Database] = None):
        self.settings = settings
        self.db = db or Database(settings.db_path)
        self.start_time: datetime = datetime.utcnow()
        self.end_time: Optional[datetime] = None
        self.scan_id: Optional[int] = None
        self.metadata: Dict[str, Any] = {
            "target": settings.target,
            "mode":   settings.mode,
            "modules_run": [],
        }

    def begin(self) -> int:
        self.scan_id = self.db.create_scan(self.settings.target, self.settings.mode)
        self.metadata["scan_id"] = self.scan_id
        self.metadata["start_time"] = self.start_time.isoformat() + "Z"
        return self.scan_id

    def finish(self, status: str = "completed") -> None:
        self.end_time = datetime.utcnow()
        self.metadata["end_time"] = self.end_time.isoformat() + "Z"
        duration = (self.end_time - self.start_time).total_seconds()
        self.metadata["duration"] = f"{int(duration // 60)}m {int(duration % 60)}s"
        if self.scan_id is not None:
            self.db.finalize_scan(self.scan_id, status)

    def record_module(self, name: str) -> None:
        if name not in self.metadata["modules_run"]:
            self.metadata["modules_run"].append(name)

    def save_findings(self, findings: List[Dict[str, Any]]) -> None:
        if self.scan_id is None:
            return
        import logging
        log = logging.getLogger("hunterpy.session")
        failures = 0
        for f in findings:
            try:
                self.db.insert_finding(self.scan_id, f)
            except Exception as e:
                failures += 1
                # Don't log every single failure — that could dump thousands
                # of lines. Log the first one with full detail, then a
                # count at the end.
                if failures == 1:
                    log.warning("insert_finding failed (will count rest): %s "
                                "[finding=%s]", e, f.get("id") or f.get("title"))
        if failures:
            log.warning("save_findings: %d of %d findings failed to persist",
                        failures, len(findings))
