"""SQLite persistence for scans, findings, resume checkpoints, and NVD cache."""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    start_time  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time    TIMESTAMP,
    status      TEXT CHECK(status IN ('running','completed','failed','partial')),
    scan_mode   TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_uid      TEXT,
    scan_id          INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module           TEXT NOT NULL,
    classification   TEXT CHECK(classification IN ('FALSE_ALARM','COMMON','INTERESTING')),
    severity         TEXT,
    title            TEXT,
    url              TEXT,
    description      TEXT,
    raw_data         TEXT,
    confidence       REAL,
    score            REAL,
    is_false_positive INTEGER DEFAULT 0,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_checkpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module_name TEXT NOT NULL,
    status      TEXT,
    payload     TEXT,
    saved_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nvd_cache (
    query_key   TEXT PRIMARY KEY,
    payload     TEXT NOT NULL,
    fetched_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_scan           ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_classification ON findings(classification);
CREATE INDEX IF NOT EXISTS idx_findings_severity       ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_checkpoints_scan        ON scan_checkpoints(scan_id);
"""


class Database:
    """Plain SQLite wrapper. Findings are stored as dicts (no dataclass coupling)."""

    def __init__(self, db_path: str = "hunterpy.db"):
        self.path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---------- scans ----------
    def create_scan(self, target: str, mode: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (target, scan_mode, status) VALUES (?, ?, 'running')",
            (target, mode),
        )
        self.conn.commit()
        return cur.lastrowid

    def finalize_scan(self, scan_id: int, status: str) -> None:
        self.conn.execute(
            "UPDATE scans SET status=?, end_time=CURRENT_TIMESTAMP WHERE id=?",
            (status, scan_id),
        )
        self.conn.commit()

    def list_scans(self) -> List[Dict[str, Any]]:
        cur = self.conn.execute(
            "SELECT id, target, start_time, end_time, status, scan_mode "
            "FROM scans ORDER BY id DESC"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        cur = self.conn.execute(
            "SELECT id, target, scan_mode, status FROM scans WHERE id=?", (scan_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return {"id": row[0], "target": row[1], "mode": row[2], "status": row[3]}

    # ---------- findings ----------
    def insert_finding(self, scan_id: int, f: Dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT INTO findings
               (finding_uid, scan_id, module, classification, severity, title, url,
                description, raw_data, confidence, score, is_false_positive)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f.get("id") or f.get("finding_uid"),
                scan_id,
                f.get("module", "unknown"),
                f.get("classification", "COMMON"),
                f.get("severity", "INFO"),
                f.get("title", ""),
                f.get("url", ""),
                str(f.get("details", "") or f.get("description", "")),
                json.dumps(f.get("details", {}), default=str),
                float(f.get("classification_confidence", f.get("confidence", 0.0)) or 0.0),
                float(f.get("score", 0.0)),
                1 if f.get("classification") == "FALSE_ALARM" else 0,
            ),
        )
        self.conn.commit()

    # ---------- checkpoints ----------
    def save_checkpoint(self, scan_id: int, module_name: str,
                        status: str, payload: Dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT INTO scan_checkpoints (scan_id, module_name, status, payload)
               VALUES (?, ?, ?, ?)""",
            (scan_id, module_name, status, json.dumps(payload, default=str)),
        )
        self.conn.commit()

    def get_completed_modules(self, scan_id: int) -> List[str]:
        cur = self.conn.execute(
            "SELECT module_name FROM scan_checkpoints "
            "WHERE scan_id=? AND status='completed'",
            (scan_id,),
        )
        return [r[0] for r in cur.fetchall()]

    def close(self) -> None:
        self.conn.close()
