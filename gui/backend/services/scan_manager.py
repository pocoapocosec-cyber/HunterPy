"""In-memory scan orchestration for the FastAPI layer.

The CLI's `ScannerEngine` is synchronous and runs every module to completion
before returning. For a web UI we need:

  * background execution (non-blocking POST /api/scans/{id}/start)
  * live progress + log streaming
  * cancellation
  * resume / re-load on process restart (via SQLite, same as the CLI)

This module wraps `ScannerEngine` in a thread-per-scan manager. We do NOT
use asyncio for the scan body because the engine calls into blocking
subprocess wrappers (nmap, nikto, …) that aren't async-aware. Threads
with a process-wide lock are simpler than retrofitting `asyncio.to_thread`
into every module.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

from config.settings import Settings
from core.scanner_engine import ScannerEngine
from utils.database import Database


log = logging.getLogger("hunterpy.api.scan_manager")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------
@dataclass
class ScanRecord:
    """Per-scan state held in memory.

    The SQLite DB still gets the official persistence; this is the live
    snapshot the HTTP layer queries every few seconds. Both stay in sync
    via `update_progress` calls inside the engine wrapper.
    """
    id: str
    db_scan_id: Optional[int]
    target: str
    mode: str
    modules: List[str]
    status: str = "pending"     # pending|running|paused|completed|failed|cancelled
    phase: str = "initialization"
    progress: int = 0
    current_module: Optional[str] = None
    modules_completed: int = 0
    modules_total: int = 0
    findings_count: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_tier: Dict[str, int] = field(default_factory=dict)
    created_at: datetime = field(default_factory=_utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    # Logs are capped (ring buffer) so a long scan can't OOM the API.
    _logs: Deque[str] = field(default_factory=lambda: deque(maxlen=2000))
    # Non-serialisable runtime bits — exposed via dunder so dataclasses.asdict skips them
    _cancel_event: threading.Event = field(default_factory=threading.Event)
    _thread: Optional[threading.Thread] = None

    def append_log(self, line: str) -> None:
        ts = _utcnow().strftime("%H:%M:%S")
        self._logs.append(f"[{ts}] {line}")

    def get_logs(self) -> List[str]:
        return list(self._logs)

    def to_public_dict(self) -> Dict[str, Any]:
        """JSON-safe representation for the HTTP layer."""
        out = {
            "id": self.id,
            "db_scan_id": self.db_scan_id,
            "target": self.target,
            "mode": self.mode,
            "modules": list(self.modules),
            "status": self.status,
            "phase": self.phase,
            "progress": int(self.progress),
            "current_module": self.current_module,
            "modules_completed": self.modules_completed,
            "modules_total": self.modules_total,
            "findings_count": self.findings_count,
            "findings_by_severity": dict(self.findings_by_severity),
            "findings_by_tier": dict(self.findings_by_tier),
            "created_at": self.created_at.isoformat() + "Z",
            "started_at": self.started_at.isoformat() + "Z" if self.started_at else None,
            "completed_at": self.completed_at.isoformat() + "Z" if self.completed_at else None,
            "error": self.error,
            "options": dict(self.options),
        }
        if self.started_at:
            end = self.completed_at or _utcnow()
            out["duration"] = (end - self.started_at).total_seconds()
        return out


# ---------------------------------------------------------------------------
# Manager (singleton-per-process)
# ---------------------------------------------------------------------------
class ScanManager:
    """Thread-safe registry of in-flight + recent scans."""

    def __init__(self, db_path: str = "hunterpy.db"):
        self._lock = threading.RLock()
        self._scans: Dict[str, ScanRecord] = {}
        self._db_path = db_path

    # ---------- CRUD ----------
    def create(self, target: str, mode: str,
               modules: Optional[List[str]] = None,
               options: Optional[Dict[str, Any]] = None) -> ScanRecord:
        scan_id = f"scan_{uuid.uuid4().hex[:10]}"
        rec = ScanRecord(
            id=scan_id,
            db_scan_id=None,
            target=target,
            mode=mode,
            modules=list(modules or []),
            options=dict(options or {}),
        )
        with self._lock:
            self._scans[scan_id] = rec
        rec.append_log(f"scan created for {target} (mode={mode})")
        return rec

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        with self._lock:
            return self._scans.get(scan_id)

    def list(self, status: Optional[str] = None) -> List[ScanRecord]:
        with self._lock:
            items = list(self._scans.values())
        if status:
            items = [s for s in items if s.status == status]
        items.sort(key=lambda r: r.created_at, reverse=True)
        return items

    def delete(self, scan_id: str) -> bool:
        with self._lock:
            rec = self._scans.pop(scan_id, None)
        if rec is None:
            return False
        # Don't kill the thread mid-run — request graceful cancel first.
        if rec._thread and rec._thread.is_alive():
            rec._cancel_event.set()
            rec._thread.join(timeout=5)
        return True

    # ---------- lifecycle ----------
    def start(self, scan_id: str) -> bool:
        rec = self.get(scan_id)
        if rec is None:
            return False
        with self._lock:
            if rec.status == "running":
                return True
            if rec.status in ("completed", "failed", "cancelled"):
                rec.append_log(f"refusing to start; scan is already {rec.status}")
                return False
            rec.status = "running"
            rec.started_at = _utcnow()
            rec._cancel_event.clear()
            t = threading.Thread(
                target=self._run_scan,
                args=(rec,),
                name=f"hunterpy-scan-{scan_id}",
                daemon=True,
            )
            rec._thread = t
            t.start()
        return True

    def cancel(self, scan_id: str) -> bool:
        rec = self.get(scan_id)
        if rec is None or rec.status not in ("running", "paused"):
            return False
        rec._cancel_event.set()
        rec.append_log("cancellation requested")
        # The engine doesn't natively check cancellation; we'll flip the
        # status to cancelled once the current module finishes.
        rec.status = "cancelling"
        return True

    def pause(self, scan_id: str) -> bool:
        # Real pause requires engine cooperation we don't have. Treat as a
        # no-op that the UI can still query; document the limitation.
        rec = self.get(scan_id)
        if rec is None or rec.status != "running":
            return False
        rec.append_log("pause not implemented (engine is synchronous) — no-op")
        return False

    def resume(self, scan_id: str) -> bool:
        return self.start(scan_id)

    # ---------- internal: thread body ----------
    def _run_scan(self, rec: ScanRecord) -> None:
        """Background-thread entry point. Wraps ScannerEngine.run()."""
        try:
            settings = self._build_settings(rec)
            engine = ScannerEngine(settings)
            rec.db_scan_id = engine.db.create_scan(settings.target, settings.mode)
            engine.session.scan_id = rec.db_scan_id
            rec.modules_total = len(settings.modules)

            # Hook into the engine so we can publish progress/logs as
            # modules complete. We monkey-patch `_safe_run` for *this*
            # engine instance only — keeps the patch surface tiny.
            orig_safe_run = engine._safe_run

            def instrumented_safe_run(name, module):
                if rec._cancel_event.is_set():
                    rec.append_log(f"skipping {name} (cancelled)")
                    return {}
                rec.current_module = name
                rec.append_log(f"running module: {name}")
                result = orig_safe_run(name, module)
                rec.modules_completed += 1
                rec.progress = int(
                    100 * rec.modules_completed / max(1, rec.modules_total)
                )
                count = len((result or {}).get("findings", []))
                rec.append_log(f"{name}: {count} findings")
                return result

            engine._safe_run = instrumented_safe_run

            # Run!
            engine.run()

            # Final state
            rec.findings_count = len(engine.all_findings)
            sev: Dict[str, int] = {}
            tier: Dict[str, int] = {}
            for f in engine.all_findings:
                s = (f.get("severity") or "INFO").upper()
                sev[s] = sev.get(s, 0) + 1
                t = (f.get("classification") or "COMMON").upper()
                tier[t] = tier.get(t, 0) + 1
            rec.findings_by_severity = sev
            rec.findings_by_tier = tier

            if rec._cancel_event.is_set():
                rec.status = "cancelled"
            else:
                rec.status = "completed"
            rec.phase = "reporting"
            rec.progress = 100
            rec.completed_at = _utcnow()
            rec.current_module = None
            rec.append_log(f"scan {rec.status}; {rec.findings_count} findings")

        except Exception as e:
            log.exception("scan %s failed", rec.id)
            rec.status = "failed"
            rec.error = str(e)
            rec.completed_at = _utcnow()
            rec.append_log(f"ERROR: {e}")

    def _build_settings(self, rec: ScanRecord) -> Settings:
        """Translate a ScanRecord into a fully populated Settings dataclass."""
        from argparse import Namespace
        # Pull every Settings field from rec.options with safe defaults so a
        # partial UI payload doesn't crash the engine.
        opts = rec.options or {}
        ns = Namespace(
            target=rec.target,
            target_list=None,
            scope=opts.get("scope_file"),
            mode=rec.mode,
            modules=rec.modules or None,
            threads=opts.get("threads", 10),
            timeout=opts.get("timeout", 30),
            rate_limit=opts.get("rate_limit", 10),
            delay=opts.get("delay", 0.1),
            auth_url=opts.get("auth_url"),
            username=opts.get("username"),
            username_list=opts.get("username_list"),
            password_list=opts.get("password_list"),
            proxy=opts.get("proxy"),
            user_agent=opts.get("user_agent"),
            user_agent_preset=opts.get("user_agent_preset"),
            user_agent_pool=opts.get("user_agent_pool"),
            user_agent_file=opts.get("user_agent_file"),
            user_agent_strategy=opts.get("user_agent_strategy", "static"),
            cookies=opts.get("cookies"),
            output=opts.get("output_dir", "./output"),
            format=opts.get("report_format", "all"),
            verbose=opts.get("verbose", False),
            no_color=True,
            headers=opts.get("headers"),
            no_nvd=opts.get("no_nvd", False),
            nvd_offline=opts.get("nvd_offline", False),
            nvd_api_key=opts.get("nvd_api_key"),
            dorks_active=False,
            confirm_dork_scraping=False,
            dork_max_queries=5,
            dork_max_results=10,
            dork_templates=None,
            dork_extra="",
        )
        return Settings(ns)


# ---------------------------------------------------------------------------
# Module-level singleton (FastAPI dependency uses this)
# ---------------------------------------------------------------------------
_SINGLETON: Optional[ScanManager] = None


def get_scan_manager() -> ScanManager:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = ScanManager()
    return _SINGLETON


def reset_for_tests() -> None:
    """Hard-reset used only by the test suite."""
    global _SINGLETON
    _SINGLETON = None
