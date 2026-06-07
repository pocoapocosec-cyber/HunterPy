"""Subprocess wrapper with timeout + safe process-group cleanup."""
from __future__ import annotations

import os
import signal
import subprocess
import threading
from typing import Dict, List, Optional


class ProcessRunner:
    """Run CLI tools safely. Returns dict with stdout/stderr/returncode/timed_out."""

    def __init__(self) -> None:
        self.active: List[subprocess.Popen] = []
        self._lock = threading.Lock()

    def run(self, cmd: List[str], timeout: int = 300,
            env: Optional[dict] = None,
            cwd: Optional[str] = None) -> Dict[str, object]:
        result: Dict[str, object] = {
            "stdout": "", "stderr": "", "returncode": -1, "timed_out": False
        }
        try:
            popen_kwargs: dict = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "env": env or os.environ.copy(),
                "cwd": cwd,
            }
            if os.name != "nt":
                popen_kwargs["preexec_fn"] = os.setsid
            proc = subprocess.Popen(cmd, **popen_kwargs)
            with self._lock:
                self.active.append(proc)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                result["stdout"]     = stdout
                result["stderr"]     = stderr
                result["returncode"] = proc.returncode
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                self._kill(proc)
                stdout, stderr = proc.communicate()
                result["stdout"] = stdout or ""
                result["stderr"] = stderr or "timeout"
            finally:
                with self._lock:
                    if proc in self.active:
                        self.active.remove(proc)
        except FileNotFoundError:
            result["stderr"] = f"command not found: {cmd[0]}"
        except PermissionError:
            result["stderr"] = f"permission denied: {cmd[0]}"
        except Exception as e:
            result["stderr"] = str(e)
        return result

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.kill()
        except Exception:
            pass

    def cleanup_all(self) -> None:
        with self._lock:
            for p in self.active:
                self._kill(p)
            self.active.clear()
