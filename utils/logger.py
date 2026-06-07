"""Per-scan logging + command audit trail."""
from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import List


class ScanLogger:
    """Centralized logging — writes a log file + a commands_run.txt audit trail."""

    def __init__(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        self.output_dir    = output_dir
        self.log_file      = os.path.join(output_dir, "scan.log")
        self.commands_file = os.path.join(output_dir, "commands_run.txt")
        self.logger = logging.getLogger("hunterpy")
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            fh = logging.FileHandler(self.log_file)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s"))
            self.logger.addHandler(fh)

    def log_command(self, module: str, cmd: List[str]) -> None:
        cmd_str = " ".join(str(c) for c in cmd)
        ts = datetime.utcnow().isoformat()
        with open(self.commands_file, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{module}] {cmd_str}\n")
        self.logger.info("[%s] running: %s", module, cmd_str[:200])

    def log_error(self, message: str) -> None:
        self.logger.error(message)

    def log_info(self, message: str) -> None:
        self.logger.info(message)
