"""WFuzz wrapper (no-op when wfuzz not installed)."""
from __future__ import annotations

import os
from typing import Any, Dict, List

from config.tool_paths import ToolPathValidator
from utils.logger import ScanLogger
from utils.process_runner import ProcessRunner


class WFuzzModule:
    MODULE_NAME = "wfuzz"

    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target if "://" in settings.target \
                      else f"https://{settings.target}"
        self.logger = ScanLogger(settings.output_dir)
        self.runner = ProcessRunner()
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    def run(self) -> Dict[str, Any]:
        if not ToolPathValidator.has("wfuzz"):
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "wfuzz not installed"}
        wl = "/usr/share/wfuzz/wordlist/general/common.txt"
        if not os.path.exists(wl):
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "no wfuzz wordlist available"}
        cmd = [
            "wfuzz", "-c", "-z", f"file,{wl}",
            "--hc", "404",
            f"{self.target}/FUZZ",
        ]
        self.logger.log_command(self.MODULE_NAME, cmd)
        out = self.runner.run(cmd, timeout=300)
        findings: List[Dict[str, Any]] = []
        for line in (out.get("stdout") or "").splitlines():
            if line.startswith("0000"):
                findings.append({
                    "module": self.MODULE_NAME,
                    "type": "fuzz_hit",
                    "url": self.target,
                    "title": "WFuzz hit",
                    "severity": "LOW",
                    "details": line.strip(),
                    "raw": line.strip(),
                })
        return {"module": self.MODULE_NAME, "findings": findings}
