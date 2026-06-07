"""FFUF wrapper (skipped gracefully when ffuf is not installed)."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from config.tool_paths import ToolPathValidator
from utils.logger import ScanLogger
from utils.process_runner import ProcessRunner


class FFUFModule:
    MODULE_NAME = "ffuf"

    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target if "://" in settings.target \
                      else f"https://{settings.target}"
        self.logger = ScanLogger(settings.output_dir)
        self.runner = ProcessRunner()
        self.context: Dict[str, Any] = {}
        self.output_dir = settings.output_dir

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    def run(self) -> Dict[str, Any]:
        if not ToolPathValidator.has("ffuf"):
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "ffuf not installed"}

        wordlist = self._find_wordlist([
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ])
        if not wordlist:
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "no wordlist available"}

        out_file = os.path.join(self.output_dir, "ffuf_dirs.json")
        cmd = [
            "ffuf",
            "-u", f"{self.target}/FUZZ",
            "-w", wordlist,
            "-o", out_file, "-of", "json",
            "-t", str(self.settings.threads),
            "-timeout", str(self.settings.timeout),
            "-rate", str(self.settings.rate_limit),
            "-mc", "200,201,301,302,401,403",
            "-ac",
        ]
        if self.settings.proxy:
            cmd += ["-x", self.settings.proxy]
        if self.settings.cookies:
            cmd += ["-b", self.settings.cookies]

        self.logger.log_command(self.MODULE_NAME, cmd)
        self.runner.run(cmd, timeout=600)
        findings = self._parse_json(out_file, "directory")
        return {"module": self.MODULE_NAME, "findings": findings,
                "endpoints": [f["url"] for f in findings]}

    @staticmethod
    def _find_wordlist(paths: List[str]) -> str:
        for p in paths:
            if os.path.exists(p):
                return p
        return ""

    def _parse_json(self, json_file: str, kind: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not os.path.exists(json_file):
            return out
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            self.logger.log_error(f"ffuf parse error: {e}")
            return out
        for r in data.get("results", []):
            out.append({
                "module": self.MODULE_NAME,
                "type": f"ffuf_{kind}",
                "url": r.get("url", ""),
                "title": f"FFUF found {kind}: {r.get('input', {}).get('FUZZ', '')}",
                "severity": "LOW",
                "details": {"status": r.get("status"), "length": r.get("length")},
                "status_code": r.get("status"),
                "raw": str(r)[:300],
            })
        return out
