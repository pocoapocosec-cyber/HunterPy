"""Nuclei integration — opt-in, severity-gated.

Nuclei is the modern replacement for Nikto: community-maintained YAML
templates, low false-positive rate when run with severity filters.

Defaults are conservative on purpose:
  * only critical/high templates run unless --nuclei-medium is set
  * a hard rate limit + concurrency cap, regardless of nuclei's defaults
  * no `intrusive` templates (those send real attack payloads)

Skipped gracefully when nuclei isn't installed.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from config.tool_paths import ToolPathValidator
from utils.logger import ScanLogger
from utils.process_runner import ProcessRunner


class NucleiModule:
    MODULE_NAME = "nuclei"

    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target if "://" in settings.target \
                      else f"https://{settings.target}"
        self.logger = ScanLogger(settings.output_dir)
        self.runner = ProcessRunner()
        self.output_file = os.path.join(settings.output_dir, "nuclei.jsonl")
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    def run(self) -> Dict[str, Any]:
        if not ToolPathValidator.has("nuclei"):
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "nuclei not installed — "
                               "install from https://github.com/projectdiscovery/nuclei"}

        severities = ["critical", "high"]
        if getattr(self.settings, "nuclei_medium", False):
            severities.append("medium")

        cmd = [
            "nuclei",
            "-target", self.target,
            "-jsonl",                                   # newline-delimited JSON
            "-output", self.output_file,
            "-severity", ",".join(severities),
            "-exclude-tags", "intrusive,dos,fuzz",       # never run those
            "-rate-limit", str(self.settings.rate_limit),
            "-concurrency", str(min(self.settings.threads, 25)),
            "-timeout", str(self.settings.timeout),
            "-retries", "1",
            "-silent",
            "-no-color",
            "-disable-update-check",
        ]
        if self.settings.proxy:
            cmd += ["-proxy", self.settings.proxy]

        self.logger.log_command(self.MODULE_NAME, cmd)
        # Real nuclei runs can be long; cap to 5 minutes by default
        timeout = min(getattr(self.settings, "module_timeout", 300) or 300, 300)
        result = self.runner.run(cmd, timeout=timeout)
        if result.get("timed_out"):
            return {"module": self.MODULE_NAME, "findings": [],
                    "error": "nuclei timed out — narrow scope or raise --timeout"}

        findings = self._parse_jsonl(self.output_file)
        return {"module": self.MODULE_NAME, "findings": findings,
                "raw_output_path": self.output_file}

    # ---------- parse ----------
    def _parse_jsonl(self, path: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not os.path.exists(path):
            return out
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    info = rec.get("info") or {}
                    sev = (info.get("severity") or "INFO").upper()
                    out.append({
                        "module": self.MODULE_NAME,
                        "type": "nuclei_match",
                        "url": rec.get("matched-at") or rec.get("host") or self.target,
                        "title": info.get("name") or rec.get("template-id", "nuclei finding"),
                        "severity": sev,
                        "details": info.get("description") or "",
                        "evidence": {
                            "template_id": rec.get("template-id"),
                            "tags": info.get("tags"),
                            "matched_at": rec.get("matched-at"),
                            "matcher_name": rec.get("matcher-name"),
                            "references": info.get("reference"),
                            "cvss": (info.get("classification") or {}).get("cvss-score"),
                            "cve_id": (info.get("classification") or {}).get("cve-id"),
                        },
                        "cvss": float((info.get("classification") or {}).get("cvss-score") or 0),
                        "confirmed": True,
                        "interesting": sev in ("HIGH", "CRITICAL"),
                    })
        except OSError as e:
            self.logger.log_error(f"nuclei parse error: {e}")
        return out
