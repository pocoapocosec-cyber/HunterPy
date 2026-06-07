"""SQLMap wrapper. Conservative defaults; no destructive flags."""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Tuple

from config.tool_paths import ToolPathValidator
from utils.logger import ScanLogger
from utils.process_runner import ProcessRunner


class SQLMapModule:
    MODULE_NAME = "sqlmap"

    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target if "://" in settings.target \
                      else f"https://{settings.target}"
        self.logger = ScanLogger(settings.output_dir)
        self.runner = ProcessRunner()
        self.output_dir = os.path.join(settings.output_dir, "sqlmap")
        os.makedirs(self.output_dir, exist_ok=True)
        self.additional_targets: List[str] = []
        self.context: Dict[str, Any] = {}

    def set_targets(self, urls: List[str]) -> None:
        self.additional_targets = urls

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    # ---------- entry ----------
    def run(self) -> Dict[str, Any]:
        if not ToolPathValidator.has("sqlmap"):
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "sqlmap not installed"}

        candidates = list(set([self.target] + self.additional_targets))
        testable = [u for u in candidates if "?" in u or self._likely_form(u)]
        if not testable:
            testable = [self.target]

        findings: List[Dict[str, Any]] = []
        for url in testable[:5]:
            cmd = self._cmd(url)
            self.logger.log_command(self.MODULE_NAME, cmd)
            result = self.runner.run(cmd, timeout=600)
            findings.extend(self._parse(result.get("stdout", ""), url))
        return {"module": self.MODULE_NAME, "findings": findings}

    # Per-mode (level, risk) defaults. Level controls how many payloads
    # are tested per parameter; risk controls how dangerous the payloads
    # can get (stacked queries, time-based heavy delays, etc.). Pre-v2.6
    # everything ran at (1, 1) — that's "quick triage" and misses most
    # real-world blind / second-order / JSON-based SQLi. Bumping
    # `standard` to (2, 1) and `full` to (3, 2) tracks what an
    # experienced pentester runs on a paid engagement.
    _MODE_LEVEL_RISK = {
        "passive":     (1, 1),
        "quick":       (1, 1),
        "best-effort": (1, 1),
        "stealth":     (1, 1),
        "standard":    (2, 1),
        "full":        (3, 2),
        "strict":      (3, 2),
    }

    def _resolve_level_risk(self) -> Tuple[int, int]:
        """Resolve (level, risk) from settings overrides + mode preset."""
        default_lvl, default_risk = self._MODE_LEVEL_RISK.get(
            self.settings.mode, (1, 1))
        lvl = getattr(self.settings, "sqlmap_level", None) or default_lvl
        risk = getattr(self.settings, "sqlmap_risk", None) or default_risk
        # Clamp to sqlmap's valid ranges (level 1-5, risk 1-3).
        return max(1, min(5, int(lvl))), max(1, min(3, int(risk)))

    def _cmd(self, url: str) -> List[str]:
        level, risk = self._resolve_level_risk()
        cmd = [
            "sqlmap", "-u", url, "--batch",
            "--level", str(level), "--risk", str(risk),
            "--output-dir", self.output_dir,
            "--timeout", str(self.settings.timeout),
            "--retries", "2",
            "--threads", str(min(self.settings.threads, 10)),
            "--forms", "--crawl", "2",
            "--random-agent",
        ]
        if self.settings.proxy:
            cmd += ["--proxy", self.settings.proxy]
        if self.settings.cookies:
            cmd += ["--cookie", self.settings.cookies]
        if self.settings.mode == "stealth":
            cmd += ["--delay", "2", "--safe-freq", "3"]
        return cmd

    @staticmethod
    def _likely_form(url: str) -> bool:
        return any(k in url.lower() for k in
                   ("login", "search", "contact", "register",
                    "submit", "comment", "order", "checkout"))

    # ---------- parse ----------
    def _parse(self, stdout: str, url: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if "sqlmap identified the following injection point" in stdout:
            out.append({
                "module": self.MODULE_NAME, "type": "sql_injection",
                "url": url, "severity": "CRITICAL",
                "title": "SQL injection confirmed",
                "details": self._extract_details(stdout),
                "confirmed": True, "interesting": True,
                "raw": stdout[:2000],
            })
        elif "does not seem to be injectable" in stdout:
            out.append({
                "module": self.MODULE_NAME, "type": "sql_injection_test",
                "url": url, "severity": "INFO",
                "title": "No SQL injection found",
                "details": "Target does not appear vulnerable",
                "likely_false_alarm": True,
            })
        for line in stdout.splitlines():
            if "[WARNING]" in line and "might" in line.lower():
                out.append({
                    "module": self.MODULE_NAME, "type": "sql_warning",
                    "url": url, "severity": "LOW",
                    "title": "SQLMap warning",
                    "details": line.strip(), "raw": line,
                })
        return out

    @staticmethod
    def _extract_details(stdout: str) -> Dict[str, str]:
        patterns = {
            "parameter": r"Parameter: (.+?) \[",
            "type":      r"Type: (.+)",
            "title":     r"Title: (.+)",
            "payload":   r"Payload: (.+)",
            "dbms":      r"back-end DBMS: (.+)",
        }
        out = {}
        for k, p in patterns.items():
            m = re.search(p, stdout)
            if m:
                out[k] = m.group(1).strip()
        return out
