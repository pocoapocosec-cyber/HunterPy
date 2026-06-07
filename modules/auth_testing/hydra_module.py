"""Hydra wrapper for HTTP form / SSH / FTP brute-forcing.

Safety: defaults to a tiny built-in credential list. The user must
explicitly pass --password-list to use a larger wordlist.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from config.tool_paths import ToolPathValidator
from utils.logger import ScanLogger
from utils.process_runner import ProcessRunner


DEFAULT_USERS     = ["admin", "root", "user", "test", "guest",
                     "administrator", "webmaster"]
DEFAULT_PASSWORDS = ["password", "123456", "admin", "root",
                     "test", "letmein", "qwerty", "welcome",
                     "password123", "admin123", ""]


class HydraModule:
    MODULE_NAME = "hydra"

    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target
        self.logger = ScanLogger(settings.output_dir)
        self.runner = ProcessRunner()
        self.output_file = os.path.join(settings.output_dir, "hydra_output.txt")
        self._prepare_wordlists()

    def set_context(self, recon: Dict[str, Any]) -> None:
        pass  # not used currently

    # ---------- entry ----------
    def run(self) -> Dict[str, Any]:
        if not ToolPathValidator.has("hydra"):
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "hydra not installed"}
        if not self.settings.auth_url and not self.settings.password_list:
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "no auth url or password list supplied"}

        cmd = self._cmd()
        self.logger.log_command(self.MODULE_NAME, cmd)
        result = self.runner.run(cmd, timeout=600)
        return {"module": self.MODULE_NAME,
                "findings": self._parse(result.get("stdout", ""))}

    # ---------- setup ----------
    def _prepare_wordlists(self) -> None:
        self.user_file = self.settings.username_list or self._materialize(
            "default_users.txt", DEFAULT_USERS)
        self.pass_file = self.settings.password_list or self._materialize(
            "default_passwords.txt", DEFAULT_PASSWORDS)

    def _materialize(self, name: str, words: List[str]) -> str:
        path = os.path.join(self.settings.output_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(words))
        return path

    def _detect_service(self) -> Tuple[str, str]:
        url = self.settings.auth_url or self.target
        parsed = urlparse(url if "://" in url else f"https://{url}")
        if "ssh" in url or (parsed.port == 22):
            return "ssh", ""
        if "ftp" in url or (parsed.port == 21):
            return "ftp", ""
        path = parsed.path or "/login"
        form = f"{path}:username=^USER^&password=^PASS^:Invalid"
        return "http-post-form", form

    def _cmd(self) -> List[str]:
        service, form = self._detect_service()
        url = self.settings.auth_url or self.target
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.hostname or self.target

        cmd = [
            "hydra",
            "-L", self.user_file,
            "-P", self.pass_file,
            "-o", self.output_file,
            "-t", str(min(self.settings.threads, 16)),
            "-f", "-e", "nsr",
            "-W", "3" if self.settings.mode == "stealth" else "1",
        ]
        if parsed.port:
            cmd += ["-s", str(parsed.port)]
        if service == "http-post-form":
            cmd += ["-V", host, "http-post-form", form]
        else:
            cmd += [host, service]
        return cmd

    # ---------- parse ----------
    def _parse(self, stdout: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            m = re.search(
                r"\[(\d+)\]\[(.+?)\] host: (\S+)\s+login: (\S+)\s+password: (\S+)",
                line)
            if not m:
                continue
            out.append({
                "module": self.MODULE_NAME, "type": "weak_credentials",
                "url": self.target,
                "severity": "CRITICAL",
                "title": f"Weak credentials: {m.group(4)}:{m.group(5)}",
                "details": {
                    "service": m.group(2), "host": m.group(3),
                    "username": m.group(4), "password": m.group(5),
                    "port": m.group(1),
                },
                "confirmed": True, "interesting": True,
                "raw": line,
            })
        if not out and "0 valid passwords found" in stdout:
            out.append({
                "module": self.MODULE_NAME, "type": "auth_test_result",
                "url": self.target,
                "title": "No weak credentials found",
                "severity": "INFO",
                "details": "Hydra found no valid credentials",
                "likely_false_alarm": True,
            })
        return out
