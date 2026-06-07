"""Gobuster wrapper with pure-Python fallback brute-forcer."""
from __future__ import annotations

import os
import urllib.error
import urllib.request
from typing import Any, Dict, List

from config.tool_paths import ToolPathValidator
from utils.logger import ScanLogger
from utils.process_runner import ProcessRunner
from utils.rate_limiter import RateLimiter


DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

# Tiny bundled fallback wordlist so the module works on any host
BUILTIN_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "phpinfo.php", "config", "config.php", "backup",
    "backups", ".git", ".git/HEAD", ".env", "api", "api/v1", "swagger",
    "swagger-ui", "console", "panel", "dashboard", "upload", "uploads",
    "shell", ".htpasswd", ".htaccess", "credentials", "secret", "private",
    "debug", "test", "tests", "old", "tmp", "temp", "logs", "log",
    "server-status", "server-info", "actuator", "actuator/env",
    "actuator/health", "metrics", "graphql", "robots.txt", "sitemap.xml",
    "crossdomain.xml", ".well-known/security.txt",
]

HIGH_INTEREST_PATHS = (
    "admin", "administrator", "login", "wp-admin", "phpmyadmin",
    "config", "backup", ".git", ".env", "api", "swagger",
    "console", "panel", "dashboard", "upload", "shell",
    ".htpasswd", "credentials", "secret", "private", "debug",
)


class GobusterModule:
    MODULE_NAME = "gobuster"

    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target if "://" in settings.target \
                      else f"https://{settings.target}"
        self.logger = ScanLogger(settings.output_dir)
        self.runner = ProcessRunner()
        self.output_file = os.path.join(settings.output_dir, "gobuster_output.txt")
        self.wordlist = self._find_wordlist()
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    # ---------- entry ----------
    def run(self) -> Dict[str, Any]:
        if ToolPathValidator.has("gobuster") and self.wordlist:
            return self._run_real()
        return self._run_fallback()

    # ---------- real ----------
    def _run_real(self) -> Dict[str, Any]:
        cmd = [
            "gobuster", "dir",
            "-u", self.target,
            "-w", self.wordlist,
            "-o", self.output_file,
            "-t", str(min(self.settings.threads, 50)),
            "--timeout", f"{self.settings.timeout}s",
            "-r", "--no-error",
            "-s", "200,201,202,203,204,301,302,307,401,403,405,500",
            "-a", self.settings.user_agent,
            "--wildcard",
        ]
        exts = "php,html,js,txt,bak,old,conf,config,sql,zip,tar,gz"
        if self.settings.mode == "full":
            exts += ",asp,aspx,jsp,do,action,xml,json,yaml,yml,log"
        cmd += ["-x", exts]
        if self.settings.proxy:
            cmd += ["--proxy", self.settings.proxy]
        if self.settings.mode == "stealth":
            cmd += ["--delay", "2000ms"]

        self.logger.log_command(self.MODULE_NAME, cmd)
        self.runner.run(cmd, timeout=900)
        findings = self._parse_output_file()
        return {"module": self.MODULE_NAME, "findings": findings,
                "endpoints": [f["url"] for f in findings]}

    def _parse_output_file(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not os.path.exists(self.output_file):
            return out
        with open(self.output_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if not parts:
                    continue
                path = parts[0]
                status = self._extract_kv(parts, "Status:")
                size   = self._extract_kv(parts, "Size:")
                full_url = self.target.rstrip("/") + (
                    path if path.startswith("/") else "/" + path)
                out.append(self._make_finding(full_url, path, status, size, line))
        return out

    @staticmethod
    def _extract_kv(parts, key):
        for p in parts:
            if key in p:
                try:
                    return int("".join(c for c in p if c.isdigit()))
                except ValueError:
                    return None
        return None

    # ---------- fallback ----------
    def _run_fallback(self) -> Dict[str, Any]:
        out: List[Dict[str, Any]] = []
        words = self._load_words()
        limiter = RateLimiter(self.settings.rate_limit, period_sec=1.0)
        for word in words:
            url = self.target.rstrip("/") + "/" + word
            limiter.acquire()
            status = self._head(url)
            if status and 200 <= status < 400:
                out.append(self._make_finding(url, "/" + word, status, None,
                                              f"HEAD {url} => {status}"))
        return {"module": self.MODULE_NAME, "findings": out,
                "endpoints": [f["url"] for f in out]}

    def _load_words(self) -> List[str]:
        if self.wordlist and os.path.exists(self.wordlist):
            try:
                with open(self.wordlist, "r", encoding="utf-8",
                          errors="replace") as fh:
                    return [w.strip() for w in fh if w.strip()
                            and not w.startswith("#")][:500]
            except OSError as e:
                # Falling back to built-ins is fine but the analyst
                # asked for a specific wordlist — make the substitution
                # visible.
                self.logger.log_error(
                    f"could not read {self.wordlist!r} ({e}); "
                    "falling back to BUILTIN_PATHS")
        return list(BUILTIN_PATHS)

    def _head(self, url: str):
        req = urllib.request.Request(url, method="HEAD", headers={
            "User-Agent": self.settings.user_agent,
        })
        try:
            with urllib.request.urlopen(req, timeout=4) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None

    # ---------- shared ----------
    def _make_finding(self, url, path, status, size, raw) -> Dict[str, Any]:
        path_low = path.lower()
        interesting = any(k in path_low for k in HIGH_INTEREST_PATHS)
        ftype = "admin_panel" if "admin" in path_low \
                else "git_exposed" if ".git" in path_low \
                else "env_exposed" if ".env" in path_low \
                else "directory_found"
        return {
            "module": self.MODULE_NAME, "type": ftype,
            "url": url, "path": path,
            "title": f"Found path: {path}",
            "severity": "HIGH" if interesting else "LOW",
            "details": f"Status: {status}, Size: {size}",
            "status_code": status, "size": size,
            "high_interest_path": interesting,
            "has_params": "?" in path,
            "interesting": interesting,
            "raw": raw,
        }

    @staticmethod
    def _find_wordlist() -> str:
        for wl in DEFAULT_WORDLISTS:
            if os.path.exists(wl):
                return wl
        return ""
