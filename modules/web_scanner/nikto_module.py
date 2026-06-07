"""Nikto wrapper with pure-Python fallback for environments without nikto."""
from __future__ import annotations

import os
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from config.tool_paths import ToolPathValidator
from utils.logger import ScanLogger
from utils.output_parser import NiktoParser
from utils.process_runner import ProcessRunner


FALLBACK_PROBES = [
    ("/.git/HEAD",      "Exposed .git repository",       "git_exposed",      "CRITICAL", True),
    ("/.env",           "Exposed .env file",             "env_exposed",      "CRITICAL", True),
    ("/wp-admin/",      "WordPress admin reachable",     "admin_panel",      "HIGH",     True),
    ("/admin/",         "Generic admin path reachable",  "admin_panel",      "MEDIUM",   True),
    ("/server-status",  "Apache server-status exposed",  "info_disclosure",  "MEDIUM",   True),
    ("/phpmyadmin/",    "phpMyAdmin reachable",          "admin_panel",      "HIGH",     True),
    ("/robots.txt",     "robots.txt present",            "robots_txt",       "INFO",     False),
    ("/sitemap.xml",    "sitemap.xml present",           "sitemap_xml",      "INFO",     False),
]


class NiktoModule:
    MODULE_NAME = "nikto"

    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target if "://" in settings.target \
                      else f"https://{settings.target}"
        self.logger = ScanLogger(settings.output_dir)
        self.runner = ProcessRunner()
        self.parser = NiktoParser()
        self.output_file = os.path.join(settings.output_dir, "nikto_output.xml")
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    # ---------- entry ----------
    def run(self) -> Dict[str, Any]:
        if ToolPathValidator.has("nikto"):
            return self._run_real()
        return self._run_fallback()

    # ---------- real nikto ----------
    def _run_real(self) -> Dict[str, Any]:
        cmd = [
            "nikto", "-h", self.target,
            "-output", self.output_file, "-Format", "xml",
            "-maxtime", "300", "-timeout", str(self.settings.timeout),
        ]
        if self.settings.proxy:
            cmd += ["-useproxy", self.settings.proxy]
        if self.settings.cookies:
            cmd += ["-cookies", self.settings.cookies]
        if self.settings.mode == "stealth":
            cmd += ["-Pause", "2"]
        elif self.settings.mode == "full":
            cmd += ["-Tuning", "123457890abc"]
        if self.target.startswith("https://"):
            cmd.append("-ssl")

        self.logger.log_command(self.MODULE_NAME, cmd)
        result = self.runner.run(cmd, timeout=600)

        findings = self._parse_xml()
        if not findings:
            findings = self._parse_stdout(result.get("stdout", ""))

        return {"module": self.MODULE_NAME, "findings": findings,
                "raw_output": result.get("stdout", "")}

    def _parse_xml(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not os.path.exists(self.output_file):
            return out
        try:
            tree = ET.parse(self.output_file)
            for item in tree.getroot().findall(".//item"):
                title = item.findtext("description", "")
                osvdb = item.get("osvdbid", "")
                out.append({
                    "module": self.MODULE_NAME,
                    "type": "web_vulnerability",
                    "url": self.target,
                    "title": title[:120],
                    "details": title,
                    "severity": "MEDIUM",
                    "osvdb": osvdb,
                    "nikto_id": item.get("id", ""),
                    "raw": title,
                })
        except ET.ParseError as e:
            self.logger.log_error(f"nikto xml parse error: {e}")
        return out

    def _parse_stdout(self, stdout: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            p = self.parser.parse_line(line)
            if not p:
                continue
            out.append({
                "module": self.MODULE_NAME,
                "type": "web_vulnerability",
                "url": self.target,
                "title": (p.get("raw") or "")[:120],
                "details": p.get("raw", ""),
                "severity": "MEDIUM",
                "osvdb": p.get("osvdb"),
                "raw": p.get("raw"),
            })
        return out

    # ---------- pure-Python fallback ----------
    def _run_fallback(self) -> Dict[str, Any]:
        out: List[Dict[str, Any]] = []
        for path, title, ftype, sev, interesting in FALLBACK_PROBES:
            url = self.target.rstrip("/") + path
            status = self._head_status(url)
            if status and 200 <= status < 400:
                out.append({
                    "module": self.MODULE_NAME, "type": ftype, "url": url,
                    "title": title, "severity": sev,
                    "details": f"{url} returned HTTP {status}",
                    "status_code": status,
                    "interesting": interesting,
                    "raw": f"HEAD {url} => {status}",
                })
        return {"module": self.MODULE_NAME, "findings": out,
                "raw_output": "fallback mode (nikto not installed)"}

    def _head_status(self, url: str):
        req = urllib.request.Request(url, method="HEAD", headers={
            "User-Agent": self.settings.user_agent,
        })
        try:
            with urllib.request.urlopen(req, timeout=6) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None
