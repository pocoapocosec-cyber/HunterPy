"""Tool path validation & availability detection."""
from __future__ import annotations

import shutil
import subprocess
from typing import Dict


REQUIRED_TOOLS: Dict[str, dict] = {
    "nikto":    {"cmd": "nikto",    "install": "apt install nikto"},
    "sqlmap":   {"cmd": "sqlmap",   "install": "pip install sqlmap / apt install sqlmap"},
    "gobuster": {"cmd": "gobuster", "install": "go install / apt install gobuster"},
    "ffuf":     {"cmd": "ffuf",     "install": "go install / apt install ffuf"},
    "wfuzz":    {"cmd": "wfuzz",    "install": "pip install wfuzz"},
    "hydra":    {"cmd": "hydra",    "install": "apt install hydra"},
    "nuclei":   {"cmd": "nuclei",   "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
}

OPTIONAL_TOOLS: Dict[str, dict] = {
    "nmap":    {"cmd": "nmap",    "install": "apt install nmap"},
    "curl":    {"cmd": "curl",    "install": "apt install curl"},
    "whatweb": {"cmd": "whatweb", "install": "apt install whatweb"},
}


class ToolPathValidator:
    """Detects which CLI tools are on PATH and prints a status table."""

    def check_all_tools(self, *, console=None) -> Dict[str, dict]:
        results: Dict[str, dict] = {}
        rows = []
        for name, info in REQUIRED_TOOLS.items():
            path = shutil.which(info["cmd"])
            version = self._version(info["cmd"]) if path else "n/a"
            results[name] = {"available": bool(path), "path": path,
                             "version": version, "required": True}
            rows.append((name, "✓" if path else "✗", version, "Required"))

        for name, info in OPTIONAL_TOOLS.items():
            path = shutil.which(info["cmd"])
            version = self._version(info["cmd"]) if path else "n/a"
            results[name] = {"available": bool(path), "path": path,
                             "version": version, "required": False}
            rows.append((name, "✓" if path else "~", version, "Optional"))

        if console is not None:
            try:
                from rich.table import Table
                table = Table(title="Tool Status", show_header=True)
                table.add_column("Tool", style="cyan")
                table.add_column("Status", style="bold")
                table.add_column("Version", style="dim")
                table.add_column("Type", style="yellow")
                for name, status, ver, ttype in rows:
                    color = "[green]✓[/]" if status == "✓" else \
                            ("[red]✗[/]" if status == "✗" else "[yellow]~[/]")
                    table.add_row(name, color, ver, ttype)
                console.print(table)
            except Exception:
                for name, status, ver, ttype in rows:
                    console.print(f"  {status} {name:<10} {ttype:<8} {ver}")
        return results

    # Per-tool version invocation. Different scanners use different
    # conventions; defaulting to --version misses gobuster (which uses
    # the `version` subcommand) and nikto (`-Version`).
    _VERSION_INVOCATION = {
        "gobuster": ["version"],
        "nikto":    ["-Version"],
        "nuclei":   ["-version"],
    }

    @classmethod
    def _version(cls, cmd: str) -> str:
        # Try the tool-specific invocation first, then fall back to a
        # short list of common flags.
        invocations = []
        if cmd in cls._VERSION_INVOCATION:
            invocations.append(cls._VERSION_INVOCATION[cmd])
        invocations.extend([["--version"], ["-V"], ["-v"]])
        for argv in invocations:
            try:
                r = subprocess.run([cmd] + argv, capture_output=True,
                                   text=True, timeout=4)
                line = (r.stdout + r.stderr).strip().splitlines()
                if line:
                    return line[0][:64]
            except Exception:
                continue
        return "unknown"

    @staticmethod
    def get_tool_path(tool_name: str) -> str:
        info = REQUIRED_TOOLS.get(tool_name) or OPTIONAL_TOOLS.get(tool_name)
        if info:
            return shutil.which(info["cmd"]) or info["cmd"]
        return tool_name

    @staticmethod
    def has(tool_name: str) -> bool:
        info = REQUIRED_TOOLS.get(tool_name) or OPTIONAL_TOOLS.get(tool_name)
        if not info:
            return False
        return shutil.which(info["cmd"]) is not None
