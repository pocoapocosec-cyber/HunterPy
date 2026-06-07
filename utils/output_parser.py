"""Tool output parsers (nmap & nikto). Tolerant of unknown lines."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional


class NmapParser:
    """Line-by-line parser for nmap stdout."""

    PORT_LINE = re.compile(
        r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
        r"(?P<state>open|closed|filtered|open\|filtered)\s+"
        r"(?P<service>\S+)(?:\s+(?P<version>.+))?$"
    )

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        m = self.PORT_LINE.match((line or "").strip())
        if not m:
            return None
        return {
            "port":    int(m.group("port")),
            "proto":   m.group("proto"),
            "state":   m.group("state"),
            "service": m.group("service"),
            "version": (m.group("version") or "").strip() or None,
        }


class NiktoParser:
    """Parser for Nikto's '+ ...' style stdout."""

    OSVDB = re.compile(r"OSVDB-(\d+)")
    PATH  = re.compile(r"(/\S+)")

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        line = (line or "").strip()
        if not line.startswith("+"):
            return None
        body = line.lstrip("+ ").strip()
        out: Dict[str, Any] = {"raw": body}

        m = self.OSVDB.search(body)
        if m:
            out["osvdb"] = f"OSVDB-{m.group(1)}"
        p = self.PATH.search(body)
        if p:
            out["path"] = p.group(1).rstrip(":")

        low = body.lower()
        if "header is not present" in low or "header not present" in low:
            out["type"] = "missing_header"
        elif ".git" in low or ".env" in low or "backup" in low:
            out["type"] = "exposed_file"
        elif "default" in low and ("file" in low or "page" in low):
            out["type"] = "default_file"
        else:
            out["type"] = "generic"
        return out
