"""Export HunterPy findings into Burp Suite's issue-import XML format.

Burp Suite (Pro and Community) can import issues via:
    Project ▸ Project options ▸ Misc ▸ Issue import...
or by opening the file directly with the "Import issues" entry on the
Issues view context menu.

The XML format is the same one Burp emits when you export issues. We
generate it without any Burp-specific Python library (which doesn't
exist for Python anyway).

Honest scope: Burp issue-import only accepts a small set of severity /
confidence enums and treats the request/response as informational
(it does NOT add the host to Site Map automatically — only the issue).
That's why we also ship a Java extension (gui/burp-extension/) for users
who want richer integration.

Reference for the XML format:
    https://portswigger.net/burp/documentation/desktop/tools/target/issues
    (Burp's own export → import round-trip is the authoritative spec)
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape


log = logging.getLogger("hunterpy.burp_exporter")


# Burp accepts these exact severity strings (case-sensitive).
_SEVERITY_MAP = {
    "CRITICAL": "High",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
    "INFO":     "Information",
    "UNKNOWN":  "Information",
}

# Burp accepts: Certain / Firm / Tentative.
_CONFIDENCE_BY_TIER = {
    "INTERESTING": "Firm",
    "COMMON":      "Tentative",
    "FALSE_ALARM": "Tentative",
}

# Burp's issue-type codes are hex. We don't pretend to know Burp's
# internal taxonomy for our custom findings, so we use 0x08000000 +
# a stable hash of the type string. Burp treats unknown codes as
# "custom" issues — exactly what we want.
_CUSTOM_TYPE_BASE = 0x08000000


def _stable_type_code(finding_type: str) -> str:
    """Deterministic 32-bit hex code per finding type."""
    # Trim to 24 bits so we stay inside Burp's display width and never
    # collide with built-in codes (Burp's are <= 0x07FFFFFF).
    h = abs(hash(finding_type or "unknown")) & 0x00FFFFFF
    return f"0x{_CUSTOM_TYPE_BASE | h:08X}"


def _cdata(text: Optional[str]) -> str:
    """Wrap text in CDATA, escaping any nested ]]> sequences."""
    if not text:
        return "<![CDATA[]]>"
    safe = str(text).replace("]]>", "]]]]><![CDATA[>")
    return f"<![CDATA[{safe}]]>"


def _split_url(url: str) -> Dict[str, str]:
    """Return {host_url, path} for Burp's <host> + <path> fields."""
    try:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            # Fallback when we only have a hostname or partial URL.
            return {"host_url": url or "", "path": "/"}
        return {
            "host_url": f"{p.scheme}://{p.netloc}",
            "path":     (p.path or "/") + (f"?{p.query}" if p.query else ""),
        }
    except Exception:
        return {"host_url": url or "", "path": "/"}


def _build_background(finding: Dict[str, Any]) -> str:
    """Issue background = description + the rationale that led us here."""
    parts: List[str] = []
    if finding.get("description"):
        parts.append(finding["description"])
    if finding.get("classification_reason"):
        parts.append("Classifier rationale: "
                     + str(finding["classification_reason"]))
    if not parts:
        parts.append(finding.get("title", ""))
    return "\n\n".join(parts)


def _build_detail(finding: Dict[str, Any],
                  poc: Optional[Dict[str, Any]] = None) -> str:
    """Detail section = evidence + PoC steps + sample command."""
    lines: List[str] = []
    ev = finding.get("evidence") or {}
    if ev:
        lines.append("Evidence:")
        for k, v in ev.items():
            # Keep evidence concise; Burp's detail pane handles wrapping.
            lines.append(f"  {k}: {v}")
        lines.append("")

    if poc:
        if poc.get("description"):
            lines.append(poc["description"])
            lines.append("")
        steps = poc.get("steps") or []
        if steps:
            lines.append("Verification steps:")
            for s in steps:
                lines.append(f"  {s}")
            lines.append("")
        if poc.get("sample_command"):
            lines.append("Sample command:")
            lines.append("  " + str(poc["sample_command"]))
            lines.append("")
        refs = poc.get("references") or []
        if refs:
            lines.append("References:")
            for r in refs:
                lines.append(f"  - {r}")
    return "\n".join(lines).strip() or finding.get("description", "")


def _build_remediation(finding: Dict[str, Any],
                       poc: Optional[Dict[str, Any]] = None) -> str:
    if poc and poc.get("remediation"):
        return str(poc["remediation"])
    rem = finding.get("remediation")
    if isinstance(rem, dict):
        return rem.get("summary") or ""
    return str(rem or "")


def _build_synthetic_request_response(finding: Dict[str, Any]) -> Dict[str, str]:
    """Burp likes to see a request/response. We synthesize a minimal one
    based on the finding URL so the issue is browseable in the Burp UI.

    These are NOT real captured traffic; they're hints for the analyst.
    """
    url = finding.get("url") or ""
    p = urlparse(url)
    host = p.netloc or "example"
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: HunterPy/2.0 (synthetic; for triage only)\r\n"
        f"Accept: */*\r\n\r\n"
    )
    response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n\r\n"
        f"[HunterPy synthetic placeholder]\n"
        f"This issue was imported from a HunterPy scan.\n"
        f"Original module: {finding.get('module','?')}\n"
        f"Original type:   {finding.get('type','?')}\n"
    )
    return {"request": request, "response": response}


def _build_issue_xml(finding: Dict[str, Any],
                     serial: int,
                     poc: Optional[Dict[str, Any]] = None) -> str:
    url = finding.get("url") or ""
    parts = _split_url(url)
    severity = _SEVERITY_MAP.get(
        (finding.get("severity") or "INFO").upper(),
        "Information")
    tier = (finding.get("classification") or finding.get("tier") or "COMMON").upper()
    confidence = _CONFIDENCE_BY_TIER.get(tier, "Tentative")

    name = finding.get("title") or finding.get("type") or "HunterPy finding"
    type_code = _stable_type_code(finding.get("type", ""))

    rr = _build_synthetic_request_response(finding)

    return (
        "<issue>"
        f"<serialNumber>{serial}</serialNumber>"
        f"<type>{type_code}</type>"
        f"<name>{xml_escape(name)}</name>"
        f"<host>{xml_escape(parts['host_url'])}</host>"
        f"<path>{_cdata(parts['path'])}</path>"
        f"<location>{_cdata(parts['path'] + ' [' + (finding.get('module','') or '') + ']')}</location>"
        f"<severity>{severity}</severity>"
        f"<confidence>{confidence}</confidence>"
        f"<issueBackground>{_cdata(_build_background(finding))}</issueBackground>"
        f"<remediationBackground>{_cdata(_build_remediation(finding, poc))}</remediationBackground>"
        f"<issueDetail>{_cdata(_build_detail(finding, poc))}</issueDetail>"
        "<requestresponse>"
        f'<request method="GET" base64="false">{_cdata(rr["request"])}</request>'
        f'<response base64="false">{_cdata(rr["response"])}</response>'
        "</requestresponse>"
        "</issue>"
    )


def export_findings_to_burp_xml(findings: List[Dict[str, Any]],
                                 pocs: Optional[Dict[str, Any]] = None,
                                 burp_version: str = "2024.10") -> str:
    """Render a list of HunterPy findings as a Burp-compatible XML string.

    Args:
        findings: list of finding dicts as produced by HunterPy.
        pocs:     optional dict keyed by the same `_finding_key` used in
                  reporting/poc_generator.py; values are PoC dicts.
        burp_version: cosmetic — what Burp version string to write in
                  the root <issues> element. Burp accepts anything.

    Returns:
        A complete XML document string ready to write to disk.
    """
    pocs = pocs or {}
    # Local import to avoid a circular dependency when this module is
    # imported as part of report_engine.
    from reporting.poc_generator import _finding_key

    body_parts: List[str] = []
    for i, f in enumerate(findings, start=1):
        try:
            key = _finding_key(f)
            poc_obj = pocs.get(key)
            if hasattr(poc_obj, "to_dict"):
                poc_obj = poc_obj.to_dict()
            body_parts.append(_build_issue_xml(f, serial=i, poc=poc_obj))
        except Exception as e:
            log.warning("burp export: skipping finding #%d: %s", i, e)

    export_time = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE issues [\n'
        '  <!ELEMENT issues (issue*)>\n'
        '  <!ATTLIST issues burpVersion CDATA "">\n'
        '  <!ATTLIST issues exportTime CDATA "">\n'
        ']>\n'
        f'<issues burpVersion="{xml_escape(burp_version)}" '
        f'exportTime="{xml_escape(export_time)}">\n'
        + "\n".join(body_parts) +
        "\n</issues>\n"
    )


def write_burp_xml(findings: List[Dict[str, Any]],
                   output_path: str,
                   pocs: Optional[Dict[str, Any]] = None,
                   burp_version: str = "2024.10") -> str:
    """Convenience wrapper: render + write to disk. Returns the path."""
    xml = export_findings_to_burp_xml(findings, pocs=pocs,
                                       burp_version=burp_version)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(xml)
    return output_path


__all__ = ["export_findings_to_burp_xml", "write_burp_xml"]
