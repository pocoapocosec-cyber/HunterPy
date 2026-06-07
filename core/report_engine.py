"""Report engine — terminal, JSON, HTML, Markdown, and plaintext outputs.

The Markdown report is specifically structured to be pasted into an AI
assistant (ChatGPT, Claude, etc.) for next-step strategic guidance.
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.markdown_report import build_findings_summary, render_markdown
from reporting.burp_exporter import write_burp_xml
from reporting.impact_analyzer import ImpactAnalyzer
from reporting.interactive_html import render_interactive_html
from reporting.poc_generator import PoCGenerator


SEVERITY_COLOR = {
    "CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107",
    "LOW": "#28a745", "INFO": "#6c757d", "UNKNOWN": "#6c757d",
}


class ReportEngine:
    def __init__(self, settings):
        self.settings = settings
        self.output_dir = settings.output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    # ---------- entry ----------
    def generate_all_reports(self, findings: List[Dict[str, Any]],
                              metadata: Dict[str, Any],
                              artifacts: Optional[Dict[str, Dict[str, Any]]] = None,
                              chains: Optional[List[Dict[str, Any]]] = None,
                              baseline: Optional[Dict[str, Any]] = None,
                              ) -> List[str]:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        slug = (self.settings.target or "scan").replace("://", "_") \
            .replace("/", "_").replace(":", "_")
        base = f"{slug}_{timestamp}"
        written: List[str] = []
        artifacts = artifacts or {}
        chains = chains or []

        # PoC + impact are computed once and reused across report formats
        poc_gen   = PoCGenerator()
        impact_gen = ImpactAnalyzer()
        pocs    = poc_gen.generate_many(findings)
        impacts = impact_gen.analyze_many(findings)

        fmt = self.settings.report_format or "all"
        if fmt in ("json", "all", "md", "markdown"):
            written.append(self.render_json(
                findings, metadata, artifacts, pocs, impacts, chains, baseline,
                os.path.join(self.output_dir, base + ".json")))
        if fmt in ("html", "all"):
            # Interactive HTML replaces the old static one
            written.append(self.render_interactive(
                findings, metadata, pocs, impacts, chains, baseline,
                os.path.join(self.output_dir, base + ".html")))
        if fmt in ("txt", "all"):
            written.append(self.render_txt(findings, metadata,
                                           os.path.join(self.output_dir, base + ".txt")))
        if fmt in ("md", "markdown", "all"):
            written.append(self.render_markdown(findings, metadata, artifacts,
                                                os.path.join(self.output_dir, base + ".md")))
        if fmt in ("burp", "all"):
            try:
                burp_path = os.path.join(self.output_dir, base + ".burp.xml")
                write_burp_xml(findings, burp_path, pocs=pocs)
                written.append(burp_path)
            except Exception as e:
                print(f"[!] Burp XML export failed: {e}")

        for path in written:
            print(f"[+] Wrote {path}")
        return written

    # ---------- interactive HTML ----------
    def render_interactive(self, findings, metadata, pocs, impacts,
                           chains, baseline, path) -> str:
        html_doc = render_interactive_html(
            target=self.settings.target,
            metadata=metadata, findings=findings,
            pocs=pocs, impacts=impacts,
            chains=chains, baseline=baseline,
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        return path

    # ---------- payload ----------
    @staticmethod
    def _bucket(findings: List[Dict[str, Any]]) -> Dict[str, List]:
        out = {"INTERESTING": [], "COMMON": [], "FALSE_ALARM": []}
        for f in findings:
            out.setdefault(f.get("classification", "COMMON"), []).append(f)
        for k in out:
            out[k].sort(key=lambda x: -float(x.get("score") or 0))
        return out

    # ---------- JSON ----------
    def render_json(self, findings, metadata, artifacts, pocs, impacts,
                    chains, baseline, path) -> str:
        buckets = self._bucket(findings)
        cookies = (artifacts.get("headers") or {}).get("cookies", [])
        surface = (artifacts.get("surface") or {}).get("surface", {})
        javascript = (artifacts.get("js") or {}).get("javascript", {})
        dns_records = (artifacts.get("dns") or {}).get("records", {})
        whois_data = (artifacts.get("whois") or {}).get("whois", {})
        tech_recon = (artifacts.get("fingerprint") or {})

        meta = dict(metadata)
        meta.setdefault("scan_timestamp",
                        datetime.utcnow().isoformat() + "Z")
        meta.setdefault("tool_name", "HunterPy")
        meta.setdefault("tool_version", "2.0.0")

        findings_summary = build_findings_summary(
            findings, surface, javascript, cookies)

        # Normalize PoC + impact dicts (they may be dataclasses)
        def _norm(d):
            out = {}
            for k, v in (d or {}).items():
                out[k] = v.to_dict() if hasattr(v, "to_dict") else v
            return out

        payload = {
            "meta": meta,
            "summary": {
                "total": len(findings),
                "interesting":  len(buckets["INTERESTING"]),
                "common":       len(buckets["COMMON"]),
                "false_alarms": len(buckets["FALSE_ALARM"]),
            },
            "technology": {
                "headers": (artifacts.get("headers") or {}).get("headers", {}),
                "technologies": tech_recon.get("technologies", []),
            },
            "headers": (artifacts.get("headers") or {}).get("headers", {}),
            "cookies": cookies,
            "dns": dns_records,
            "whois": whois_data,
            "surface": surface,
            "javascript": javascript,
            "dorks":   (artifacts.get("dorks") or {}).get("dorks", {}),
            "baseline": baseline or {},
            "attack_chains": chains or [],
            "pocs":    _norm(pocs),
            "impacts": _norm(impacts),
            "findings_summary": findings_summary,
            "findings": buckets,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        return path

    # ---------- Markdown (AI-consumable) ----------
    def render_markdown(self, findings, metadata, artifacts, path) -> str:
        cookies = (artifacts.get("headers") or {}).get("cookies", [])
        surface = (artifacts.get("surface") or {}).get("surface", {})
        javascript = (artifacts.get("js") or {}).get("javascript", {})
        dns_records = (artifacts.get("dns") or {}).get("records", {})
        whois_data = (artifacts.get("whois") or {}).get("whois", {})
        dorks_data = (artifacts.get("dorks") or {}).get("dorks", {})
        recon = {
            "headers": (artifacts.get("headers") or {}).get("headers", {}),
            "technologies": (artifacts.get("fingerprint") or {}).get("technologies", []),
        }
        md = render_markdown(
            target=self.settings.target,
            metadata=metadata,
            findings=findings,
            recon=recon,
            surface=surface,
            javascript=javascript,
            dns_records=dns_records,
            whois_data=whois_data,
            cookies=cookies,
            dorks=dorks_data,
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        return path

    # ---------- TXT ----------
    def render_txt(self, findings, metadata, path) -> str:
        buckets = self._bucket(findings)
        with open(path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("HUNTERPY SECURITY SCAN REPORT\n")
            f.write("=" * 80 + "\n\n")
            for k, v in metadata.items():
                f.write(f"{k}: {v}\n")
            f.write("\nSUMMARY:\n")
            f.write(f"  INTERESTING: {len(buckets['INTERESTING'])}\n")
            f.write(f"  COMMON:      {len(buckets['COMMON'])}\n")
            f.write(f"  FALSE ALARM: {len(buckets['FALSE_ALARM'])}\n\n")
            for label, key in (("INTERESTING", "INTERESTING"),
                               ("COMMON", "COMMON"),
                               ("FALSE ALARM", "FALSE_ALARM")):
                items = buckets[key]
                f.write("\n" + "=" * 60 + "\n")
                f.write(f"{label} ({len(items)} findings)\n")
                f.write("=" * 60 + "\n")
                for i, item in enumerate(items, 1):
                    f.write(f"\n[{i}] {item.get('title', 'n/a')}\n")
                    f.write(f"    Module: {item.get('module')}\n")
                    f.write(f"    Severity: {item.get('severity')}\n")
                    f.write(f"    URL: {item.get('url')}\n")
                    f.write(f"    Details: {item.get('details')}\n")
                    f.write(f"    Reason: {item.get('classification_reason')}\n")
                    f.write(f"    Confidence: "
                            f"{item.get('classification_confidence', 0):.0%}\n")
        return path

    # ---------- HTML ----------
    def render_html(self, findings, metadata, path) -> str:
        buckets = self._bucket(findings)

        def rows(items):
            html_rows = []
            for f in items:
                sev = f.get("severity", "INFO")
                color = SEVERITY_COLOR.get(sev, "#6c757d")
                html_rows.append(f"""
                    <tr>
                      <td><b>{html.escape(f.get('module', ''))}</b></td>
                      <td>{html.escape(f.get('title', ''))}</td>
                      <td><span style="color:{color};font-weight:bold">{sev}</span></td>
                      <td><a href="{html.escape(f.get('url', ''))}" target="_blank">
                          {html.escape((f.get('url') or '')[:60])}</a></td>
                      <td>{html.escape(f.get('classification_reason', ''))}</td>
                      <td>{f.get('classification_confidence', 0):.0%}</td>
                    </tr>""")
            return "".join(html_rows) or "<tr><td colspan='6'>None</td></tr>"

        doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>HunterPy Report — {html.escape(metadata.get('target', ''))}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,sans-serif;background:#1a1a2e;color:#eee;
       margin:0;padding:24px}}
 .header{{background:#16213e;padding:18px;border-radius:8px;margin-bottom:18px}}
 .summary{{display:flex;gap:16px;margin-bottom:18px}}
 .stat{{flex:1;padding:14px;border-radius:8px;text-align:center}}
 .interesting{{background:#3d0000;border:1px solid #dc3545}}
 .common     {{background:#3d3d00;border:1px solid #ffc107}}
 .false      {{background:#003d00;border:1px solid #28a745}}
 .num{{font-size:2em;font-weight:bold}}
 table{{width:100%;border-collapse:collapse;background:#16213e;margin-bottom:24px}}
 th{{background:#0f3460;padding:10px;text-align:left}}
 td{{padding:8px;border-bottom:1px solid #333;vertical-align:top}}
 tr:hover{{background:#1a1a3e}}
 h2{{padding:8px 12px;border-radius:6px}}
 a{{color:#5fb3ff;text-decoration:none}}
</style></head><body>

<div class="header">
  <h1>🛡️ HunterPy Security Scan Report</h1>
  <p><b>Target:</b> {html.escape(metadata.get('target', ''))}</p>
  <p><b>Mode:</b> {metadata.get('mode', '')} &nbsp; <b>Duration:</b> {metadata.get('duration', '-')}</p>
  <p><b>Modules:</b> {", ".join(metadata.get('modules_run', []))}</p>
  <p><b>Scan ID:</b> {metadata.get('scan_id', '-')}</p>
</div>

<div class="summary">
  <div class="stat interesting">
    <div class="num" style="color:#dc3545">{len(buckets['INTERESTING'])}</div>
    <div>🔴 INTERESTING</div><div>Investigate these!</div></div>
  <div class="stat common">
    <div class="num" style="color:#ffc107">{len(buckets['COMMON'])}</div>
    <div>🟡 COMMON</div><div>Review these</div></div>
  <div class="stat false">
    <div class="num" style="color:#28a745">{len(buckets['FALSE_ALARM'])}</div>
    <div>🟢 FALSE ALARM</div><div>Safe to ignore</div></div>
</div>

<h2 style="background:#6c0000">🔴 INTERESTING — Investigate!</h2>
<table>
  <tr><th>Module</th><th>Finding</th><th>Severity</th><th>URL</th>
      <th>Reason</th><th>Confidence</th></tr>
  {rows(buckets['INTERESTING'])}
</table>

<h2 style="background:#6c6c00">🟡 COMMON — Worth Reviewing</h2>
<table>
  <tr><th>Module</th><th>Finding</th><th>Severity</th><th>URL</th>
      <th>Reason</th><th>Confidence</th></tr>
  {rows(buckets['COMMON'])}
</table>

<h2 style="background:#006c00">🟢 FALSE ALARM — No Action</h2>
<table>
  <tr><th>Module</th><th>Finding</th><th>Severity</th><th>URL</th>
      <th>Reason</th><th>Confidence</th></tr>
  {rows(buckets['FALSE_ALARM'])}
</table>

<p style="text-align:center;color:#666;margin-top:30px">
  Generated by HunterPy on {datetime.utcnow().isoformat()}Z — authorized testing only
</p>
</body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(doc)
        return path
