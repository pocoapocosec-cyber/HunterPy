"""Reports listing + generation endpoints."""
from __future__ import annotations

import glob
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from gui.backend.schemas import ReportSummary
from gui.backend.services.scan_manager import ScanManager, get_scan_manager


router = APIRouter(prefix="/api/reports", tags=["reports"])


def _slug(target: str) -> str:
    return target.replace("://", "_").replace("/", "_").replace(":", "_")


@router.get("")
def list_reports(mgr: ScanManager = Depends(get_scan_manager)) -> dict:
    reports = []
    seen = set()
    for rec in mgr.list():
        slug = _slug(rec.target)
        out_dir = (rec.options.get("output_dir") if rec.options else None) \
                  or "./output"
        for path in sorted(glob.glob(os.path.join(out_dir, f"{slug}_*.json"))):
            if path in seen:
                continue
            seen.add(path)
            ts = datetime.fromtimestamp(os.path.getmtime(path),
                                        tz=timezone.utc).isoformat()
            reports.append({
                "id":        os.path.basename(path),
                "scan_id":   rec.id,
                "format":    "json",
                "generated_at": ts,
                "title":     f"Scan report — {rec.target}",
            })
    return {"reports": reports, "total": len(reports)}


@router.get("/templates")
def list_templates() -> dict:
    # We don't have configurable report templates yet; return the
    # canonical list of formats the report engine can emit so the UI
    # can render a selector.
    return {
        "templates": [
            {"id": "default-json",     "name": "Default JSON",
             "format": "json", "description": "Full structured output."},
            {"id": "default-html",     "name": "Interactive HTML",
             "format": "html", "description": "Self-contained interactive report."},
            {"id": "default-markdown", "name": "AI-pasteable Markdown",
             "format": "markdown", "description": "Designed to paste into an LLM."},
            {"id": "burp-import",      "name": "Burp Suite issue XML",
             "format": "burp", "description": "Import via Burp ▸ Project options ▸ Misc ▸ Issue import."},
        ],
    }


@router.get("/{report_id}")
def get_report(report_id: str,
               mgr: ScanManager = Depends(get_scan_manager)) -> dict:
    # report_id is the on-disk filename (returned by list).
    for rec in mgr.list():
        out_dir = (rec.options.get("output_dir") if rec.options else None) \
                  or "./output"
        path = os.path.join(out_dir, report_id)
        if os.path.isfile(path):
            try:
                import json
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (OSError, ValueError) as e:
                raise HTTPException(status_code=500,
                                    detail=f"could not read report: {e}")
    raise HTTPException(status_code=404, detail="report not found")
