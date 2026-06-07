"""Scan-related HTTP endpoints (matches src/lib/api/endpoints.ts)."""
from __future__ import annotations

import io
import json
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from core.target_validator import TargetValidator
from gui.backend.schemas import (
    GenericMessage,
    LogsResponse,
    ModuleStatusResponse,
    ScanCreateRequest,
    ScanListResponse,
    ScanProgressResponse,
    ScanResponse,
    ValidateTargetRequest,
    ValidateTargetResponse,
)
from gui.backend.services.scan_manager import ScanManager, get_scan_manager


log = logging.getLogger("hunterpy.api.scans")
router = APIRouter(prefix="/api/scans", tags=["scans"])


def _to_response(rec) -> ScanResponse:
    return ScanResponse(**rec.to_public_dict())


# ---------- list / create ----------
@router.get("", response_model=ScanListResponse)
def list_scans(
    status: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    mgr: ScanManager = Depends(get_scan_manager),
) -> ScanListResponse:
    items = mgr.list(status=status)
    total = len(items)
    page = items[offset : offset + limit]
    return ScanListResponse(
        scans=[_to_response(r) for r in page],
        total=total,
    )


@router.post("", response_model=ScanResponse, status_code=201)
def create_scan(
    body: ScanCreateRequest,
    mgr: ScanManager = Depends(get_scan_manager),
) -> ScanResponse:
    # Defence in depth: validate the target server-side too.
    try:
        clean = TargetValidator().validate_and_normalize(body.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    rec = mgr.create(
        target=clean,
        mode=body.mode,
        modules=body.modules,
        options=body.options,
    )
    return _to_response(rec)


# ---------- single-scan operations ----------
@router.get("/validate-target", response_model=ValidateTargetResponse)
def validate_target_get(target: str = Query(...)) -> ValidateTargetResponse:
    return _validate(target)


@router.post("/validate-target", response_model=ValidateTargetResponse)
def validate_target_post(body: ValidateTargetRequest) -> ValidateTargetResponse:
    return _validate(body.target)


def _validate(target: str) -> ValidateTargetResponse:
    try:
        TargetValidator().validate_and_normalize(target)
        return ValidateTargetResponse(valid=True)
    except ValueError as e:
        return ValidateTargetResponse(valid=False, reason=str(e))


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str,
             mgr: ScanManager = Depends(get_scan_manager)) -> ScanResponse:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"scan {scan_id} not found")
    return _to_response(rec)


@router.delete("/{scan_id}", response_model=GenericMessage)
def delete_scan(scan_id: str,
                mgr: ScanManager = Depends(get_scan_manager)) -> GenericMessage:
    ok = mgr.delete(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"scan {scan_id} not found")
    return GenericMessage(message=f"scan {scan_id} deleted")


@router.post("/{scan_id}/start", response_model=ScanResponse)
def start_scan(scan_id: str,
               mgr: ScanManager = Depends(get_scan_manager)) -> ScanResponse:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if not mgr.start(scan_id):
        raise HTTPException(status_code=409, detail=f"cannot start (status={rec.status})")
    return _to_response(rec)


@router.post("/{scan_id}/pause", response_model=ScanResponse)
def pause_scan(scan_id: str,
               mgr: ScanManager = Depends(get_scan_manager)) -> ScanResponse:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")
    mgr.pause(scan_id)   # logs the no-op internally
    return _to_response(rec)


@router.post("/{scan_id}/resume", response_model=ScanResponse)
def resume_scan(scan_id: str,
                mgr: ScanManager = Depends(get_scan_manager)) -> ScanResponse:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")
    mgr.resume(scan_id)
    return _to_response(rec)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(scan_id: str,
                mgr: ScanManager = Depends(get_scan_manager)) -> ScanResponse:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")
    mgr.cancel(scan_id)
    return _to_response(rec)


# ---------- progress / logs / modules ----------
@router.get("/{scan_id}/progress", response_model=ScanProgressResponse)
def scan_progress(scan_id: str,
                  mgr: ScanManager = Depends(get_scan_manager)
                  ) -> ScanProgressResponse:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")
    elapsed = 0.0
    if rec.started_at:
        end = rec.completed_at or _now()
        elapsed = (end - rec.started_at).total_seconds()
    remaining = 0.0
    if rec.progress > 5 and rec.status == "running":
        remaining = max(0.0, (elapsed / rec.progress) * (100 - rec.progress))
    return ScanProgressResponse(
        scan_id=rec.id,
        phase=rec.phase,
        phase_name=rec.phase.replace("_", " ").title(),
        percent=rec.progress,
        current_module=rec.current_module,
        modules_completed=rec.modules_completed,
        modules_total=rec.modules_total,
        elapsed_time=elapsed,
        estimated_remaining=remaining,
        status=rec.status,
    )


@router.get("/{scan_id}/logs", response_model=LogsResponse)
def scan_logs(scan_id: str,
              mgr: ScanManager = Depends(get_scan_manager)) -> LogsResponse:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return LogsResponse(logs=rec.get_logs())


@router.get("/{scan_id}/modules", response_model=list[ModuleStatusResponse])
def scan_modules(scan_id: str,
                 mgr: ScanManager = Depends(get_scan_manager)
                 ) -> list[ModuleStatusResponse]:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")
    # We don't track per-module state in granular detail; synthesise from
    # the ordered list + which one is currently running.
    out: list[ModuleStatusResponse] = []
    for i, m in enumerate(rec.modules):
        if i < rec.modules_completed:
            status = "completed"
        elif m == rec.current_module:
            status = "running"
        else:
            status = "pending"
        out.append(ModuleStatusResponse(name=m, status=status))
    return out


# ---------- findings / target / report ----------
@router.get("/{scan_id}/findings")
def scan_findings(scan_id: str,
                  mgr: ScanManager = Depends(get_scan_manager)) -> dict:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")
    # Lazy import to avoid circular dep at module load time
    from gui.backend.services.report_reader import latest_report_for
    report = latest_report_for(rec)
    findings = []
    if report:
        f = report.get("findings", {})
        if isinstance(f, dict):
            for tier in ("INTERESTING", "COMMON", "FALSE_ALARM"):
                findings.extend(f.get(tier, []))
        elif isinstance(f, list):
            findings = f
    return {"findings": findings, "total": len(findings)}


@router.get("/{scan_id}/target")
def scan_target(scan_id: str,
                mgr: ScanManager = Depends(get_scan_manager)) -> dict:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")
    from gui.backend.services.report_reader import latest_report_for
    report = latest_report_for(rec) or {}
    return {
        "url":       f"https://{rec.target}",
        "hostname":  rec.target,
        "port":      443,
        "protocol":  "https",
        "tech_stack": (report.get("technology") or {}),
        "dns_records": report.get("dns") or {},
        "whois":     report.get("whois") or {},
    }


@router.get("/{scan_id}/report")
def scan_report(scan_id: str,
                mgr: ScanManager = Depends(get_scan_manager)) -> dict:
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")
    from gui.backend.services.report_reader import latest_report_for
    report = latest_report_for(rec)
    if report is None:
        raise HTTPException(status_code=404, detail="no report on disk yet")
    return report


@router.get("/{scan_id}/findings/export")
def export_findings(scan_id: str,
                    format: str = Query(default="json", regex="^(json|csv)$"),
                    mgr: ScanManager = Depends(get_scan_manager)):
    rec = mgr.get(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="scan not found")

    from gui.backend.services.report_reader import latest_report_for
    report = latest_report_for(rec)
    if report is None:
        raise HTTPException(status_code=404, detail="no report on disk yet")
    findings_raw = report.get("findings", {})
    findings: list = []
    if isinstance(findings_raw, dict):
        for tier in ("INTERESTING", "COMMON", "FALSE_ALARM"):
            findings.extend(findings_raw.get(tier, []))
    elif isinstance(findings_raw, list):
        findings = findings_raw

    if format == "json":
        body = json.dumps(findings, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(body.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition":
                     f'attachment; filename="{scan_id}_findings.json"'},
        )

    # CSV
    from utils.parser import NmapParser   # noqa  (sanity-import; unused)
    from reporting.burp_exporter import _split_url   # noqa
    import csv as csv_mod
    buf = io.StringIO()
    writer = csv_mod.writer(buf)
    writer.writerow(["id", "severity", "classification", "module",
                     "title", "url", "cvss", "score"])
    for f in findings:
        writer.writerow([
            f.get("id", ""),
            f.get("severity", ""),
            f.get("classification", f.get("tier", "")),
            f.get("module", ""),
            f.get("title", ""),
            f.get("url", ""),
            f.get("cvss", ""),
            f.get("score", ""),
        ])
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="{scan_id}_findings.csv"'},
    )


# ---------- helpers ----------
def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(tzinfo=None)
