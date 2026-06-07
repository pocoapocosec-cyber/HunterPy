"""Cross-scan findings endpoints + per-finding actions."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from gui.backend.schemas import FindingListResponse, GenericMessage
from gui.backend.services.report_reader import latest_report_for
from gui.backend.services.scan_manager import ScanManager, get_scan_manager


router = APIRouter(prefix="/api/findings", tags=["findings"])


def _all_findings(mgr: ScanManager) -> list[dict]:
    out: list[dict] = []
    for rec in mgr.list():
        report = latest_report_for(rec)
        if report is None:
            continue
        f = report.get("findings", {})
        if isinstance(f, dict):
            for tier in ("INTERESTING", "COMMON", "FALSE_ALARM"):
                for item in f.get(tier, []):
                    item = dict(item)
                    item.setdefault("scan_id", rec.id)
                    out.append(item)
        elif isinstance(f, list):
            for item in f:
                item = dict(item)
                item.setdefault("scan_id", rec.id)
                out.append(item)
    return out


@router.get("", response_model=FindingListResponse)
def list_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    tier: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    mgr: ScanManager = Depends(get_scan_manager),
) -> FindingListResponse:
    all_items = _all_findings(mgr)
    if scan_id:
        all_items = [f for f in all_items if f.get("scan_id") == scan_id]
    if severity:
        sev = severity.lower()
        all_items = [f for f in all_items
                     if (f.get("severity") or "").lower() == sev]
    if tier:
        t = tier.upper()
        all_items = [f for f in all_items
                     if (f.get("classification") or f.get("tier") or "").upper() == t]
    if status:
        all_items = [f for f in all_items if f.get("status") == status]
    total = len(all_items)
    return FindingListResponse(findings=all_items[offset:offset + limit],
                               total=total)


@router.get("/{finding_id}")
def get_finding(finding_id: str,
                mgr: ScanManager = Depends(get_scan_manager)) -> dict:
    for f in _all_findings(mgr):
        if f.get("id") == finding_id:
            return f
    raise HTTPException(status_code=404, detail="finding not found")


@router.post("/{finding_id}/exploit", response_model=GenericMessage)
def run_exploit(finding_id: str) -> GenericMessage:
    """Deliberately disabled. The frontend's ExploitRunner panel exists
    for future use; in production this endpoint must require explicit
    per-finding authorisation before doing anything."""
    raise HTTPException(
        status_code=501,
        detail=("exploit execution intentionally not implemented. "
                "Wiring this requires per-finding scope authorisation "
                "that HunterPy does not yet track."),
    )


@router.post("/{finding_id}/tags", response_model=GenericMessage)
def add_tags(finding_id: str) -> GenericMessage:
    # Tags are a UI-only concept until we add a SQLite table for them.
    return GenericMessage(message="tagging is client-side only in v2.1",
                          success=True)
