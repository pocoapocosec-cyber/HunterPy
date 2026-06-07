"""Pydantic request/response models for the FastAPI layer.

We define ONLY the shapes the frontend actually consumes (see
gui/frontend/src/types/*). The internal `ScanRecord` dataclass has
extra fields that don't need to round-trip through HTTP.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------- Scan ----------
class ScanCreateRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=255)
    mode: str = Field(default="passive")
    modules: Optional[List[str]] = None
    options: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    id: str
    db_scan_id: Optional[int] = None
    target: str
    mode: str
    status: str
    phase: str
    progress: int
    modules: List[str]
    options: Dict[str, Any]
    findings_count: int
    findings_by_severity: Dict[str, int]
    findings_by_tier: Dict[str, int]
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration: Optional[float] = None
    error: Optional[str] = None


class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int


class ScanProgressResponse(BaseModel):
    scan_id: str
    phase: str
    phase_name: str
    percent: int
    current_module: Optional[str] = None
    modules_completed: int
    modules_total: int
    elapsed_time: float
    estimated_remaining: float
    status: str


class ModuleStatusResponse(BaseModel):
    name: str
    status: str
    progress: int = 0
    findings_count: int = 0


class LogsResponse(BaseModel):
    logs: List[str]


# ---------- Findings ----------
class FindingResponse(BaseModel):
    id: Optional[str] = None
    scan_id: Optional[str] = None
    type: Optional[str] = None
    severity: Optional[str] = None
    classification: Optional[str] = None
    tier: Optional[str] = None
    confidence: Optional[float] = None
    classification_confidence: Optional[float] = None
    classification_reason: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    details: Optional[Any] = None
    url: Optional[str] = None
    module: Optional[str] = None
    score: Optional[float] = None
    cvss: Optional[float] = None
    evidence: Optional[Dict[str, Any]] = None
    references: Optional[List[str]] = None


class FindingListResponse(BaseModel):
    findings: List[Dict[str, Any]]
    total: int


# ---------- Misc ----------
class ValidateTargetRequest(BaseModel):
    target: str


class ValidateTargetResponse(BaseModel):
    valid: bool
    reason: Optional[str] = None
    warnings: Optional[List[str]] = None


class ToolStatus(BaseModel):
    name: str
    available: bool
    path: Optional[str] = None
    version: Optional[str] = None
    required: bool = False


class ReportSummary(BaseModel):
    id: str
    scan_id: str
    format: str
    generated_at: str
    title: str


class GenericMessage(BaseModel):
    message: str
    success: bool = True
