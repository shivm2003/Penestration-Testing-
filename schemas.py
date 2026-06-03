from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from datetime import datetime

class TargetBase(BaseModel):
    url: str

class TargetCreate(TargetBase):
    pass

class TargetResponse(TargetBase):
    id: int
    status: str
    iteration_count: int = 0
    created_at: datetime

    class Config:
        from_attributes = True

class ReconDataResponse(BaseModel):
    id: int
    target_id: int
    data_type: str
    path: str
    method: str
    details: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class VulnerabilityResponse(BaseModel):
    id: int
    target_id: int
    recon_data_id: Optional[int] = None
    vuln_type: str
    path: Optional[str] = None
    method: Optional[str] = None
    cwe_id: Optional[str] = None
    severity: str
    evidence: Optional[str] = None
    status: str
    explanation: Optional[str] = None
    risk: Optional[str] = None
    fix: Optional[str] = None
    ai_report_status: str = "none"
    advanced_ai_report: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class TargetReport(TargetResponse):
    recon_data: List[ReconDataResponse] = []
    vulnerabilities: List[VulnerabilityResponse] = []

    class Config:
        from_attributes = True

class LogResponse(BaseModel):
    id: int
    target_id: int
    log_level: str
    agent_name: str
    message: str
    created_at: datetime

    class Config:
        from_attributes = True

class CodeReviewResponse(BaseModel):
    id: int
    target_id: int
    file_path: str
    snippet: str
    ai_analysis: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True

class ChainFindingResponse(BaseModel):
    id: int
    target_id: int
    chain_title: str
    vuln_ids_involved: str
    attack_narrative: Optional[str] = None
    severity: str
    confidence: int
    created_at: datetime

    class Config:
        from_attributes = True

class BruteFindingResponse(BaseModel):
    id: int
    target_id: int
    url: str
    method: str
    payload_summary: Optional[str] = None
    success_status: str
    otp_leak: Optional[str] = None
    severity: str
    created_at: datetime

    class Config:
        from_attributes = True


class AuthSurfaceResponse(BaseModel):
    id: int
    target_id: int
    url: str
    page_type: str
    detection_method: str
    confidence_score: float
    form_structure: Optional[str] = None
    page_title: Optional[str] = None
    response_code: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True


class AuthTestResultResponse(BaseModel):
    id: int
    target_id: int
    url: str
    payload: Optional[str] = None
    payload_type: Optional[str] = None
    response_code: Optional[int] = None
    response_diff: Optional[str] = None
    sensitive_data_detected: Optional[str] = None
    vulnerability_type: Optional[str] = None
    confidence: float
    raw_response_snippet: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class TrafficLogResponse(BaseModel):
    id: int
    target_id: Optional[int] = None
    timestamp: datetime
    method: str
    url: str
    request_headers: Optional[str] = None
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Optional[str] = None
    response_body: Optional[str] = None
    latency_ms: Optional[float] = None
    tag: str
    sensitive_flags: Optional[str] = None

    class Config:
        from_attributes = True


class PayloadLibraryResponse(BaseModel):
    id: int
    payload: str
    vuln_type: str
    context: Optional[str] = None
    success_rate: float
    used_count: int
    source: str
    created_at: datetime

    class Config:
        from_attributes = True


class CWEDataResponse(BaseModel):
    cwe_id: str
    name: str
    description: Optional[str] = None
    common_consequences: Optional[str] = None
    mitigation_strategies: Optional[str] = None
    last_modified: datetime
    created_at: datetime

    class Config:
        from_attributes = True

