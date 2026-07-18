"""Pydantic schemas for reading vulnerability findings via the API."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.models.finding import Severity, VulnerabilityType


class SafePocRead(BaseModel):
    """Safe proof-of-concept content as returned by the API."""

    example_request: str
    example_response: str
    expected_safe_output: str
    impact: str
    verification_steps: list[str]


class FindingRead(BaseModel):
    """Full finding representation returned by the API."""

    id: str
    scan_id: str
    vulnerability_type: VulnerabilityType
    severity: Severity
    title: str
    url: str
    method: str
    parameter: Optional[str] = None
    evidence: str
    confidence: float
    is_false_positive: bool
    cvss_score: Optional[float] = None
    owasp_category: Optional[str] = None
    risk_explanation: Optional[str] = None
    business_impact: Optional[str] = None
    developer_explanation: Optional[str] = None
    remediation: Optional[str] = None
    safe_poc: Optional[SafePocRead] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingListResponse(BaseModel):
    """Paginated-friendly wrapper for a list of findings plus summary counts."""

    total: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    findings: list[FindingRead]