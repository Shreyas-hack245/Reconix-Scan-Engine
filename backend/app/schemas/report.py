"""
Pydantic schemas describing the data shape consumed by every reporting
module (HTML, Markdown, PDF, JSON) in Reconix Scan Engine.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ReportPocSchema(BaseModel):
    """Safe proof-of-concept content for inclusion in a report."""

    example_request: str
    example_response: str
    expected_safe_output: str
    impact: str
    verification_steps: list[str]


class ReportFindingSchema(BaseModel):
    """A single, fully AI-enriched finding as rendered in a report."""

    id: str
    vulnerability_type: str
    severity: str
    title: str
    url: str
    method: str
    parameter: Optional[str] = None
    evidence: str
    confidence: float
    confidence_band: str
    is_likely_false_positive: bool
    owasp_category: str
    cvss_score: float
    cvss_vector: str
    risk_explanation: str
    business_impact: str
    developer_explanation: str
    remediation: str
    safe_poc: Optional[ReportPocSchema] = None


class ReportAuditEntrySchema(BaseModel):
    """A single audit trail entry as rendered in a report."""

    timestamp: datetime
    module: str
    method: str
    url: str
    response_code: Optional[int] = None
    duration_ms: float


class ReportSummarySchema(BaseModel):
    """Executive-summary-level statistics for a scan."""

    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: float = Field(description="Weighted 0-100 aggregate risk score for the scan")
    endpoints_discovered: int
    pages_crawled: int


class ScanReportData(BaseModel):
    """The complete, format-agnostic data set used to render any report type."""

    scan_id: str
    target_url: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    summary: ReportSummarySchema
    findings: list[ReportFindingSchema]
    audit_trail: list[ReportAuditEntrySchema] = Field(default_factory=list)