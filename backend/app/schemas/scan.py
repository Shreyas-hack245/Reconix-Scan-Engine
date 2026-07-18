"""Pydantic schemas for creating, listing, and reading scans."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    """Payload for launching a new scan."""

    target_url: str = Field(description="The base URL of the application to scan, e.g. https://example.com")
    max_depth: int = Field(default=3, ge=0, le=10)
    max_pages: int = Field(default=200, ge=1, le=2000)
    requests_per_second: float = Field(default=5.0, gt=0, le=50)
    max_concurrent_requests: int = Field(default=5, ge=1, le=50)
    respect_robots: bool = True

    @field_validator("target_url")
    @classmethod
    def _must_be_http_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        return value.rstrip("/")


class ScanSummary(BaseModel):
    """Lightweight scan representation used in list views."""

    id: str
    target_url: str
    status: ScanStatus
    findings_count: int
    risk_score: float
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanRead(BaseModel):
    """Full scan representation, including progress counters."""

    id: str
    owner_id: str
    target_url: str
    status: ScanStatus
    max_depth: int
    max_pages: int
    pages_crawled: int
    endpoints_discovered: int
    findings_count: int
    risk_score: float
    error_message: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}