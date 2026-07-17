"""Finding ORM model representing a single detected vulnerability."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Severity(str, enum.Enum):
    """Severity levels for a finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityType(str, enum.Enum):
    """Supported vulnerability categories detected by Reconix Scan Engine."""

    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    RCE = "rce"
    COMMAND_INJECTION = "command_injection"
    AUTH_ISSUE = "auth_issue"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    INFO_DISCLOSURE = "info_disclosure"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    SECURITY_HEADERS = "security_headers"
    COOKIE_SECURITY = "cookie_security"
    FILE_UPLOAD = "file_upload"
    CLICKJACKING = "clickjacking"
    CORS_MISCONFIGURATION = "cors_misconfiguration"


class Finding(Base):
    """A single vulnerability finding produced by a scanner module."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    endpoint_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("endpoints.id"), nullable=True)

    vulnerability_type: Mapped[VulnerabilityType] = mapped_column(Enum(VulnerabilityType), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)

    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)  # 0.0 - 1.0
    is_false_positive: Mapped[bool] = mapped_column(default=False, nullable=False)

    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    owasp_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    risk_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    business_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    developer_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    safe_poc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON-encoded safe PoC payload

    duplicate_of: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Finding {self.vulnerability_type} severity={self.severity} url={self.url}>"