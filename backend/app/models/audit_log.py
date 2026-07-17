"""AuditLog ORM model recording every request Reconix Scan Engine makes during a scan."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AuditLog(Base):
    """
    An immutable audit trail entry for a single HTTP request performed by
    the crawler or a scanner module during a scan.
    """

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    request_headers: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON-encoded
    response_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    module: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. "crawler", "xss", "sqli"
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan = relationship("Scan", back_populates="audit_logs")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<AuditLog {self.method} {self.url} module={self.module}>"