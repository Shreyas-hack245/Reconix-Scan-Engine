"""Endpoint ORM model representing a discovered URL/route during crawling."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Endpoint(Base):
    """A discovered endpoint (URL + method) belonging to a scan's sitemap."""

    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)

    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    source: Mapped[str] = mapped_column(
        String(50), default="crawler", nullable=False
    )  # crawler, form, js, openapi, robots
    has_form: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    requires_auth: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    parameters: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON-encoded list of param names
    content_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    scan = relationship("Scan", back_populates="endpoints")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Endpoint {self.method} {self.url}>"