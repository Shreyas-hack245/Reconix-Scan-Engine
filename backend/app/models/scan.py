"""Scan ORM model representing a single vulnerability scan job."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScanStatus(str, enum.Enum):
    """Lifecycle states of a scan job."""

    PENDING = "pending"
    CRAWLING = "crawling"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    """A single scan job targeting a base URL."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)

    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)

    max_depth: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    max_pages: Mapped[int] = mapped_column(Integer, default=200, nullable=False)

    pages_crawled: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    endpoints_discovered: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Integer, default=0, nullable=False)

    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    owner = relationship("User", back_populates="scans")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Scan id={self.id} target={self.target_url} status={self.status}>"