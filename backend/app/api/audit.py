"""
Audit trail API routes for Reconix Scan Engine.

Exposes the immutable, per-request audit log recorded during a scan
(timestamp, endpoint, method, response code, module, duration) for
transparency and compliance review.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.scan import Scan
from app.models.user import User, UserRole

router = APIRouter()


class AuditLogEntryRead(BaseModel):
    """A single audit trail entry."""

    id: str
    scan_id: str
    timestamp: datetime
    url: str
    method: str
    module: str
    response_code: Optional[int] = None
    finding_id: Optional[str] = None
    duration_ms: float
    notes: Optional[str] = None

    model_config = {"from_attributes": True}


class AuditLogPage(BaseModel):
    """A page of audit log entries plus the total count for the scan."""

    total: int
    entries: list[AuditLogEntryRead]


@router.get("/{scan_id}", response_model=AuditLogPage)
async def list_audit_log(
    scan_id: str,
    module: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditLogPage:
    """List audit trail entries for a scan, most recent first."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if current_user.role != UserRole.ADMIN and scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have access to this scan")

    base_query = select(AuditLog).where(AuditLog.scan_id == scan_id)
    count_query = select(func.count()).select_from(AuditLog).where(AuditLog.scan_id == scan_id)

    if module:
        base_query = base_query.where(AuditLog.module == module)
        count_query = count_query.where(AuditLog.module == module)

    total = (await db.execute(count_query)).scalar_one()

    result = await db.execute(base_query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset))
    entries = list(result.scalars().all())

    return AuditLogPage(total=total, entries=[AuditLogEntryRead.model_validate(e) for e in entries])