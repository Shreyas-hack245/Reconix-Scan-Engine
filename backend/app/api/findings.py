"""
Findings API routes for Reconix Scan Engine.

Lists and retrieves AI-enriched vulnerability findings for a scan.
"""

import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.db.session import get_db
from app.models.finding import Finding, Severity
from app.models.scan import Scan
from app.models.user import User, UserRole
from app.schemas.finding import FindingListResponse, FindingRead, SafePocRead

router = APIRouter()


async def _authorize_scan_access(scan_id: str, db: AsyncSession, current_user: User) -> Scan:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if current_user.role != UserRole.ADMIN and scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have access to this scan")
    return scan


def _to_finding_read(finding: Finding) -> FindingRead:
    safe_poc = None
    if finding.safe_poc:
        try:
            safe_poc = SafePocRead(**json.loads(finding.safe_poc))
        except (json.JSONDecodeError, TypeError):
            safe_poc = None

    return FindingRead(
        id=finding.id,
        scan_id=finding.scan_id,
        vulnerability_type=finding.vulnerability_type,
        severity=finding.severity,
        title=finding.title,
        url=finding.url,
        method=finding.method,
        parameter=finding.parameter,
        evidence=finding.evidence,
        confidence=finding.confidence,
        is_false_positive=finding.is_false_positive,
        cvss_score=finding.cvss_score,
        owasp_category=finding.owasp_category,
        risk_explanation=finding.risk_explanation,
        business_impact=finding.business_impact,
        developer_explanation=finding.developer_explanation,
        remediation=finding.remediation,
        safe_poc=safe_poc,
        created_at=finding.created_at,
    )


@router.get("/{scan_id}", response_model=FindingListResponse)
async def list_findings(
    scan_id: str,
    severity: Severity | None = None,
    include_false_positives: bool = True,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FindingListResponse:
    """List all findings for a scan, optionally filtered by severity."""
    await _authorize_scan_access(scan_id, db, current_user)

    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if not include_false_positives:
        query = query.where(Finding.is_false_positive.is_(False))
    query = query.order_by(Finding.created_at.desc())

    result = await db.execute(query)
    findings = list(result.scalars().all())

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    return FindingListResponse(
        total=len(findings),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        info_count=counts["info"],
        findings=[_to_finding_read(f) for f in findings],
    )


@router.get("/detail/{finding_id}", response_model=FindingRead)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FindingRead:
    """Retrieve a single finding by id."""
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    await _authorize_scan_access(finding.scan_id, db, current_user)
    return _to_finding_read(finding)