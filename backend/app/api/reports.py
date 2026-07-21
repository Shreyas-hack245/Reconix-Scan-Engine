"""
Report generation/download API routes for Reconix Scan Engine.

Builds a format-agnostic `ScanReportData` object from the database for
a completed (or in-progress) scan, then renders it as JSON, Markdown,
HTML, or PDF on demand.
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User, UserRole
from app.reporting.html_report import generate_html_report
from app.reporting.json_report import generate_json_report
from app.reporting.markdown_report import generate_markdown_report
from app.reporting.pdf_report import generate_pdf_report
from app.schemas.report import (
    ReportAuditEntrySchema,
    ReportFindingSchema,
    ReportPocSchema,
    ReportSummarySchema,
    ScanReportData,
)

router = APIRouter()

_LOW_CONFIDENCE_THRESHOLD = 0.35
_HIGH_CONFIDENCE_THRESHOLD = 0.7


def _confidence_band(confidence: float) -> str:
    if confidence >= _HIGH_CONFIDENCE_THRESHOLD:
        return "high"
    if confidence >= _LOW_CONFIDENCE_THRESHOLD:
        return "medium"
    return "low"


async def _build_report_data(scan_id: str, db: AsyncSession, current_user: User) -> ScanReportData:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if current_user.role != UserRole.ADMIN and scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have access to this scan")

    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at.desc()))
    findings = list(findings_result.scalars().all())

    audit_result = await db.execute(select(AuditLog).where(AuditLog.scan_id == scan_id).order_by(AuditLog.timestamp.asc()))
    audit_entries = list(audit_result.scalars().all())

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    report_findings: list[ReportFindingSchema] = []

    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        safe_poc = None
        if f.safe_poc:
            try:
                safe_poc = ReportPocSchema(**json.loads(f.safe_poc))
            except (json.JSONDecodeError, TypeError):
                safe_poc = None

        report_findings.append(
            ReportFindingSchema(
                id=f.id,
                vulnerability_type=f.vulnerability_type.value,
                severity=f.severity.value,
                title=f.title,
                url=f.url,
                method=f.method,
                parameter=f.parameter,
                evidence=f.evidence,
                confidence=f.confidence,
                confidence_band=_confidence_band(f.confidence),
                is_likely_false_positive=f.is_false_positive,
                owasp_category=f.owasp_category or "",
                cvss_score=f.cvss_score or 0.0,
                cvss_vector="",
                risk_explanation=f.risk_explanation or "",
                business_impact=f.business_impact or "",
                developer_explanation=f.developer_explanation or "",
                remediation=f.remediation or "",
                safe_poc=safe_poc,
            )
        )

    summary = ReportSummarySchema(
        total_findings=len(findings),
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        info_count=severity_counts["info"],
        risk_score=scan.risk_score,
        endpoints_discovered=scan.endpoints_discovered,
        pages_crawled=scan.pages_crawled,
    )

    return ScanReportData(
        scan_id=scan.id,
        target_url=scan.target_url,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        summary=summary,
        findings=report_findings,
        audit_trail=[
            ReportAuditEntrySchema(
                timestamp=entry.timestamp,
                module=entry.module,
                method=entry.method,
                url=entry.url,
                response_code=entry.response_code,
                duration_ms=entry.duration_ms,
            )
            for entry in audit_entries
        ],
    )


@router.get("/{scan_id}/json")
async def download_json_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download the scan report as JSON."""
    report_data = await _build_report_data(scan_id, db, current_user)
    content = generate_json_report(report_data)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="reconix-report-{scan_id}.json"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/{scan_id}/markdown")
async def download_markdown_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download the scan report as Markdown."""
    report_data = await _build_report_data(scan_id, db, current_user)
    content = generate_markdown_report(report_data)
    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="reconix-report-{scan_id}.md"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/{scan_id}/html")
async def download_html_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Render the scan report as HTML (viewable directly in a browser)."""
    report_data = await _build_report_data(scan_id, db, current_user)
    content = generate_html_report(report_data)
    return Response(content=content, media_type="text/html; charset=utf-8")


@router.get("/{scan_id}/pdf")
async def download_pdf_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download the scan report as PDF."""
    report_data = await _build_report_data(scan_id, db, current_user)
    try:
        content = generate_pdf_report(report_data)
    except Exception as exc:  # pragma: no cover - depends on optional system libs
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF generation failed: {exc}",
        ) from exc

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="reconix-report-{scan_id}.pdf"'},
    )