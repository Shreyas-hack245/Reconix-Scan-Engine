"""
Scan management API routes for Reconix Scan Engine.

Handles creating scans (which launches the crawl -> vulnerability scan
-> AI enrichment pipeline as a background task), listing a user's
scans, and reading individual scan status/progress.
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.confidence import assess_all
from app.ai.explainer import RiskExplainer
from app.auth.dependencies import get_current_user
from app.crawler.crawler import Crawler
from app.db.session import AsyncSessionLocal, get_db
from app.models.audit_log import AuditLog
from app.models.endpoint import Endpoint
from app.models.finding import Finding, Severity, VulnerabilityType
from app.models.scan import Scan, ScanStatus
from app.models.user import User, UserRole
from app.reporting import compute_risk_score
from app.schemas.scan import ScanCreate, ScanRead, ScanSummary
from app.scanner.orchestrator import ScannerOrchestrator

router = APIRouter()


async def _run_scan_background(scan_id: str, config: dict) -> None:
    """
    Background job: crawl the target, run every vulnerability scanner
    module, enrich findings with AI explanations, persist everything,
    and update the parent scan's status/summary counters.
    """
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            return

        scan.status = ScanStatus.CRAWLING
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

        try:
            crawler = Crawler(
                base_url=scan.target_url,
                max_depth=scan.max_depth,
                max_pages=scan.max_pages,
                requests_per_second=config["requests_per_second"],
                max_concurrent=config["max_concurrent_requests"],
                respect_robots=config["respect_robots"],
            )
            crawl_result = await crawler.crawl()

            for discovered in crawl_result.endpoints:
                db.add(
                    Endpoint(
                        scan_id=scan.id,
                        url=discovered.url,
                        method=discovered.method,
                        source=discovered.source,
                        has_form=discovered.has_form,
                        parameters=json.dumps(discovered.parameters),
                        content_type=discovered.content_type,
                        status_code=discovered.status_code,
                    )
                )

            scan.pages_crawled = crawl_result.pages_crawled
            scan.endpoints_discovered = len(crawl_result.endpoints)
            scan.status = ScanStatus.SCANNING
            await db.commit()

            # Audit events are buffered in memory during the (highly concurrent)
            # scan phase and flushed to the database sequentially afterward,
            # since AsyncSession is not safe to share across concurrent tasks.
            audit_events: list[dict] = []

            async def _audit_recorder(**kwargs) -> None:
                audit_events.append(kwargs)

            orchestrator = ScannerOrchestrator(
                requests_per_second=config["requests_per_second"],
                max_concurrent=config["max_concurrent_requests"],
                audit_recorder=_audit_recorder,
            )
            orchestrator_result = await orchestrator.run(crawl_result)

            for event in audit_events:
                db.add(
                    AuditLog(
                        scan_id=scan.id,
                        url=event.get("url", ""),
                        method=event.get("method", ""),
                        module=event.get("module", "unknown"),
                        response_code=event.get("status_code"),
                        duration_ms=event.get("duration_ms", 0.0),
                        finding_id=event.get("finding_id"),
                        notes=event.get("notes"),
                    )
                )

            explainer = RiskExplainer()
            assessments = assess_all(orchestrator_result.findings)
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            for finding in orchestrator_result.findings:
                assessment = assessments[id(finding)]
                explanation = explainer.explain(finding)
                severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

                db.add(
                    Finding(
                        scan_id=scan.id,
                        vulnerability_type=VulnerabilityType(finding.vulnerability_type),
                        severity=Severity(finding.severity),
                        title=finding.title,
                        url=finding.url,
                        method=finding.method,
                        parameter=finding.parameter,
                        evidence=finding.evidence,
                        confidence=assessment.adjusted_confidence,
                        is_false_positive=assessment.likely_false_positive,
                        cvss_score=finding.cvss_score,
                        owasp_category=finding.owasp_category,
                        risk_explanation=explanation.risk_explanation,
                        business_impact=explanation.business_impact,
                        developer_explanation=explanation.developer_explanation,
                        remediation=explanation.remediation,
                        safe_poc=json.dumps(finding.safe_poc.to_dict()) if finding.safe_poc else None,
                    )
                )

            scan.findings_count = len(orchestrator_result.findings)
            scan.risk_score = compute_risk_score(severity_counts)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()

        except Exception as exc:  # defensive: a failed scan should be recorded, not crash the worker
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:2000]
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()


@router.post("/", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Scan:
    """Launch a new scan against `target_url`. The scan runs asynchronously in the background."""
    scan = Scan(
        owner_id=current_user.id,
        target_url=payload.target_url,
        status=ScanStatus.PENDING,
        max_depth=payload.max_depth,
        max_pages=payload.max_pages,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(
        _run_scan_background,
        scan.id,
        {
            "requests_per_second": payload.requests_per_second,
            "max_concurrent_requests": payload.max_concurrent_requests,
            "respect_robots": payload.respect_robots,
        },
    )

    return scan


@router.get("/", response_model=list[ScanSummary])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Scan]:
    """List scans belonging to the current user (or all scans, for admins)."""
    query = select(Scan).order_by(Scan.created_at.desc())
    if current_user.role != UserRole.ADMIN:
        query = query.where(Scan.owner_id == current_user.id)

    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Scan:
    """Retrieve a single scan's status and progress counters."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if current_user.role != UserRole.ADMIN and scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have access to this scan")

    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """Delete a scan and all of its associated endpoints, findings, and audit logs."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if current_user.role != UserRole.ADMIN and scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have access to this scan")

    await db.delete(scan)
    await db.commit()