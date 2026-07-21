from app.reporting.pdf_report import generate_pdf_report
from app.schemas.report import (
    ReportAuditEntrySchema,
    ReportFindingSchema,
    ReportSummarySchema,
    ScanReportData,
)


def test_generate_pdf_report_returns_valid_pdf_bytes():
    report = ScanReportData(
        scan_id="demo-scan",
        target_url="https://example.com",
        summary=ReportSummarySchema(
            total_findings=1,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=1,
            risk_score=10.0,
            endpoints_discovered=1,
            pages_crawled=1,
        ),
        findings=[
            ReportFindingSchema(
                id="1",
                vulnerability_type="xss",
                severity="high",
                title="Reflected XSS",
                url="https://example.com",
                method="GET",
                parameter=None,
                evidence="Sample evidence",
                confidence=0.9,
                confidence_band="high",
                is_likely_false_positive=False,
                owasp_category="A03",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                risk_explanation="Sample explanation",
                business_impact="Sample impact",
                developer_explanation="Sample remediation guidance",
                remediation="Sanitize output",
                safe_poc=None,
            )
        ],
        audit_trail=[ReportAuditEntrySchema(timestamp="2026-01-01T00:00:00", module="crawler", method="GET", url="https://example.com", response_code=200, duration_ms=10.0)],
    )

    data = generate_pdf_report(report)

    assert data.startswith(b"%PDF")
    assert b"Reconix Scan Report" in data
    assert b"Executive Summary" in data
    assert b"Findings" in data
    assert b"Reflected XSS" in data
    assert b"%%EOF" in data
