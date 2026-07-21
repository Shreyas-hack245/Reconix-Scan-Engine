"""
PDF report generator for Reconix Scan Engine.

Attempts to render the HTML report using WeasyPrint when available.
If the optional system dependencies are missing, it falls back to a
minimal PDF-compatible placeholder payload so the endpoint still
returns a valid download instead of failing.
"""

from app.reporting.html_report import generate_html_report
from app.schemas.report import ScanReportData


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_fallback_pdf(report_data: ScanReportData) -> bytes:
    lines: list[str] = []
    lines.append("Reconix Scan Report")
    lines.append(f"Target: {report_data.target_url}")
    lines.append(f"Scan ID: {report_data.scan_id}")
    lines.append(f"Generated: {report_data.generated_at}")
    lines.append("")
    lines.append("Executive Summary")
    lines.append(
        f"Findings: {report_data.summary.total_findings} total, "
        f"Critical={report_data.summary.critical_count}, "
        f"High={report_data.summary.high_count}, "
        f"Medium={report_data.summary.medium_count}, "
        f"Low={report_data.summary.low_count}, "
        f"Info={report_data.summary.info_count}"
    )
    lines.append(f"Risk Score: {report_data.summary.risk_score}")
    lines.append(
        f"Pages crawled: {report_data.summary.pages_crawled}; "
        f"Endpoints discovered: {report_data.summary.endpoints_discovered}"
    )

    if report_data.findings:
        lines.append("")
        lines.append("Findings")
        for index, finding in enumerate(report_data.findings, start=1):
            lines.append(f"{index}. {finding.severity.upper()}: {finding.title}")
            lines.append(f"   URL: {finding.url}")
            lines.append(f"   Evidence: {finding.evidence}")
            if finding.remediation:
                lines.append(f"   Remediation: {finding.remediation}")
            lines.append("")

    if report_data.audit_trail:
        lines.append("Audit Trail")
        for entry in report_data.audit_trail[-10:]:
            lines.append(
                f"- {entry.timestamp} {entry.method} {entry.url} "
                f"status={entry.response_code or '-'} duration={entry.duration_ms}ms"
            )

    content_stream_parts: list[str] = []
    y_position = 760
    for line in lines:
        escaped = _escape_pdf_text(line)
        content_stream_parts.append(f"BT\n/F1 12 Tf\n72 {y_position} Td\n({escaped}) Tj\nET\n")
        y_position -= 14

    payload = "".join(content_stream_parts)
    payload_bytes = payload.encode("utf-8")

    objects: list[bytes] = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    objects.append(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n")
    objects.append(f"4 0 obj\n<< /Length {len(payload_bytes)} >>\nstream\n{payload}endstream\nendobj\n".encode("utf-8"))
    objects.append(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

    pdf = b"%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj

    xref_offset = len(pdf)
    pdf += b"xref\n0 6\n"
    pdf += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        pdf += f"{offset:010d} 00000 n \n".encode("utf-8")

    pdf += b"trailer\n<< /Size 6 /Root 1 0 R >>\n"
    pdf += f"startxref\n{xref_offset}\n%%EOF\n".encode("utf-8")
    return pdf


def generate_pdf_report(report_data: ScanReportData) -> bytes:
    """Render a ScanReportData object to PDF bytes when possible."""
    html_content = generate_html_report(report_data)

    try:
        from weasyprint import HTML  # local import: optional system dependency
    except Exception:
        return _build_fallback_pdf(report_data)

    return HTML(string=html_content).write_pdf()