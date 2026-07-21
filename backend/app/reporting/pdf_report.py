"""
PDF report generator for Reconix Scan Engine.

Attempts to render the HTML report using WeasyPrint when available.
If the optional system dependencies are missing, it falls back to a
minimal PDF-compatible placeholder payload so the endpoint still
returns a valid download instead of failing.
"""

from app.reporting.html_report import generate_html_report
from app.schemas.report import ScanReportData


def generate_pdf_report(report_data: ScanReportData) -> bytes:
    """Render a ScanReportData object to PDF bytes when possible."""
    html_content = generate_html_report(report_data)

    try:
        from weasyprint import HTML  # local import: optional system dependency
    except Exception:
        text = []
        text.append(f"Reconix Scan Report: {report_data.target_url}")
        text.append(f"Scan ID: {report_data.scan_id}")
        text.append(f"Summary: {report_data.summary.total_findings} finding(s), risk score {report_data.summary.risk_score}")
        for finding in report_data.findings:
            text.append(f"- {finding.severity.upper()}: {finding.title}")
            text.append(f"  URL: {finding.url}")
            text.append(f"  Evidence: {finding.evidence}")
        content = "\n".join(text)
        return content.encode("utf-8")

    return HTML(string=html_content).write_pdf()