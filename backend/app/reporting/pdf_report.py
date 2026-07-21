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
        return (
            b"%PDF-1.4\n"
            b"1 0 obj<< /Type /Catalog /Pages 2 0 R>>endobj\n"
            b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1>>endobj\n"
            b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n"
            b"4 0 obj<< /Length 44>>stream\nBT /F1 16 Tf 72 720 Td (Report export unavailable in this environment) Tj ET\nendstream\nendobj\n"
            b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n"
            b"xref\n0 6\n0000000000 65535 f \n0000000010 00000 n \n0000000062 00000 n \n0000000119 00000 n \n0000000207 00000 n \n0000000301 00000 n \ntrailer<< /Size 6 /Root 1 0 R>>\nstartxref\n0\n%%EOF"
        )

    return HTML(string=html_content).write_pdf()