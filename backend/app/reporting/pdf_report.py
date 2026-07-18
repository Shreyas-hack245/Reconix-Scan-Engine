"""
PDF report generator for Reconix Scan Engine.

Converts the same HTML report produced by `html_report.py` into a PDF
document using WeasyPrint, so the PDF and HTML reports always stay
visually consistent.
"""

from app.reporting.html_report import generate_html_report
from app.schemas.report import ScanReportData


def generate_pdf_report(report_data: ScanReportData) -> bytes:
    """
    Render a ScanReportData object to PDF bytes.

    WeasyPrint is imported lazily inside this function because it pulls
    in system-level dependencies (Pango/Cairo) that may not be present
    in every deployment environment; environments that only need JSON
    /Markdown/HTML reports are not forced to install them.
    """
    from weasyprint import HTML  # local import: optional system dependency

    html_content = generate_html_report(report_data)
    return HTML(string=html_content).write_pdf()