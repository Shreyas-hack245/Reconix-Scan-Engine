"""
HTML report generator for Reconix Scan Engine.

Renders a self-contained, dark-themed HTML report (inline CSS, no
external assets) from a ScanReportData object using the Jinja2
template in `templates/report.html.j2`. The resulting HTML is also
the input to the PDF report generator.
"""

import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.schemas.report import ScanReportData

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "j2"]),
)


def generate_html_report(report_data: ScanReportData) -> str:
    """Render a complete, self-contained HTML report for a scan."""
    template = _env.get_template("report.html.j2")
    return template.render(report=report_data)