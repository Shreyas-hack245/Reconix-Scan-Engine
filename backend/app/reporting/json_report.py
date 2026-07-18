"""
JSON report generator for Reconix Scan Engine.
"""

import json

from app.schemas.report import ScanReportData


def generate_json_report(report_data: ScanReportData, indent: int = 2) -> str:
    """Serialize a ScanReportData object to a formatted JSON string."""
    return report_data.model_dump_json(indent=indent)


def generate_json_report_dict(report_data: ScanReportData) -> dict:
    """Return a ScanReportData object as a plain Python dict (e.g. for API responses)."""
    return json.loads(report_data.model_dump_json())