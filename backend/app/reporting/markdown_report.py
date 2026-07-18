"""
Markdown report generator for Reconix Scan Engine.
"""

from app.schemas.report import ReportFindingSchema, ScanReportData

_SEVERITY_EMOJI = {
    "critical": "\U0001F534",
    "high": "\U0001F7E0",
    "medium": "\U0001F7E1",
    "low": "\U0001F535",
    "info": "\u26AA",
}


def _render_finding(finding: ReportFindingSchema, index: int) -> str:
    emoji = _SEVERITY_EMOJI.get(finding.severity, "")
    lines = [
        f"### {index}. {emoji} [{finding.severity.upper()}] {finding.title}",
        "",
        f"- **URL:** `{finding.method} {finding.url}`",
        f"- **Parameter:** `{finding.parameter or 'N/A'}`",
        f"- **OWASP Category:** {finding.owasp_category}",
        f"- **CVSS Score:** {finding.cvss_score}" + (f" (`{finding.cvss_vector}`)" if finding.cvss_vector else ""),
        f"- **Confidence:** {finding.confidence:.2f} ({finding.confidence_band})"
        + (" \u26A0\uFE0F possible false positive -- verify manually" if finding.is_likely_false_positive else ""),
        "",
        "**Evidence**",
        "",
        f"> {finding.evidence}",
        "",
        "**Risk Explanation**",
        "",
        finding.risk_explanation,
        "",
        "**Business Impact**",
        "",
        finding.business_impact,
        "",
        "**Remediation**",
        "",
        finding.remediation,
        "",
    ]

    if finding.safe_poc:
        poc = finding.safe_poc
        steps = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(poc.verification_steps))
        lines += [
            "**Safe Proof of Concept**",
            "",
            "```",
            poc.example_request,
            "```",
            "",
            f"_Example vulnerable response:_ {poc.example_response}",
            "",
            f"_Expected safe output:_ {poc.expected_safe_output}",
            "",
            f"_Impact:_ {poc.impact}",
            "",
            "_Verification steps:_",
            "",
            steps,
            "",
        ]

    lines.append("---")
    return "\n".join(lines)


def generate_markdown_report(report_data: ScanReportData) -> str:
    """Render a complete Markdown report for a scan."""
    s = report_data.summary
    sections = [
        f"# Reconix Scan Engine Report",
        "",
        f"**Target:** {report_data.target_url}",
        f"**Scan ID:** `{report_data.scan_id}`",
        f"**Generated:** {report_data.generated_at.isoformat()}",
        "",
        "## Executive Summary",
        "",
        f"- **Risk Score:** {s.risk_score} / 100",
        f"- **Total Findings:** {s.total_findings}",
        f"- {_SEVERITY_EMOJI['critical']} Critical: {s.critical_count}",
        f"- {_SEVERITY_EMOJI['high']} High: {s.high_count}",
        f"- {_SEVERITY_EMOJI['medium']} Medium: {s.medium_count}",
        f"- {_SEVERITY_EMOJI['low']} Low: {s.low_count}",
        f"- {_SEVERITY_EMOJI['info']} Info: {s.info_count}",
        f"- **Pages Crawled:** {s.pages_crawled}",
        f"- **Endpoints Discovered:** {s.endpoints_discovered}",
        "",
        "## Findings",
        "",
    ]

    if not report_data.findings:
        sections.append("No findings were reported for this scan.")
    else:
        for i, finding in enumerate(report_data.findings, start=1):
            sections.append(_render_finding(finding, i))
            sections.append("")

    sections += [
        "## Audit Trail",
        "",
        f"A total of {len(report_data.audit_trail)} requests were logged during this scan. "
        f"Showing the most recent 50 below; the full trail is available via the API/audit viewer.",
        "",
        "| Timestamp | Module | Method | URL | Status | Duration (ms) |",
        "|---|---|---|---|---|---|",
    ]

    for entry in report_data.audit_trail[-50:]:
        sections.append(
            f"| {entry.timestamp.isoformat()} | {entry.module} | {entry.method} | {entry.url} | "
            f"{entry.response_code or '-'} | {entry.duration_ms:.1f} |"
        )

    return "\n".join(sections)