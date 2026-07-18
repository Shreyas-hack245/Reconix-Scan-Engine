"""
Reporting engine package for Reconix Scan Engine.

Generates developer- and stakeholder-facing scan reports in multiple
formats (JSON, Markdown, HTML, PDF) from a completed scan's findings,
each including an executive summary, risk score, OWASP/CVSS mapping,
evidence, safe proof-of-concept, remediation, and audit trail.
"""

_SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 6,
    "medium": 3,
    "low": 1,
    "info": 0,
}

_MAX_SCORE_CAP = 100.0
_SATURATION_FINDING_COUNT = 20  # findings count at which the score approaches the cap


def compute_risk_score(severity_counts: dict[str, int]) -> float:
    """
    Compute a weighted, 0-100 aggregate risk score for a scan from its
    per-severity finding counts.
    """
    weighted_sum = sum(_SEVERITY_WEIGHTS.get(sev, 0) * count for sev, count in severity_counts.items())
    total_findings = sum(severity_counts.values())

    if total_findings == 0:
        return 0.0

    saturation_factor = min(total_findings / _SATURATION_FINDING_COUNT, 1.0)
    normalized = (weighted_sum / (total_findings * _SEVERITY_WEIGHTS["critical"])) * _MAX_SCORE_CAP
    score = normalized * (0.5 + 0.5 * saturation_factor)

    return round(min(score, _MAX_SCORE_CAP), 1)