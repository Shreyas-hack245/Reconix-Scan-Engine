"""
Lightweight CVSS v3.1 base score estimation for Reconix Scan Engine.
"""

from dataclasses import dataclass

_CVSS_TABLE: dict[tuple[str, str], tuple[float, str]] = {
    ("sqli", "critical"): (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("sqli", "high"): (8.6, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    ("rce", "critical"): (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("command_injection", "critical"): (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("command_injection", "high"): (8.6, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("ssrf", "high"): (8.6, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"),
    ("ssrf", "medium"): (6.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    ("xss", "high"): (7.4, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("xss", "medium"): (6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("broken_access_control", "high"): (8.1, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    ("idor", "high"): (7.5, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    ("idor", "medium"): (5.4, "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"),
    ("auth_issue", "high"): (8.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("open_redirect", "medium"): (4.7, "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    ("open_redirect", "low"): (3.1, "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    ("csrf", "medium"): (6.5, "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    ("directory_traversal", "high"): (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("info_disclosure", "medium"): (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    ("info_disclosure", "low"): (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    ("security_headers", "low"): (3.1, "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    ("cookie_security", "medium"): (5.4, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    ("cookie_security", "low"): (3.1, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    ("file_upload", "high"): (8.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("clickjacking", "medium"): (4.3, "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    ("cors_misconfiguration", "high"): (7.4, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    ("cors_misconfiguration", "medium"): (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

_SEVERITY_FALLBACK: dict[str, float] = {
    "critical": 9.5,
    "high": 7.8,
    "medium": 5.5,
    "low": 3.2,
    "info": 0.0,
}


@dataclass
class CvssEstimate:
    """A CVSS v3.1 base score estimate with its contributing vector."""

    score: float
    vector: str


def estimate_cvss(vulnerability_type: str, severity: str) -> CvssEstimate:
    """Estimate a representative CVSS v3.1 base score/vector for a (type, severity) pair."""
    key = (vulnerability_type, severity)
    if key in _CVSS_TABLE:
        score, vector = _CVSS_TABLE[key]
        return CvssEstimate(score=score, vector=vector)

    fallback_score = _SEVERITY_FALLBACK.get(severity, 5.0)
    return CvssEstimate(score=fallback_score, vector="")