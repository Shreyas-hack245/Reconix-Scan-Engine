"""
Broken Access Control detection module.

SAFE DETECTION METHODOLOGY: purely observational. For endpoints marked
as requiring authentication (or that reside under commonly-sensitive
path prefixes such as /admin, /internal, /api/v1/admin), this module
issues a request with NO Authorization header/cookies and checks
whether it still receives a 200 response with substantive content
instead of a 401/403. No credentials are guessed, brute-forced, or
otherwise attacked.
"""

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc

_SENSITIVE_PATH_HINTS = ("/admin", "/internal", "/private", "/manage", "/dashboard", "/settings", "/account")


def _looks_sensitive(url: str) -> bool:
    lowered = url.lower()
    return any(hint in lowered for hint in _SENSITIVE_PATH_HINTS)


class AccessControlScanner(BaseScanner):
    """Detects endpoints that appear to require authorization but allow unauthenticated access."""

    module_name = "access_control"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        if not _looks_sensitive(endpoint.url):
            return findings

        response = await self._request(
            endpoint.method,
            endpoint.url,
            headers={},  # explicitly no Authorization header/cookies
            notes="unauthenticated access-control probe",
        )

        if response is None:
            return findings

        if response.status_code == 200 and len(response.text or "") > 50:
            findings.append(
                ScanFinding(
                    vulnerability_type=VulnerabilityType.BROKEN_ACCESS_CONTROL.value,
                    severity=Severity.HIGH.value,
                    title="Sensitive-looking endpoint accessible without authentication",
                    url=endpoint.url,
                    method=endpoint.method,
                    parameter=None,
                    evidence=(
                        f"URL path suggests restricted functionality ({endpoint.url}), but an "
                        f"unauthenticated request returned HTTP 200 with "
                        f"{len(response.text)} bytes of content instead of 401/403."
                    ),
                    confidence=0.45,
                    safe_poc=SafePoc(
                        example_request=f"{endpoint.method} {endpoint.url} (no Authorization header/cookies)",
                        example_response=f"HTTP {response.status_code} with substantive content",
                        expected_safe_output="HTTP 401 Unauthorized or 403 Forbidden.",
                        impact="Unauthenticated users may be able to view or manipulate administrative/internal functionality.",
                        verification_steps=[
                            f"Request {endpoint.url} in a fresh, unauthenticated browser session or HTTP client.",
                            "Confirm whether protected content/functionality is returned.",
                        ],
                    ),
                )
            )

        return findings