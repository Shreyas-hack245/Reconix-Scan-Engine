"""
Security HTTP headers detection module.

SAFE DETECTION METHODOLOGY: purely observational -- issues a single GET
request and inspects standard, well-known security response headers.
No injection or state change of any kind.
"""

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc

# header_name -> (severity if missing, human description)
_EXPECTED_HEADERS: dict[str, tuple[str, str]] = {
    "content-security-policy": (Severity.MEDIUM.value, "Content-Security-Policy mitigates XSS and data-injection attacks."),
    "x-frame-options": (Severity.MEDIUM.value, "X-Frame-Options prevents clickjacking via iframe embedding."),
    "x-content-type-options": (Severity.LOW.value, "X-Content-Type-Options prevents MIME-type sniffing attacks."),
    "strict-transport-security": (Severity.MEDIUM.value, "Strict-Transport-Security enforces HTTPS and prevents downgrade attacks."),
    "referrer-policy": (Severity.LOW.value, "Referrer-Policy controls what referrer data leaks to other origins."),
    "permissions-policy": (Severity.LOW.value, "Permissions-Policy restricts access to sensitive browser features."),
}


class SecurityHeadersScanner(BaseScanner):
    """Detects missing standard security response headers."""

    module_name = "headers"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        response = await self._request("GET", endpoint.url, notes="security headers inspection")
        if response is None:
            return findings

        present_headers = {k.lower() for k in response.headers.keys()}

        for header_name, (severity, description) in _EXPECTED_HEADERS.items():
            if header_name in present_headers:
                continue

            findings.append(
                ScanFinding(
                    vulnerability_type=VulnerabilityType.SECURITY_HEADERS.value,
                    severity=severity,
                    title=f"Missing security header: {header_name}",
                    url=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence=f"The response did not include a '{header_name}' header. {description}",
                    confidence=0.95,
                    safe_poc=SafePoc(
                        example_request=f"GET {endpoint.url}",
                        example_response=f"Response headers: {sorted(present_headers)}",
                        expected_safe_output=f"Response headers include '{header_name}' with an appropriate value.",
                        impact=description,
                        verification_steps=[
                            f"Send a GET request to {endpoint.url}.",
                            f"Inspect the response headers for '{header_name}'.",
                        ],
                    ),
                )
            )

        return findings