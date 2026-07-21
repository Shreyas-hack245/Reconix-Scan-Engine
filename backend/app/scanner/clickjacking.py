"""
Clickjacking detection module.

SAFE DETECTION METHODOLOGY: purely observational -- checks whether the
response permits framing (missing X-Frame-Options AND no CSP
frame-ancestors directive). No actual framing/embedding is performed.
"""

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc


class ClickjackingScanner(BaseScanner):
    """Detects missing anti-framing protections (X-Frame-Options / CSP frame-ancestors)."""

    module_name = "clickjacking"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        response = await self._request("GET", endpoint.url, notes="clickjacking header inspection")
        if response is None:
            return findings

        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return findings

        xfo = response.headers.get("x-frame-options", "")
        csp = response.headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if not xfo and not has_frame_ancestors:
            findings.append(
                ScanFinding(
                    vulnerability_type=VulnerabilityType.CLICKJACKING.value,
                    severity=Severity.MEDIUM.value,
                    title="Page can be framed (clickjacking risk)",
                    url=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence=(
                        "Response has neither an X-Frame-Options header nor a "
                        "Content-Security-Policy frame-ancestors directive, so browsers "
                        "will allow this page to be embedded in an <iframe> on any site."
                    ),
                    confidence=0.9,
                    safe_poc=SafePoc(
                        example_request=f"GET {endpoint.url}",
                        example_response="No X-Frame-Options / CSP frame-ancestors header present",
                        expected_safe_output="X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'none'/'self'.",
                        impact=(
                            "An attacker can overlay invisible UI elements from this page inside their "
                            "own site to trick users into clicking buttons/links they did not intend to "
                            "(e.g. 'confirm transfer', 'grant access')."
                        ),
                        verification_steps=[
                            f"Embed {endpoint.url} in an <iframe> on a test page.",
                            "Confirm the browser renders it rather than blocking the frame.",
                        ],
                    ),
                )
            )

        return findings