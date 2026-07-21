"""
Reflected Cross-Site Scripting (XSS) detection module.

SAFE DETECTION METHODOLOGY: this module injects a unique, non-executing
benign marker containing HTML metacharacters (e.g. `reconixAB12<rx>`)
into each parameter and checks whether the marker is reflected back
UNESCAPED in the response body. It never injects or executes a real
`<script>`/`onerror=` payload -- unescaped reflection of HTML
metacharacters is itself sufficient, well-established evidence of a
missing-output-encoding vulnerability, without requiring an actual
working exploit to be sent to the target.
"""

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import (
    BaseScanner,
    ScanFinding,
    ScanTarget,
    SafePoc,
    build_form_payload,
    new_marker,
    with_query_param,
)


class XssScanner(BaseScanner):
    """Detects reflected XSS via unescaped reflection of a benign HTML marker."""

    module_name = "xss"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        for param in endpoint.parameters:
            marker = new_marker("rx")
            probe_value = f'{marker}<rxtag>'

            if endpoint.method.upper() == "GET":
                test_url = with_query_param(endpoint.url, param, probe_value)
                response = await self._request("GET", test_url, notes=f"xss probe on param={param}")
            else:
                payload = build_form_payload(endpoint.parameters, param, probe_value)
                response = await self._request(endpoint.method, endpoint.url, data=payload, notes=f"xss probe on param={param}")
                test_url = endpoint.url

            if response is None or not response.text:
                continue

            body = response.text
            unescaped_marker = f"{marker}<rxtag>"

            if unescaped_marker in body:
                findings.append(
                    ScanFinding(
                        vulnerability_type=VulnerabilityType.XSS.value,
                        severity=Severity.HIGH.value,
                        title=f"Reflected XSS in parameter '{param}'",
                        url=test_url,
                        method=endpoint.method,
                        parameter=param,
                        evidence=(
                            f"Injected benign marker '{unescaped_marker}' into parameter '{param}' "
                            f"and it was reflected back in the response body without HTML encoding, "
                            f"indicating user input is rendered without proper output encoding."
                        ),
                        confidence=0.75,
                        safe_poc=SafePoc(
                            example_request=f"{endpoint.method} {test_url}",
                            example_response=f"...{unescaped_marker}... (reflected verbatim, unescaped)",
                            expected_safe_output=(
                                "A properly encoded application would render this as "
                                f"'{marker}&lt;rxtag&gt;' rather than raw HTML."
                            ),
                            impact=(
                                "An attacker could craft a malicious script payload instead of this "
                                "benign marker, which would execute in a victim's browser in the "
                                "context of this site (session theft, credential phishing, defacement)."
                            ),
                            verification_steps=[
                                "Open the request URL in a browser or HTTP client.",
                                "View the page source or response body.",
                                f"Confirm the marker '{unescaped_marker}' appears unescaped (not as &lt;rxtag&gt;).",
                                "Confirm the reflection occurs in an HTML/script-executable context, not just plain text.",
                            ],
                        ),
                    )
                )
            elif marker in body:
                # Marker reflected but HTML-encoded/stripped -- likely safe, lower-confidence note.
                findings.append(
                    ScanFinding(
                        vulnerability_type=VulnerabilityType.XSS.value,
                        severity=Severity.INFO.value,
                        title=f"Input reflected (appears encoded) in parameter '{param}'",
                        url=test_url,
                        method=endpoint.method,
                        parameter=param,
                        evidence=(
                            f"Marker '{marker}' was reflected but HTML metacharacters appear to have "
                            f"been encoded or stripped, suggesting output encoding is in place."
                        ),
                        confidence=0.2,
                    )
                )

        return findings