"""
Open Redirect detection module.

SAFE DETECTION METHODOLOGY: for parameters whose name suggests a
redirect target (redirect, url, next, return, dest, ...), this module
submits a benign, clearly-fake external domain
(`https://reconix-redirect-probe.invalid`) and checks whether the
server's 3xx `Location` header points directly at that domain. No
actual redirection is followed (redirects are disabled on the shared
HTTP client), so no request ever reaches the fake domain.
"""

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc, with_query_param

_REDIRECT_PARAM_HINTS = ("redirect", "url", "next", "return", "returnurl", "return_url", "dest", "destination", "continue", "target", "callback")
_PROBE_TARGET = "https://reconix-redirect-probe.invalid/"


def _looks_like_redirect_param(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _REDIRECT_PARAM_HINTS)


class OpenRedirectScanner(BaseScanner):
    """Detects unvalidated open redirects via a benign external probe domain."""

    module_name = "redirect"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        candidate_params = [p for p in endpoint.parameters if _looks_like_redirect_param(p)]

        for param in candidate_params:
            test_url = with_query_param(endpoint.url, param, _PROBE_TARGET)
            response = await self._request("GET", test_url, notes=f"open redirect probe on param={param}")

            if response is None or response.status_code not in (301, 302, 303, 307, 308):
                continue

            location = response.headers.get("location", "")
            if _PROBE_TARGET.rstrip("/") in location:
                findings.append(
                    ScanFinding(
                        vulnerability_type=VulnerabilityType.OPEN_REDIRECT.value,
                        severity=Severity.MEDIUM.value,
                        title=f"Open redirect via parameter '{param}'",
                        url=test_url,
                        method="GET",
                        parameter=param,
                        evidence=(
                            f"Setting '{param}' to an arbitrary external domain caused a "
                            f"{response.status_code} redirect with Location: {location}, without "
                            f"validating the destination against an allow-list."
                        ),
                        confidence=0.85,
                        safe_poc=SafePoc(
                            example_request=f"GET {test_url}",
                            example_response=f"{response.status_code} Location: {location}",
                            expected_safe_output="Redirect target validated against an allow-list of known-safe paths/domains, or rejected.",
                            impact=(
                                "An attacker can craft a link that appears to point at this trusted "
                                "domain but silently redirects victims to a phishing or malware site."
                            ),
                            verification_steps=[
                                f"Request {test_url} without following the redirect automatically.",
                                "Inspect the Location header and confirm it points to the arbitrary external domain.",
                            ],
                        ),
                    )
                )

        return findings