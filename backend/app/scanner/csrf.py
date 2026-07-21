"""
Cross-Site Request Forgery (CSRF) detection module.

SAFE DETECTION METHODOLOGY: purely observational. For state-changing
endpoints (POST/PUT/PATCH/DELETE), this module checks (a) whether any
CSRF-token-like field is present among the endpoint's known parameters,
and (b) whether the response's Set-Cookie headers use a SameSite
attribute that would mitigate CSRF. No forged cross-origin request is
actually sent; this module never performs a real CSRF attack.
"""

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc

_CSRF_TOKEN_NAME_HINTS = ("csrf", "token", "authenticity", "_token", "nonce", "xsrf")
_STATE_CHANGING_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def _has_csrf_token_param(parameters: list[str]) -> bool:
    return any(any(hint in p.lower() for hint in _CSRF_TOKEN_NAME_HINTS) for p in parameters)


class CsrfScanner(BaseScanner):
    """Detects likely missing CSRF protections on state-changing endpoints."""

    module_name = "csrf"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        if endpoint.method.upper() not in _STATE_CHANGING_METHODS or not endpoint.has_form:
            return findings

        if _has_csrf_token_param(endpoint.parameters):
            return findings  # a token field is present; not flagging further here

        response = await self._request("GET", endpoint.url, notes="csrf cookie inspection")
        samesite_present = False
        if response is not None:
            set_cookie_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
            samesite_present = any("samesite" in h.lower() for h in set_cookie_headers)

        findings.append(
            ScanFinding(
                vulnerability_type=VulnerabilityType.CSRF.value,
                severity=Severity.MEDIUM.value,
                title=f"State-changing endpoint may lack CSRF protection",
                url=endpoint.url,
                method=endpoint.method,
                parameter=None,
                evidence=(
                    f"This {endpoint.method} form was discovered with fields {endpoint.parameters} and "
                    f"none of them appear to be a CSRF token. "
                    f"{'A SameSite cookie attribute was observed, which partially mitigates this.' if samesite_present else 'No SameSite cookie attribute was observed either.'}"
                ),
                confidence=0.4 if not samesite_present else 0.25,
                safe_poc=SafePoc(
                    example_request=f"{endpoint.method} {endpoint.url}",
                    example_response="Request succeeds without any per-session CSRF token",
                    expected_safe_output="Request rejected (403) when a valid CSRF token is not supplied.",
                    impact=(
                        "An attacker could host a malicious page that silently submits this form from "
                        "a logged-in victim's browser, performing the action on their behalf."
                    ),
                    verification_steps=[
                        "Submit this form's request from a different origin using the victim's active session cookies.",
                        "Confirm whether the server processes the request despite the missing/foreign origin.",
                    ],
                ),
            )
        )

        return findings