"""
Cookie security attribute detection module.

SAFE DETECTION METHODOLOGY: purely observational -- inspects
Set-Cookie headers returned by a single GET request for the Secure,
HttpOnly, and SameSite attributes. No injection or state change.
"""

import httpx

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc


def _parse_cookie_name(set_cookie_header: str) -> str:
    return set_cookie_header.split("=", 1)[0].strip()


class CookieSecurityScanner(BaseScanner):
    """Detects cookies missing Secure, HttpOnly, or SameSite attributes."""

    module_name = "cookies"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        response = await self._request("GET", endpoint.url, notes="cookie security inspection")
        if response is None:
            return findings

        set_cookie_headers: list[str]
        if hasattr(response.headers, "get_list"):
            set_cookie_headers = response.headers.get_list("set-cookie")
        else:  # pragma: no cover - defensive fallback for older httpx
            raw = response.headers.get("set-cookie")
            set_cookie_headers = [raw] if raw else []

        for cookie_header in set_cookie_headers:
            cookie_name = _parse_cookie_name(cookie_header)
            lowered = cookie_header.lower()

            missing_attrs = []
            if "secure" not in lowered and endpoint.url.startswith("https://"):
                missing_attrs.append("Secure")
            if "httponly" not in lowered:
                missing_attrs.append("HttpOnly")
            if "samesite" not in lowered:
                missing_attrs.append("SameSite")

            if not missing_attrs:
                continue

            severity = Severity.HIGH.value if "session" in cookie_name.lower() or "auth" in cookie_name.lower() else Severity.MEDIUM.value

            findings.append(
                ScanFinding(
                    vulnerability_type=VulnerabilityType.COOKIE_SECURITY.value,
                    severity=severity,
                    title=f"Cookie '{cookie_name}' missing security attribute(s): {', '.join(missing_attrs)}",
                    url=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence=f"Set-Cookie header for '{cookie_name}' is missing: {', '.join(missing_attrs)}. Raw header: {cookie_header[:200]}",
                    confidence=0.9,
                    safe_poc=SafePoc(
                        example_request=f"GET {endpoint.url}",
                        example_response=f"Set-Cookie: {cookie_header[:200]}",
                        expected_safe_output=f"Set-Cookie: {cookie_name}=<value>; Secure; HttpOnly; SameSite=Strict",
                        impact=(
                            "Missing HttpOnly allows client-side scripts (e.g. via XSS) to read the "
                            "cookie; missing Secure allows it to be sent over plaintext HTTP; missing "
                            "SameSite increases exposure to CSRF."
                        ),
                        verification_steps=[
                            f"Send a GET request to {endpoint.url}.",
                            f"Inspect the Set-Cookie header for '{cookie_name}'.",
                            f"Confirm which of {missing_attrs} are absent.",
                        ],
                    ),
                )
            )

        return findings