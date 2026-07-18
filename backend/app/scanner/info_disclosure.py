"""
Sensitive information disclosure detection module.

SAFE DETECTION METHODOLOGY: read-only GET requests to a small,
well-known list of commonly-exposed sensitive paths (.git/HEAD, .env,
backup archives, etc.) relative to the target origin, plus regex
scanning of any response body for verbose stack-trace / debug-error
signatures. No data is exfiltrated beyond what is needed to confirm
presence; findings truncate evidence to short excerpts.
"""

import re

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc

_SENSITIVE_PATHS = [
    ("/.env", Severity.CRITICAL.value),
    ("/.git/HEAD", Severity.HIGH.value),
    ("/.git/config", Severity.HIGH.value),
    ("/.DS_Store", Severity.LOW.value),
    ("/web.config", Severity.MEDIUM.value),
    ("/backup.zip", Severity.HIGH.value),
    ("/backup.sql", Severity.CRITICAL.value),
    ("/phpinfo.php", Severity.MEDIUM.value),
    ("/server-status", Severity.MEDIUM.value),
    ("/.well-known/security.txt", Severity.INFO.value),
]

_STACK_TRACE_SIGNATURES = [
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"Fatal error:.*on line \d+"),
    re.compile(r"Exception in thread"),
    re.compile(r"at System\.[A-Za-z.]+\("),
    re.compile(r"Whitelabel Error Page"),
    re.compile(r"django\.core\.exceptions"),
    re.compile(r"Warning:.*failed to open stream"),
]


class InfoDisclosureScanner(BaseScanner):
    """Detects exposed sensitive files and verbose error/stack-trace disclosure."""

    module_name = "info_disclosure"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        response = await self._request(endpoint.method, endpoint.url, notes="stack trace inspection")
        if response is not None and response.text:
            for pattern in _STACK_TRACE_SIGNATURES:
                match = pattern.search(response.text)
                if match:
                    excerpt = response.text[max(0, match.start() - 40): match.start() + 80]
                    findings.append(
                        ScanFinding(
                            vulnerability_type=VulnerabilityType.INFO_DISCLOSURE.value,
                            severity=Severity.MEDIUM.value,
                            title="Verbose error/stack trace disclosed in response",
                            url=endpoint.url,
                            method=endpoint.method,
                            parameter=None,
                            evidence=f"Response matched pattern /{pattern.pattern}/. Excerpt: ...{excerpt}...",
                            confidence=0.7,
                            safe_poc=SafePoc(
                                example_request=f"{endpoint.method} {endpoint.url}",
                                example_response=f"...{excerpt}...",
                                expected_safe_output="A generic error page with no internal implementation details.",
                                impact="Stack traces can reveal file paths, framework versions, and internal logic useful for further attacks.",
                                verification_steps=[
                                    f"Trigger this response from {endpoint.url}.",
                                    "Confirm internal paths, class names, or query text are visible.",
                                ],
                            ),
                        )
                    )
                    break

        return findings

    async def scan_common_paths(self, base_url: str) -> list[ScanFinding]:
        """Probe a small set of well-known sensitive paths under the scan's base origin."""
        findings: list[ScanFinding] = []
        base = base_url.rstrip("/")

        for path, severity in _SENSITIVE_PATHS:
            url = base + path
            response = await self._request("GET", url, notes=f"sensitive path probe {path}")

            if response is None or response.status_code != 200:
                continue
            if not response.text or len(response.text) < 1:
                continue

            excerpt = (response.text or "")[:200]
            findings.append(
                ScanFinding(
                    vulnerability_type=VulnerabilityType.INFO_DISCLOSURE.value,
                    severity=severity,
                    title=f"Sensitive file exposed: {path}",
                    url=url,
                    method="GET",
                    parameter=None,
                    evidence=f"GET {path} returned HTTP 200 with content. Excerpt: {excerpt}",
                    confidence=0.8,
                    safe_poc=SafePoc(
                        example_request=f"GET {url}",
                        example_response=f"HTTP 200: {excerpt}",
                        expected_safe_output="HTTP 404 Not Found, or the path removed/blocked from public access.",
                        impact="This file may contain credentials, source history, or internal configuration useful to an attacker.",
                        verification_steps=[f"Request {url} directly and confirm it is publicly accessible."],
                    ),
                )
            )

        return findings