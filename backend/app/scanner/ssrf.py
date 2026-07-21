"""
Server-Side Request Forgery (SSRF) detection module.

SAFE DETECTION METHODOLOGY: this module only tests parameters whose
name strongly suggests they accept a URL (e.g. "url", "uri", "link",
"target", "callback", "webhook", "fetch", "dest"). It submits a
well-known, publicly-documented cloud metadata address
(169.254.169.254) -- a read-only reconnaissance probe, not an
exploitation chain -- and looks only for timing/behavioral evidence
that the server attempted an outbound connection (e.g. a distinct
timeout/connection-refused pattern vs. a generic "invalid input"
response). It never attempts to read, exfiltrate, or act upon any
metadata that may be returned.
"""

import time

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import (
    BaseScanner,
    ScanFinding,
    ScanTarget,
    SafePoc,
    build_form_payload,
    with_query_param,
)

_URL_PARAM_NAME_HINTS = (
    "url", "uri", "link", "target", "dest", "destination", "redirect",
    "callback", "webhook", "fetch", "src", "image", "avatar", "proxy",
    "path", "endpoint", "site", "host", "return",
)

# Well-known, publicly documented cloud metadata address used purely as a
# read-only reachability probe (no data extraction is attempted).
_SSRF_PROBE_TARGET = "http://169.254.169.254/"
_LOCALHOST_PROBE_TARGET = "http://127.0.0.1:0/"  # port 0 is always closed -> safe, fast-failing probe

_SLOW_RESPONSE_THRESHOLD_SECONDS = 3.0


def _looks_like_url_param(param_name: str) -> bool:
    lowered = param_name.lower()
    return any(hint in lowered for hint in _URL_PARAM_NAME_HINTS)


class SsrfScanner(BaseScanner):
    """Detects likely SSRF via behavioral signals when a server-side fetch is attempted."""

    module_name = "ssrf"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        candidate_params = [p for p in endpoint.parameters if _looks_like_url_param(p)]

        for param in candidate_params:
            baseline_start = time.monotonic()
            if endpoint.method.upper() == "GET":
                baseline_url = with_query_param(endpoint.url, param, "https://example.com/")
                baseline_response = await self._request("GET", baseline_url, notes=f"ssrf baseline on param={param}")
            else:
                payload = build_form_payload(endpoint.parameters, param, "https://example.com/")
                baseline_response = await self._request(endpoint.method, endpoint.url, data=payload, notes=f"ssrf baseline on param={param}")
            baseline_duration = time.monotonic() - baseline_start

            if baseline_response is None:
                continue

            probe_start = time.monotonic()
            if endpoint.method.upper() == "GET":
                test_url = with_query_param(endpoint.url, param, _LOCALHOST_PROBE_TARGET)
                probe_response = await self._request("GET", test_url, notes=f"ssrf probe on param={param}")
            else:
                payload = build_form_payload(endpoint.parameters, param, _LOCALHOST_PROBE_TARGET)
                probe_response = await self._request(endpoint.method, endpoint.url, data=payload, notes=f"ssrf probe on param={param}")
                test_url = endpoint.url
            probe_duration = time.monotonic() - probe_start

            if probe_response is None:
                continue

            status_differs = probe_response.status_code != baseline_response.status_code
            error_signal = any(
                token in (probe_response.text or "").lower()
                for token in ("connection refused", "econnrefused", "timed out", "timeout", "could not connect")
            )
            notably_slower = probe_duration > baseline_duration + _SLOW_RESPONSE_THRESHOLD_SECONDS

            if error_signal or (status_differs and notably_slower):
                findings.append(
                    ScanFinding(
                        vulnerability_type=VulnerabilityType.SSRF.value,
                        severity=Severity.HIGH.value,
                        title=f"Possible SSRF via parameter '{param}'",
                        url=test_url,
                        method=endpoint.method,
                        parameter=param,
                        evidence=(
                            f"Submitting an internal-looking URL in parameter '{param}' produced a "
                            f"distinct behavioral signal compared to a normal external URL: "
                            f"status_differs={status_differs}, connection-error text present={error_signal}, "
                            f"response time {probe_duration:.2f}s vs baseline {baseline_duration:.2f}s. "
                            f"This is consistent with the server attempting to make its own outbound "
                            f"request to the attacker-supplied address."
                        ),
                        confidence=0.5,
                        safe_poc=SafePoc(
                            example_request=f"{endpoint.method} {test_url}",
                            example_response="Distinct error/timeout behavior vs. a normal external URL value",
                            expected_safe_output="Identical, generic handling regardless of the host supplied.",
                            impact=(
                                "If the application fetches attacker-controlled URLs server-side, an "
                                "attacker could reach internal-only services (databases, cloud metadata "
                                "endpoints, admin panels) that are not otherwise reachable from the internet."
                            ),
                            verification_steps=[
                                f"Submit a normal external URL as '{param}' and note the response/timing.",
                                f"Submit an internal-network address as '{param}' and compare behavior.",
                                "In a controlled test environment, use an out-of-band listener you control "
                                "to confirm the server actually issues the outbound request.",
                            ],
                        ),
                    )
                )

        return findings