"""
Remote Code Execution / OS Command Injection detection module.

SAFE DETECTION METHODOLOGY (detection only, per project requirements):
this module uses TIME-BASED BLIND detection exclusively. It injects a
harmless delay command (a short `sleep`) wrapped in a handful of
well-known shell metacharacter contexts, and measures whether the
response takes measurably longer than an equivalent baseline request.
A consistent, reproducible delay matching the requested sleep duration
is strong evidence of command injection -- without ever running a
destructive, data-exfiltrating, or persistence-establishing command.
No reverse shells, file writes, or destructive payloads are used.
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

_DELAY_SECONDS = 4
_TIME_TOLERANCE_SECONDS = 1.5

# Harmless delay command wrapped in common shell metacharacter injection
# contexts. `sleep` performs no destructive action -- it only pauses.
_DELAY_PAYLOADS = [
    f"; sleep {_DELAY_SECONDS}",
    f"| sleep {_DELAY_SECONDS}",
    f"`sleep {_DELAY_SECONDS}`",
    f"$(sleep {_DELAY_SECONDS})",
    f"& sleep {_DELAY_SECONDS} &",
]


class RceScanner(BaseScanner):
    """Detects OS command injection / RCE via safe, time-based blind probing."""

    module_name = "rce"

    async def _timed_request(self, endpoint: ScanTarget, param: str, value: str) -> tuple[float, int | None]:
        start = time.monotonic()
        if endpoint.method.upper() == "GET":
            url = with_query_param(endpoint.url, param, value)
            response = await self._request("GET", url, notes=f"rce timing probe on param={param}")
        else:
            payload = build_form_payload(endpoint.parameters, param, value)
            response = await self._request(endpoint.method, endpoint.url, data=payload, notes=f"rce timing probe on param={param}")
        duration = time.monotonic() - start
        return duration, (response.status_code if response else None)

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        for param in endpoint.parameters:
            baseline_duration, baseline_status = await self._timed_request(endpoint, param, "1")
            if baseline_status is None:
                continue

            for payload in _DELAY_PAYLOADS:
                probe_value = f"1{payload}"
                probe_duration, probe_status = await self._timed_request(endpoint, param, probe_value)

                if probe_status is None:
                    continue

                extra_delay = probe_duration - baseline_duration
                delay_matches = abs(extra_delay - _DELAY_SECONDS) <= _TIME_TOLERANCE_SECONDS

                if delay_matches:
                    test_url = with_query_param(endpoint.url, param, probe_value) if endpoint.method.upper() == "GET" else endpoint.url
                    findings.append(
                        ScanFinding(
                            vulnerability_type=VulnerabilityType.COMMAND_INJECTION.value,
                            severity=Severity.CRITICAL.value,
                            title=f"Possible OS command injection in parameter '{param}'",
                            url=test_url,
                            method=endpoint.method,
                            parameter=param,
                            evidence=(
                                f"Injecting a harmless {_DELAY_SECONDS}-second delay command via '{param}' "
                                f"using context \"{payload}\" caused the response to take "
                                f"{probe_duration:.1f}s vs. a {baseline_duration:.1f}s baseline "
                                f"(~{extra_delay:.1f}s extra delay), closely matching the requested "
                                f"delay. This is strong evidence the input reaches an OS shell."
                            ),
                            confidence=0.7,
                            safe_poc=SafePoc(
                                example_request=f"{endpoint.method} {test_url}",
                                example_response=f"Response delayed by ~{_DELAY_SECONDS}s compared to baseline",
                                expected_safe_output="Identical, fast response regardless of injected shell metacharacters.",
                                impact=(
                                    "An attacker could substitute the harmless 'sleep' command used here "
                                    "for a real command to read files, exfiltrate data, or gain a foothold "
                                    "on the server."
                                ),
                                verification_steps=[
                                    f"Send a baseline request with '{param}'=1 and note the response time.",
                                    f"Send a request with '{param}'=\"1{payload}\" and time it again.",
                                    f"Confirm the difference is consistently close to {_DELAY_SECONDS} seconds "
                                    f"across repeated attempts (to rule out network jitter).",
                                ],
                            ),
                        )
                    )
                    break  # one confirmed context per parameter is sufficient

        return findings