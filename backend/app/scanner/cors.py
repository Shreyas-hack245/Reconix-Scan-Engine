"""
CORS misconfiguration detection module.

SAFE DETECTION METHODOLOGY: sends a GET request with a benign,
clearly-fake `Origin` header (`https://reconix-cors-probe.invalid`)
and inspects whether the response reflects that origin back in
`Access-Control-Allow-Origin` -- especially combined with
`Access-Control-Allow-Credentials: true`, which together allow any
website to make authenticated cross-origin requests. Purely
observational; no cross-origin request is actually completed from a
browser context.
"""

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc

_PROBE_ORIGIN = "https://reconix-cors-probe.invalid"


class CorsScanner(BaseScanner):
    """Detects overly permissive CORS configurations."""

    module_name = "cors"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        response = await self._request(
            "GET",
            endpoint.url,
            headers={"Origin": _PROBE_ORIGIN},
            notes="cors origin reflection probe",
        )
        if response is None:
            return findings

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower() == "true"

        if acao == "*" and acac:
            findings.append(self._finding(endpoint, acao, acac, Severity.MEDIUM.value,
                                           "Wildcard Access-Control-Allow-Origin combined with credentials=true"))
        elif acao == _PROBE_ORIGIN:
            severity = Severity.HIGH.value if acac else Severity.MEDIUM.value
            findings.append(self._finding(endpoint, acao, acac, severity,
                                           "Arbitrary Origin reflected in Access-Control-Allow-Origin"))
        elif acao == "*":
            findings.append(self._finding(endpoint, acao, acac, Severity.LOW.value,
                                           "Wildcard Access-Control-Allow-Origin (no credentials)"))

        return findings

    def _finding(self, endpoint: ScanTarget, acao: str, acac: bool, severity: str, title_suffix: str) -> ScanFinding:
        return ScanFinding(
            vulnerability_type=VulnerabilityType.CORS_MISCONFIGURATION.value,
            severity=severity,
            title=f"CORS misconfiguration: {title_suffix}",
            url=endpoint.url,
            method="GET",
            parameter=None,
            evidence=(
                f"Sent Origin: {_PROBE_ORIGIN}. Response returned "
                f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}."
            ),
            confidence=0.8,
            safe_poc=SafePoc(
                example_request=f"GET {endpoint.url}\nOrigin: {_PROBE_ORIGIN}",
                example_response=(
                    f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}"
                ),
                expected_safe_output="Access-Control-Allow-Origin restricted to an explicit allow-list of trusted origins.",
                impact=(
                    "Any website can issue cross-origin requests to this endpoint" +
                    (" WITH the victim's cookies/credentials," if acac else ",") +
                    " potentially reading sensitive response data in the victim's browser."
                ),
                verification_steps=[
                    f"Send a GET request to {endpoint.url} with header 'Origin: {_PROBE_ORIGIN}'.",
                    "Inspect the Access-Control-Allow-Origin and Access-Control-Allow-Credentials response headers.",
                    "Confirm the arbitrary origin is reflected rather than validated against an allow-list.",
                ],
            ),
        )