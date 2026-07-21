"""
Insecure Direct Object Reference (IDOR) detection module.

SAFE DETECTION METHODOLOGY: for endpoints where a URL path segment or
parameter value is purely numeric (a common object-ID pattern, e.g.
`/orders/1042` or `?id=1042`), this module requests an adjacent ID
(id-1) with NO authentication/session context and checks whether a
200 response with substantive content is still returned. This is a
read-only comparison of response status/shape and never modifies or
deletes any resource.
"""

import re

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc, with_query_param

_NUMERIC_PARAM_HINTS = ("id", "user", "account", "order", "invoice", "record", "doc", "num")
_PATH_ID_PATTERN = re.compile(r"(/)(\d+)(/|$)")


def _looks_like_id_param(name: str) -> bool:
    lowered = name.lower()
    return lowered == "id" or any(hint in lowered for hint in _NUMERIC_PARAM_HINTS)


class IdorScanner(BaseScanner):
    """Detects potential IDOR by probing adjacent numeric object IDs."""

    module_name = "idor"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        # --- Case 1: numeric ID in the path, e.g. /orders/1042 ---
        match = _PATH_ID_PATTERN.search(endpoint.url)
        if match:
            original_id = int(match.group(2))
            if original_id > 1:
                adjacent_id = original_id - 1
                adjacent_url = endpoint.url[: match.start(2)] + str(adjacent_id) + endpoint.url[match.end(2):]

                original_response = await self._request(endpoint.method, endpoint.url, notes="idor baseline (original id)")
                adjacent_response = await self._request(endpoint.method, adjacent_url, notes="idor probe (adjacent id)")

                if (
                    original_response is not None
                    and adjacent_response is not None
                    and original_response.status_code == 200
                    and adjacent_response.status_code == 200
                    and len(adjacent_response.text or "") > 50
                ):
                    findings.append(
                        ScanFinding(
                            vulnerability_type=VulnerabilityType.IDOR.value,
                            severity=Severity.HIGH.value,
                            title=f"Possible IDOR: sequential object id accessible ({original_id} -> {adjacent_id})",
                            url=adjacent_url,
                            method=endpoint.method,
                            parameter="(path id)",
                            evidence=(
                                f"Requesting id={original_id} returned 200, and the adjacent id={adjacent_id} "
                                f"also returned 200 with substantive content ({len(adjacent_response.text)} bytes) "
                                f"using the SAME (unauthenticated) request context, suggesting object-level "
                                f"access control is not enforced per-record."
                            ),
                            confidence=0.45,
                            safe_poc=SafePoc(
                                example_request=f"{endpoint.method} {adjacent_url}",
                                example_response="200 OK with record content for an id not explicitly granted",
                                expected_safe_output="403/404 for records the requester does not own.",
                                impact=(
                                    "An attacker could enumerate sequential IDs to read or manipulate other "
                                    "users' records (orders, invoices, profiles, documents)."
                                ),
                                verification_steps=[
                                    f"Access {endpoint.url} and note the returned record.",
                                    f"Access {adjacent_url} using the same session/credentials (or none).",
                                    "Confirm whether a different user's record is returned without an ownership check.",
                                ],
                            ),
                        )
                    )

        # --- Case 2: numeric ID in a query parameter, e.g. ?id=1042 ---
        for param in endpoint.parameters:
            if not _looks_like_id_param(param):
                continue

            probe_value = "1"
            test_url = with_query_param(endpoint.url, param, probe_value)
            response = await self._request(endpoint.method, test_url, notes=f"idor param probe on {param}")

            if response is not None and response.status_code == 200 and len(response.text or "") > 50:
                findings.append(
                    ScanFinding(
                        vulnerability_type=VulnerabilityType.IDOR.value,
                        severity=Severity.MEDIUM.value,
                        title=f"Object reference parameter '{param}' accepts arbitrary low id without apparent ownership check",
                        url=test_url,
                        method=endpoint.method,
                        parameter=param,
                        evidence=(
                            f"Setting '{param}=1' returned 200 with {len(response.text)} bytes of content "
                            f"with no observable authorization check performed by this scan."
                        ),
                        confidence=0.3,
                        safe_poc=SafePoc(
                            example_request=f"{endpoint.method} {test_url}",
                            example_response="200 OK returning a record for an arbitrary id",
                            expected_safe_output="403/404 unless the requester legitimately owns/can access that id.",
                            impact="Potential unauthorized access to other users' data by varying this parameter.",
                            verification_steps=[
                                f"Vary '{param}' across a small range of values using a low-privilege account.",
                                "Confirm whether records belonging to other users are returned.",
                            ],
                        ),
                    )
                )

        return findings