"""
SQL Injection (SQLi) detection module.

SAFE DETECTION METHODOLOGY: two well-established, read-only techniques
are used, neither of which extracts, modifies, or destroys data:

1. Error-based: append a single quote (') to the parameter value and
   check the response for well-known database error message
   signatures (a strong, standard indicator of unsanitized input
   reaching a SQL query).
2. Boolean-based blind: compare the response to an always-true
   condition (` OR '1'='1`) against an always-false condition
   (` OR '1'='2`). A meaningful difference in status code or response
   length between the two is evidence of blind SQL injection, without
   ever reading actual database contents.

No UNION-based extraction, stacked queries, or data-modifying payloads
are ever used.
"""

import re

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import (
    BaseScanner,
    ScanFinding,
    ScanTarget,
    SafePoc,
    build_form_payload,
    with_query_param,
)

_SQL_ERROR_SIGNATURES = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:\s*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"pg_query\(\)|postgresql.*error", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError|sqlite_error", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"microsoft odbc.*sql server", re.IGNORECASE),
    re.compile(r"SQLSTATE\[\d+\]", re.IGNORECASE),
    re.compile(r"System\.Data\.SqlClient\.SqlException", re.IGNORECASE),
]

_ERROR_BASED_PAYLOAD = "'"
_TRUE_CONDITION_SUFFIX = " OR '1'='1"
_FALSE_CONDITION_SUFFIX = " OR '1'='2"

_LENGTH_DIFFERENCE_THRESHOLD_RATIO = 0.15  # 15% relative difference in body length


class SqliScanner(BaseScanner):
    """Detects SQL injection via error-based and boolean-based blind techniques."""

    module_name = "sqli"

    async def _probe(self, endpoint: ScanTarget, param: str, injected_value: str) -> tuple[int | None, str]:
        if endpoint.method.upper() == "GET":
            test_url = with_query_param(endpoint.url, param, injected_value)
            response = await self._request("GET", test_url, notes=f"sqli probe on param={param}")
        else:
            payload = build_form_payload(endpoint.parameters, param, injected_value)
            response = await self._request(endpoint.method, endpoint.url, data=payload, notes=f"sqli probe on param={param}")

        if response is None:
            return None, ""
        return response.status_code, response.text or ""

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        for param in endpoint.parameters:
            baseline_status, baseline_body = await self._probe(endpoint, param, "1")

            # --- Technique 1: error-based ---
            error_status, error_body = await self._probe(endpoint, param, _ERROR_BASED_PAYLOAD)
            matched_signature = next((sig.pattern for sig in _SQL_ERROR_SIGNATURES if sig.search(error_body)), None)

            if matched_signature:
                test_url = with_query_param(endpoint.url, param, _ERROR_BASED_PAYLOAD) if endpoint.method.upper() == "GET" else endpoint.url
                findings.append(
                    ScanFinding(
                        vulnerability_type=VulnerabilityType.SQLI.value,
                        severity=Severity.CRITICAL.value,
                        title=f"Error-based SQL injection in parameter '{param}'",
                        url=test_url,
                        method=endpoint.method,
                        parameter=param,
                        evidence=(
                            f"Submitting a single quote in parameter '{param}' produced a database "
                            f"error matching pattern /{matched_signature}/, indicating the input is "
                            f"concatenated directly into a SQL query without parameterization."
                        ),
                        confidence=0.85,
                        safe_poc=SafePoc(
                            example_request=f"{endpoint.method} {test_url}",
                            example_response="Database error message revealing SQL syntax/engine details",
                            expected_safe_output="A generic error page with no database details leaked.",
                            impact=(
                                "A real attacker could use this injection point to read, modify, or "
                                "delete data, or in some configurations execute further commands."
                            ),
                            verification_steps=[
                                f"Submit a single quote (') as the value of '{param}'.",
                                "Observe the response for a raw database error/stack trace.",
                                "Confirm the same request with a normal value returns no error.",
                            ],
                        ),
                    )
                )
                continue  # error-based already confirms this param; skip boolean-based noise

            # --- Technique 2: boolean-based blind ---
            true_status, true_body = await self._probe(endpoint, param, f"1{_TRUE_CONDITION_SUFFIX}")
            false_status, false_body = await self._probe(endpoint, param, f"1{_FALSE_CONDITION_SUFFIX}")

            if true_status is None or false_status is None:
                continue

            status_differs = true_status != false_status
            length_differs = False
            if true_body and false_body:
                longer, shorter = sorted([len(true_body), len(false_body)], reverse=True)
                if shorter > 0:
                    length_differs = (longer - shorter) / shorter > _LENGTH_DIFFERENCE_THRESHOLD_RATIO
                elif longer > 0:
                    length_differs = True

            baseline_matches_true = baseline_status == true_status and (
                not baseline_body or not true_body or abs(len(baseline_body) - len(true_body)) < 5
            )

            if (status_differs or length_differs) and baseline_matches_true:
                test_url = with_query_param(endpoint.url, param, f"1{_TRUE_CONDITION_SUFFIX}") if endpoint.method.upper() == "GET" else endpoint.url
                findings.append(
                    ScanFinding(
                        vulnerability_type=VulnerabilityType.SQLI.value,
                        severity=Severity.HIGH.value,
                        title=f"Possible boolean-based blind SQL injection in parameter '{param}'",
                        url=test_url,
                        method=endpoint.method,
                        parameter=param,
                        evidence=(
                            f"An always-true condition on '{param}' produced a response matching the "
                            f"baseline (status={true_status}), while an always-false condition produced "
                            f"a materially different response (status={false_status}, "
                            f"length_differs={length_differs}). This pattern is consistent with blind "
                            f"SQL injection."
                        ),
                        confidence=0.55,
                        safe_poc=SafePoc(
                            example_request=f"{endpoint.method} {test_url}",
                            example_response="Response content/length/status differs between TRUE and FALSE conditions",
                            expected_safe_output="Identical response regardless of the injected boolean condition.",
                            impact=(
                                "An attacker could extract data one bit at a time by asking the "
                                "database true/false questions through this parameter."
                            ),
                            verification_steps=[
                                f"Submit \"1{_TRUE_CONDITION_SUFFIX}\" as '{param}' and note the response.",
                                f"Submit \"1{_FALSE_CONDITION_SUFFIX}\" as '{param}' and compare.",
                                "Confirm a consistent, repeatable difference between the two responses.",
                            ],
                        ),
                    )
                )

        return findings