"""
Directory / Path Traversal detection module.

SAFE DETECTION METHODOLOGY: for parameters whose name suggests a file
or path is being referenced (file, path, page, doc, template,
include), this module submits standard, publicly-documented traversal
sequences targeting universally-present, non-sensitive OS files
(/etc/hosts on Linux, or a relative parent-directory probe) and checks
the response for well-known content markers. This is read-only
reconnaissance -- it never writes, deletes, or modifies any file, and
deliberately avoids targeting files with sensitive credential material.
"""

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc, with_query_param

_PATH_PARAM_HINTS = ("file", "path", "page", "doc", "document", "template", "include", "filename", "folder", "dir")

_TRAVERSAL_PAYLOADS = [
    "../../../../etc/hosts",
    "..%2f..%2f..%2f..%2fetc%2fhosts",
    "....//....//....//....//etc/hosts",
]

_CONTENT_MARKERS = ("localhost", "127.0.0.1")


def _looks_like_path_param(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _PATH_PARAM_HINTS)


class DirectoryTraversalScanner(BaseScanner):
    """Detects path traversal via read-only probes against a non-sensitive system file."""

    module_name = "directory_traversal"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        candidate_params = [p for p in endpoint.parameters if _looks_like_path_param(p)]

        for param in candidate_params:
            for payload in _TRAVERSAL_PAYLOADS:
                test_url = with_query_param(endpoint.url, param, payload)
                response = await self._request("GET", test_url, notes=f"traversal probe on param={param}")

                if response is None or response.status_code != 200 or not response.text:
                    continue

                body_lower = response.text.lower()
                if any(marker in body_lower for marker in _CONTENT_MARKERS) and "html" not in response.headers.get("content-type", ""):
                    findings.append(
                        ScanFinding(
                            vulnerability_type=VulnerabilityType.DIRECTORY_TRAVERSAL.value,
                            severity=Severity.HIGH.value,
                            title=f"Possible path traversal in parameter '{param}'",
                            url=test_url,
                            method="GET",
                            parameter=param,
                            evidence=(
                                f"Submitting a traversal sequence in '{param}' targeting a standard "
                                f"system hosts file returned content containing expected markers "
                                f"({', '.join(m for m in _CONTENT_MARKERS if m in body_lower)}), "
                                f"suggesting the application reads arbitrary files based on this input."
                            ),
                            confidence=0.6,
                            safe_poc=SafePoc(
                                example_request=f"GET {test_url}",
                                example_response=f"Response body contains system file content markers",
                                expected_safe_output="400/403, or the traversal sequence is normalized/rejected before file access.",
                                impact=(
                                    "An attacker could read arbitrary files on the server's filesystem "
                                    "(source code, configuration, credentials) by adjusting the path depth "
                                    "and target file."
                                ),
                                verification_steps=[
                                    f"Request {test_url}.",
                                    "Confirm the response contains content from outside the intended directory.",
                                ],
                            ),
                        )
                    )
                    break

        return findings