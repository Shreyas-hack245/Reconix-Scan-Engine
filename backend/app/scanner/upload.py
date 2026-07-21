"""
File upload vulnerability detection module.

SAFE DETECTION METHODOLOGY: this module uploads a completely benign,
non-executable text file (containing only a plain marker string -- NO
script/PHP/executable code of any kind) using filenames with
commonly-dangerous extensions (.php, .jsp, .asp, .exe, .sh). It only
checks (a) whether the upload is accepted despite the risky extension,
and (b) whether the server's response reveals a directly-accessible
URL for the uploaded file. It never uploads working executable
payloads and never attempts to trigger/execute anything server-side.
"""

from app.models.finding import Severity, VulnerabilityType
from app.scanner.base import BaseScanner, ScanFinding, ScanTarget, SafePoc

_BENIGN_FILE_CONTENT = b"reconix-scan-engine-upload-test-marker (harmless plain text, not executable)\n"

_DANGEROUS_EXTENSION_PROBES = [
    ("reconix_test.php", "application/x-php"),
    ("reconix_test.jsp", "application/octet-stream"),
    ("reconix_test.asp", "application/octet-stream"),
    ("reconix_test.exe", "application/octet-stream"),
    ("reconix_test.sh", "application/x-sh"),
]

_FILE_FIELD_NAME_HINTS = ("file", "upload", "attachment", "image", "avatar", "photo", "document")


def _guess_file_field(parameters: list[str]) -> str | None:
    for param in parameters:
        if any(hint in param.lower() for hint in _FILE_FIELD_NAME_HINTS):
            return param
    return parameters[0] if parameters else None


class FileUploadScanner(BaseScanner):
    """Detects weak file-upload validation using benign, non-executable test files."""

    module_name = "upload"

    async def scan_endpoint(self, endpoint: ScanTarget) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        if endpoint.method.upper() != "POST" or not endpoint.has_form:
            return findings

        field_name = _guess_file_field(endpoint.parameters)
        if not field_name:
            return findings

        for filename, content_type in _DANGEROUS_EXTENSION_PROBES:
            files = {field_name: (filename, _BENIGN_FILE_CONTENT, content_type)}
            other_fields = {p: "1" for p in endpoint.parameters if p != field_name}

            response = await self._request(
                "POST",
                endpoint.url,
                files=files,
                data=other_fields,
                notes=f"upload probe filename={filename}",
            )

            if response is None:
                continue

            accepted = response.status_code in (200, 201, 202)
            if not accepted:
                continue

            body = response.text or ""
            exposed_url = None
            for token in body.split():
                cleaned = token.strip('"\'<>,)')
                if filename.split(".")[0] in cleaned and cleaned.startswith(("http", "/")):
                    exposed_url = cleaned
                    break

            severity = Severity.HIGH.value if exposed_url else Severity.MEDIUM.value
            confidence = 0.6 if exposed_url else 0.35

            findings.append(
                ScanFinding(
                    vulnerability_type=VulnerabilityType.FILE_UPLOAD.value,
                    severity=severity,
                    title=f"Upload accepted file with dangerous extension ({filename.split('.')[-1]})",
                    url=endpoint.url,
                    method="POST",
                    parameter=field_name,
                    evidence=(
                        f"Uploading a benign, non-executable text file named '{filename}' via field "
                        f"'{field_name}' was accepted (HTTP {response.status_code}) without apparent "
                        f"extension/content-type validation."
                        + (f" A likely accessible URL was found in the response: {exposed_url}" if exposed_url else "")
                    ),
                    confidence=confidence,
                    safe_poc=SafePoc(
                        example_request=f"POST {endpoint.url} (multipart file field '{field_name}' = '{filename}', harmless text content)",
                        example_response=f"HTTP {response.status_code}" + (f", exposed at {exposed_url}" if exposed_url else ""),
                        expected_safe_output="Upload rejected, or extension stripped/renamed and never served with executable MIME type.",
                        impact=(
                            "If executable server-side script extensions are accepted and the upload "
                            "directory is web-accessible and executes scripts, an attacker could achieve "
                            "remote code execution by uploading a real malicious script instead of this "
                            "harmless test file."
                        ),
                        verification_steps=[
                            f"Upload a file named '{filename}' with benign content via the '{field_name}' field.",
                            "Confirm the server accepts it despite the risky extension.",
                            "If a URL is returned, confirm whether the file is served from a script-executing directory.",
                            "Do NOT upload real executable payloads outside of an authorized, isolated test.",
                        ],
                    ),
                )
            )
            break

        return findings