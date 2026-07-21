"""
OWASP Top 10 (2021) mapping for Reconix Scan Engine findings.
"""

OWASP_TOP_10_2021 = {
    "xss": "A03:2021 - Injection",
    "sqli": "A03:2021 - Injection",
    "ssrf": "A10:2021 - Server-Side Request Forgery (SSRF)",
    "rce": "A03:2021 - Injection",
    "command_injection": "A03:2021 - Injection",
    "auth_issue": "A07:2021 - Identification and Authentication Failures",
    "broken_access_control": "A01:2021 - Broken Access Control",
    "idor": "A01:2021 - Broken Access Control",
    "open_redirect": "A01:2021 - Broken Access Control",
    "csrf": "A01:2021 - Broken Access Control",
    "info_disclosure": "A05:2021 - Security Misconfiguration",
    "directory_traversal": "A01:2021 - Broken Access Control",
    "security_headers": "A05:2021 - Security Misconfiguration",
    "cookie_security": "A05:2021 - Security Misconfiguration",
    "file_upload": "A04:2021 - Insecure Design",
    "clickjacking": "A05:2021 - Security Misconfiguration",
    "cors_misconfiguration": "A05:2021 - Security Misconfiguration",
}


def get_owasp_category(vulnerability_type: str) -> str:
    """Return the OWASP Top 10 2021 category for a given vulnerability type."""
    return OWASP_TOP_10_2021.get(vulnerability_type, "A05:2021 - Security Misconfiguration")