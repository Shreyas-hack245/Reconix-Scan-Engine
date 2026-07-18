"""
Risk explanation engine for Reconix Scan Engine.

Generates developer-friendly risk explanations, business impact
statements, and step-by-step remediation guidance for each finding,
keyed on vulnerability type and severity. Implemented as a
deterministic template engine so the platform runs fully offline; the
`explain()` method is the single seam where a call to a hosted LLM API
could be substituted for more dynamic, context-aware prose without
changing any calling code in the reporting or API layers.
"""

from dataclasses import dataclass

from app.scanner.base import ScanFinding


@dataclass
class Explanation:
    """AI-generated explanation content attached to a finding."""

    risk_explanation: str
    business_impact: str
    developer_explanation: str
    remediation: str


_RISK_EXPLANATIONS: dict[str, str] = {
    "xss": "Reflected XSS allows an attacker to inject client-side script that executes in a victim's browser under this site's origin, because user-controlled input is rendered without proper output encoding.",
    "sqli": "SQL injection allows an attacker to influence the structure of a database query using unsanitized input, potentially reading, modifying, or deleting data beyond what the application intends to expose.",
    "ssrf": "Server-Side Request Forgery allows an attacker to induce the server itself to make network requests to arbitrary destinations, potentially reaching internal-only systems that are not exposed to the public internet.",
    "command_injection": "OS command injection allows attacker-supplied input to be interpreted as a shell command by the server, potentially leading to full server compromise.",
    "auth_issue": "An authentication weakness allows identity or session verification to be bypassed or weakened, undermining every other access control built on top of it.",
    "broken_access_control": "Broken access control allows a user to perform an action or access a resource that should be restricted based on their identity, role, or ownership.",
    "idor": "Insecure Direct Object Reference allows a user to access or modify another user's data simply by changing an identifier, because the server does not verify ownership before returning the record.",
    "open_redirect": "An open redirect allows an attacker to craft a link that appears to point at this trusted domain but silently forwards victims to an attacker-controlled destination.",
    "csrf": "Missing CSRF protection allows a malicious third-party site to submit state-changing requests using a victim's active session without their knowledge or consent.",
    "info_disclosure": "This finding exposes information (configuration, source history, internal error details) that can materially assist an attacker in planning further attacks.",
    "directory_traversal": "Path traversal allows an attacker to reference files outside the application's intended directory, potentially reading sensitive source code, configuration, or credential material.",
    "security_headers": "Missing security headers remove a defense-in-depth layer that browsers use to mitigate common web attack classes, increasing the impact of other vulnerabilities if present.",
    "cookie_security": "Cookies without proper security attributes are more easily stolen (via XSS) or transmitted insecurely, increasing the risk of session hijacking.",
    "file_upload": "Weak file upload validation can allow an attacker to place executable content on the server, potentially leading to remote code execution if that content can later be triggered.",
    "clickjacking": "Without anti-framing protections, this page can be invisibly embedded in an attacker's site to trick users into performing unintended actions.",
    "cors_misconfiguration": "An overly permissive CORS policy allows other websites to make cross-origin requests to this endpoint, potentially reading response data that should be restricted to this site alone.",
}

_BUSINESS_IMPACTS: dict[str, str] = {
    "xss": "Could lead to account takeover, session theft, or brand-damaging defacement, and may trigger customer trust and regulatory (e.g. breach notification) concerns.",
    "sqli": "Could result in large-scale data breach, regulatory fines (GDPR/CCPA/PCI-DSS), and significant reputational damage from customer data exposure.",
    "ssrf": "Could expose internal infrastructure, cloud credentials, or admin systems, potentially escalating to a full internal network compromise.",
    "command_injection": "Could result in complete server takeover, data destruction, ransomware deployment, or use of the server as a pivot point into internal networks.",
    "auth_issue": "Could allow account takeover at scale, undermining trust in the platform's core security guarantees.",
    "broken_access_control": "Could expose sensitive customer or business data to users who should not have access, with compliance and contractual implications.",
    "idor": "Could allow systematic harvesting of other customers' records (PII, financial data, documents), a common driver of large-scale data breach incidents.",
    "open_redirect": "Frequently used in phishing campaigns; may damage the brand's reputation if the domain is used to lend credibility to malicious links.",
    "csrf": "Could result in unauthorized financial transactions, account changes, or data modification performed silently on behalf of victims.",
    "info_disclosure": "Lowers the effort required for an attacker to compromise the system further; source/config leaks are frequently a precursor to more serious breaches.",
    "directory_traversal": "Could expose source code, credentials, or configuration secrets, often enabling full application compromise.",
    "security_headers": "Increases the blast radius of other vulnerabilities (e.g. an XSS finding becomes more exploitable without CSP in place).",
    "cookie_security": "Increases the likelihood that a session hijacking attempt (via network interception or XSS) succeeds.",
    "file_upload": "Could lead to full server compromise if uploaded content can be executed, one of the most severe outcomes possible.",
    "clickjacking": "Could be used to trick users (including administrators) into approving sensitive actions unintentionally.",
    "cors_misconfiguration": "Could allow attacker-controlled websites to silently read sensitive user data via the victim's authenticated session.",
}

_REMEDIATIONS: dict[str, list[str]] = {
    "xss": [
        "Apply context-aware output encoding (HTML entity encoding) to all user-controlled data rendered in HTML.",
        "Adopt a templating engine that auto-escapes by default (e.g. Jinja2 autoescape, React's default JSX escaping).",
        "Deploy a strict Content-Security-Policy as defense-in-depth.",
        "Validate and constrain input format server-side wherever a strict format (e.g. numeric ID) is expected.",
    ],
    "sqli": [
        "Use parameterized queries / prepared statements for all database access; never concatenate user input into SQL strings.",
        "Adopt an ORM (e.g. SQLAlchemy) with parameter binding for all queries touching user input.",
        "Apply least-privilege database credentials so a compromised query cannot access unrelated tables.",
        "Add server-side input validation as defense-in-depth (not a substitute for parameterization).",
    ],
    "ssrf": [
        "Maintain an explicit allow-list of permitted destination hosts/schemes for any server-side outbound request feature.",
        "Resolve and validate the destination IP before connecting, rejecting private/link-local/loopback ranges (RFC 1918, 169.254.0.0/16, ::1).",
        "Disable HTTP redirects when fetching user-supplied URLs, or re-validate the destination after each redirect hop.",
        "Run outbound-fetch functionality from a network-segmented service with no route to sensitive internal systems.",
    ],
    "rce": [
        "Never pass user input to a shell interpreter; use language-native APIs (e.g. subprocess with an argument list, not shell=True) instead of building shell command strings.",
        "If shell execution is unavoidable, apply strict allow-list validation and use proper escaping/quoting libraries.",
        "Run the affected service with the minimum OS privileges required.",
    ],
    "command_injection": [
        "Never pass user input to a shell interpreter; use language-native APIs (e.g. subprocess with an argument list, not shell=True) instead of building shell command strings.",
        "If shell execution is unavoidable, apply strict allow-list validation and use proper escaping/quoting libraries.",
        "Run the affected service with the minimum OS privileges required.",
    ],
    "auth_issue": [
        "Use a well-vetted authentication library rather than a custom implementation.",
        "Enforce strong password policies and, where possible, multi-factor authentication.",
        "Ensure session tokens are generated with a cryptographically secure random source and invalidated on logout/password change.",
    ],
    "broken_access_control": [
        "Enforce authorization checks server-side on every request, not just in the UI.",
        "Default to deny; require an explicit, positive authorization check before granting access.",
        "Centralize authorization logic (e.g. a single middleware/decorator) rather than duplicating checks per endpoint.",
    ],
    "idor": [
        "Verify server-side that the authenticated user owns or is authorized to access the requested object, on every request.",
        "Prefer non-guessable identifiers (UUIDs) over sequential integers where feasible, as defense-in-depth (not a substitute for authorization checks).",
    ],
    "open_redirect": [
        "Validate redirect targets against an explicit allow-list of internal paths/trusted domains.",
        "Avoid accepting a fully-qualified URL from user input for redirect purposes; prefer indexed/named redirect targets.",
    ],
    "csrf": [
        "Implement per-session, per-request CSRF tokens on all state-changing requests, validated server-side.",
        "Set the SameSite=Lax or SameSite=Strict attribute on session cookies.",
        "Consider requiring re-authentication or additional confirmation for highly sensitive actions.",
    ],
    "info_disclosure": [
        "Remove or block public access to sensitive files (.env, .git, backups) at the web server/reverse-proxy layer.",
        "Disable verbose error/debug output in production; log detailed errors server-side only.",
        "Add these paths to automated pre-deployment security checks (e.g. CI pipeline scanning).",
    ],
    "directory_traversal": [
        "Avoid constructing file paths directly from user input; map user input to a fixed set of allowed files/identifiers server-side.",
        "Canonicalize and validate that the resolved path remains within the intended base directory before access.",
    ],
    "security_headers": [
        "Add the missing security header(s) at the application or reverse-proxy layer with an appropriate, tested policy value.",
        "Add automated header checks to CI/CD to prevent regression.",
    ],
    "cookie_security": [
        "Set Secure, HttpOnly, and SameSite attributes on all session and authentication cookies.",
        "Audit all cookie-setting code paths (including third-party libraries) for consistent attribute application.",
    ],
    "file_upload": [
        "Validate uploaded file type using content inspection (magic bytes), not just file extension or client-supplied Content-Type.",
        "Store uploads outside the web root, or in a location configured to never execute scripts, and serve them via a controlled download handler.",
        "Rename uploaded files to server-generated names to prevent path/extension manipulation.",
    ],
    "clickjacking": [
        "Set X-Frame-Options: DENY or SAMEORIGIN, and/or a Content-Security-Policy frame-ancestors directive.",
    ],
    "cors_misconfiguration": [
        "Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted origins; never reflect arbitrary Origin headers.",
        "Only set Access-Control-Allow-Credentials: true for explicitly trusted, allow-listed origins -- never combined with a wildcard or reflected origin.",
    ],
}


class RiskExplainer:
    """Generates risk explanation, business impact, and remediation content for a finding."""

    def explain(self, finding: ScanFinding) -> Explanation:
        """Produce an `Explanation` for the given finding based on its vulnerability type."""
        vuln_type = finding.vulnerability_type

        risk_explanation = _RISK_EXPLANATIONS.get(
            vuln_type, "This finding represents a deviation from security best practices that could be leveraged by an attacker."
        )
        business_impact = _BUSINESS_IMPACTS.get(
            vuln_type, "Could negatively affect confidentiality, integrity, or availability of the application or its data."
        )
        remediation_steps = _REMEDIATIONS.get(vuln_type, ["Review this finding against current OWASP guidance for its category."])
        remediation = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(remediation_steps))

        developer_explanation = (
            f"{risk_explanation} This was detected on {finding.method} {finding.url}"
            + (f" (parameter: '{finding.parameter}')" if finding.parameter else "")
            + f". Evidence: {finding.evidence}"
        )

        return Explanation(
            risk_explanation=risk_explanation,
            business_impact=business_impact,
            developer_explanation=developer_explanation,
            remediation=remediation,
        )