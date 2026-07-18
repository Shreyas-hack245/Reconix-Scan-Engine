"""
Safe proof-of-concept formatting for Reconix Scan Engine.

Every scanner module already constructs a `SafePoc` (example request,
example response, expected safe output, impact, verification steps)
at detection time using only non-destructive probes. This module is
responsible solely for rendering that structured data into consistent
Markdown/plain-text blocks for reports and the API -- it does not
generate any new payloads or exploit content itself.
"""

from app.scanner.base import SafePoc


def render_safe_poc_markdown(poc: SafePoc) -> str:
    """Render a SafePoc as a Markdown block suitable for reports."""
    steps = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(poc.verification_steps))
    return (
        "**Example Request**\n"
        f"```\n{poc.example_request}\n```\n\n"
        "**Example Vulnerable Response**\n"
        f"```\n{poc.example_response}\n```\n\n"
        "**Expected Safe Output**\n"
        f"{poc.expected_safe_output}\n\n"
        "**Impact**\n"
        f"{poc.impact}\n\n"
        "**Verification Steps**\n"
        f"{steps}\n"
    )


def render_safe_poc_plaintext(poc: SafePoc) -> str:
    """Render a SafePoc as a plain-text block (e.g. for CLI output or plaintext email)."""
    steps = "\n".join(f"  {i + 1}. {step}" for i, step in enumerate(poc.verification_steps))
    return (
        f"Request:\n  {poc.example_request}\n\n"
        f"Response:\n  {poc.example_response}\n\n"
        f"Expected safe output:\n  {poc.expected_safe_output}\n\n"
        f"Impact:\n  {poc.impact}\n\n"
        f"Verification steps:\n{steps}\n"
    )