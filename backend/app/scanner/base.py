"""
Shared base classes and helpers for all Reconix Scan Engine scanner
modules.

Defines the `ScanFinding` result type, the `BaseScanner` interface,
an `AuditRecorder` protocol used to persist a record of every request
performed, and small helper functions (unique marker generation, safe
PoC construction, URL/form parameter injection) reused across every
vulnerability module.
"""

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from app.core.rate_limiter import RateLimiter
from app.utils.cvss import estimate_cvss
from app.utils.http_client import safe_request
from app.utils.owasp_mapping import get_owasp_category


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class SafePoc:
    """A safe, non-destructive proof-of-concept for a finding."""

    example_request: str
    example_response: str
    expected_safe_output: str
    impact: str
    verification_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "example_request": self.example_request,
            "example_response": self.example_response,
            "expected_safe_output": self.expected_safe_output,
            "impact": self.impact,
            "verification_steps": self.verification_steps,
        }


@dataclass
class ScanFinding:
    """A single vulnerability finding produced by a scanner module."""

    vulnerability_type: str
    severity: str
    title: str
    url: str
    method: str = "GET"
    parameter: Optional[str] = None
    evidence: str = ""
    confidence: float = 0.5
    safe_poc: Optional[SafePoc] = None
    owasp_category: str = field(init=False, default="")
    cvss_score: float = field(init=False, default=0.0)
    cvss_vector: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self.owasp_category = get_owasp_category(self.vulnerability_type)
        estimate = estimate_cvss(self.vulnerability_type, self.severity)
        self.cvss_score = estimate.score
        self.cvss_vector = estimate.vector


class AuditRecorder(Protocol):
    """Callback protocol used by scanners to log every request they make."""

    async def __call__(
        self,
        *,
        url: str,
        method: str,
        module: str,
        status_code: Optional[int],
        duration_ms: float,
        finding_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        ...


async def _noop_audit_recorder(**kwargs: Any) -> None:
    """Default no-op audit recorder, used when scanners run standalone/in tests."""
    return None


# ---------------------------------------------------------------------------
# URL / form parameter helpers
# ---------------------------------------------------------------------------


def new_marker(prefix: str = "reconix") -> str:
    """Generate a unique, easily-identifiable benign marker for safe probing."""
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def with_query_param(url: str, param: str, value: str) -> str:
    """Return a copy of `url` with `param` set to `value`, preserving other query params."""
    parts = urlsplit(url)
    query_pairs = dict(parse_qsl(parts.query, keep_blank_values=True))
    query_pairs[param] = value
    new_query = urlencode(query_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))


def existing_query_params(url: str) -> list[str]:
    """Return the list of query parameter names already present on a URL."""
    parts = urlsplit(url)
    return [name for name, _ in parse_qsl(parts.query, keep_blank_values=True)]


def build_form_payload(parameters: list[str], target_param: str, value: str, default: str = "1") -> dict[str, str]:
    """Build a form/body payload where every field is a benign default except `target_param`."""
    return {p: (value if p == target_param else default) for p in parameters}


# ---------------------------------------------------------------------------
# Base scanner
# ---------------------------------------------------------------------------


class BaseScanner(ABC):
    """
    Abstract base class for all vulnerability scanner modules.

    Subclasses implement `scan_endpoint`, which receives a discovered
    endpoint (url, method, and parameter names) and returns a list of
    `ScanFinding` objects. Subclasses should use `self._request(...)`
    for all outbound HTTP calls so that rate limiting and the audit
    trail are applied consistently.
    """

    #: Short machine-readable module name, used in the audit trail (e.g. "xss").
    module_name: str = "base"

    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
        audit_recorder: Optional[AuditRecorder] = None,
    ) -> None:
        self.client = client
        self.rate_limiter = rate_limiter
        self.audit_recorder: AuditRecorder = audit_recorder or _noop_audit_recorder

    async def _request(
        self,
        method: str,
        url: str,
        *,
        finding_id: Optional[str] = None,
        notes: Optional[str] = None,
        **kwargs: Any,
    ) -> Optional[httpx.Response]:
        """Perform a rate-limited, audited HTTP request on behalf of this scanner module."""
        start = time.monotonic()
        response = await safe_request(self.client, self.rate_limiter, method, url, **kwargs)
        duration_ms = (time.monotonic() - start) * 1000

        await self.audit_recorder(
            url=url,
            method=method,
            module=self.module_name,
            status_code=response.status_code if response is not None else None,
            duration_ms=duration_ms,
            finding_id=finding_id,
            notes=notes,
        )
        return response

    @abstractmethod
    async def scan_endpoint(self, endpoint: "ScanTarget") -> list[ScanFinding]:
        """Run this module's detection logic against a single endpoint."""
        raise NotImplementedError


@dataclass
class ScanTarget:
    """A minimal, scanner-facing view of an endpoint to be tested."""

    url: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    has_form: bool = False