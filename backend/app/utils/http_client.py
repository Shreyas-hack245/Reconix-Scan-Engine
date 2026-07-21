"""
Shared async HTTP client utilities for Reconix Scan Engine.

Provides a pre-configured httpx.AsyncClient factory and a `safe_request`
helper that combines rate limiting, timeouts, and bounded retries with
exponential backoff.
"""

from typing import Any, Optional

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.config import settings
from app.core.logging_config import logger
from app.core.rate_limiter import RateLimiter

USER_AGENT = "ReconixScanEngine/0.1 (+defensive-security-scanner; authorized-testing-only)"

RETRYABLE_EXCEPTIONS = (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError, httpx.RemoteProtocolError)


def build_http_client(
    timeout: Optional[float] = None,
    follow_redirects: bool = False,
    verify_tls: bool = True,
) -> httpx.AsyncClient:
    """Build a pre-configured async HTTP client for scanning."""
    return httpx.AsyncClient(
        timeout=timeout or settings.default_request_timeout_seconds,
        follow_redirects=follow_redirects,
        verify=verify_tls,
        headers={"User-Agent": USER_AGENT},
    )


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
    retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
)
async def _do_request(client: httpx.AsyncClient, method: str, url: str, **kwargs: Any) -> httpx.Response:
    return await client.request(method, url, **kwargs)


async def safe_request(
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    method: str,
    url: str,
    **kwargs: Any,
) -> Optional[httpx.Response]:
    """Perform a rate-limited, retried HTTP request. Returns None on final failure."""
    try:
        async with rate_limiter:
            response = await _do_request(client, method, url, **kwargs)
            return response
    except RETRYABLE_EXCEPTIONS as exc:
        logger.warning("Request failed after retries: %s %s (%s)", method, url, exc)
        return None
    except httpx.HTTPError as exc:
        logger.warning("HTTP error requesting %s %s: %s", method, url, exc)
        return None