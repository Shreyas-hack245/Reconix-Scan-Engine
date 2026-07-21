"""
JavaScript endpoint extraction for Reconix Scan Engine.

Scans inline <script> blocks and (bounded) fetched external script
files for string literals that look like API paths or full URLs, so
that client-side-only routes (e.g. those called via fetch/XHR/axios)
are added to the discovered sitemap even if never linked as <a href>.
"""

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from app.core.logging_config import logger
from app.core.rate_limiter import RateLimiter
from app.utils.http_client import safe_request

_ENDPOINT_PATTERN = re.compile(
    r"""["'](?P<path>(?:https?://[^"'\s]+)|(?:/(?:api|v[0-9]+|graphql|rest)[^"'\s]*)|(?:/[a-zA-Z0-9_\-./]+))["']"""
)

_STATIC_ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2",
    ".ttf", ".ico", ".map", ".mp4", ".webp",
)

MAX_EXTERNAL_SCRIPTS_PER_PAGE = 10


@dataclass
class JsEndpoint:
    """A candidate endpoint discovered inside JavaScript source."""

    url: str
    source: str


def _extract_candidate_paths(js_source: str) -> set[str]:
    candidates: set[str] = set()
    for match in _ENDPOINT_PATTERN.finditer(js_source):
        path = match.group("path")
        if len(path) < 2 or len(path) > 500:
            continue
        if path.lower().endswith(_STATIC_ASSET_EXTENSIONS):
            continue
        candidates.add(path)
    return candidates


async def extract_js_endpoints(
    html: str,
    page_url: str,
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    fetch_external: bool = True,
) -> list[JsEndpoint]:
    """
    Extract candidate API/endpoint paths referenced from a page's inline
    and (optionally) external JavaScript.
    """
    soup = BeautifulSoup(html, "html.parser")
    discovered: list[JsEndpoint] = []
    seen_urls: set[str] = set()

    def _add(path: str, source: str) -> None:
        resolved = urljoin(page_url, path)
        if resolved not in seen_urls:
            seen_urls.add(resolved)
            discovered.append(JsEndpoint(url=resolved, source=source))

    for script_tag in soup.find_all("script"):
        if script_tag.get("src"):
            continue
        inline_source = script_tag.string or ""
        for path in _extract_candidate_paths(inline_source):
            _add(path, source="inline")

    if not fetch_external:
        return discovered

    external_srcs = [
        urljoin(page_url, tag.get("src"))
        for tag in soup.find_all("script")
        if tag.get("src")
    ]

    page_origin = urlsplit(page_url).netloc
    same_origin_srcs = [src for src in external_srcs if urlsplit(src).netloc == page_origin]

    for script_url in same_origin_srcs[:MAX_EXTERNAL_SCRIPTS_PER_PAGE]:
        response = await safe_request(client, rate_limiter, "GET", script_url)
        if response is None or response.status_code != 200:
            continue
        try:
            for path in _extract_candidate_paths(response.text):
                _add(path, source=script_url)
        except Exception as exc:
            logger.debug("Failed to parse script %s: %s", script_url, exc)

    return discovered