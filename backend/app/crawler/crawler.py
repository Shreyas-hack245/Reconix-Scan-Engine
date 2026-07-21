"""
Core crawler / discovery engine for Reconix Scan Engine.

Performs a breadth-first crawl of a target application starting from a
base URL, respecting robots.txt, page/depth limits, and rate limits.
Along the way it discovers HTML forms, JavaScript-referenced endpoints,
and (once, up front) any published OpenAPI specification. The result
is a de-duplicated sitemap of `DiscoveredEndpoint` records ready to be
persisted and handed to the vulnerability scanner modules.
"""

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from app.core.logging_config import logger
from app.core.rate_limiter import RateLimiter
from app.crawler.form_extractor import DiscoveredForm, extract_forms
from app.crawler.js_endpoint_extractor import extract_js_endpoints
from app.crawler.openapi_parser import discover_openapi_endpoints
from app.crawler.robots import RobotsInfo, fetch_robots_txt
from app.utils.dedup import UrlDeduplicator, normalize_url
from app.utils.http_client import build_http_client, safe_request

HTML_CONTENT_TYPE_HINT = "text/html"


@dataclass
class DiscoveredEndpoint:
    """A single endpoint discovered anywhere during crawling."""

    url: str
    method: str = "GET"
    source: str = "crawler"
    status_code: int | None = None
    content_type: str | None = None
    has_form: bool = False
    parameters: list[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    """Aggregate output of a full crawl/discovery run."""

    base_url: str
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    pages_crawled: int = 0
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    robots_info: RobotsInfo | None = None


class Crawler:
    """
    Breadth-first, same-origin web crawler with safety limits.
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 200,
        requests_per_second: float = 5.0,
        max_concurrent: int = 5,
        respect_robots: bool = True,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.origin = urlsplit(self.base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.timeout = timeout

        self.rate_limiter = RateLimiter(requests_per_second=requests_per_second, max_concurrent=max_concurrent)
        self.dedup = UrlDeduplicator()

    def _in_scope(self, url: str) -> bool:
        """A URL is in scope if it shares the same network location (host:port) as base_url."""
        return urlsplit(url).netloc == self.origin

    @staticmethod
    def _extract_links(html: str, page_url: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        links: list[str] = []
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            links.append(urljoin(page_url, href))
        return links

    async def crawl(self) -> CrawlResult:
        """Run the full discovery process and return a CrawlResult."""
        start_time = time.monotonic()
        result = CrawlResult(base_url=self.base_url)

        async with build_http_client(timeout=self.timeout) as client:
            result.robots_info = await fetch_robots_txt(self.base_url, client, self.rate_limiter)

            openapi_endpoints = await discover_openapi_endpoints(self.base_url, client, self.rate_limiter)
            for oa_endpoint in openapi_endpoints:
                full_url = urljoin(self.base_url, oa_endpoint.path)
                if self.dedup.is_new(f"{oa_endpoint.method}:{full_url}"):
                    result.endpoints.append(
                        DiscoveredEndpoint(
                            url=full_url,
                            method=oa_endpoint.method,
                            source="openapi",
                            parameters=oa_endpoint.parameters,
                        )
                    )

            for sitemap_url in (result.robots_info.sitemap_urls if result.robots_info else []):
                await self._ingest_sitemap(sitemap_url, client, result)

            queue: list[tuple[str, int]] = [(self.base_url, 0)]
            visited_pages: set[str] = set()

            while queue and result.pages_crawled < self.max_pages:
                url, depth = queue.pop(0)
                norm_url = normalize_url(url)

                if norm_url in visited_pages:
                    continue
                if depth > self.max_depth:
                    continue
                if not self._in_scope(url):
                    continue
                if self.respect_robots and result.robots_info and result.robots_info.is_disallowed(urlsplit(url).path):
                    logger.info("Skipping %s (disallowed by robots.txt)", url)
                    continue

                visited_pages.add(norm_url)

                response = await safe_request(client, self.rate_limiter, "GET", url)
                if response is None:
                    result.errors.append(f"Failed to fetch {url}")
                    continue

                result.pages_crawled += 1
                content_type = response.headers.get("content-type", "")

                if self.dedup.is_new(f"GET:{url}"):
                    result.endpoints.append(
                        DiscoveredEndpoint(
                            url=url,
                            method="GET",
                            source="crawler",
                            status_code=response.status_code,
                            content_type=content_type,
                        )
                    )

                if HTML_CONTENT_TYPE_HINT not in content_type or response.status_code >= 400:
                    continue

                html = response.text

                forms = extract_forms(html, url)
                if forms:
                    result.forms.extend(forms)
                    for discovered_form in forms:
                        for endpoint in result.endpoints:
                            if endpoint.url == discovered_form.action_url and endpoint.method == discovered_form.method:
                                endpoint.has_form = True
                                endpoint.parameters = list(set(endpoint.parameters) | set(discovered_form.field_names))
                                break
                        else:
                            if self.dedup.is_new(f"{discovered_form.method}:{discovered_form.action_url}"):
                                result.endpoints.append(
                                    DiscoveredEndpoint(
                                        url=discovered_form.action_url,
                                        method=discovered_form.method,
                                        source="form",
                                        has_form=True,
                                        parameters=discovered_form.field_names,
                                    )
                                )

                js_endpoints = await extract_js_endpoints(html, url, client, self.rate_limiter)
                for js_endpoint in js_endpoints:
                    if self._in_scope(js_endpoint.url) and self.dedup.is_new(f"GET:{js_endpoint.url}"):
                        result.endpoints.append(
                            DiscoveredEndpoint(url=js_endpoint.url, method="GET", source="js")
                        )

                if depth < self.max_depth:
                    for link in self._extract_links(html, url):
                        if self._in_scope(link) and normalize_url(link) not in visited_pages:
                            queue.append((link, depth + 1))

        result.duration_seconds = time.monotonic() - start_time
        logger.info(
            "Crawl of %s complete: %d pages, %d endpoints, %d errors in %.2fs",
            self.base_url,
            result.pages_crawled,
            len(result.endpoints),
            len(result.errors),
            result.duration_seconds,
        )
        return result

    async def _ingest_sitemap(self, sitemap_url: str, client: httpx.AsyncClient, result: CrawlResult) -> None:
        """Fetch an XML sitemap referenced by robots.txt and add its URLs as endpoints."""
        response = await safe_request(client, self.rate_limiter, "GET", sitemap_url)
        if response is None or response.status_code != 200:
            return

        try:
            soup = BeautifulSoup(response.text, "xml")
        except Exception as exc:
            logger.debug("Failed to parse sitemap %s: %s", sitemap_url, exc)
            return

        for loc_tag in soup.find_all("loc"):
            url = loc_tag.get_text(strip=True)
            if url and self._in_scope(url) and self.dedup.is_new(f"GET:{url}"):
                result.endpoints.append(DiscoveredEndpoint(url=url, method="GET", source="robots_sitemap"))