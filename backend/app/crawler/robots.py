"""
robots.txt parser for Reconix Scan Engine.

Fetches and parses a target's robots.txt so the crawler can respect
Disallow rules and discover any linked XML sitemaps. Reconix Scan
Engine treats robots.txt as an ethical boundary during automated
crawling of third-party-adjacent paths; disallowed paths are skipped
by default unless the operator explicitly opts to include them for an
authorized, in-scope assessment.
"""

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.logging_config import logger
from app.core.rate_limiter import RateLimiter
from app.utils.http_client import safe_request

DEFAULT_USER_AGENT_TOKEN = "*"


@dataclass
class RobotsInfo:
    """Parsed robots.txt rules relevant to crawling."""

    disallowed_paths: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    fetched_successfully: bool = False

    def is_disallowed(self, path: str) -> bool:
        """Check whether a given URL path is disallowed for the default user-agent group."""
        for rule in self.disallowed_paths:
            if rule and path.startswith(rule):
                return True
        return False


async def fetch_robots_txt(
    base_url: str,
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
) -> RobotsInfo:
    """Fetch and parse robots.txt for the given base URL's origin."""
    parts = urlsplit(base_url)
    robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"

    info = RobotsInfo()
    response = await safe_request(client, rate_limiter, "GET", robots_url)

    if response is None or response.status_code != 200:
        logger.info("robots.txt not available at %s (skipping robots-based restrictions)", robots_url)
        return info

    info.fetched_successfully = True
    current_agent_matches = False

    for raw_line in response.text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue

        field_name, _, value = line.partition(":")
        field_name = field_name.strip().lower()
        value = value.strip()

        if field_name == "user-agent":
            current_agent_matches = value == DEFAULT_USER_AGENT_TOKEN
        elif field_name == "disallow" and current_agent_matches and value:
            info.disallowed_paths.append(value)
        elif field_name == "allow" and current_agent_matches and value:
            info.allowed_paths.append(value)
        elif field_name == "sitemap" and value:
            info.sitemap_urls.append(urljoin(base_url, value))

    logger.info(
        "Parsed robots.txt: %d disallow rules, %d sitemap(s)",
        len(info.disallowed_paths),
        len(info.sitemap_urls),
    )
    return info