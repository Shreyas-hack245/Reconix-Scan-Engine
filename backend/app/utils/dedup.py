"""
URL normalization and deduplication helpers for Reconix Scan Engine.
"""

from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """Normalize a URL for deduplication purposes."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()

    path = parts.path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    query_pairs = sorted(parse_qsl(parts.query, keep_blank_values=True))
    query = urlencode(query_pairs)

    return urlunsplit((scheme, netloc, path, query, ""))


class UrlDeduplicator:
    """Tracks normalized URLs that have already been seen/visited."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def is_new(self, url: str) -> bool:
        """Return True and record the URL if it hasn't been seen before."""
        key = normalize_url(url)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    def __contains__(self, url: str) -> bool:
        return normalize_url(url) in self._seen

    def __len__(self) -> int:
        return len(self._seen)


class FindingDeduplicator:
    """Suppresses duplicate vulnerability findings within a scan."""

    def __init__(self) -> None:
        self._seen: dict[str, str] = {}

    @staticmethod
    def _key(url: str, method: str, vulnerability_type: str, parameter: str | None) -> str:
        return "|".join([normalize_url(url), method.upper(), vulnerability_type, parameter or ""])

    def register(self, url: str, method: str, vulnerability_type: str, parameter: str | None, finding_id: str) -> Optional[str]:
        """Register a finding. Returns None if unique, or the original finding_id if a duplicate."""
        key = self._key(url, method, vulnerability_type, parameter)
        if key in self._seen:
            return self._seen[key]
        self._seen[key] = finding_id
        return None