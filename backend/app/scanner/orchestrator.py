"""
Scanner orchestrator for Reconix Scan Engine.

Coordinates every independent vulnerability scanner module across the
full set of endpoints discovered by the crawler, applies shared rate
limiting/concurrency, suppresses duplicate findings, and returns a
single aggregated, de-duplicated list of `ScanFinding` objects ready
for AI enrichment (Module 4) and reporting (Module 5).
"""

import asyncio
from dataclasses import dataclass, field

import httpx

from app.core.logging_config import logger
from app.core.rate_limiter import RateLimiter
from app.crawler.crawler import CrawlResult, DiscoveredEndpoint
from app.scanner.access_control import AccessControlScanner
from app.scanner.base import AuditRecorder, BaseScanner, ScanFinding, ScanTarget
from app.scanner.clickjacking import ClickjackingScanner
from app.scanner.cookies import CookieSecurityScanner
from app.scanner.cors import CorsScanner
from app.scanner.csrf import CsrfScanner
from app.scanner.directory_traversal import DirectoryTraversalScanner
from app.scanner.headers import SecurityHeadersScanner
from app.scanner.idor import IdorScanner
from app.scanner.info_disclosure import InfoDisclosureScanner
from app.scanner.redirect import OpenRedirectScanner
from app.scanner.rce import RceScanner
from app.scanner.sqli import SqliScanner
from app.scanner.ssrf import SsrfScanner
from app.scanner.upload import FileUploadScanner
from app.scanner.xss import XssScanner
from app.utils.dedup import FindingDeduplicator
from app.utils.http_client import build_http_client

ALL_SCANNER_CLASSES: list[type[BaseScanner]] = [
    XssScanner,
    SqliScanner,
    SsrfScanner,
    RceScanner,
    IdorScanner,
    CsrfScanner,
    SecurityHeadersScanner,
    CorsScanner,
    CookieSecurityScanner,
    OpenRedirectScanner,
    FileUploadScanner,
    AccessControlScanner,
    InfoDisclosureScanner,
    DirectoryTraversalScanner,
    ClickjackingScanner,
]


@dataclass
class OrchestratorResult:
    """Aggregate output of running all scanner modules over a crawl result."""

    findings: list[ScanFinding] = field(default_factory=list)
    endpoints_scanned: int = 0
    modules_run: int = 0
    duplicate_findings_suppressed: int = 0


def _to_scan_target(endpoint: DiscoveredEndpoint) -> ScanTarget:
    return ScanTarget(
        url=endpoint.url,
        method=endpoint.method,
        parameters=endpoint.parameters,
        has_form=endpoint.has_form,
    )


class ScannerOrchestrator:
    """
    Runs every registered vulnerability scanner module against every
    discovered endpoint, sharing a single HTTP client and rate limiter
    so the target is never hit harder than the configured limits allow.
    """

    def __init__(
        self,
        requests_per_second: float = 5.0,
        max_concurrent: int = 5,
        timeout: float = 10.0,
        audit_recorder: AuditRecorder | None = None,
    ) -> None:
        self.rate_limiter = RateLimiter(requests_per_second=requests_per_second, max_concurrent=max_concurrent)
        self.timeout = timeout
        self.audit_recorder = audit_recorder

    async def run(self, crawl_result: CrawlResult, max_concurrent_scans: int = 5) -> OrchestratorResult:
        """Execute all scanner modules across all discovered endpoints."""
        result = OrchestratorResult()
        dedup = FindingDeduplicator()
        semaphore = asyncio.Semaphore(max_concurrent_scans)

        async with build_http_client(timeout=self.timeout) as client:
            scanners = [cls(client, self.rate_limiter, self.audit_recorder) for cls in ALL_SCANNER_CLASSES]
            result.modules_run = len(scanners)

            async def _scan_one(endpoint: DiscoveredEndpoint) -> list[ScanFinding]:
                async with semaphore:
                    target = _to_scan_target(endpoint)
                    endpoint_findings: list[ScanFinding] = []
                    for scanner in scanners:
                        try:
                            endpoint_findings.extend(await scanner.scan_endpoint(target))
                        except Exception as exc:  # defensive: one module failing should not abort the scan
                            logger.warning("Scanner module %s failed on %s: %s", scanner.module_name, endpoint.url, exc)
                    return endpoint_findings

            tasks = [_scan_one(endpoint) for endpoint in crawl_result.endpoints]
            per_endpoint_results = await asyncio.gather(*tasks) if tasks else []

            for findings in per_endpoint_results:
                for finding in findings:
                    self._register_or_suppress(finding, dedup, result)

            info_scanner = InfoDisclosureScanner(client, self.rate_limiter, self.audit_recorder)
            try:
                base_findings = await info_scanner.scan_common_paths(crawl_result.base_url)
                for finding in base_findings:
                    self._register_or_suppress(finding, dedup, result)
            except Exception as exc:  # defensive
                logger.warning("info_disclosure common-path probe failed: %s", exc)

            result.endpoints_scanned = len(crawl_result.endpoints)

        logger.info(
            "Scan complete: %d findings (%d duplicates suppressed) across %d endpoints using %d modules",
            len(result.findings),
            result.duplicate_findings_suppressed,
            result.endpoints_scanned,
            result.modules_run,
        )
        return result

    @staticmethod
    def _register_or_suppress(finding: ScanFinding, dedup: FindingDeduplicator, result: OrchestratorResult) -> None:
        finding_id = f"{finding.vulnerability_type}:{finding.url}:{finding.parameter}"
        original = dedup.register(finding.url, finding.method, finding.vulnerability_type, finding.parameter, finding_id)
        if original is None:
            result.findings.append(finding)
        else:
            result.duplicate_findings_suppressed += 1