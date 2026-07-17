"""
Async rate limiter and concurrency guard used by the crawler and scanner
modules to ensure Reconix Scan Engine never overwhelms a target system.

This module implements a simple token-bucket style limiter combined with
a semaphore for bounding concurrent in-flight requests. Being a well
-behaved, non-disruptive scanner is a core safety requirement of
Reconix Scan Engine.
"""

import asyncio
import time


class RateLimiter:
    """
    Limits the rate of operations to at most `requests_per_second` and the
    number of concurrent operations to at most `max_concurrent`.

    Usage:
        limiter = RateLimiter(requests_per_second=5, max_concurrent=5)
        async with limiter:
            await do_request()
    """

    def __init__(self, requests_per_second: float = 5.0, max_concurrent: int = 5) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")
        if max_concurrent <= 0:
            raise ValueError("max_concurrent must be positive")

        self._min_interval = 1.0 / requests_per_second
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._lock = asyncio.Lock()
        self._last_call_time: float = 0.0

    async def _throttle(self) -> None:
        """Ensure at least `_min_interval` seconds pass between calls."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call_time
            wait_time = self._min_interval - elapsed
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self._last_call_time = time.monotonic()

    async def __aenter__(self) -> "RateLimiter":
        await self._semaphore.acquire()
        await self._throttle()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self._semaphore.release()

    async def acquire(self) -> None:
        """Explicit acquire, mirrors the async context manager behavior."""
        await self._semaphore.acquire()
        await self._throttle()

    def release(self) -> None:
        """Explicit release, mirrors the async context manager behavior."""
        self._semaphore.release()