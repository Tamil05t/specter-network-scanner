"""Token bucket rate limiter for async workflows."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class RateLimiter:
    """Async token bucket rate limiter.

    rate: tokens per second
    capacity: maximum bucket size
    """

    rate: float
    capacity: int

    def __post_init__(self) -> None:
        """Initialize internal token bucket state.

        Args:
            None

        Returns:
            None: Initializes token counters.

        Raises:
            Exception: Unexpected initialization errors.

        Example:
            >>> limiter = RateLimiter(rate=10.0, capacity=20)

        Note:
            Tokens start at full capacity.
        """
        self._tokens = float(self.capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, waiting until available.

        Args:
            tokens (int): Number of tokens to consume.

        Returns:
            None: Returns when tokens are available.

        Raises:
            asyncio.CancelledError: If the coroutine is cancelled.

        Example:
            >>> await limiter.acquire(1)

        Note:
            Uses a lock to serialize token updates.
        """
        if tokens <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_refill
                if elapsed > 0:
                    refill = elapsed * self.rate
                    if refill > 0:
                        self._tokens = min(self.capacity, self._tokens + refill)
                        self._last_refill = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                # Wait enough time for required tokens to accumulate.
                deficit = tokens - self._tokens
                sleep_for = max(deficit / self.rate, 0.01)
                await asyncio.sleep(sleep_for)
