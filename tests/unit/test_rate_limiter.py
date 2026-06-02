import pytest
import time
from specter.core.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_acquire():
    limiter = RateLimiter(rate=100, capacity=10)
    await limiter.acquire(1)

    limiter._tokens = 0
    limiter._last_refill = time.monotonic() - 10
    await limiter.acquire(1)
    assert limiter._tokens >= 0


@pytest.mark.asyncio
async def test_rate_limiter_zero():
    limiter = RateLimiter(rate=100, capacity=10)
    await limiter.acquire(0)
