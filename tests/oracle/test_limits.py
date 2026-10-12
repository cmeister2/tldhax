"""Offline fake-clock tests of quota, resume, retry and cross-check behavior."""

import asyncio

import httpx
from tools.oracle.limits import Quota, Window, retry_delay

from ._clock import FakeClock


def test_retry_after_dates_and_multiwindow_quotas():
    """Retry after dates and multiwindow quotas."""
    assert retry_delay("Tue, 14 Nov 2023 22:13:27 GMT", 1_700_000_000) == 7
    assert retry_delay("nonsense", 1_700_000_000) == 0
    clock = FakeClock()

    async def acquire():
        """Acquire the configured quota in the fake-clock scenario."""
        quota = Quota((Window(1, 1), Window(2, 10)), clock)
        await quota.acquire()
        await quota.acquire()
        await quota.acquire()

    asyncio.run(acquire())
    assert clock.now == 10


def test_rate_headers_can_delay_but_cannot_expand_local_limits():
    """Interpret standard reset durations and legacy reset epochs conservatively."""
    clock = FakeClock()
    quota = Quota((Window(1, 1),), clock)
    quota.headers(httpx.Headers({"RateLimit-Remaining": "0", "RateLimit-Reset": "7"}))
    asyncio.run(quota.acquire())
    assert clock.now == 7
    quota.headers(
        httpx.Headers(
            {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(clock.time() + 8)}
        )
    )
    asyncio.run(quota.acquire())
    assert clock.now == 15


def test_shared_cooldown_survives_restart(tmp_path):
    """A persisted Retry-After pause applies to a new limiter and token configuration."""
    from tools.oracle.store import Store

    path = tmp_path / "quota.sqlite"
    clock = FakeClock()
    with Store(path) as store:
        quota = Quota((Window(10, 1),), clock, store, "source-ip")
        quota.defer(7)
    restarted_clock = FakeClock()
    with Store(path) as resumed:
        quota = Quota((Window(10, 1),), restarted_clock, resumed, "source-ip")
        asyncio.run(quota.acquire())
    assert restarted_clock.now == 7
