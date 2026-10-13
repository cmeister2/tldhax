"""Direct transmission tests before scheduler dispatch or provider fallback."""

import asyncio

import pytest
from tools.oracle.checks import check_batch
from tools.oracle.dispatch_config import ProviderConfig
from tools.oracle.limits import Quota, Window
from tools.oracle.models import Candidate
from tools.oracle.providers import ProviderError
from tools.oracle.store import Store

from ._clock import FakeClock
from ._helpers import FakeProvider


def test_auth_failure_is_tool_error_and_native_invalid_is_never_retried():
    """Keep authentication errors separate and retain an explicit policy signal."""

    async def check():
        clock = FakeClock()
        provider = FakeProvider(
            "a", clock, lambda *_: ProviderError("authentication_failure", 401)
        )
        quota = Quota((Window(1, 1),), clock)
        paused, errors = set(), []
        with Store(":memory:") as store:
            config = ProviderConfig(provider)
            items = await check_batch(
                config,
                [Candidate("a.com")],
                store=store,
                dataset="v1",
                clock=clock,
                quota=quota,
                semaphore=asyncio.Semaphore(1),
                paused=paused,
                tool_errors=errors,
                refresh=False,
            )
            assert (
                items == []
                and paused == {"a"}
                and errors[0]["code"] == "authentication_failure"
            )
        provider = FakeProvider(
            "a",
            clock,
            lambda *_: {
                "validity_signal": "explicitly_invalid",
                "native_status": "error_invalid",
            },
        )
        with Store(":memory:") as store:
            items = await check_batch(
                ProviderConfig(provider),
                [Candidate("_a.com")],
                store=store,
                dataset="v1",
                clock=clock,
                quota=quota,
                semaphore=asyncio.Semaphore(1),
                paused=set(),
                tool_errors=[],
                refresh=False,
            )
            assert (
                len(provider.calls) == 1
                and items[0].validity_signal == "explicitly_invalid"
            )

    asyncio.run(check())


def test_terminal_retry_after_stays_on_shared_quota():
    """Keep the last 429 cooldown even when another adapter receives fallback work."""

    async def check():
        clock = FakeClock()
        provider = FakeProvider(
            "a", clock, lambda *_: ProviderError("quota_failure", 429, "7", True)
        )
        quota = Quota((Window(1, 1),), clock)
        with Store(":memory:") as store:
            items = await check_batch(
                ProviderConfig(provider, retries=0),
                [Candidate("a.com")],
                store=store,
                dataset="v1",
                clock=clock,
                quota=quota,
                semaphore=asyncio.Semaphore(1),
                paused=set(),
                tool_errors=[],
                refresh=False,
            )
            assert len(provider.calls) == 1 and items[0].native_status == "HTTP429"
            await quota.acquire()
            assert clock.now == 7

    asyncio.run(check())


def test_concurrent_auth_pause_prevents_waiting_request():
    """Recheck provider health after waiting for quota and before transmission."""

    class YieldingClock(FakeClock):
        async def sleep(self, delay):
            self.now += delay
            await asyncio.sleep(0)

    class YieldingProvider(FakeProvider):
        async def check(self, candidates, dataset):
            await asyncio.sleep(0)
            return await super().check(candidates, dataset)

    async def check():
        clock = YieldingClock()
        provider = YieldingProvider(
            "a", clock, lambda *_: ProviderError("authentication_failure", 401)
        )
        config, quota = (
            ProviderConfig(provider, concurrency=2),
            Quota((Window(1, 10),), clock),
        )
        paused, errors, semaphore = set(), [], asyncio.Semaphore(2)
        with Store(":memory:") as store:
            await asyncio.gather(
                *(
                    check_batch(
                        config,
                        [Candidate(name)],
                        store=store,
                        dataset="v1",
                        clock=clock,
                        quota=quota,
                        semaphore=semaphore,
                        paused=paused,
                        tool_errors=errors,
                        refresh=False,
                    )
                    for name in ("first.com", "second.com")
                )
            )
        assert len(provider.calls) == 1 and errors == [
            {"provider": "a", "code": "authentication_failure"}
        ]

    asyncio.run(check())


@pytest.mark.parametrize("field", ["concurrency", "max_candidates", "retries"])
@pytest.mark.parametrize("value", [True, 1.5])
def test_noninteger_provider_budgets_fail_before_transmission(field, value):
    """A fractional semaphore budget must never defeat concurrency limits."""
    clock = FakeClock()
    provider = FakeProvider("a", clock)
    with pytest.raises(ValueError):
        ProviderConfig(provider, **{field: value})
    assert provider.calls == []
