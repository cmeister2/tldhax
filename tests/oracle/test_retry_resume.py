"""Offline fake-clock tests of quota, resume, retry and cross-check behavior."""

import asyncio

from tools.oracle.models import Candidate
from tools.oracle.providers import ProviderError
from tools.oracle.runner import ProviderConfig, Runner
from tools.oracle.store import Store, observation_key

from ._clock import FakeClock
from ._helpers import FakeProvider
from ._runner import run


def test_resume_refresh_age_and_dataset_comparison(tmp_path):
    """Resume refresh age and dataset comparison."""
    clock = FakeClock()
    provider = FakeProvider("a", clock)
    with Store(tmp_path / "observations.sqlite") as store:
        config = ProviderConfig(provider)
        first = run([config], store, [Candidate("A.COM")], clock)
        second = asyncio.run(
            Runner([config], store, "v2", clock=clock).run([Candidate("a.com")])
        )
        assert len(provider.calls) == 1 and second.reused == 1
        assert (
            second.observations[0].requested_name == "a.com"
            and second.observations[0].dataset_version == "v2"
        )
        assert first.observations[0].observed_at == second.observations[0].observed_at
        run([config], store, [Candidate("a.com")], clock, refresh=True)
        assert len(provider.calls) == 2
        clock.now += 86401
        run([config], store, [Candidate("a.com")], clock)
        assert len(provider.calls) == 3


def test_retry_after_bounded_backoff_and_auth_fallback():
    """Retry after bounded backoff and auth fallback."""
    clock = FakeClock()
    a = FakeProvider(
        "a",
        clock,
        lambda number, _: (
            ProviderError("quota_failure", 429, "7", True) if number == 1 else None
        ),
    )
    with Store(":memory:") as store:
        result = run([ProviderConfig(a)], store, [Candidate("a.com")], clock)
    assert [when for when, _ in a.calls] == [0, 7]
    assert result.observations[0].validity_signal == "accepted"
    clock = FakeClock()
    a = FakeProvider(
        "a", clock, lambda *_: ProviderError("authentication_failure", 401)
    )
    b = FakeProvider("b", clock)
    with Store(":memory:") as store:
        result = run(
            [ProviderConfig(a), ProviderConfig(b)],
            store,
            [Candidate("a.com")],
            clock,
            cross_check_rate=0,
        )
    assert len(a.calls) == len(b.calls) == 1
    assert result.tool_errors == [{"provider": "a", "code": "authentication_failure"}]
    assert [item.provider for item in result.observations] == ["b"]


def test_persistent_failures_pause_and_fallback():
    """Persistent failures pause and fallback."""
    clock = FakeClock()
    a = FakeProvider(
        "a", clock, lambda *_: ProviderError("server_failure", 503, transient=True)
    )
    b = FakeProvider("b", clock)
    with Store(":memory:") as store:
        result = run(
            [ProviderConfig(a), ProviderConfig(b)],
            store,
            [Candidate("a.com")],
            clock,
            cross_check_rate=0,
        )
    assert len(a.calls) == 3 and len(b.calls) == 1
    assert {item.validity_signal for item in result.observations} == {
        "accepted",
        "inconclusive",
    }


def test_crashed_attempts_remain_bounded_across_resume():
    """Crashed attempts remain bounded across resume."""
    clock = FakeClock()
    adapter = FakeProvider("a", clock)
    with Store(":memory:") as store:
        key = observation_key(Candidate("a.com"), adapter)
        for _ in range(3):
            store.start(key, clock.time())  # Simulated crash before a response.
        result = run([ProviderConfig(adapter)], store, [Candidate("a.com")], clock)
        assert adapter.calls == [] and result.observations[0].findings == (
            "attempt_budget_exhausted",
        )
        run([ProviderConfig(adapter)], store, [Candidate("a.com")], clock, refresh=True)
        assert len(adapter.calls) == 1


def test_native_invalid_is_retained_without_retry_and_disagreement_is_review_only():
    """Native invalid is retained without retry and disagreement is review only."""
    clock = FakeClock()
    a = FakeProvider(
        "a",
        clock,
        lambda *_: {
            "validity_signal": "explicitly_invalid",
            "native_reason": "error_invalid",
        },
    )
    b = FakeProvider("b", clock)
    with Store(":memory:") as store:
        result = run(
            [ProviderConfig(a), ProviderConfig(b)],
            store,
            [Candidate("a.com")],
            clock,
            cross_check_rate=1,
        )
    assert len(a.calls) == 1
    assert {finding["code"] for finding in result.findings} == {
        "provider_policy_reason",
        "provider_disagreement",
    }


def test_native_transients_have_bounded_retries_and_resume_history():
    """Retain every native retry response and stop after the configured ceiling."""
    clock = FakeClock()
    a = FakeProvider(
        "a", clock, lambda *_: {"transient": True, "native_status": "pending"}
    )
    with Store(":memory:") as store:
        result = run([ProviderConfig(a)], store, [Candidate("a.com")], clock)
        assert len(a.calls) == 3 and result.observations[0].transient
        assert (
            store.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
            == 3
        )
        resumed = run([ProviderConfig(a)], store, [Candidate("a.com")], clock)
        assert len(a.calls) == 3 and resumed.reused == 1
