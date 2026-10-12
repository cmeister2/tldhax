"""Offline fake-clock tests of quota, resume, retry and cross-check behavior."""

import asyncio
import json

import httpx
from tools.oracle.config import Credentials
from tools.oracle.limits import Window
from tools.oracle.models import Candidate
from tools.oracle.namecom import Namecom
from tools.oracle.providers import ProviderError
from tools.oracle.runner import ProviderConfig, Runner
from tools.oracle.store import Store

from ._clock import FakeClock
from ._helpers import FakeProvider
from ._runner import run


def test_namecom_batches_at_50_and_deduplicates():
    """Namecom batches at 50 and deduplicates."""
    clock = FakeClock()
    sizes = []

    def fake(request):
        """Return a pinned HTTP response without reaching a registrar."""
        names = json.loads(request.content)["domainNames"]
        sizes.append(len(names))
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "domainName": name,
                        "purchasable": True,
                        "purchaseType": "registration",
                    }
                    for name in names
                ]
            },
        )

    async def check():
        """Query the non-purchasing endpoint for the supplied batch."""
        async with httpx.AsyncClient(transport=httpx.MockTransport(fake)) as client:
            adapter = Namecom(client, Credentials("namecom", "user", "secret"))
            with Store(":memory:") as store:
                result = await Runner(
                    [ProviderConfig(adapter, max_candidates=120)],
                    store,
                    "v1",
                    clock=clock,
                ).run(
                    [Candidate(f"n{i}.com") for i in range(120)]
                    + [Candidate("N1.COM.")]
                )
                assert len(result.observations) == 120

    asyncio.run(check())
    assert sorted(sizes) == [20, 50, 50]


def test_unique_candidate_budget_caps_default_run():
    """Unique candidate budget caps default run."""
    clock = FakeClock()
    adapter = FakeProvider("a", clock)
    with Store(":memory:") as store:
        result = run(
            [ProviderConfig(adapter)],
            store,
            [Candidate(f"n{i}.com") for i in range(35)],
            clock,
        )
    assert sum(len(names) for _, names in adapter.calls) == 30
    assert len(result.observations) == 30
    assert len(result.findings) == 5
    assert result.cross_check == "unavailable"


def test_coverage_weighted_dispatch_and_shared_quotas():
    """Coverage weighted dispatch and shared quotas."""
    clock = FakeClock()
    a, b = FakeProvider("a", clock), FakeProvider("b", clock)
    windows = (Window(1, 10),)
    with Store(":memory:") as store:
        result = run(
            [
                ProviderConfig(
                    a, windows=windows, quota_group="source-ip", namespaces=("com",)
                ),
                ProviderConfig(
                    b, windows=windows, quota_group="source-ip", namespaces=("fr",)
                ),
            ],
            store,
            [Candidate("a.com"), Candidate("b.fr")],
            clock,
            cross_check_rate=0,
        )
    assert a.calls[0][0] == 0 and b.calls[0][0] == 10
    assert len(result.observations) == 2
    clock = FakeClock()
    a, b = FakeProvider("a", clock), FakeProvider("b", clock)
    with Store(":memory:") as store:
        run(
            [ProviderConfig(a, weight=3), ProviderConfig(b)],
            store,
            [Candidate(f"n{i}.com") for i in range(20)],
            clock,
            cross_check_rate=0,
        )
    assert sum(len(names) for _, names in a.calls) == 15
    assert sum(len(names) for _, names in b.calls) == 5


def test_stratified_cross_check_and_evidenced_contradictions():
    """Stratified cross check and evidenced contradictions."""
    clock = FakeClock()
    a, b = FakeProvider("a", clock), FakeProvider("b", clock)
    candidates = [
        Candidate(f"n{i}.com", stratum="positive" if i < 10 else "negative")
        for i in range(20)
    ]
    candidates[19] = Candidate(
        "n19.com",
        stratum="negative",
        offline_validity="invalid",
        evidence_ids=("registry:1",),
    )
    with Store(":memory:") as store:
        result = run([ProviderConfig(a), ProviderConfig(b)], store, candidates, clock)
    double = {
        candidate.name
        for candidate in candidates
        if sum(item.requested_name == candidate.name for item in result.observations)
        > 1
    }
    assert 2 <= len(double) <= 3 and "n19.com" in double
    assert {c.stratum for c in candidates if c.name in double} == {
        "positive",
        "negative",
    }
    assert any(
        finding["code"] == "acceptance_contradicts_evidenced_rule"
        for finding in result.findings
    )


def test_failed_second_provider_is_not_a_completed_cross_check():
    """A second HTTP error remains query metadata and cannot count as corroboration."""
    clock = FakeClock()
    a = FakeProvider("a", clock)
    b = FakeProvider(
        "b", clock, lambda *_: ProviderError("server_failure", 503, transient=True)
    )
    with Store(":memory:") as store:
        result = run(
            [ProviderConfig(a), ProviderConfig(b, retries=0)],
            store,
            [Candidate("a.com")],
            clock,
            cross_check_rate=1,
        )
    assert result.cross_check == "unavailable"
    assert len(result.observations) == 2
    assert result.observations[1].transient


def test_quota_window_survives_runner_and_store_restart(tmp_path):
    """Repeated explicit runs share an account/IP window through their SQLite store."""
    path = tmp_path / "observations.sqlite"
    clock = FakeClock()
    a = FakeProvider("a", clock)
    with Store(path) as store:
        run(
            [ProviderConfig(a, windows=(Window(1, 10),))],
            store,
            [Candidate("first.com")],
            clock,
        )
    restarted_clock = FakeClock()
    b = FakeProvider("a", restarted_clock)
    with Store(path) as resumed:
        run(
            [ProviderConfig(b, windows=(Window(1, 10),))],
            resumed,
            [Candidate("second.com")],
            restarted_clock,
        )
    assert a.calls[0][0] == 0 and b.calls[0][0] == 10
