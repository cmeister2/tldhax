"""Offline fake-clock tests of quota, resume, retry and cross-check behavior."""

import asyncio

import httpx
import pytest
from tools.oracle.config import Credentials
from tools.oracle.gandi import Gandi
from tools.oracle.models import Candidate


@pytest.mark.parametrize(
    ("status", "signal"),
    [
        ("available", "accepted"),
        ("available_reserved", "explicitly_restricted"),
        ("unavailable_restricted", "explicitly_restricted"),
        ("error_invalid", "explicitly_invalid"),
        ("unavailable", "inconclusive"),
        ("unavailable_premium", "inconclusive"),
        ("new_status", "inconclusive"),
    ],
)
def test_gandi_documented_signals_only(status, signal):
    """Gandi documented signals only."""
    adapter = Gandi(httpx.AsyncClient(), Credentials("gandi", token="secret"))
    item = adapter.parse(
        Candidate("a.com"),
        {"products": [{"name": "a.com", "process": "create", "status": status}]},
        "v1",
    )
    assert item.validity_signal == signal
    wrong = adapter.parse(
        Candidate("_a.com"),
        {"products": [{"name": "a.com", "process": "create", "status": status}]},
        "v1",
    )
    assert wrong.validity_signal == "inconclusive" and wrong.findings == (
        "provider_changed_name",
    )
    transfer = adapter.parse(
        Candidate("a.com"),
        {"products": [{"name": "a.com", "process": "transfer", "status": status}]},
        "v1",
    )
    assert transfer.validity_signal == "inconclusive"


def test_gandi_non_purchasing_request_and_explicit_sandbox():
    """Use only GET checks with Bearer PAT and the create process parameter."""

    async def check():
        def fake(request):
            assert request.method == "GET"
            assert (
                str(request.url.copy_with(query=None))
                == "https://api.sandbox.gandi.net/v5/domain/check"
            )
            assert dict(request.url.params) == {"name": "a.com", "processes": "create"}
            assert request.headers["Authorization"] == "Bearer secret"
            return httpx.Response(
                200,
                json={
                    "products": [
                        {"name": "a.com", "process": "create", "status": "available"}
                    ]
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(fake)) as client:
            item = (
                await Gandi(
                    client, Credentials("gandi", token="secret"), "sandbox"
                ).check([Candidate("a.com")], "v1")
            )[0]
        assert item.validity_signal == "accepted" and item.environment == "sandbox"

    asyncio.run(check())
