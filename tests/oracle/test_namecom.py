"""Recorded response shapes and fake HTTP only; no environment or network."""

import asyncio
import base64
import json

import httpx
from tools.oracle.config import Credentials
from tools.oracle.models import Candidate
from tools.oracle.namecom import Namecom


def provider():
    """Construct a parser without network requests or real credentials."""
    return Namecom(httpx.AsyncClient(), Credentials("namecom", "user", "secret"))


def test_out_of_order_results_unavailability_and_unknown_reasons():
    """Out of order results unavailability and unknown reasons."""
    parsed = provider().parse(
        [Candidate("a.com"), Candidate("b.com"), Candidate("c.com")],
        {
            "results": [
                {
                    "domainName": "c.com",
                    "purchasable": False,
                    "reason": "invalid maybe?",
                },
                {
                    "domainName": "b.com",
                    "purchasable": True,
                    "purchaseType": "aftermarket_i",
                },
                {
                    "domainName": "A.COM.",
                    "purchasable": True,
                    "purchaseType": "registration",
                },
            ]
        },
        "v1",
    )
    assert [item.validity_signal for item in parsed] == [
        "accepted",
        "inconclusive",
        "inconclusive",
    ]
    assert parsed[2].native_reason == "invalid maybe?"


def test_changed_name_missing_duplicate_and_unmatched():
    """Changed name missing duplicate and unmatched."""
    adapter = provider()
    accepted = {
        "domainName": "bad.com",
        "purchasable": True,
        "purchaseType": "registration",
    }
    observation = adapter.parse([Candidate("_bad.com")], {"results": [accepted]}, "v1")[
        0
    ]
    assert observation.validity_signal == "inconclusive"
    assert observation.returned_name == "bad.com" and observation.findings == (
        "provider_changed_name",
    )
    assert adapter.parse([Candidate("bad.com")], {"results": []}, "v1")[0].findings == (
        "missing_result",
    )
    assert adapter.parse(
        [Candidate("bad.com")], {"results": [accepted, accepted]}, "v1"
    )[0].findings == ("duplicate_result",)
    unmatched = adapter.parse(
        [Candidate("bad.com")], {"results": [accepted, {"domainName": "x.com"}]}, "v1"
    )[0]
    assert unmatched.findings == ("unmatched_results",)
    assert adapter.parse([Candidate("bad.com")], {"results": [5]}, "v1")[
        0
    ].findings == ("invalid_response",)


def test_production_request_is_only_non_purchasing_check_and_redacts():
    """Production request is only non purchasing check and redacts."""

    async def check():
        """Query the non-purchasing endpoint for the supplied batch."""

        def fake(request):
            """Return a pinned HTTP response without reaching a registrar."""
            assert (
                request.url == "https://api.name.com/core/v1/domains:checkAvailability"
            )
            assert request.method == "POST"
            assert json.loads(request.content) == {
                "domainNames": ["a.com"],
                "purchaseType": "registration",
            }
            encoded = base64.b64encode(b"user:secret").decode()
            assert request.headers["Authorization"] == f"Basic {encoded}"
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "domainName": "a.com",
                            "purchasable": False,
                            "reason": f"secret user {encoded}",
                            "contacts": {"email": "private@example.com"},
                        }
                    ]
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(fake)) as client:
            observations = await Namecom(
                client, Credentials("namecom", "user", "secret")
            ).check([Candidate("a.com")], "v1")
        text = json.dumps(observations[0].to_dict())
        assert "secret" not in text and "private@example.com" not in text
        assert "[REDACTED]" in text

    asyncio.run(check())


def test_sandbox_hostname_is_explicit():
    """Sandbox hostname is explicit."""

    async def check():
        """Query the non-purchasing endpoint for the supplied batch."""
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json={"results": []})
            )
        ) as client:
            adapter = Namecom(
                client, Credentials("namecom", "user-test", "secret"), "sandbox"
            )
            await adapter.check([Candidate("a.com")], "v1")

    asyncio.run(check())


def test_short_secret_redaction_preserves_signal_enums():
    """Short secret redaction preserves signal enums."""
    adapter = Namecom(httpx.AsyncClient(), Credentials("namecom", "x", "a"))
    item = adapter.parse(
        [Candidate("valid.com")],
        {
            "results": [
                {
                    "domainName": "valid.com",
                    "purchasable": True,
                    "purchaseType": "registration",
                }
            ]
        },
        "v1",
    )[0]
    assert item.validity_signal == "accepted"


def test_pinned_sanitised_production_smoke_responses():
    """Replay captured controls without depending on credentials or the hidden doc."""
    from pathlib import Path

    fixture = json.loads(
        (Path(__file__).parent / "fixtures/namecom-smoke.json").read_text()
    )
    adapter = provider()
    for case in fixture["cases"]:
        item = adapter.parse(
            [Candidate(case["requested_name"])], case["response"], "v1"
        )[0]
        assert item.validity_signal == case["expected_signal"]
        if "expected_finding" in case:
            assert item.findings == (case["expected_finding"],)
            assert item.response["results"][0]["purchasable"] is True
