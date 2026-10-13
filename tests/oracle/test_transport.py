"""Recorded response shapes and fake HTTP only; no environment or network."""

import asyncio

import httpx
import pytest
from tools.oracle.config import Credentials
from tools.oracle.providers import Provider, ProviderError


@pytest.mark.parametrize("status", [401, 403, 429, 503, 422])
def test_http_errors_are_safe_and_auth_is_not_a_domain_verdict(status):
    """Http errors are safe and auth is not a domain verdict."""

    async def check():
        """Query the non-purchasing endpoint for the supplied batch."""
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(status, text="secret")
            )
        ) as client:
            with pytest.raises(ProviderError) as error:
                await Provider(client, Credentials("test", "user", "secret")).request(
                    "GET", "https://oracle.invalid/check"
                )
            assert "secret" not in str(error.value)
            assert error.value.transient == (status in (429, 503))
            if status in (401, 403):
                assert error.value.code == "authentication_failure"

    asyncio.run(check())
