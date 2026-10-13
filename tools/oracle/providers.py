"""Registrar-neutral transport, safe errors and observation construction.

Adapters own endpoint selection, authentication, batch limits and native response
interpretation. Shared dispatch, retry and persistence code uses this interface.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from .config import Credentials
from .models import Candidate, Observation, Redactor, timestamp


class ProviderError(Exception):
    """Safe tool failure metadata, never a domain validity verdict."""

    def __init__(
        self,
        code: str,
        status: int | None = None,
        retry_after: str | None = None,
        transient: bool = False,
    ):
        """Initialize explicit dependencies and configuration."""
        super().__init__(code)  # No URL, credential, response body, or exception repr.
        self.code, self.status = code, status
        self.retry_after, self.transient = retry_after, transient


class Provider:
    """Common pooled transport and sanitised observation construction."""

    name = ""
    api_version = ""
    batch_size = 1

    def __init__(
        self,
        client: httpx.AsyncClient,
        credentials: Credentials,
        environment: str = "production",
    ):
        """Initialize explicit dependencies and configuration."""
        if environment not in ("production", "sandbox"):
            raise ValueError("provider environment must be production or sandbox")
        self.client, self.credentials, self.environment = (
            client,
            credentials,
            environment,
        )
        self.redactor = Redactor(
            (credentials.token, credentials.username),
            (credentials.username, credentials.token),
        )
        self.last_headers: httpx.Headers = httpx.Headers()

    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        """Make a check request and report safe errors without response bodies."""
        try:
            response = await self.client.request(method, url, **kwargs)
        except httpx.RequestError:
            raise ProviderError("transport_failure", transient=True) from None
        self.last_headers = response.headers
        if response.status_code in (401, 403):
            raise ProviderError("authentication_failure", response.status_code)
        if response.status_code == 429 or response.status_code >= 500:
            raise ProviderError(
                "quota_failure" if response.status_code == 429 else "server_failure",
                response.status_code,
                response.headers.get("Retry-After"),
                True,
            )
        if not response.is_success:
            raise ProviderError("query_failure", response.status_code)
        try:
            return response.json()
        except ValueError:
            raise ProviderError("invalid_json", transient=True) from None

    def observation(
        self,
        candidate: Candidate,
        dataset_version: str,
        returned: str | None = None,
        **kwargs: Any,
    ) -> Observation:
        """Construct an observation while preserving structural enums during redaction."""
        clean = dict(kwargs)
        for key in ("response", "native_status", "native_reason"):
            if key in clean:
                clean[key] = self.redactor.clean(clean[key])
        return Observation(
            requested_name=candidate.name,
            canonical_name=candidate.canonical,
            returned_name=self.redactor.clean(returned),
            provider=self.name,
            api_version=self.api_version,
            environment=self.environment,
            observed_at=timestamp(time.time()),
            dataset_version=dataset_version,
            **clean,
        )

    async def check(
        self, candidates: list[Candidate], dataset_version: str
    ) -> list[Observation]:
        """Query the non-purchasing endpoint for the supplied batch."""
        raise NotImplementedError
