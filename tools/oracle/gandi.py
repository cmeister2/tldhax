"""Optional Gandi PAT adapter for an already eligible account; checks only.

https://api.gandi.net/docs/domains/#get-domain-availability
"""

from __future__ import annotations

from typing import Any

from .models import Candidate, Observation, identity
from .providers import Provider


class Gandi(Provider):
    """Optional Gandi create-process check adapter using an existing PAT."""

    name, api_version, batch_size = "gandi", "v5", 1
    SIGNALS = {
        "available": "accepted",
        "available_reserved": "explicitly_restricted",
        "unavailable_restricted": "explicitly_restricted",
        "error_invalid": "explicitly_invalid",
    }
    TRANSIENT = {"error_refused", "error_timeout", "error_unknown", "pending"}

    async def check(
        self, candidates: list[Candidate], dataset_version: str
    ) -> list[Observation]:
        """Query the non-purchasing endpoint for the supplied batch."""
        if len(candidates) != 1:
            raise ValueError("Gandi check accepts one name")
        host = (
            "api.gandi.net"
            if self.environment == "production"
            else "api.sandbox.gandi.net"
        )
        payload = await self.request(
            "GET",
            f"https://{host}/v5/domain/check",
            headers={"Authorization": f"Bearer {self.credentials.token}"},
            params={"name": candidates[0].name, "processes": "create"},
        )
        return [self.parse(candidates[0], payload, dataset_version)]

    def parse(
        self, candidate: Candidate, payload: Any, dataset_version: str
    ) -> Observation:
        """Interpret documented fields and reject ambiguous response identities."""
        products = payload.get("products") if isinstance(payload, dict) else None
        if not isinstance(products, list) or any(
            not isinstance(item, dict) for item in products
        ):
            return self.observation(
                candidate, dataset_version, findings=("invalid_response",)
            )
        # Keep process identity too: check statuses apply to create only.
        products = [item for item in products if item.get("process") == "create"]
        matching = [
            item
            for item in products
            if isinstance(item.get("name"), str)
            and identity(item["name"]) == candidate.key
        ]
        if len(matching) != 1:
            returned = products[0].get("name") if len(products) == 1 else None
            finding = "duplicate_result" if matching else "missing_result"
            if not matching and isinstance(returned, str):
                finding = "provider_changed_name"
            return self.observation(
                candidate,
                dataset_version,
                returned,
                findings=(finding,),
                response={
                    "products": [
                        {
                            key: item[key]
                            for key in ("name", "status", "process")
                            if key in item
                        }
                        for item in products
                    ]
                },
            )
        item = matching[0]
        status = item.get("status") if isinstance(item.get("status"), str) else None
        signal = self.SIGNALS.get(status, "inconclusive") if status else "inconclusive"
        return self.observation(
            candidate,
            dataset_version,
            item["name"],
            validity_signal=signal,
            native_status=status if isinstance(status, str) else None,
            native_reason=status if signal.startswith("explicitly_") else None,
            response={
                key: item[key] for key in ("name", "status", "process") if key in item
            },
            transient=status in self.TRANSIENT,
            support="unsupported" if status == "reserved_corporate" else "unknown",
        )
