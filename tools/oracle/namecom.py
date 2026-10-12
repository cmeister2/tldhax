"""Name.com Core non-purchasing checks with exact identity mapping.

https://docs.name.com/api/v1/reference/domains/check-availability
"""

from __future__ import annotations

from typing import Any

import httpx

from .models import Candidate, Observation, identity
from .providers import Provider


class Namecom(Provider):
    """Name.com Core registration-check adapter with exact identity matching."""

    name, api_version, batch_size = "namecom", "core/v1", 50

    async def check(
        self, candidates: list[Candidate], dataset_version: str
    ) -> list[Observation]:
        """Query the non-purchasing endpoint for the supplied batch."""
        if not 1 <= len(candidates) <= self.batch_size:
            raise ValueError("Name.com batches require 1 to 50 names")
        host = (
            "api.name.com" if self.environment == "production" else "api.dev.name.com"
        )
        # Sandbox username must be explicitly supplied, including documented -test suffix.
        payload = await self.request(
            "POST",
            f"https://{host}/core/v1/domains:checkAvailability",
            auth=httpx.BasicAuth(self.credentials.username, self.credentials.token),
            json={
                "domainNames": [c.name for c in candidates],
                "purchaseType": "registration",
            },
        )
        return self.parse(candidates, payload, dataset_version)

    def parse(
        self, candidates: list[Candidate], payload: Any, dataset_version: str
    ) -> list[Observation]:
        """Interpret documented fields and reject ambiguous response identities."""
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list) or any(
            not isinstance(item, dict) for item in results
        ):
            return [
                self.observation(c, dataset_version, findings=("invalid_response",))
                for c in candidates
            ]
        by_identity: dict[str, list[dict[str, Any]]] = {}
        for item in results:
            if isinstance(item.get("domainName"), str):
                by_identity.setdefault(identity(item["domainName"]), []).append(item)
        observations = []
        expected = {c.key for c in candidates}
        unmatched = [
            item
            for item in results
            if not isinstance(item.get("domainName"), str)
            or identity(item["domainName"]) not in expected
        ]
        for candidate in candidates:
            matches = by_identity.get(candidate.key, [])
            if len(matches) != 1:
                finding = "duplicate_result" if matches else "missing_result"
                returned = None
                # A single changed answer is attributable, without permissive sanitisation.
                if not matches and len(candidates) == 1 and len(unmatched) == 1:
                    returned = unmatched[0].get("domainName")
                    finding = (
                        "provider_changed_name"
                        if isinstance(returned, str)
                        else "missing_identity"
                    )
                safe = {
                    "results": [
                        {
                            key: result[key]
                            for key in (
                                "domainName",
                                "purchasable",
                                "purchaseType",
                                "reason",
                                "premium",
                            )
                            if key in result
                        }
                        for result in matches + unmatched
                    ]
                }
                observations.append(
                    self.observation(
                        candidate,
                        dataset_version,
                        returned,
                        findings=(finding,),
                        response=safe,
                    )
                )
                continue
            item = matches[0]
            safe = {
                key: item[key]
                for key in (
                    "domainName",
                    "purchasable",
                    "purchaseType",
                    "reason",
                    "premium",
                )
                if key in item
            }
            # Reason strings have no documented validity enum: never guess from prose.
            accepted = (
                item.get("purchasable") is True
                and item.get("purchaseType") == "registration"
            )
            signal = "accepted" if accepted else "inconclusive"
            findings = ("unmatched_results",) if unmatched else ()
            observations.append(
                self.observation(
                    candidate,
                    dataset_version,
                    item["domainName"],
                    validity_signal=signal,
                    response=safe,
                    findings=findings,
                    native_status=str(item.get("purchasable")),
                    native_reason=item.get("reason")
                    if isinstance(item.get("reason"), str)
                    else None,
                    support="supported" if accepted else "unknown",
                )
            )
        return observations
