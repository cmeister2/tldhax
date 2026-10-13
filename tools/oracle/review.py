"""Compare native signals with static policy without modifying any rule."""

from __future__ import annotations

from typing import Any

from .models import Candidate, Observation


def review_findings(
    candidate: Candidate, observations: list[Observation]
) -> list[dict[str, Any]]:
    """Signals flag reviews; they never update policy or infer availability."""
    findings: list[dict[str, Any]] = []
    for item in observations:
        code = None
        if item.validity_signal in ("explicitly_invalid", "explicitly_restricted"):
            code = "provider_policy_reason"
        elif (
            item.validity_signal == "accepted"
            and candidate.offline_validity == "invalid"
            and candidate.evidence_ids
        ):
            code = "acceptance_contradicts_evidenced_rule"
        if code:
            findings.append(
                {
                    "code": code,
                    "requested_name": candidate.name,
                    "provider": item.provider,
                    "signal": item.validity_signal,
                    "evidence_ids": candidate.evidence_ids,
                    "native_reason": item.native_reason,
                    "source": item.source,
                    "api_version": item.api_version,
                    "environment": item.environment,
                    "observed_at": item.observed_at,
                    "dataset_version": item.dataset_version,
                }
            )
    signals = {item.validity_signal for item in observations} - {"inconclusive"}
    if "accepted" in signals and len(signals) > 1:
        findings.append(
            {
                "code": "provider_disagreement",
                "requested_name": candidate.name,
                "providers": [item.provider for item in observations],
            }
        )
    return findings
