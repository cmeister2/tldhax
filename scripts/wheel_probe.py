"""Installed-wheel probe: run with isolated Python from outside the checkout."""

from __future__ import annotations

import json
import socket


def forbidden(*_args, **_kwargs):
    """Fail if any runtime lookup attempts a network operation."""
    raise AssertionError("installed lookup attempted network access")


socket.create_connection = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden

from tldhax import Registry  # noqa: E402

registry = Registry()
cases = [
    "vanity.com",
    "",
    "under_score.com",
    "bücher.de",
    "xn--bcher-kva.de",
    "vanity.this-root-is-not-delegated",
]
assessments = [registry.assess(name) for name in cases]
assert assessments[1].name_validity == "invalid"
assert assessments[2].name_validity == "invalid"
assert assessments[3].canonical_ascii == assessments[4].canonical_ascii
assert assessments[3].name_validity == assessments[4].name_validity
assert assessments[3].policy_coverage == assessments[4].policy_coverage
assert not assessments[5].root_known
assert assessments[5].name_validity == "unknown"
assert assessments[0].dataset_version
assert len({assessment.dataset_version for assessment in assessments}) == 1
assert len({assessment.evaluation_date for assessment in assessments}) == 1
batch = registry.assess_many(cases)
assert [item.name_validity for item in batch] == [
    item.name_validity for item in assessments
]
assert [item.canonical_ascii for item in batch] == [
    item.canonical_ascii for item in assessments
]
print(
    json.dumps(
        {
            "dataset_version": assessments[0].dataset_version,
            "evaluation_date": assessments[0].evaluation_date,
            "inventory_date": assessments[0].inventory_date,
            "normalization_profile": assessments[0].normalization_profile,
            "cases": [item.to_dict() for item in assessments],
        },
        sort_keys=True,
    )
)
