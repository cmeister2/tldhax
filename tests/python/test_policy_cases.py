"""Interpreted policy cases exercise the packaged Rust evaluator through Python."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tldhax import Registry

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "policy"
CASES: list[dict[str, Any]] = []
for path in sorted(FIXTURE_ROOT.glob("*.json")):
    document = json.loads(path.read_text(encoding="utf-8"))
    CASES.extend(document["cases"])


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_interpreted_policy_case(registry: Registry, case: dict[str, Any]) -> None:
    """Compare independent expected decisions, reason codes and missing facts."""
    result = registry.assess(case["domain"], case.get("profile"))
    expected = case["expected"]
    assert result.decision == expected["decision"], case.get("rationale", case["id"])
    assert set(expected.get("reason_codes", [])) <= {
        reason.code for reason in result.reasons
    }
    if "missing_profile_fields" in expected:
        assert set(result.missing_profile_fields) == set(
            expected["missing_profile_fields"]
        )
