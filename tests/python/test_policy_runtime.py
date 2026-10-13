"""Run independently authored source-backed cases against the built extension."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tldhax import Registry

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/policy"
CASES = [
    case
    for path in sorted(FIXTURES.glob("*.json"))
    for case in json.loads(path.read_text(encoding="utf-8"))["cases"]
]


@pytest.fixture(scope="module")
def registry() -> Registry:
    """Reuse the immutable release handle across independent cases."""
    return Registry()


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_source_backed_case(registry: Registry, case: dict):
    """Known prohibitions survive gaps; unreviewed permission stays unknown."""
    actual = registry.assess(case["domain"], case.get("registrant")).to_dict()
    expected = case["expected"]
    for key in ["name_validity", "status", "eligibility"]:
        if key in expected:
            assert actual[key] == expected[key], case["rationale"]
    failed: set[str] = set()
    passed: set[str] = set()
    for rule in actual["rules"]:
        if rule["truth"] == "unknown" or rule["effect"] == "context":
            continue
        failure_truth = "false" if rule["effect"] == "require" else "true"
        target = failed if rule["truth"] == failure_truth else passed
        target.add(rule["rule_id"])
    assert set(expected.get("failed_rule_ids", [])) <= failed, case["rationale"]
    assert set(expected.get("passed_rule_ids", [])) <= passed, case["rationale"]
    assert not set(expected.get("absent_rule_ids", [])) & {
        rule["rule_id"] for rule in actual["rules"]
    }, case["rationale"]
    assert set(expected.get("gap_families", [])) <= {
        gap["family"] for gap in actual["gaps"]
    }, case["rationale"]
