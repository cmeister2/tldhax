"""Keep independently authored policy expectations connected to real evidence.

The runtime tests consume these same JSON cases. These checks catch stale or
invented evidence references and invalid declared profiles before integration.
They do not derive expected verdicts from predicates or generated policy output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = sorted((ROOT / "tests/fixtures/policy").glob("*.json"))


def records(path: Path, key: str) -> dict[str, dict]:
    """Read provenance records without interpreting policy predicates."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return {item["id"]: item for item in data[key]}


SOURCES = records(ROOT / "evidence/sources.toml", "sources")
ASSERTIONS = records(ROOT / "evidence/assertions.toml", "assertions")
FACTS = {
    item["field"]: item
    for item in tomllib.loads(
        (ROOT / "rules/profiles/registrant-facts.toml").read_text(encoding="utf-8")
    )["facts"]
}
EXPECTED_FIELDS = {
    "name_validity",
    "status",
    "eligibility",
    "failed_rule_ids",
    "passed_rule_ids",
    "gap_families",
    "absent_rule_ids",
}


@pytest.mark.parametrize("path", FIXTURES, ids=lambda path: path.stem)
def test_fixture_expectations_have_sources_and_typed_profiles(path: Path):
    """Evidence IDs and profile declarations must remain reviewable and valid."""
    fixture = json.loads(path.read_text(encoding="utf-8"))
    assert fixture["schema_version"] == 1
    assert fixture["operation"] == "new_registration"
    assert fixture["evaluation_date"] == "2026-10-12"
    assert fixture["cases"]
    for case in fixture["cases"]:
        assert case["domain"] and case["rationale"]
        source_ids = set(case["source_ids"])
        assert source_ids and source_ids <= SOURCES.keys(), case["id"]
        expected = case["expected"]
        assert expected and expected.keys() <= EXPECTED_FIELDS, case["id"]
        groups = [
            set(expected.get(key, []))
            for key in ["failed_rule_ids", "passed_rule_ids", "absent_rule_ids"]
        ]
        assert not (
            groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2]
        )
        for assertion_id in set.union(*groups):
            assert assertion_id in ASSERTIONS, (case["id"], assertion_id)
            assert ASSERTIONS[assertion_id]["source_id"] in source_ids
        for field, value in case.get("registrant", {}).items():
            assert field in FACTS, (case["id"], field)
            fact = FACTS[field]
            if fact["kind"] == "boolean":
                assert type(value) is bool
            elif fact["kind"] == "string":
                assert isinstance(value, str)
            elif fact["kind"] == "string_set":
                assert isinstance(value, list) and all(
                    isinstance(item, str) for item in value
                )
            else:
                pytest.fail(f"unknown fixture fact kind: {fact['kind']}")
            if fact.get("allowed_values"):
                supplied = value if isinstance(value, list) else [value]
                assert set(supplied) <= set(fact["allowed_values"])
            if fact.get("string_format") == "uppercase_alpha2":
                supplied = value if isinstance(value, list) else [value]
                assert all(
                    len(item) == 2 and all("A" <= char <= "Z" for char in item)
                    for item in supplied
                )


def test_case_ids_are_unique_across_policy_files():
    """A repeated ID must not silently replace an independently reviewed case."""
    ids = [
        case["id"]
        for path in FIXTURES
        for case in json.loads(path.read_text(encoding="utf-8"))["cases"]
    ]
    assert len(ids) == len(set(ids))
