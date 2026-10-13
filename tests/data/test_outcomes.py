"""Saved release comparison uses independent outcomes and never emits facts."""

import copy
import json
from pathlib import Path

import pytest
from scripts.maintenance import outcomes


def row(request="fixture.case", *, release="release-before"):
    """Synthetic compact result with deliberately excluded private/prose fields."""
    return {
        "request_id": request,
        "assessment": {
            "canonical_ascii": "xn--bcher-kva.de",
            "dataset_version": release,
            "evaluation_date": "2026-10-12",
            "inventory_date": "2026-10-12",
            "normalization_profile": "fixture-profile-v1",
            "diagnostics_truncated": False,
            "status": "unknown",
            "name_validity": "unknown",
            "eligibility": "unknown_policy",
            "policy_coverage": "partial",
            "gaps": [],
            "rules": [],
            "registrant": {"private_field": "sensitive-profile-token"},
            "findings": [{"params": {"value": "sensitive-profile-token"}}],
        },
    }


def write(path: Path, rows):
    """Write the interchange format without invoking production projection code."""
    path.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in rows),
        encoding="utf-8",
    )
    return path


def test_changed_semantics_retain_releases_and_exclude_supplied_private_values(
    tmp_path,
):
    """A newly decisive prohibition must retain its evidence and release context."""
    old = row()
    new = row(release="release-after")
    new["assessment"].update(
        status="no",
        name_validity="invalid",
        eligibility="does_not_match",
        policy_coverage="unknown",
    )
    new["assessment"]["gaps"] = [
        {
            "family": "idn",
            "input_class": "idn",
            "knowledge": "unknown",
            "scope": "*.de",
            "evidence_ids": ["fixture.table"],
            "reason": "sensitive-profile-token",
        }
    ]
    new["assessment"]["rules"] = [
        {"effect": "require", "truth": "false", "rule_id": "fixture.required"},
        {"effect": "deny", "truth": "true", "rule_id": "fixture.denied"},
        {"effect": "deny", "truth": "false", "rule_id": "fixture.allowed"},
        {"effect": "require", "truth": "unknown", "rule_id": "fixture.unknown"},
    ]
    report = outcomes.compare(
        write(tmp_path / "old", [old]), write(tmp_path / "new", [new])
    )
    assert report["before_release"]["dataset_version"] == "release-before"
    assert report["after_release"]["dataset_version"] == "release-after"
    assert report["compared_requests"] == report["changed_requests"] == 1
    delta = report["changes"][0]["changes"]
    assert delta["status"] == {"before": "unknown", "after": "no"}
    assert delta["name_validity"]["after"] == "invalid"
    assert delta["eligibility"]["after"] == "does_not_match"
    assert delta["policy_coverage"]["after"] == "unknown"
    assert delta["failed_rule_ids"]["after"] == ["fixture.denied", "fixture.required"]
    assert delta["gaps"]["after"][0]["scope"] == "*.de"
    assert "sensitive-profile-token" not in json.dumps(report)


def test_record_rule_and_evidence_order_and_release_changes_do_not_create_outcome_drift(
    tmp_path,
):
    """Equivalent records compare equally despite serialization and release changes."""
    original = row()
    original["assessment"]["gaps"] = [
        {
            "family": "reserved",
            "input_class": "ascii",
            "knowledge": "partial",
            "scope": "de",
            "evidence_ids": ["fixture.b", "fixture.a"],
        }
    ]
    original["assessment"]["rules"] = [
        {"effect": "require", "truth": "false", "rule_id": "fixture.b"},
        {"effect": "deny", "truth": "true", "rule_id": "fixture.a"},
    ]
    other = copy.deepcopy(original)
    other["request_id"] = "fixture.other"
    newer = copy.deepcopy([other, original])
    for item in newer:
        item["assessment"]["dataset_version"] = "release-after"
        item["assessment"]["rules"].reverse()
        item["assessment"]["gaps"][0]["evidence_ids"].reverse()
    report = outcomes.compare(
        write(tmp_path / "old", [original, other]), write(tmp_path / "new", newer)
    )
    assert report["changed_requests"] == 0


@pytest.mark.parametrize(
    "mutation,error",
    [
        (lambda r: r.update(request_id="different.case"), "request_corpus_mismatch"),
        (
            lambda r: r["assessment"].update(canonical_ascii="another.de"),
            "canonical_identity_mismatch",
        ),
        (lambda r: r["assessment"].update(diagnostics_truncated=True), "truncated"),
        (
            lambda r: r["assessment"].update(status="sensitive-profile-token"),
            "invalid_outcome_enum",
        ),
    ],
)
def test_mismatched_or_incomplete_comparisons_fail_privately(tmp_path, mutation, error):
    """Corpus mismatch and missing diagnostics prevent an apparent stable release."""
    before, after = row(), row(release="release-after")
    mutation(after)
    with pytest.raises(ValueError, match=error) as caught:
        outcomes.compare(
            write(tmp_path / "old", [before]), write(tmp_path / "new", [after])
        )
    assert "sensitive-profile-token" not in str(caught.value)


def test_duplicate_mixed_release_invalid_utf8_and_record_budget_are_rejected(
    tmp_path, monkeypatch
):
    """Reject ambiguity and bounded-input failures before emitting review data."""
    path = tmp_path / "input"
    with pytest.raises(ValueError, match="duplicate_request"):
        outcomes.saved(write(path, [row(), row()]))
    with pytest.raises(ValueError, match="mixed_release"):
        outcomes.saved(write(path, [row(), row("other", release="other-release")]))
    for content in (b"\xff\n", b'{"request_id":"a","request_id":"b"}\n'):
        path.write_bytes(content)
        with pytest.raises(ValueError, match="invalid_saved_json"):
            outcomes.saved(path)
    monkeypatch.setattr(outcomes, "MAX_LINE", 64)
    with pytest.raises(ValueError, match="saved_record_limit"):
        outcomes.saved(write(path, [row()]))
