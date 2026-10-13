"""Independent freshness and drift cases; no live requests or policy approvals."""

import hashlib
import http.client
import json
import urllib.error
from pathlib import Path

import pytest
from scripts.data.reconcile import reconcile, verify
from scripts.maintenance import refresh
from scripts.maintenance.report import date, freshness


def evidence(tree: Path) -> None:
    """Author two representation types and a documented future boundary."""
    directory = tree / "evidence"
    directory.mkdir()
    directory.joinpath("sources.toml").write_text(
        '[[sources]]\nid="fixture.bytes"\nurl="https://registry.example/policy"\n'
        f'sha256="{hashlib.sha256(b"original").hexdigest()}"\n'
        'retrieved_on="2026-10-12"\nversion="fixture-v1"\n'
        '[[sources]]\nid="fixture.extracted"\nurl="https://registry.example/pdf"\n'
        f'sha256="{"a" * 64}"\nhash_representation="extracted_text/v1"\n'
        'retrieved_on="2026-10-12"\nversion="extracted-fixture"\n',
        encoding="utf-8",
    )
    directory.joinpath("assertions.toml").write_text(
        '[[assertions]]\nid="fixture.transition"\nreview_due="2027-01-10"\n'
        'effective_from="2027-02-09"\n',
        encoding="utf-8",
    )


def test_freshness_surfaces_deadlines_without_activating_future_policy(
    tree: Path,
) -> None:
    """Report deadlines while keeping the published evaluation reproducible."""
    reconcile(tree, "2026-10-12", "2026-10-12")
    evidence(tree)
    before = (tree / "data/manifest.json").read_bytes()
    report = freshness(tree, "2027-02-09")
    assert report["pinned_evaluation_date"] == "2026-10-12"
    assert report["inventory_dataset_version"] == verify(tree)["dataset_version"]
    assert "dataset_version" not in report
    assert report["dataset_age_days"] == 120
    assert {t["reason"] for t in report["review_tasks"]} == {
        "review_expired",
        "effective_from_reached",
    }
    assert all(s["check_due"] for s in report["sources"])
    assert (tree / "data/manifest.json").read_bytes() == before
    assert verify(tree)["evaluation_date"] == "2026-10-12"


def test_same_date_is_fresh_and_future_clock_queries_fail(tree: Path) -> None:
    """Reject impossible freshness dates and preserve the pinned boundary."""
    reconcile(tree, "2026-10-12", "2026-10-12")
    assert not any(s["check_due"] for s in freshness(tree, "2026-10-12")["sources"])
    with pytest.raises(ValueError):
        freshness(tree, "2026-10-11")
    for value in ("20261012", "2026-02-29", "2026-1-01"):
        with pytest.raises(ValueError):
            date(value)


def test_content_changes_require_review_and_extraction_hashes_are_not_compared(
    tree: Path, monkeypatch
) -> None:
    """Distinguish changed bytes from incomparable extraction fingerprints."""
    evidence(tree)
    called = []

    def observed(url: str) -> bytes:
        called.append(url)
        return b"changed"

    monkeypatch.setattr(refresh, "download", observed)
    result = refresh.policies(tree, "2026-10-12")
    assert [r["status"] for r in result] == [
        "changed_review_required",
        "manual_representation_check_required",
    ]
    assert called == ["https://registry.example/policy"]
    assert "observed_sha256" not in result[1]


def test_unreachable_publisher_is_a_gap_instead_of_unchanged(
    tree: Path, monkeypatch
) -> None:
    """An HTTP denial provides no evidence that source bytes are unchanged."""
    evidence(tree)

    def rejected(url: str) -> bytes:
        raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

    monkeypatch.setattr(refresh, "download", rejected)
    result = refresh.policies(tree, "2026-10-12")
    assert result[0]["status"] == "inaccessible"
    assert result[0]["http_status"] == 403


def test_truncated_http_body_is_a_check_gap(tree: Path, monkeypatch) -> None:
    """A transport framing failure cannot abort unrelated source observations."""
    evidence(tree)

    def truncated(_url: str) -> bytes:
        raise http.client.IncompleteRead(b"prefix", 10)

    monkeypatch.setattr(refresh, "download", truncated)
    result = refresh.policies(tree, "2026-10-12")
    assert result[0]["status"] == "check_failed"
    assert result[1]["status"] == "manual_representation_check_required"


def test_refresh_staging_does_not_advance_evaluation_or_modify_pinned_tree(
    tree: Path, monkeypatch, tmp_path: Path
) -> None:
    """Refresh into staging without activating newly published policies."""
    reconcile(tree, "2026-10-12", "2026-10-12")
    before = (tree / "data/manifest.json").read_bytes()
    destination = tmp_path / "candidate"

    def fake_fetch(path: Path, evaluation_date: str, retrieved_on: str) -> None:
        assert evaluation_date == "2026-10-12"
        assert retrieved_on == "2026-10-20"
        import shutil

        shutil.copytree(tree / "data", path / "data")
        record = json.loads((path / "data/manifest.json").read_text(encoding="utf-8"))
        assert record["evaluation_date"] == evaluation_date

    monkeypatch.setattr(refresh, "fetch", fake_fetch)
    result = refresh.inventory(tree, destination, "2026-10-20")
    assert result["approval_status"] == "review_required"
    assert (tree / "data/manifest.json").read_bytes() == before
