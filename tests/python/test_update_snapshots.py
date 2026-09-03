"""Regression tests for authored-policy freshness dependency discovery."""

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools import update_snapshots  # noqa: E402


def test_freshness_dependencies_follow_inheritance_and_claim_status() -> None:
    """Inherited verified claims stay active while stale overrides become history."""
    profiles: list[dict[str, Any]] = [
        {
            "id": "base",
            "public_access": {
                "value": "conditional",
                "evidence": ["access-evidence"],
            },
            "eligibility": {
                "mode": "all",
                "requirements": [
                    {"id": "member", "evidence": ["eligibility-evidence"]}
                ],
            },
        },
        {"id": "inherited", "extends": "base"},
        {
            "id": "historical",
            "extends": "base",
            "public_access": {
                "status": "stale",
                "value": "conditional",
                "evidence": ["historical-evidence"],
            },
        },
    ]

    required = update_snapshots._required_current_evidence(
        update_snapshots._flatten_policy_profiles(profiles)
    )

    assert required["access-evidence"] == {
        "base.public_access",
        "inherited.public_access",
    }
    assert required["eligibility-evidence"] == {
        "base.eligibility",
        "inherited.eligibility",
    }
    assert "historical-evidence" not in required


def test_freshness_dependencies_include_active_label_subclaims() -> None:
    """Every evaluator-active label subclaim contributes freshness edges."""
    profiles: list[dict[str, Any]] = [
        {
            "id": "labels",
            "label_policy": {
                "completeness": "stale",
                "completeness_evidence": ["historical-audit"],
                "length": {"evidence": ["length-evidence"]},
                "idn_support": {
                    "value": "supported",
                    "evidence": ["idn-support-evidence"],
                },
                "idn_profile": {"evidence": ["idn-profile-evidence"]},
                "reserved_status": "verified",
                "reserved_set_evidence": ["reserved-set-evidence"],
                "reserved_labels": [
                    {"label": "blocked", "evidence": ["reserved-label-evidence"]}
                ],
            },
        }
    ]

    required = update_snapshots._required_current_evidence(profiles)

    assert "historical-audit" not in required
    assert set(required) == {
        "length-evidence",
        "idn-support-evidence",
        "idn-profile-evidence",
        "reserved-set-evidence",
        "reserved-label-evidence",
    }


def test_release_check_allows_expired_history_but_rejects_active_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An expired source is legal history until a verified claim depends on it."""
    sources_path = tmp_path / "sources.toml"
    profiles_path = tmp_path / "profiles.toml"
    sources_path.write_text(
        """
[[sources]]
id = "old-source"
retrieved_at = "2025-01-01T00:00:00Z"
review_after = "2025-06-01"

[[evidence]]
id = "old-evidence"
source = "old-source"
""",
        encoding="utf-8",
    )
    profiles_path.write_text(
        """
[[profiles]]
id = "historical"
public_access = { status = "stale", value = "open", evidence = ["old-evidence"] }
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(update_snapshots, "POLICY_SOURCES_PATH", sources_path)
    monkeypatch.setattr(update_snapshots, "POLICY_PROFILES_PATH", profiles_path)
    catalog_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    release_time = datetime(2026, 2, 1, tzinfo=timezone.utc)

    update_snapshots._check_policy_source_freshness(catalog_time, release_time)

    profiles_path.write_text(
        """
[[profiles]]
id = "active"
public_access = { value = "open", evidence = ["old-evidence"] }
""",
        encoding="utf-8",
    )
    with pytest.raises(update_snapshots.SnapshotError, match="active.public_access"):
        update_snapshots._check_policy_source_freshness(catalog_time, release_time)
