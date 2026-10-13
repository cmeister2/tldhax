"""Inventory importer and reconciliation regression tests."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from scripts.data.reconcile import (
    changes,
    dataset_version,
    derive,
    encode,
    reconcile,
    verify,
)
from scripts.data.sources import SOURCES


def test_reconcile_is_byte_idempotent_and_never_approves_policy(tree: Path) -> None:
    """Reconcile is byte idempotent and never approves policy."""
    first = reconcile(tree, "2026-10-12", "2026-10-12")
    paths = [
        tree / "data/manifest.json",
        *[tree / row["path"] for row in first["outputs"]],
    ]
    before = [path.read_bytes() for path in paths]
    second = reconcile(tree, "2026-10-12", "2026-10-13")
    assert first == second
    assert before == [path.read_bytes() for path in paths]
    assert verify(tree) == first
    roots = json.loads((tree / "data/root/inventory.json").read_text())["roots"]
    assert [x["tld"] for x in roots] == ["ck", "com", "uk"]
    assert all(x["active"] and x["policy_state"] == "unknown" for x in roots)
    queue = json.loads((tree / "data/research-queue.json").read_text())
    selectors = {
        x["selector"] for group in queue["groups"] for x in group["namespaces"]
    }
    assert "*.ck" in selectors and "co.uk" in selectors
    assert "blogspot.com" not in selectors and "!www.ck" not in selectors


@pytest.mark.parametrize(
    "artifact", ["data/root/tlds-alpha-by-domain.txt", "data/root/inventory.json"]
)
def test_integrity_detects_changed_bytes(tree: Path, artifact: str) -> None:
    """Integrity detects changed bytes."""
    reconcile(tree, "2026-10-12", "2026-10-12")
    path = tree / artifact
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        verify(tree)


def test_missing_or_duplicate_manifest_reference_is_rejected(tree: Path) -> None:
    """Missing or duplicate manifest reference is rejected."""
    record = reconcile(tree, "2026-10-12", "2026-10-12")
    record["inputs"].append(record["inputs"][0])
    (tree / "data/manifest.json").write_bytes(encode(record))
    with pytest.raises(ValueError, match="duplicate"):
        verify(tree)


def test_cross_source_special_scope_disagreement(tree: Path) -> None:
    """Cross source special scope disagreement."""
    path = tree / SOURCES["iana.special-use.csv"][0]
    path.write_text(path.read_text().replace("onion.", "other."))
    with pytest.raises(ValueError, match="disagree"):
        derive(tree)


def test_reconciliation_reports_lifecycle_operator_and_spec13_changes(
    tree: Path, tmp_path_factory
) -> None:
    """Reconciliation reports lifecycle operator and spec13 changes."""
    reconcile(tree, "2026-10-12", "2026-10-12")
    previous = tmp_path_factory.mktemp("previous")
    shutil.copytree(tree, previous, dirs_exist_ok=True)
    root_path = tree / SOURCES["iana.active-roots"][0]
    root_path.write_text(root_path.read_text().replace("CK\n", ""))
    database_path = tree / SOURCES["iana.root-database"][0]
    database_path.write_text(
        database_path.read_text().replace("COM registry", "New COM registry")
    )
    metadata_path = tree / SOURCES["icann.gtlds"][0]
    metadata_path.write_text(
        metadata_path.read_text().replace(
            '"specification13":false', '"specification13":true'
        )
    )
    root_path.write_text(root_path.read_text() + "NEW\n")
    database_path.write_text(
        database_path.read_text().replace(
            "</table>",
            '<tr><td><a href="/domains/root/db/new.html">.new</a></td><td>generic</td><td>New registry</td></tr></table>',
        )
    )
    reconcile(tree, "2026-10-12", "2026-10-13")
    report = changes(previous, tree)
    assert report["roots_added"] == ["new"]
    assert report["roots_withdrawn"] == ["ck"]
    assert report["root_metadata_changes"] == [
        {
            "tld": "com",
            "changes": {
                "operator": {"before": "COM registry", "after": "New COM registry"},
                "specification13": {"before": False, "after": True},
            },
        }
    ]
    assert report["rules"] == {"added": [], "removed": [], "changed": []}
    assert encode(report) == encode(changes(previous, tree))


def test_same_snapshot_diff_is_empty(tree: Path) -> None:
    """Same snapshot diff is empty."""
    reconcile(tree, "2026-10-12", "2026-10-12")
    report = changes(tree, tree)
    assert report["before"] == report["after"]
    assert (
        report["roots_added"]
        == report["roots_withdrawn"]
        == report["root_metadata_changes"]
        == []
    )


@pytest.mark.parametrize(
    "value", ["20261012", "2026-99-99", "2026-10-12T00:00:00Z", None]
)
def test_invalid_release_dates_are_rejected(value) -> None:
    """Strict release date spelling behaves identically on Python 3.10+."""
    with pytest.raises(ValueError):
        dataset_version(value, [])


def test_utf8_inventory_diff_is_locale_independent(tree: Path) -> None:
    """UTF-8 publisher names remain readable under an ASCII process locale."""
    path = tree / SOURCES["iana.root-database"][0]
    path.write_text(
        path.read_text(encoding="utf-8").replace("COM registry", "München registry"),
        encoding="utf-8",
    )
    reconcile(tree, "2026-10-12", "2026-10-12")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; import sys; "
            "from scripts.data.reconcile import changes; "
            "assert changes(Path(sys.argv[1]), Path(sys.argv[1]))['roots_added'] == []",
            str(tree),
        ],
        cwd=Path(__file__).resolve().parents[2],
        env={
            **os.environ,
            "LC_ALL": "C",
            "PYTHONCOERCECLOCALE": "0",
            "PYTHONUTF8": "0",
        },
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
