"""Offline entry-point contracts and explicit source-update dates."""

from pathlib import Path

import pytest
from scripts.data.__main__ import main
from scripts.data.reconcile import reconcile
from scripts.data.sources import SOURCES


def test_verify_and_reconcile_work_offline(monkeypatch, tree: Path, capsys) -> None:
    """Existing snapshots can be regenerated and checked without credentials."""
    reconcile(tree, "2026-10-12", "2026-10-12")
    for action in ("--reconcile", "--verify"):
        monkeypatch.setattr("sys.argv", ["inventory", action, "--root", str(tree)])
        assert main() == 0
    assert "Verified 2026-10-12+" in capsys.readouterr().out


@pytest.mark.parametrize("action", ["--reconcile", "--fetch"])
def test_new_dataset_needs_both_dates(monkeypatch, tree: Path, action: str) -> None:
    """Evaluation dates cannot silently become fresh retrieval claims."""
    argv = ["inventory", action]
    if action == "--fetch":
        argv.append(str(tree / "next"))
    argv += ["--root", str(tree), "--evaluation-date", "2026-10-12"]
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2


def test_changed_source_requires_retrieval_date(monkeypatch, tree: Path) -> None:
    """A retained evaluation date does not misdate a new source fetch."""
    reconcile(tree, "2026-10-12", "2026-10-12")
    path = tree / SOURCES["iana.active-roots"][0]
    path.write_text(path.read_text().replace("fixture UTC", "changed UTC"))
    monkeypatch.setattr("sys.argv", ["inventory", "--reconcile", "--root", str(tree)])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
