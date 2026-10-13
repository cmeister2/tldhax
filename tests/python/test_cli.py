"""CLI integration tests for the Python entrypoint."""

from __future__ import annotations

import json
import subprocess
import sys


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the CLI module in a subprocess and capture its output."""
    return subprocess.run(
        [sys.executable, "-m", "tldhax.cli", *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_check_json_output() -> None:
    """The check command should emit machine-readable JSON when requested."""
    result = run_cli("check", "za.sk", "--json")
    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "unknown"


def test_info_output() -> None:
    """The old info command cannot invent a complete legacy policy summary."""
    result = run_cli("info", "co.uk")
    assert result.returncode == 2
    assert "No data available" in result.stdout


def test_stats_output() -> None:
    """The stats command should print aggregate registry statistics."""
    result = run_cli("stats")
    assert result.returncode == 0
    assert "Coverage: 0.0%" in result.stdout
