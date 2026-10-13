"""Command-line configuration checks without credentials or network access."""

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "tools/registrar_oracle.py"


def test_help_and_no_implicit_env_file(tmp_path):
    """The developer tool documents explicit environment choice and credential loading."""
    help_result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_result.returncode == 0 and "--env-file" in help_result.stdout
    (tmp_path / ".env").write_text(
        "NAMECOM_USERNAME=private\nNAMECOM_API_TOKEN=secret\n"
    )
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--environment",
            "production",
            "--name",
            "a.com",
            "--dataset-version",
            "v1",
            "--store",
            str(tmp_path / "observations.sqlite"),
        ],
        cwd=tmp_path,
        env={},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (
        result.returncode == 2
        and "secret" not in result.stderr
        and "private" not in result.stderr
    )
    assert not (tmp_path / "observations.sqlite").exists()
