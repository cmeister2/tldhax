"""Local profile transport, machine output and privacy through the public CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys

from tldhax.cli import main


def test_cli_profile_detailed_json_and_ordered_jsonl(tmp_path, capsys):
    """Global facts are parsed locally once, then omitted from emitted results."""
    marker = "private-cli-value-789456"
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps({"au_trademark_exact_labels": [marker]}), encoding="utf-8"
    )
    assert (
        main(["check", "vanity.au", "--profile", str(profile), "--json", "--details"])
        == 2
    )
    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert payload["detailed"] and payload["canonical_ascii"] == "vanity.au"
    assert marker not in output.out + output.err
    names = tmp_path / "names.jsonl"
    names.write_text(
        '"bücher.de"\n{"domain":"xn--bcher-kva.de"}\n"_bad.com"\n', encoding="utf-8"
    )
    assert main(["batch", str(names)]) == 1
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(rows) == 3 and rows[0]["canonical_ascii"] == rows[1]["canonical_ascii"]
    assert rows[2]["status"] == "no"


def test_cli_profile_errors_do_not_expose_values(tmp_path, capsys):
    """Malformed/duplicate/oversized profiles return stable diagnostics."""
    marker = "private-cli-value-938274"
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"unknown_field": marker}), encoding="utf-8")
    assert main(["check", "vanity.au", "--profile", str(profile)]) == 2
    output = capsys.readouterr()
    assert output.err.strip() == "unknown_profile_field"
    assert marker not in output.out + output.err
    profile.write_text(
        '{"proxy_registration":false,"proxy_registration":true}', encoding="utf-8"
    )
    assert main(["check", "vanity.us", "--profile", str(profile)]) == 2
    assert capsys.readouterr().err.strip() == "invalid_profile_json"
    profile.write_text(" " * 65537, encoding="utf-8")
    assert main(["check", "vanity.us", "--profile", str(profile)]) == 2
    assert capsys.readouterr().err.strip() == "profile_input_limit"


def test_cli_inventory_info_and_release_statistics(capsys):
    """Info remains useful for known roots whose registration policy is unknown."""
    assert main(["info", "aaa", "--json"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["namespace"] == "aaa" and info["policy"] is None
    assert main(["stats", "--json"]) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["dataset"]["dataset_version"] == info["dataset_version"]


def test_cli_utf8_argv_stdin_and_stdout_ignore_ascii_locale():
    """Unicode identity and JSONL remain UTF-8 with Python's UTF8 mode off."""
    environment = dict(os.environ)
    environment.update(LC_ALL="C", PYTHONUTF8="0", PYTHONCOERCECLOCALE="0")
    for arguments, input_text in [
        (["check", "ß.com", "--json"], None),
        (["check", "xn--zca.com", "--json"], None),
        (["batch", "-"], '"ß.com"\n'),
    ]:
        process = subprocess.run(
            [sys.executable, "-m", "tldhax.cli", *arguments],
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=environment,
            check=False,
        )
        assert process.returncode == 1 and not process.stderr
        payload = json.loads(process.stdout)
        assert payload["canonical_unicode"] == "ß.com"
        assert payload["canonical_ascii"] == "xn--zca.com"
        assert payload["name_validity"] == "invalid" and payload["status"] == "no"
