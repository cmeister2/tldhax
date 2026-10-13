"""CLI decisions, direct explanations, local profiles and ordered JSONL output."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tldhax.cli import main


def test_human_denial_explains_the_actual_failed_rule(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Default output must give the useful why without a details flag."""
    assert main(["check", "a.au"]) == 1
    output = capsys.readouterr()
    assert "a.au: NO" in output.out
    assert "2" in output.out and "1" in output.out
    assert "evidence" not in output.out.lower()
    assert not output.err


def test_json_single_decision_and_quiet_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """JSON is compact and quiet mode preserves the three public decisions."""
    assert main(["assess", "sunflower.com", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "yes"
    assert payload["canonical_domain"] == "sunflower.com"
    assert set(payload) == {
        "decision",
        "canonical_domain",
        "namespace",
        "reasons",
        "missing_profile_fields",
    }
    assert main(["check", "sunflower.aaa", "--quiet"]) == 2
    assert capsys.readouterr().out == "UNKNOWN\n"


def test_local_profile_and_batch_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A prepared local profile is shared by ordered batch results."""
    profile = tmp_path / "profile.json"
    profile.write_text('{"de_contract_capacity":true}', encoding="utf-8")
    assert main(["assess", "bücher.de", "--profile", str(profile), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "yes"
    names = tmp_path / "names.jsonl"
    names.write_text(
        '"bücher.de"\n{"domain":"xn--bcher-kva.de"}\n"_bad.com"\n', encoding="utf-8"
    )
    assert main(["batch", str(names), "--profile", str(profile)]) == 1
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(rows) == 3 and rows[0] == rows[1]
    assert [row["decision"] for row in rows] == ["yes", "yes", "no"]
    assert main(["batch", str(names), "--profile", str(profile), "--json"]) == 1
    assert json.loads(capsys.readouterr().out) == rows


def test_missing_profile_is_unknown_and_names_needed_facts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The default interface explains an incomplete applicant declaration."""
    assert main(["check", "vanity.me.uk"]) == 2
    output = capsys.readouterr().out
    assert "vanity.me.uk: UNKNOWN" in output
    assert "entity_kind" in output and "organizational_proxy" in output


def test_profile_input_errors_are_value_free(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Invalid local declarations produce input errors without revealing values."""
    marker = "private-profile-value-341739"
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"unsupported_field": marker}), encoding="utf-8")
    assert main(["check", "sunflower.com", "--profile", str(path)]) == 2
    output = capsys.readouterr()
    assert output.err == "unknown_profile_field\n"
    assert marker not in output.out + output.err
    path.write_text(
        '{"proxy_registration":false,"proxy_registration":true}', encoding="utf-8"
    )
    assert main(["check", "sunflower.com", "--profile", str(path)]) == 2
    assert capsys.readouterr().err == "invalid_profile_json\n"


def test_invalid_jsonl_record_and_candidate_input_limit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Batch structure and implementation budgets produce explicit input errors."""
    path = tmp_path / "input.jsonl"
    path.write_text('{"domain":"sunflower.com","domain":"other.com"}', encoding="utf-8")
    assert main(["batch", str(path)]) == 2
    assert capsys.readouterr().err == "duplicate_input_field\n"
    assert main(["assess", "a" * 4097]) == 2
    assert capsys.readouterr().err == "input_limit\n"


def test_small_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    """Original metadata fields remain available without invented defaults."""
    assert main(["info", ".COM", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tld"] == "com"
    assert payload["min_length"] is None
    assert payload["max_length"] is None
    assert "assess" in payload["note"]
    assert main(["info", "aaa", "--json"]) == 2
    assert "No data available" in capsys.readouterr().out
    assert main(["stats", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == {
        "compiled_rules",
        "total_known_suffixes",
        "registerable",
        "not_registerable",
        "restricted",
        "coverage_percent",
    }
    assert payload["compiled_rules"] > 0


def test_utf8_argv_and_jsonl_ignore_ascii_process_locale() -> None:
    """CLI stream behavior keeps Unicode candidates usable under ASCII locales."""
    environment = {
        **os.environ,
        "LC_ALL": "C",
        "PYTHONUTF8": "0",
        "PYTHONCOERCECLOCALE": "0",
    }
    for args, input_data in [
        (["assess", "faß.com", "--json"], None),
        (["batch", "--json"], '"faß.com"\n'.encode()),
    ]:
        process = subprocess.run(
            [sys.executable, "-m", "tldhax.cli", *args],
            input=input_data,
            capture_output=True,
            env=environment,
            check=False,
        )
        assert process.returncode == 1, process.stderr
        payload = json.loads(process.stdout.decode("utf-8"))
        if isinstance(payload, list):
            payload = payload[0]
        assert payload["decision"] == "no"
        assert payload["canonical_domain"] == "xn--fa-hia.com"


def test_original_check_json_contract(capsys: pytest.CaptureFixture[str]) -> None:
    """Existing scripts retain domain/status/reason-string output."""
    assert main(["check", "faß.com", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == {"domain", "status", "reasons"}
    assert payload["domain"] == "faß.com"
    assert payload["status"] == "no"
    assert payload["reasons"] and all(
        isinstance(reason, str) for reason in payload["reasons"]
    )
