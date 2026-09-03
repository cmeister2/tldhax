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


def test_assess_json_output_and_indeterminate_exit_code() -> None:
    """JSON contains every independent axis and uses verdict exit semantics."""
    result = run_cli("assess", "ordinary-candidate.com", "--json")
    payload = json.loads(result.stdout)

    assert result.returncode == 2
    assert payload["verdict"] == "indeterminate"
    assert payload["public_suffix"] == "com"
    assert payload["root_state"] == "delegated"
    assert payload["namespace_state"] == "ordinary"
    assert payload["suffix_evidence"]
    assert payload["root_state_evidence"]
    assert payload["namespace_state_evidence"]
    assert payload["public_access_status"] == "unknown"
    assert payload["public_access_evidence"] == []
    assert payload["application_channel_evidence"] == []
    assert payload["findings"]


def test_assess_impossible_exit_code() -> None:
    """Verified hard failures exit with status one."""
    result = run_cli("assess", "example.arpa", "--quiet")

    assert result.returncode == 1
    assert result.stdout.strip() == "IMPOSSIBLE"


def test_assess_accepts_repeatable_eligibility_facts() -> None:
    """Requirement IDs flow from CLI options into typed eligibility evaluation."""
    result = run_cli(
        "assess",
        "candidate.bank",
        "--satisfied",
        "bank-regulated-entity",
        "--json",
    )
    payload = json.loads(result.stdout)

    assert result.returncode == 2
    assert payload["eligibility"] == "satisfied"
    assert payload["public_access"] == "conditional"
    assert payload["eligibility_requirements"][0]["outcome"] == "satisfied"


def test_assess_reports_unknown_eligibility_ids() -> None:
    """CLI callers see typos without changing missing-context semantics."""
    result = run_cli(
        "assess",
        "candidate.bank",
        "--satisfied",
        "definitely-a-typo",
        "--json",
    )
    payload = json.loads(result.stdout)

    assert result.returncode == 2
    assert payload["eligibility"] == "required"
    assert "unknown_eligibility_requirement" in {
        finding["code"] for finding in payload["findings"]
    }


def test_suffix_info_output() -> None:
    """The suffix-info command prints topology and product independently."""
    result = run_cli("suffix-info", "de", "--json")
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert payload["canonical_suffix"] == "de"
    assert payload["product_id"] == "de-direct"
    assert payload["public_access"] == "open"
    assert payload["suffix_evidence"]
    assert payload["root_state_evidence"]
    assert payload["namespace_state_evidence"]
    assert payload["offering_state_evidence"] == ["denic-public-applicants"]
    assert payload["public_access_evidence"] == ["denic-public-applicants"]


def test_evidence_output() -> None:
    """Evidence identifiers can be audited from the CLI."""
    result = run_cli("evidence", "denic-public-applicants", "--json")
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert payload["id"] == "denic-public-applicants"
    assert payload["kind"] == "registry_policy"
    assert payload["review_after"] == "2027-03-02"


def test_unknown_evidence_exit_code() -> None:
    """Missing evidence is an indeterminate lookup, not a false record."""
    result = run_cli("evidence", "does-not-exist")

    assert result.returncode == 2
    assert result.stdout == ""
    assert "No evidence record" in result.stderr


def test_unknown_evidence_json_is_a_stable_error_object() -> None:
    """JSON consumers never receive a human-only lookup failure."""
    result = run_cli("evidence", "does-not-exist", "--json")
    payload = json.loads(result.stdout)

    assert result.returncode == 2
    assert result.stderr == ""
    assert payload == {
        "error": {
            "code": "evidence_not_found",
            "evidence_id": "does-not-exist",
            "message": "No evidence record with id 'does-not-exist'",
        }
    }


def test_invalid_suffix_json_is_a_stable_error_object() -> None:
    """Invalid suffix lookups retain JSON framing and a nonzero status."""
    result = run_cli("suffix-info", "bad..suffix", "--json")
    payload = json.loads(result.stdout)

    assert result.returncode == 2
    assert result.stderr == ""
    assert payload == {
        "error": {
            "code": "suffix_not_found",
            "message": "No namespace data available for suffix 'bad..suffix'",
            "suffix": "bad..suffix",
        }
    }


def test_invalid_suffix_human_error_uses_stderr() -> None:
    """Human lookup failures leave stdout available for successful data."""
    result = run_cli("suffix-info", "bad..suffix")

    assert result.returncode == 2
    assert result.stdout == ""
    assert "No namespace data available" in result.stderr


def test_stats_output() -> None:
    """Stats report per-dimension evidence quality rather than fake coverage."""
    result = run_cli("stats", "--json")
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert set(payload["roots"]) == {"current", "special_use", "absent", "unresolved"}
    assert payload["roots"]["current"] > 0
    assert set(payload["topology"]) == {"icann", "private"}
    assert payload["topology"]["icann"] > 0
    assert payload["products"] > 0
    assert set(payload["selectors"]) == {"exact", "one_label_below"}
    assert set(payload["public_access"]) == {
        "by_product",
        "by_selector",
    }
    assert set(payload["public_access"]["by_product"]) == {
        "verified",
        "unknown",
        "stale",
        "conflicting",
    }
    assert "idn_policy" in payload
    assert "reserved_labels" in payload
    assert "suffix_rules" not in payload
    assert "unsupported_verdicts" not in payload
