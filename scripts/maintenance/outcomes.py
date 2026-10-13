"""Compare bounded saved release assessments; never evaluate or publish policy.

Each JSONL row is {"request_id": "stable-fixture-id", "assessment": result.to_dict()}.
IDs identify the same candidate/profile scenario in both files; no profiles belong
in this interchange format. Only selected value-free semantic fields are reported.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_ROWS = 10_000
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,511}")
ENUMS = {
    "status": {"yes", "no", "restricted", "unknown"},
    "name_validity": {"valid", "invalid", "unknown"},
    "eligibility": {
        "not_required",
        "needs_profile",
        "declared_match",
        "does_not_match",
        "unknown_policy",
    },
    "policy_coverage": {"complete", "partial", "unknown", "conflicting"},
    "family": {
        "namespace",
        "length",
        "characters",
        "idn",
        "reserved",
        "allocation",
        "eligibility",
        "access",
    },
    "input_class": {"ascii", "idn", "any"},
    "knowledge": {"reviewed", "not_applicable", "partial", "unknown", "conflicting"},
    "effect": {"require", "deny", "context"},
    "truth": {"true", "false", "unknown"},
}
RELEASE_FIELDS = (
    "dataset_version",
    "evaluation_date",
    "inventory_date",
    "normalization_profile",
)


def identifier(value: object, *, limit: int = 512) -> str:
    """Accept bounded machine identities, without echoing rejected input."""
    if (
        not isinstance(value, str)
        or len(value) > limit
        or not IDENTIFIER.fullmatch(value)
    ):
        raise ValueError("invalid_identifier")
    return value


def enumeration(row: dict, field: str) -> str:
    """Require documented result vocabulary rather than arbitrary supplied prose."""
    value = row.get(field)
    if not isinstance(value, str) or value not in ENUMS[field]:
        raise ValueError("invalid_outcome_enum")
    return value


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate JSON keys before any outcome is selected."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def semantic(assessment: dict) -> dict:
    """Keep outcomes and machine evidence IDs; discard prose, params and facts."""
    if assessment.get("diagnostics_truncated") is not False:
        raise ValueError("truncated_or_incomplete_assessment")
    result: dict = {
        field: enumeration(assessment, field)
        for field in ("status", "name_validity", "eligibility", "policy_coverage")
    }
    gaps, rules = assessment.get("gaps"), assessment.get("rules")
    if (
        not isinstance(gaps, list)
        or len(gaps) > 8
        or not isinstance(rules, list)
        or len(rules) > 128
    ):
        raise ValueError("invalid_assessment_collections")
    normalized = []
    for gap in gaps:
        if not isinstance(gap, dict):
            raise ValueError("invalid_gap")
        evidence = gap.get("evidence_ids")
        if not isinstance(evidence, list) or len(evidence) > 128:
            raise ValueError("invalid_gap_evidence")
        normalized.append(
            {
                **{
                    key: enumeration(gap, key)
                    for key in ("family", "input_class", "knowledge")
                },
                "scope": scope(gap.get("scope")),
                "evidence_ids": sorted({identifier(value) for value in evidence}),
            }
        )
    result["gaps"] = sorted(normalized, key=lambda gap: json.dumps(gap, sort_keys=True))
    failed = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("invalid_rule")
        effect, truth = enumeration(rule, "effect"), enumeration(rule, "truth")
        rule_id = identifier(rule.get("rule_id"))
        if (effect, truth) in {("require", "false"), ("deny", "true")}:
            failed.add(rule_id)
    result["failed_rule_ids"] = sorted(failed)
    return result


def scope(value: object) -> str:
    """Preserve literal wildcard namespace keys alongside ordinary machine scopes."""
    if isinstance(value, str) and value.startswith("*."):
        return "*." + identifier(value[2:])
    return identifier(value)


def saved(path: Path) -> tuple[dict, dict]:
    """Read finite UTF-8 JSONL while validating identity and release consistency."""
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("saved_file_limit")
    rows: dict[str, dict] = {}
    release: dict | None = None
    total = 0
    with path.open("rb") as stream:
        while line := stream.readline(MAX_LINE + 1):
            total += len(line)
            if total > MAX_BYTES or len(line) > MAX_LINE or len(rows) >= MAX_ROWS:
                raise ValueError("saved_record_limit")
            try:
                row = json.loads(line.decode("utf-8"), object_pairs_hook=unique_object)
            except (UnicodeError, ValueError, RecursionError) as exc:
                raise ValueError("invalid_saved_json") from exc
            if not isinstance(row, dict) or set(row) != {"request_id", "assessment"}:
                raise ValueError("invalid_saved_record")
            request = identifier(row["request_id"], limit=128)
            if request in rows:
                raise ValueError("duplicate_request_id")
            assessment = row["assessment"]
            if not isinstance(assessment, dict):
                raise ValueError("invalid_assessment")
            if "canonical_ascii" not in assessment:
                raise ValueError("missing_canonical_identity")
            identity = assessment.get("canonical_ascii")
            if identity is not None and (
                not isinstance(identity, str)
                or len(identity) > 253
                or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", identity)
            ):
                raise ValueError("invalid_canonical_identity")
            current = {
                field: identifier(assessment.get(field)) for field in RELEASE_FIELDS
            }
            if release is not None and current != release:
                raise ValueError("mixed_release_input")
            release = current
            rows[request] = {"canonical_ascii": identity, **semantic(assessment)}
    if not rows:
        raise ValueError("empty_saved_assessments")
    assert release is not None
    return release, rows


def compare(before: Path, after: Path) -> dict:
    """Compare the same request corpus, retaining both pinned release identities."""
    old_release, old = saved(before)
    new_release, new = saved(after)
    if old.keys() != new.keys():
        raise ValueError("request_corpus_mismatch")
    changes = []
    for request in sorted(old):
        previous, current = old[request], new[request]
        if previous["canonical_ascii"] != current["canonical_ascii"]:
            raise ValueError("canonical_identity_mismatch")
        delta = {
            field: {"before": previous[field], "after": current[field]}
            for field in previous
            if previous[field] != current[field]
        }
        if delta:
            changes.append(
                {
                    "request_id": request,
                    "canonical_ascii": current["canonical_ascii"],
                    "changes": delta,
                }
            )
    return {
        "schema_version": 1,
        "before_release": old_release,
        "after_release": new_release,
        "compared_requests": len(old),
        "changed_requests": len(changes),
        "changes": changes,
        "approval_status": "review_required",
    }


def main() -> int:
    """Write a review report with stable, value-free validation diagnostics."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = compare(args.before, args.after)
        encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if args.report:
            args.report.write_bytes(encoded)
        else:
            sys.stdout.buffer.write(encoded)
    except (ValueError, OSError):
        print("Saved outcome comparison failed validation", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
