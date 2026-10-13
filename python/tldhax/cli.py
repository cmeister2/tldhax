"""Bounded offline CLI with optional local declared-profile input."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from . import Registry
from .registry import MAX_BATCH, MAX_PROFILE_BYTES


def build_parser() -> argparse.ArgumentParser:
    """Build profile, JSON/JSONL and opt-in evidence presentation options."""
    parser = argparse.ArgumentParser(prog="tldhax")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ["check", "batch"]:
        child = commands.add_parser(name)
        if name == "check":
            child.add_argument("domain")
        else:
            child.add_argument(
                "input", nargs="?", default="-", help="JSONL file or stdin"
            )
        child.add_argument("--profile", type=Path, help="local JSON registrant profile")
        child.add_argument("--json", action="store_true", dest="as_json")
        child.add_argument("--quiet", action="store_true")
        child.add_argument("--details", action="store_true")
        child.add_argument("--include-private", action="store_true")
    info = commands.add_parser("info")
    info.add_argument("namespace")
    info.add_argument("--json", action="store_true", dest="as_json")
    stats = commands.add_parser("stats")
    stats.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _profile(registry: Registry, path: Path | None) -> Any:
    """Bound local file reads and preserve native duplicate-key detection."""
    if path is None:
        return None
    with path.open("rb") as stream:
        content = stream.read(MAX_PROFILE_BYTES + 1)
    if len(content) > MAX_PROFILE_BYTES:
        raise ValueError("profile_input_limit")
    return registry.prepare_registrant_json(content.decode("utf-8"))


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate record keys without exposing supplied values."""
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate_input_field")
        result[key] = value
    return result


def _names(stream: TextIO) -> list[str]:
    """Read up to 10,000 bounded JSON strings or {domain: string} records."""
    names: list[str] = []
    while True:
        line = stream.readline(MAX_PROFILE_BYTES + 1)
        if not line:
            return names
        if len(line) > MAX_PROFILE_BYTES:
            raise ValueError("input_line_limit")
        if not line.strip():
            continue
        if len(names) >= MAX_BATCH:
            raise ValueError("batch_input_limit")
        try:
            value = json.loads(line, object_pairs_hook=_pairs)
        except json.JSONDecodeError:
            raise ValueError("invalid_jsonl") from None
        if isinstance(value, dict) and value.keys() == {"domain"}:
            value = value["domain"]
        if not isinstance(value, str):
            raise ValueError("invalid_candidate_record")
        names.append(value)


def _exit(statuses: list[str]) -> int:
    """Known denial takes precedence; incomplete and restricted remain distinct."""
    for status, code in [("no", 1), ("unknown", 2), ("restricted", 3)]:
        if status in statuses:
            return code
    return 0


def _run(args: argparse.Namespace, registry: Registry) -> int:
    """Present candidate/static evidence only; profile values are never output."""
    if args.command in {"check", "batch"}:
        profile = _profile(registry, args.profile)
        flags = {"detailed": args.details, "include_private": args.include_private}
        if args.command == "check":
            results = [registry.assess(args.domain, profile, **flags)]
        elif args.input == "-":
            results = registry.assess_many(_names(sys.stdin), profile, **flags)
        else:
            with Path(args.input).open(encoding="utf-8") as stream:
                results = registry.assess_many(_names(stream), profile, **flags)
        if args.quiet:
            for result in results:
                print(result.status.upper())
        elif args.as_json:
            payload: Any = [result.to_dict() for result in results]
            if args.command == "check":
                payload = payload[0]
            print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            for result in results:
                payload = result.to_dict()
                if args.command == "batch":
                    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
                    continue
                print(
                    f"{result.canonical_unicode or '(invalid input)'}: {result.status.upper()}"
                )
                print(
                    f"  Name: {result.name_validity}; eligibility: {result.eligibility}; coverage: {result.policy_coverage}"
                )
                if result.canonical_ascii != result.canonical_unicode:
                    print(f"  Canonical ASCII: {result.canonical_ascii}")
                for finding in payload["findings"]:
                    print(f"  {finding.get('message', finding['code'])}")
                if args.details:
                    print(f"  Dataset: {result.dataset_version}")
                    for gap in payload["gaps"]:
                        print(
                            f"  {gap['family']}: {gap['knowledge']} — {gap.get('reason') or 'research incomplete'}"
                        )
        return _exit([result.status for result in results])
    if args.command == "info":
        info = registry.namespace_info(args.namespace)
        if info is None:
            print("Namespace is outside the pinned inventory and policy corpus")
            return 2
        payload = info.to_dict()
        if args.as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            print(f"Namespace: {info.namespace}")
            if payload["root_inventory"]:
                print(f"Root operator: {payload['root_inventory']['operator']}")
            if payload["policy"]:
                for coverage in payload["policy"]["coverage"]:
                    print(
                        f"  {coverage['family']}: ASCII {coverage['ascii']}; IDN {coverage['idn']}"
                    )
            else:
                print("Registration policy: unknown")
            print(f"Dataset: {info.dataset_version}")
        return 0
    dataset = registry.dataset_info()
    if args.as_json:
        print(
            json.dumps(
                {
                    "statistics": registry.dataset_stats(),
                    "legacy": registry.stats(),
                    "dataset": dataset,
                },
                sort_keys=True,
            )
        )
    else:
        print(f"Active delegated roots: {dataset['root_count']:,}")
        print(f"Compiled namespace policies: {dataset['namespace_count']:,}")
        print(f"Evidence assertions: {dataset['assertion_count']:,}")
        print(f"Dataset: {dataset['dataset_version']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Return established status codes, with stable value-free input errors."""
    # Candidate JSONL and displayed names are UTF-8, independently of locale.
    # Test/caller-owned streams without reconfigure retain their own contract.
    for stream in [sys.stdin, sys.stdout, sys.stderr]:
        reconfigure = getattr(stream, "reconfigure", None)
        desired_errors = "backslashreplace" if stream is sys.stderr else "strict"
        if reconfigure is not None and (
            stream.encoding.lower().replace("_", "-") not in {"utf-8", "utf8"}
            or stream.errors != desired_errors
        ):
            reconfigure(
                encoding="utf-8",
                errors=desired_errors,
            )
    args = build_parser().parse_args(argv)
    if argv is None and args.command == "check" and str.__len__(args.domain) <= 4096:
        # Under an ASCII filesystem locale, CPython represents UTF-8 argv bytes
        # using surrogateescape. Recover that CLI name without altering paths
        # or caller-supplied Python strings. Non-UTF8 bytes remain invalid input.
        try:
            args.domain = os.fsencode(args.domain).decode("utf-8")
        except UnicodeError:
            pass
    try:
        return _run(args, Registry())
    except OSError:
        print("file_error", file=sys.stderr)
    except UnicodeError:
        print("invalid_utf8", file=sys.stderr)
    except ValueError as error:
        print(str(error), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
