"""Command-line static registration decisions with direct explanations."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from .registry import MAX_BATCH, MAX_PROFILE_BYTES, Registry


def build_parser() -> argparse.ArgumentParser:
    """Define single-name, ordered JSONL batch and small metadata commands."""
    parser = argparse.ArgumentParser(prog="tldhax")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ["check", "assess", "batch"]:
        child = commands.add_parser(name)
        if name == "batch":
            child.add_argument(
                "input", nargs="?", default="-", help="JSONL file or stdin"
            )
        else:
            child.add_argument("domain")
        child.add_argument("--profile", type=Path, help="local JSON registrant profile")
        child.add_argument("--json", action="store_true", dest="as_json")
        child.add_argument("--quiet", action="store_true")
    info = commands.add_parser("info")
    info.add_argument("namespace")
    info.add_argument("--json", action="store_true", dest="as_json")
    stats = commands.add_parser("stats")
    stats.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _profile(registry: Registry, path: Path | None) -> Any:
    """Bound local reads and retain native duplicate-key validation."""
    if path is None:
        return None
    with path.open("rb") as stream:
        content = stream.read(MAX_PROFILE_BYTES + 1)
    if len(content) > MAX_PROFILE_BYTES:
        raise ValueError("profile_input_limit")
    return registry.prepare_registrant_json(content.decode("utf-8"))


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate input fields without echoing candidate or profile data."""
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate_input_field")
        result[key] = value
    return result


def _names(stream: TextIO) -> list[str]:
    """Read at most 10,000 bounded JSON strings or single-domain records."""
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


def _exit(decisions: list[str]) -> int:
    """Use 1 for any denial, 2 for unresolved decisions and 0 for all permitted."""
    if "no" in decisions:
        return 1
    if "unknown" in decisions:
        return 2
    return 0


def _run(args: argparse.Namespace, registry: Registry) -> int:
    """Present the decision and reasons produced by the Rust evaluator."""
    if args.command == "check":
        profile = _profile(registry, args.profile)
        if profile is None:
            check = registry.check(args.domain)
            status, reasons = check.status, check.reasons
        else:
            assessment = registry.assess(args.domain, profile)
            status = assessment.decision
            reasons = [reason.message for reason in assessment.reasons]
        if args.quiet:
            print(status.upper())
        elif args.as_json:
            print(
                json.dumps(
                    {"domain": args.domain, "status": status, "reasons": reasons},
                    indent=2,
                )
            )
        else:
            printable = args.domain.encode("utf-8", errors="backslashreplace").decode(
                "utf-8"
            )
            print(f"{printable}: {status.upper()}")
            for explanation in reasons:
                print(f"  {explanation}")
        return _exit([status])
    if args.command in {"assess", "batch"}:
        profile = _profile(registry, args.profile)
        if args.command != "batch":
            results = [registry.assess(args.domain, profile)]
        elif args.input == "-":
            results = registry.assess_many(_names(sys.stdin), profile)
        else:
            with Path(args.input).open(encoding="utf-8") as stream:
                results = registry.assess_many(_names(stream), profile)
        if args.quiet:
            for result in results:
                print(result.decision)
        elif args.as_json:
            payload: Any = [result.to_dict() for result in results]
            if args.command != "batch":
                payload = payload[0]
            print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        elif args.command == "batch":
            for result in results:
                print(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True))
        else:
            result = results[0]
            print(f"{result.canonical_domain or '(invalid input)'}: {result.decision}")
            for reason in result.reasons:
                print(f"  {reason.message}")
            if result.missing_profile_fields:
                print(
                    f"  Needed profile fields: {', '.join(result.missing_profile_fields)}"
                )
        return _exit([result.decision for result in results])
    if args.command == "info":
        info = registry.tld_info(args.namespace)
        if info is None:
            print(f"No data available for TLD '{args.namespace}'")
            return 2
        payload = {
            "tld": info.tld,
            "registerable": info.registerable,
            "reason": info.reason,
            "note": info.note,
            "restrictions": info.restrictions,
            "min_length": info.min_length,
            "max_length": info.max_length,
            "length_basis": info.length_basis,
            "banned": info.banned,
            "charset": info.charset,
            "idn_chars": info.idn_chars,
            "sources": dict(info.sources),
        }
        if args.as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"TLD: {info.tld}")
            print(f"Registerable: {info.registerable}")
            if info.reason:
                print(f"Reason: {info.reason}")
            if info.note:
                print(f"Note: {info.note}")
            print(
                f"Min length: {info.min_length if info.min_length is not None else 'unknown'}"
            )
            print(
                f"Max length: {info.max_length if info.max_length is not None else 'unknown'}"
            )
            print(f"Length basis: {info.length_basis or 'unknown'}")
            print(
                f"Banned labels: {', '.join(info.banned) if info.banned else '(none represented)'}"
            )
            print(f"Charset: {info.charset or 'unknown'}")
            print(
                f"Restrictions: {', '.join(info.restrictions) if info.restrictions else '(none represented)'}"
            )
            print("Sources:")
            for field, source in info.sources.items():
                print(f"  {field}: {source}")
        return 0
    stats = registry.stats()
    if args.as_json:
        print(json.dumps(stats, sort_keys=True))
    else:
        print(f"Total known suffixes: {stats['total_known_suffixes']:,}")
        print(f"Compiled rule entries: {stats['compiled_rules']:,}")
        print(f"  Registerable: {stats['registerable']:,}")
        print(f"  Not registerable: {stats['not_registerable']:,}")
        print(f"  Restricted: {stats['restricted']:,}")
        print(f"Coverage: {stats['coverage_percent']:.1f}% of known suffixes")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI with UTF-8 streams and stable value-free input errors."""
    for stream in [sys.stdin, sys.stdout, sys.stderr]:
        reconfigure = getattr(stream, "reconfigure", None)
        errors = "backslashreplace" if stream is sys.stderr else "strict"
        if reconfigure is not None and (
            stream.encoding.lower().replace("_", "-") not in {"utf-8", "utf8"}
            or stream.errors != errors
        ):
            reconfigure(encoding="utf-8", errors=errors)
    args = build_parser().parse_args(argv)
    if (
        argv is None
        and args.command in {"check", "assess"}
        and str.__len__(args.domain) <= 4096
    ):
        # Recover UTF-8 argv under Python's ASCII-locale surrogateescape mode.
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
