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
    if args.command in {"check", "assess", "batch"}:
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
        namespace = args.namespace.lower().removeprefix(".").removesuffix(".")
        authored = namespace in registry.supported_namespaces()
        if args.as_json:
            print(json.dumps({"namespace": namespace, "policy_available": authored}))
        else:
            print(f"Namespace: {namespace}")
            print(f"Authored policy: {'yes' if authored else 'unknown'}")
        return 0 if authored else 2
    dataset = registry.dataset_info()
    if args.as_json:
        print(json.dumps(dataset, sort_keys=True))
    else:
        print(f"Authored namespace policies: {dataset['namespace_count']}")
        print(f"Dataset: {dataset['dataset_version']}")
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
