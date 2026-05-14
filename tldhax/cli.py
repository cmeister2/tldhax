"""Command-line interface for the Python tldhax bindings."""

from __future__ import annotations

import argparse
import json
import sys

from . import Registry


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser for the CLI."""
    parser = argparse.ArgumentParser(prog="tldhax")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("domain")
    check_parser.add_argument("--json", action="store_true", dest="as_json")
    check_parser.add_argument("--quiet", action="store_true")

    info_parser = subparsers.add_parser("info")
    info_parser.add_argument("tld")
    info_parser.add_argument("--json", action="store_true", dest="as_json")

    subparsers.add_parser("stats")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    registry = Registry()

    if args.command == "check":
        result = registry.check(args.domain)
        if args.as_json:
            print(json.dumps({"domain": args.domain, "status": result.status, "reasons": result.reasons}, indent=2))
        elif args.quiet:
            print(result.status.upper())
        else:
            print(f"{args.domain}: {result.status.upper()}")
            for reason in result.reasons:
                print(f"  {reason}")
        return {"YES": 0, "NO": 1, "UNKNOWN": 2, "RESTRICTED": 3}[result.status.upper()]

    if args.command == "info":
        info = registry.tld_info(args.tld)
        if info is None:
            print(f"No data available for TLD '{args.tld}'")
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
            return 0

        print(f"TLD: {info.tld}")
        print(f"Registerable: {info.registerable}")
        if info.reason:
            print(f"Reason: {info.reason}")
        if info.note:
            print(f"Note: {info.note}")
        print(f"Min length: {info.min_length}")
        print(f"Max length: {info.max_length}")
        print(f"Length basis: {info.length_basis}")
        print(f"Banned labels: {', '.join(info.banned) if info.banned else '(none)'}")
        print(f"Charset: {info.charset}")
        print(f"Restrictions: {', '.join(info.restrictions) if info.restrictions else '(none)'}")
        print("Sources:")
        for field, source in dict(info.sources).items():
            print(f"  {field}: {source}")
        return 0

    stats = registry.stats()
    print(f"Total known suffixes: {stats['total_known_suffixes']:,}")
    print(f"Compiled rule entries: {stats['compiled_rules']:,}")
    print(f"  Registerable: {stats['registerable']:,}")
    print(f"  Not registerable: {stats['not_registerable']:,}")
    print(f"  Restricted: {stats['restricted']:,}")
    print(f"Coverage: {stats['coverage_percent']:.1f}% of known suffixes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))