#!/usr/bin/env python3
"""Explicit developer oracle. No purchases, runtime integration or implicit .env.

Install with: pip install -e '.[oracle]'
python tools/registrar_oracle.py --environment production --env-file .env \
    --name example.com --dataset-version DATASET --store /tmp/oracle.sqlite

An input JSONL file can include name, namespace, stratum, offline_validity and
published evidence_ids. Never include registrant data or credentials in inputs.
Optional --config JSON sets each provider's windows [{requests, seconds}],
quota_group (shared account/source-IP), namespaces, concurrency, weight and
max_candidates. Defaults deliberately cap each provider at 30 unique names.
Gandi is optional for an existing eligible account, with a usable PAT.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

# Direct script execution imports the adjacent package, independently of Rust.
try:
    import httpx
    from oracle.config import load_credentials
    from oracle.dispatch_config import ProviderConfig
    from oracle.gandi import Gandi
    from oracle.limits import Window
    from oracle.models import Candidate
    from oracle.namecom import Namecom
    from oracle.runner import Runner
    from oracle.store import Store
except ModuleNotFoundError as error:
    if error.name in ("httpx", "dotenv", "idna"):
        raise SystemExit(
            "Install optional developer dependencies: pip install -e '.[oracle]'"
        ) from None
    raise


def inputs(args: argparse.Namespace) -> list[Candidate]:
    """Read bounded explicit probes without registrant or credential fields."""
    candidates = [Candidate(name) for name in args.name]
    if args.input:
        with args.input.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                item = json.loads(line)
                allowed = {
                    "name",
                    "namespace",
                    "stratum",
                    "offline_validity",
                    "evidence_ids",
                }
                if not isinstance(item, dict) or set(item) - allowed:
                    raise ValueError(
                        "JSONL candidates contain only documented candidate fields"
                    )
                candidates.append(Candidate(**item))
    if not candidates:
        raise ValueError("supply --name or --input")
    for candidate in candidates:
        if (
            not isinstance(candidate.name, str)
            or not candidate.name
            or len(candidate.name.encode()) > 4096
        ):
            raise ValueError("candidate names require 1 to 4096 UTF-8 bytes")
        if candidate.offline_validity not in (
            "valid",
            "invalid",
            "conditional",
            "unknown",
        ):
            raise ValueError("unsupported offline_validity")
    return candidates


async def execute(args: argparse.Namespace) -> dict:
    """Configure adapters and run only the requested developer checks."""
    candidates = inputs(args)
    credentials = load_credentials(args.env_file)
    if not credentials:
        raise ValueError(
            "no configured provider; supply environment credentials or --env-file"
        )
    settings = (
        json.loads(args.config.read_text(encoding="utf-8")) if args.config else {}
    )
    if not isinstance(settings, dict):
        raise ValueError("provider configuration must be a JSON object")
    async with httpx.AsyncClient(
        timeout=20,
        follow_redirects=False,
        trust_env=False,
        limits=httpx.Limits(max_connections=8),
    ) as client:
        configs = []
        for credential in credentials:
            adapter = {"namecom": Namecom, "gandi": Gandi}[credential.provider](
                client, credential, args.environment
            )
            setting = dict(settings.get(credential.provider, {}))
            windows = tuple(
                Window(**window)
                for window in setting.pop(
                    "windows",
                    [{"requests": 1, "seconds": 1}, {"requests": 30, "seconds": 60}],
                )
            )
            if "namespaces" in setting:
                setting["namespaces"] = tuple(setting["namespaces"])
            # All Gandi tokens share an IP quota even if account configuration changes.
            setting.setdefault(
                "quota_group",
                "gandi-source-ip"
                if credential.provider == "gandi"
                else "namecom-account",
            )
            configs.append(ProviderConfig(adapter, windows=windows, **setting))
        with Store(args.store) as store:
            result = await Runner(
                configs,
                store,
                args.dataset_version,
                refresh=args.refresh,
                max_age=args.max_age,
                cross_check_rate=args.cross_check_rate,
            ).run(candidates)
    return asdict(result)


def main(argv: list[str] | None = None) -> int:
    """Parse explicit settings and emit sanitised JSON observations."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--name", action="append", default=[])
    parser.add_argument("--input", type=Path, help="candidate JSONL")
    parser.add_argument(
        "--env-file", type=Path, help="explicit local credential file; environment wins"
    )
    parser.add_argument(
        "--environment", choices=("production", "sandbox"), required=True
    )
    parser.add_argument("--dataset-version", required=True)
    parser.add_argument(
        "--store", type=Path, required=True, help="local SQLite observation history"
    )
    parser.add_argument(
        "--config", type=Path, help="credential-free provider quota/coverage JSON"
    )
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--max-age", type=float, default=86400)
    parser.add_argument("--cross-check-rate", type=float, default=0.1)
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(execute(args))
    except (OSError, ValueError, TypeError, KeyError):
        # Do not print external responses, configuration values or credentials.
        print(
            "Oracle input or configuration failed; check credential names, file paths and documented fields.",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 1 if result["tool_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
