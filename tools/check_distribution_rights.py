#!/usr/bin/env python3
"""Block publication while bundled snapshot redistribution is unresolved."""

from __future__ import annotations

import sys
from pathlib import Path

import tomllib

MANIFEST = Path(__file__).resolve().parents[1] / "data" / "manifest.toml"


def main() -> int:
    """Reject snapshot records whose redistribution status is not asserted."""
    document = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    unresolved = [
        record["id"]
        for record in document.get("snapshots", [])
        if record.get("license_spdx") == "NOASSERTION"
    ]
    if unresolved:
        print(
            "release blocked: bundled snapshot redistribution rights are unresolved for "
            + ", ".join(sorted(unresolved)),
            file=sys.stderr,
        )
        print(
            "record a reviewed distributable license or stop bundling those payloads "
            "before publishing",
            file=sys.stderr,
        )
        return 1

    print("all bundled snapshots have an asserted redistribution license")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
