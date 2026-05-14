"""Stamp release versions into Cargo manifests."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    """Rewrite the sentinel crate version in Cargo.toml and Cargo.lock."""
    if len(sys.argv) != 2:
        print("usage: prepare.py <version>", file=sys.stderr)
        return 1

    version = sys.argv[1].strip()
    cargo_toml = Path("Cargo.toml")
    cargo_toml_text = cargo_toml.read_text(encoding="utf-8")
    cargo_toml_updated = re.sub(
        r'^version = ".*"$',
        f'version = "{version}"',
        cargo_toml_text,
        count=1,
        flags=re.MULTILINE,
    )
    cargo_toml.write_text(cargo_toml_updated, encoding="utf-8")

    cargo_lock = Path("Cargo.lock")
    cargo_lock_text = cargo_lock.read_text(encoding="utf-8")
    cargo_lock_updated = re.sub(
        r'(^name = "tldhax"\nversion = ")[^"]+("$)',
        rf"\g<1>{version}\2",
        cargo_lock_text,
        count=1,
        flags=re.MULTILINE,
    )
    cargo_lock.write_text(cargo_lock_updated, encoding="utf-8")

    print(f"stamped Cargo.toml and Cargo.lock with version {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
