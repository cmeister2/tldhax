#!/usr/bin/env python3
"""Verify that built wheels contain the project's required license files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_LICENSES = (
    Path("LICENSE"),
    Path("THIRD_PARTY_NOTICES.md"),
    Path("data/snapshots/LICENSE.publicsuffix"),
)


def _license_member(names: list[str], relative_path: Path) -> str:
    """Return the unique PEP 639 wheel member for one repository file."""
    expected_tail = PurePosixPath("licenses", relative_path.as_posix())
    matches = [
        name
        for name in names
        if PurePosixPath(name).parts[-len(expected_tail.parts) :] == expected_tail.parts
        and any(
            part.endswith(".dist-info") for part in PurePosixPath(name).parent.parts
        )
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected one .dist-info/{expected_tail} member, found {matches!r}"
        )
    return matches[0]


def check_wheel(path: Path) -> None:
    """Validate required license paths and bytes in one wheel."""
    if not path.is_file():
        raise ValueError(f"wheel does not exist: {path}")
    if path.suffix != ".whl":
        raise ValueError(f"not a wheel: {path}")

    try:
        with ZipFile(path) as wheel:
            names = wheel.namelist()
            for relative_path in REQUIRED_LICENSES:
                source = REPOSITORY_ROOT / relative_path
                member = _license_member(names, relative_path)
                if wheel.read(member) != source.read_bytes():
                    raise ValueError(
                        f"{path}: {member} differs from repository file {relative_path}"
                    )
    except BadZipFile as error:
        raise ValueError(f"invalid wheel archive: {path}") from error


def main() -> int:
    """Check every wheel supplied on the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", nargs="+", type=Path)
    arguments = parser.parse_args()

    try:
        for wheel in arguments.wheels:
            check_wheel(wheel)
    except (OSError, ValueError) as error:
        print(f"wheel license check failed: {error}", file=sys.stderr)
        return 1

    print(f"verified required license files in {len(arguments.wheels)} wheel(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
