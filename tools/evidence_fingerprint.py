#!/usr/bin/env python3
"""Fingerprint original source bytes or a complete captured browser text response.

The extracted_text/v1 procedure retains every numbered source line in order,
removes tool line/page labels and their separator, replaces inline tool citation
wrappers with their displayed label, joins logical lines with LF and appends one
final LF. Source wording, spaces, Unicode, footers and page artifacts are retained.
A truncated, duplicated or mixed-source capture is rejected. The result is a
content fingerprint of this representation, never an original PDF byte hash.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

MARKER = re.compile(r"(?<!\w)L(\d+)(?:@P[\d-]+)?: ?")
CITATION = re.compile("\ue200cite\ue202[^†]*†([^\ue201]*)\ue201")


def extracted_text(capture: str) -> bytes:
    """Canonicalize tool metadata only, after proving every source line was captured."""
    counts = re.findall(r"Total lines: (\d+)", capture)
    if len(counts) != 1:
        raise ValueError("a capture must contain exactly one source")
    total = int(counts[0])
    if not 0 < total <= 100000:
        raise ValueError("invalid source line count")
    lines = []
    for physical in capture.splitlines():
        markers = list(MARKER.finditer(physical))
        for index, marker in enumerate(markers):
            end = (
                markers[index + 1].start()
                if index + 1 < len(markers)
                else len(physical)
            )
            text = physical[marker.end() : end]
            if index + 1 < len(markers) and text.endswith(" "):
                text = text[
                    :-1
                ]  # Separator before a tool label on the same physical line.
            lines.append((int(marker.group(1)), CITATION.sub(r"\1", text)))
    if [index for index, _ in lines] != list(range(total)):
        raise ValueError("incomplete, duplicate or reordered source lines")
    return ("\n".join(text for _, text in lines) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    """Print representation identity and SHA256 without redistributing source text."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument(
        "--representation",
        choices=("original_bytes", "extracted_text/v1"),
        required=True,
    )
    args = parser.parse_args(argv)
    content = args.capture.read_bytes()
    if len(content) > 16000000:
        raise SystemExit("source exceeds 16 MB capture limit")
    if args.representation == "extracted_text/v1":
        content = extracted_text(content.decode("utf-8"))
    print(
        json.dumps(
            {
                "hash_representation": args.representation,
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
