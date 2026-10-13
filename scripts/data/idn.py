"""Bounded IDN repertoire ingestion; table publication never approves adoption.

The text subset accepts one hexadecimal code point or inclusive range per line,
optionally prefixed with U+, plus semicolon-delimited variant columns. Version
headers are mandatory. Uninterpreted prose and variant allocation remain gaps.
Artifacts are research inputs, not ready-to-enforce registry policy profiles.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

MAX_BYTES = 5_000_000
MAX_RECORDS = 100_000
MAX_CONTEXT_SET = 256
MAX_SEQUENCE = 32
CODEPOINT = re.compile(r"(?:U\+)?([0-9A-Fa-f]{4,6})")
RANGE = re.compile(
    r"(?:U\+)?([0-9A-Fa-f]{4,6})(?:(?:\.\.|-)(?:U\+)?([0-9A-Fa-f]{4,6}))?"
)


def text_and_hash(content: str | bytes) -> tuple[str, str]:
    """Bound the original bytes and preserve their exact snapshot identity."""
    raw = content.encode("utf-8") if isinstance(content, str) else content
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("IDN snapshot requires 1 to 5000000 bytes")
    return raw.decode("utf-8-sig"), hashlib.sha256(raw).hexdigest()


def scalar(value: int) -> int:
    """Reject out-of-range values and Unicode surrogates."""
    if not 0 <= value <= 0x10FFFF or 0xD800 <= value <= 0xDFFF:
        raise ValueError("invalid Unicode scalar in IDN table")
    return value


def sequence(value: str) -> str:
    """Decode a bounded literal sequence, without Unicode normalisation."""
    fields = value.split()
    if not 1 <= len(fields) <= MAX_SEQUENCE:
        raise ValueError("IDN sequence requires 1 to 32 code points")
    if any(CODEPOINT.fullmatch(field) is None for field in fields):
        raise ValueError("malformed IDN code point sequence")
    return "".join(chr(scalar(int(field.removeprefix("U+"), 16))) for field in fields)


def interval(first: str, last: str | None = None) -> list[int]:
    """Validate a closed scalar interval, including its interior."""
    left = sequence(first)
    right = left if last is None else sequence(last)
    if len(left) != 1 or len(right) != 1:
        raise ValueError("IDN interval bounds must each be one code point")
    start, end = ord(left), ord(right)
    if start > end or start <= 0xDFFF and end >= 0xD800:
        raise ValueError("reversed or surrogate-crossing IDN range")
    return [start, end]


def intervals(values: list[list[int]]) -> list[list[int]]:
    """Sort disjoint intervals and compact adjacent ones without expanding them."""
    result: list[list[int]] = []
    for start, end in sorted(values):
        if result and start <= result[-1][1]:
            raise ValueError("overlapping or duplicated IDN repertoire intervals")
        if result and start == result[-1][1] + 1:
            result[-1][1] = end
        else:
            result.append([start, end])
    return result


def artifact(
    *,
    format_name: str,
    version: str,
    sha256: str,
    ranges: list[list[int]],
    contexts: list[dict[str, Any]],
    variants: list[dict[str, str]],
    unsupported: set[str],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Return parsed features with adoption/effective applicability unresolved."""
    if not version.strip() or len(version) > 256 or not ranges:
        raise ValueError("IDN table requires a bounded version and repertoire")
    if variants:
        unsupported.add("variant_allocation_relationship")
    unsupported = {feature_category(feature) for feature in unsupported}
    return {
        "schema_version": 1,
        "format": format_name,
        "version": version,
        "source_sha256": sha256,
        "knowledge": "partial" if unsupported else "unknown",
        "parser_coverage": "partial" if unsupported else "complete",
        "adoption_status": "requires_review",
        "repertoire_complete": False,
        "ranges": intervals(ranges),
        "contexts": sorted(
            contexts, key=lambda item: (item["codepoint"], repr(item["condition"]))
        ),
        "variants": sorted(
            variants,
            key=lambda item: (
                item["sequence"],
                item["replacement"],
                item["disposition"],
            ),
        ),
        "unsupported_features": sorted(unsupported),
        "metadata": metadata,
    }


def feature_category(feature: str) -> str:
    """Separate known constraint gaps; ambiguous syntax may alter the repertoire.

    These categories never approve completeness. They let a human review assert
    complete membership separately from unsupported context or allocation rules.
    Unknown extension syntax is conservatively repertoire-affecting.
    """
    if feature.startswith(("repertoire:", "context:", "allocation:", "metadata:")):
        return feature
    if feature.startswith(
        ("metadata_", "uninterpreted_prose_metadata:", "attribute:meta:")
    ):
        category = "metadata"
    elif feature.startswith(
        ("variant_", "contextual_variant_", "range_variant_", "attribute:var:")
    ):
        category = "allocation"
    elif feature.startswith(
        (
            "context_",
            "negative_context_",
            "combined_any_context:",
            "empty_context_rule:",
            "nonscalar_context_binding",
            "rules_element:",
            "unapplied_",
            "attribute:rules:",
            "attribute:rule:",
            "attribute:class:",
        )
    ) or feature in {"attribute:char:tag", "attribute:range:tag"}:
        category = "context"
    else:
        category = "repertoire"
    return f"{category}:{feature}"


def parse_text(content: str | bytes) -> dict[str, Any]:
    """Parse an IANA-style hexadecimal repertoire without inferring policy.

    Bare numeric variant columns are preserved as unresolved relationships; their
    preferred/allocatable semantics cannot be inferred from column position.
    """
    text, sha = text_and_hash(content)
    ranges: list[list[int]] = []
    variants: list[dict[str, str]] = []
    unsupported: set[str] = set()
    metadata: dict[str, Any] = {"headers": {}, "uninterpreted": []}
    version = ""
    for line_number, raw in enumerate(text.splitlines(), 1):
        if line_number > MAX_RECORDS:
            raise ValueError("IDN text exceeds record budget")
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            header = line[1:].strip()
            match = re.fullmatch(r"(?:Table )?Version(?:\s*:\s*|\s+)(.+)", header, re.I)
            if match:
                if version and version != match[1].strip():
                    raise ValueError("conflicting IDN table versions")
                version = match[1].strip()
            elif ":" in header and header.split(":", 1)[0].lower() in {
                "registry",
                "language",
                "date",
                "effective date",
                "unicode version",
                "title",
                "source",
                "reference",
            }:
                key, value = header.split(":", 1)
                metadata["headers"][key.lower()] = value.strip()
            else:
                unsupported.add(f"uninterpreted_text_comment:{line_number}")
                metadata["uninterpreted"].append({"line": line_number, "text": header})
            continue
        body, _, comment = line.partition("#")
        fields = [value.strip() for value in body.split(";")]
        match = RANGE.fullmatch(fields[0])
        if match is None:
            if fields[0].startswith("U+"):
                raise ValueError("malformed IDN repertoire record")
            unsupported.add(f"uninterpreted_text_record:{line_number}")
            metadata["uninterpreted"].append({"line": line_number, "text": line})
            continue
        first, last = match.groups()
        ranges.append(interval(first, last))
        if comment.strip():
            unsupported.add(f"uninterpreted_text_comment:{line_number}")
        for column in fields[1:]:
            if not column:
                continue
            unsupported.add(f"uninterpreted_text_columns:{line_number}")
            metadata["uninterpreted"].append({"line": line_number, "text": column})
            if last is None and all(
                CODEPOINT.fullmatch(item) for item in column.split()
            ):
                variants.append(
                    {
                        "sequence": sequence(first),
                        "replacement": sequence(column),
                        "disposition": "unresolved",
                    }
                )
    return artifact(
        format_name="iana-text-subset",
        version=version,
        sha256=sha,
        ranges=ranges,
        contexts=[],
        variants=variants,
        unsupported=unsupported,
        metadata=metadata,
    )
