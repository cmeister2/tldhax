"""Audit raw TOML authoring entries without treating populated fields as proof.

Run `python tools/corpus_audit.py --rules rules > /tmp/tldhax-audit.json`.
The sorted relative paths and exact file bytes define the corpus SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import idna

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 development environments.
    import tomli as tomllib

POLICY_FIELDS = (
    "registerable",
    "reason",
    "note",
    "restrictions",
    "min_length",
    "max_length",
    "length_basis",
    "banned",
    "charset",
    "idn_chars",
)


def fingerprint(rules: Path) -> str:
    """Hash sorted paths and content with unambiguous length framing."""
    digest = hashlib.sha256()
    for path in sorted(rules.glob("*.toml")):
        for value in (path.name.encode("utf-8"), path.read_bytes()):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
    return digest.hexdigest()


def canonical_key(raw: str) -> str:
    """Keep PSL selectors distinct while mapping labels with UTS46 IDNA."""
    marker = "*." if raw.startswith("*.") else "!" if raw.startswith("!") else ""
    body = raw[len(marker) :]
    return (
        marker
        + idna.encode(body, uts46=True, transitional=False, std3_rules=True)
        .decode("ascii")
        .lower()
    )


def audit(rules: Path) -> dict[str, Any]:
    """Return deterministic inventory and source-presence metrics, never approval."""
    paths = sorted(rules.glob("*.toml"))
    if not paths:
        raise ValueError(f"no TOML files in {rules}")
    entries: list[dict[str, Any]] = []
    by_raw: dict[str, list[str]] = defaultdict(list)
    by_canonical: dict[str, set[str]] = defaultdict(set)
    invalid_keys = []
    for path in paths:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        for index, entry in enumerate(document.get("domains", [])):
            raw = entry.get("tld")
            if not isinstance(raw, str) or not raw:
                raise ValueError(f"{path.name}: domains[{index}] needs a nonempty tld")
            entries.append(entry)
            by_raw[raw].append(f"{path.name}:domains[{index}]")
            try:
                by_canonical[canonical_key(raw)].add(raw)
            except idna.IDNAError as error:
                invalid_keys.append({"raw": raw, "error": str(error)})

    explicit: Counter[str] = Counter()
    sourced: Counter[str] = Counter()
    source_urls: Counter[str] = Counter()
    missing_sources = []
    for entry in entries:
        sources = entry.get("sources", {})
        source_urls.update(str(url) for url in sources.values())
        for field in POLICY_FIELDS:
            if field in entry:
                explicit[field] += 1
                if isinstance(sources.get(field), str) and sources[field].strip():
                    sourced[field] += 1
                else:
                    missing_sources.append({"raw": entry["tld"], "field": field})

    return {
        "report_schema": 1,
        "corpus_sha256": fingerprint(rules),
        "canonicalisation": {
            "implementation": "Python idna (not Rust runtime canonicalisation)",
            "version": idna.__version__,
            "uts46": True,
            "transitional": False,
            "std3_rules": True,
            "purpose": "candidate collisions; confirm against the runtime before migration",
        },
        "inventory": {
            "toml_files": len(paths),
            "raw_entries": len(entries),
            "distinct_raw_keys": len(by_raw),
            "distinct_canonical_selector_keys": len(by_canonical),
            "registerable_declarations": dict(
                sorted(
                    Counter(
                        entry.get("registerable", "missing") for entry in entries
                    ).items()
                )
            ),
            "brand_entries": sum(e.get("reason") == "brand_tld" for e in entries),
            "wildcards": sum(raw.startswith("*.") for raw in by_raw),
            "exceptions": sum(raw.startswith("!") for raw in by_raw),
            "non_ascii_keys": sum(not raw.isascii() for raw in by_raw),
        },
        "field_presence": {
            field: {"explicit": explicit[field], "source_link": sourced[field]}
            for field in POLICY_FIELDS
        },
        "evidence_assessment": {
            "reviewed_policy_coverage": None,
            "explanation": "Legacy URLs have no approved authority, clause, scope, or review record; field presence is not evidence-backed policy coverage.",
            "unique_source_urls": len(source_urls),
            "source_usage": dict(sorted(source_urls.items())),
            "explicit_fields_without_source_link": missing_sources,
        },
        "duplicate_raw_keys": {
            raw: locations
            for raw, locations in sorted(by_raw.items())
            if len(locations) > 1
        },
        "canonical_collisions": {
            key: sorted(raws)
            for key, raws in sorted(by_canonical.items())
            if len(raws) > 1
        },
        "invalid_selector_keys": invalid_keys,
    }


def main() -> None:
    """Print one JSON report; malformed inputs fail without a partial report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=Path("rules"))
    arguments = parser.parse_args()
    try:
        result = audit(arguments.rules)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
