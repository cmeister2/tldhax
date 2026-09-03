#!/usr/bin/env python3
"""Fetch and verify the authoritative data snapshots used by tldhax.

The default mode downloads the configured upstream resources, validates their
basic structure, writes them atomically under ``data/snapshots``, and records
their provenance in ``data/manifest.toml``.  ``--check`` is deliberately
offline: it reads only the checked-in files and verifies their metadata,
content hashes, and source-specific structure.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SCHEMA_VERSION = 1
MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024
USER_AGENT = "tldhax-snapshot-updater/1 (+https://github.com/cmeister2/tldhax)"

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_DIRECTORY = REPOSITORY_ROOT / "data" / "snapshots"
MANIFEST_PATH = REPOSITORY_ROOT / "data" / "manifest.toml"
POLICY_SOURCES_PATH = REPOSITORY_ROOT / "data" / "policy" / "sources.toml"
POLICY_PROFILES_PATH = REPOSITORY_ROOT / "data" / "policy" / "profiles.toml"
PSL_LICENSE_PATH = SNAPSHOT_DIRECTORY / "LICENSE.publicsuffix"
PSL_LICENSE_REPOSITORY_URL = "https://github.com/publicsuffix/list"
PSL_LICENSE_URL_TEMPLATE = (
    "https://raw.githubusercontent.com/publicsuffix/list/{commit}/LICENSE"
)
ICANN_TERMS_URL = "https://www.icann.org/privacy/tos"


class SnapshotError(RuntimeError):
    """Raised when fetching or validating snapshot data fails."""


@dataclass(frozen=True)
class Source:
    """Static provenance and validation settings for one upstream source."""

    id: str
    kind: str
    filename: str
    url: str
    parser_version: str
    content_types: tuple[str, ...]
    license_spdx: str
    license_name: str
    license_url: str
    validator: Callable[[bytes], dict[str, str]]

    @property
    def repository_path(self) -> str:
        """Return the snapshot path relative to the repository root."""
        return f"data/snapshots/{self.filename}"

    @property
    def filesystem_path(self) -> Path:
        """Return the absolute destination path for the source."""
        return SNAPSHOT_DIRECTORY / self.filename


@dataclass(frozen=True)
class Download:
    """An upstream response and the HTTP metadata needed by the manifest."""

    payload: bytes
    retrieved_at: str
    content_type: str
    http_last_modified: str | None
    http_etag: str | None


class _RootDatabaseParser(HTMLParser):
    """Collect the title and TLD record links from the IANA root DB page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_title = False
        self.title_parts: list[str] = []
        self.tld_links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Record title state and links to individual root DB records."""
        if tag == "title":
            self._in_title = True
        if tag != "a":
            return
        href = dict(attrs).get("href")
        if href and re.fullmatch(r"/domains/root/db/[a-z0-9-]+\.html", href):
            self.tld_links.add(href)

    def handle_endtag(self, tag: str) -> None:
        """Leave title state at the end of the title element."""
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        """Collect text inside the document title."""
        if self._in_title:
            self.title_parts.append(data)


def _decode_utf8(payload: bytes, source_name: str) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SnapshotError(f"{source_name} is not valid UTF-8: {error}") from error


def _parse_datetime(value: str, formats: tuple[str, ...] = ()) -> datetime:
    """Parse a source timestamp and normalize it to an aware datetime."""
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        parsed = None

    if parsed is None:
        for date_format in formats:
            try:
                parsed = datetime.strptime(value.strip(), date_format).replace(
                    tzinfo=timezone.utc
                )
                break
            except ValueError:
                continue

    if parsed is None:
        raise SnapshotError(f"invalid timestamp {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_datetime(value: datetime) -> str:
    """Render an aware datetime as a UTC RFC 3339 string."""
    normalized = value.astimezone(timezone.utc)
    rendered = normalized.isoformat(timespec="seconds")
    return rendered.replace("+00:00", "Z")


def _now() -> str:
    """Return the current UTC time with second precision."""
    return _format_datetime(datetime.now(timezone.utc))


def _normalize_http_date(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError) as error:
        raise SnapshotError(f"invalid Last-Modified header {value!r}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return _format_datetime(parsed)


def _validate_psl(payload: bytes) -> dict[str, str]:
    text = _decode_utf8(payload, "Public Suffix List")
    version_match = re.search(r"^// VERSION:\s*(\S+)\s*$", text, re.MULTILINE)
    commit_match = re.search(r"^// COMMIT:\s*([0-9a-f]{40})\s*$", text, re.MULTILINE)
    if version_match is None or commit_match is None:
        raise SnapshotError("Public Suffix List has no VERSION/COMMIT header")
    if "// ===BEGIN ICANN DOMAINS===" not in text:
        raise SnapshotError("Public Suffix List has no ICANN section")
    if "// ===BEGIN PRIVATE DOMAINS===" not in text:
        raise SnapshotError("Public Suffix List has no PRIVATE section")
    if "Mozilla Public" not in text[:500] or "License, v. 2.0" not in text[:500]:
        raise SnapshotError("Public Suffix List has no MPL-2.0 notice")

    rule_count = sum(
        1
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("//")
    )
    if rule_count < 5_000:
        raise SnapshotError(f"Public Suffix List contains too few rules ({rule_count})")

    version = version_match.group(1)
    version_time = _parse_datetime(version, formats=("%Y-%m-%d_%H-%M-%S_UTC",))
    return {
        "upstream_version": version,
        "upstream_commit": commit_match.group(1),
        "upstream_updated_at": _format_datetime(version_time),
    }


def _validate_iana_tlds(payload: bytes) -> dict[str, str]:
    text = _decode_utf8(payload, "IANA current TLD list")
    lines = text.splitlines()
    if not lines:
        raise SnapshotError("IANA current TLD list is empty")
    header_match = re.fullmatch(
        r"# Version (\d+), Last Updated (.+ UTC)", lines[0].strip()
    )
    if header_match is None:
        raise SnapshotError("IANA current TLD list has an invalid version header")

    labels = [line.strip() for line in lines[1:] if line.strip()]
    if len(labels) < 1_000:
        raise SnapshotError(f"IANA current TLD list is too short ({len(labels)})")
    invalid = next(
        (label for label in labels if re.fullmatch(r"[A-Z0-9-]+", label) is None),
        None,
    )
    if invalid is not None:
        raise SnapshotError(f"IANA current TLD list has invalid label {invalid!r}")
    if len(labels) != len(set(labels)):
        raise SnapshotError("IANA current TLD list contains duplicate labels")
    if not {"ARPA", "COM"}.issubset(labels):
        raise SnapshotError("IANA current TLD list lacks expected ARPA/COM entries")

    updated = _parse_datetime(
        header_match.group(2), formats=("%a %b %d %H:%M:%S %Y UTC",)
    )
    return {
        "upstream_version": header_match.group(1),
        "upstream_updated_at": _format_datetime(updated),
    }


def _validate_iana_root_db(payload: bytes) -> dict[str, str]:
    text = _decode_utf8(payload, "IANA Root Zone Database")
    parser = _RootDatabaseParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as error:
        raise SnapshotError(
            f"IANA Root Zone Database HTML is invalid: {error}"
        ) from error

    title = " ".join("".join(parser.title_parts).split())
    if title != "Root Zone Database":
        raise SnapshotError(f"unexpected IANA root DB title {title!r}")
    if len(parser.tld_links) < 1_000:
        raise SnapshotError(
            f"IANA root DB contains too few TLD records ({len(parser.tld_links)})"
        )
    required = {
        "/domains/root/db/arpa.html",
        "/domains/root/db/com.html",
    }
    if not required.issubset(parser.tld_links):
        raise SnapshotError("IANA root DB lacks expected ARPA/COM records")
    return {}


def _validate_icann_gtlds(payload: bytes) -> dict[str, str]:
    text = _decode_utf8(payload, "ICANN gTLD JSON")
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise SnapshotError(f"ICANN gTLD snapshot is invalid JSON: {error}") from error
    if not isinstance(document, dict):
        raise SnapshotError("ICANN gTLD JSON root is not an object")

    version = document.get("version")
    updated_on = document.get("updatedOn")
    gtlds = document.get("gTLDs")
    if not isinstance(version, (str, int)) or isinstance(version, bool):
        raise SnapshotError("ICANN gTLD JSON has no scalar version")
    if not isinstance(updated_on, str):
        raise SnapshotError("ICANN gTLD JSON has no updatedOn timestamp")
    if not isinstance(gtlds, list) or len(gtlds) < 1_000:
        count = len(gtlds) if isinstance(gtlds, list) else 0
        raise SnapshotError(f"ICANN gTLD JSON has too few records ({count})")

    labels: set[str] = set()
    required_fields = {"gTLD", "contractTerminated", "specification13"}
    for index, record in enumerate(gtlds):
        if not isinstance(record, dict) or not required_fields.issubset(record):
            raise SnapshotError(f"ICANN gTLD record {index} lacks required fields")
        label = record["gTLD"]
        if not isinstance(label, str) or re.fullmatch(r"[a-z0-9-]+", label) is None:
            raise SnapshotError(f"ICANN gTLD record {index} has invalid gTLD")
        if label in labels:
            raise SnapshotError(f"ICANN gTLD JSON repeats {label!r}")
        labels.add(label)
    if not {"aaa", "com"}.issubset(labels):
        raise SnapshotError("ICANN gTLD JSON lacks expected AAA/COM records")

    updated = _parse_datetime(updated_on)
    return {
        "upstream_version": str(version),
        "upstream_updated_at": _format_datetime(updated),
    }


def _validate_iana_special_use(payload: bytes) -> dict[str, str]:
    text = _decode_utf8(payload, "IANA special-use CSV")
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if reader.fieldnames != ["Name", "Reference"]:
            raise SnapshotError(
                f"IANA special-use CSV has unexpected columns {reader.fieldnames!r}"
            )
        rows = list(reader)
    except csv.Error as error:
        raise SnapshotError(f"IANA special-use CSV is invalid: {error}") from error
    if len(rows) < 30:
        raise SnapshotError(f"IANA special-use CSV has too few records ({len(rows)})")
    names = {row.get("Name", "") for row in rows}
    required = {"home.arpa.", "onion.", "test."}
    if not required.issubset(names):
        raise SnapshotError("IANA special-use CSV lacks expected special-use names")
    if any(not row.get("Name") or not row.get("Reference") for row in rows):
        raise SnapshotError("IANA special-use CSV contains an incomplete row")
    return {}


def _validate_psl_license(payload: bytes) -> None:
    text = _decode_utf8(payload, "Public Suffix List license")
    required = (
        "Mozilla Public License Version 2.0",
        "2. License Grants and Conditions",
        "Exhibit A - Source Code Form License Notice",
        'Exhibit B - "Incompatible With Secondary Licenses" Notice',
    )
    if len(payload) < 15_000 or any(marker not in text for marker in required):
        raise SnapshotError("Public Suffix List license is incomplete")


SOURCES = (
    Source(
        id="psl",
        kind="public_suffix_list",
        filename="public_suffix_list.dat",
        url="https://publicsuffix.org/list/public_suffix_list.dat",
        parser_version="psl-v1",
        content_types=("text/plain",),
        license_spdx="MPL-2.0",
        license_name="Mozilla Public License 2.0",
        license_url="https://www.mozilla.org/MPL/2.0/",
        validator=_validate_psl,
    ),
    Source(
        id="iana_tlds",
        kind="current_root_tld_list",
        filename="tlds-alpha-by-domain.txt",
        url="https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
        parser_version="iana-tlds-v1",
        content_types=("text/plain",),
        license_spdx="NOASSERTION",
        license_name="ICANN Terms of Service",
        license_url=ICANN_TERMS_URL,
        validator=_validate_iana_tlds,
    ),
    Source(
        id="iana_root_db",
        kind="root_zone_database",
        filename="root-zone-database.html",
        url="https://www.iana.org/domains/root/db",
        parser_version="iana-root-db-html-v1",
        content_types=("text/html",),
        license_spdx="NOASSERTION",
        license_name="ICANN Terms of Service",
        license_url=ICANN_TERMS_URL,
        validator=_validate_iana_root_db,
    ),
    Source(
        id="icann_gtlds",
        kind="gtld_registry_agreements",
        filename="icann-gtlds.json",
        url="https://www.icann.org/resources/registries/gtlds/v2/gtlds.json",
        parser_version="icann-gtlds-v2",
        content_types=("application/json",),
        license_spdx="NOASSERTION",
        license_name="ICANN Terms of Service",
        license_url=ICANN_TERMS_URL,
        validator=_validate_icann_gtlds,
    ),
    Source(
        id="iana_special_use",
        kind="special_use_domain_names",
        filename="special-use-domain.csv",
        url=(
            "https://www.iana.org/assignments/special-use-domain-names/"
            "special-use-domain.csv"
        ),
        parser_version="iana-special-use-csv-v1",
        content_types=("text/csv",),
        license_spdx="CC0-1.0",
        license_name="Creative Commons CC0 1.0 Universal",
        license_url="https://www.iana.org/help/licensing-terms",
        validator=_validate_iana_special_use,
    ),
)


def _download(url: str, expected_content_types: tuple[str, ...]) -> Download:
    request = Request(
        url,
        headers={
            "Accept": "*/*",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urlopen(request, timeout=60) as response:
            status = getattr(response, "status", None)
            if status != 200:
                raise SnapshotError(f"{url} returned HTTP status {status}")
            final_url = response.geturl()
            if not final_url.lower().startswith("https://"):
                raise SnapshotError(f"{url} redirected to insecure URL {final_url}")
            content_type = response.headers.get("Content-Type", "").strip()
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type not in expected_content_types:
                raise SnapshotError(
                    f"{url} returned unexpected content type {content_type!r}"
                )
            payload = response.read(MAX_DOWNLOAD_BYTES + 1)
            if len(payload) > MAX_DOWNLOAD_BYTES:
                raise SnapshotError(
                    f"{url} exceeds the {MAX_DOWNLOAD_BYTES}-byte download limit"
                )
            if not payload:
                raise SnapshotError(f"{url} returned an empty response")
            return Download(
                payload=payload,
                retrieved_at=_now(),
                content_type=content_type,
                http_last_modified=_normalize_http_date(
                    response.headers.get("Last-Modified")
                ),
                http_etag=response.headers.get("ETag"),
            )
    except HTTPError as error:
        raise SnapshotError(f"{url} returned HTTP {error.code}") from error
    except URLError as error:
        raise SnapshotError(f"could not fetch {url}: {error.reason}") from error


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _record_for_download(
    source: Source, download: Download, upstream: dict[str, str]
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": source.id,
        "kind": source.kind,
        "path": source.repository_path,
        "url": source.url,
        "retrieved_at": download.retrieved_at,
        "sha256": _sha256(download.payload),
        "parser_version": source.parser_version,
        "content_type": download.content_type,
        "license_spdx": source.license_spdx,
        "license_name": source.license_name,
        "license_url": source.license_url,
    }
    record.update(upstream)
    if download.http_last_modified is not None:
        record["http_last_modified"] = download.http_last_modified
    if download.http_etag is not None:
        record["http_etag"] = download.http_etag
    return record


def _toml_string(value: str) -> str:
    """Render a TOML-compatible basic string."""
    return json.dumps(value, ensure_ascii=False)


_MANIFEST_FIELD_ORDER = (
    "id",
    "kind",
    "path",
    "url",
    "retrieved_at",
    "upstream_version",
    "upstream_commit",
    "upstream_updated_at",
    "http_last_modified",
    "http_etag",
    "sha256",
    "parser_version",
    "content_type",
    "license_spdx",
    "license_name",
    "license_url",
    "license_path",
    "license_source_url",
    "license_retrieved_at",
    "license_http_etag",
    "license_sha256",
)


def _render_manifest(generated_at: str, records: list[dict[str, Any]]) -> bytes:
    lines = [
        "# Generated by tools/update_snapshots.py; do not edit by hand.",
        f"schema_version = {SCHEMA_VERSION}",
        f"generated_at = {_toml_string(generated_at)}",
        "",
    ]
    for record in records:
        unknown = set(record).difference(_MANIFEST_FIELD_ORDER)
        if unknown:
            raise SnapshotError(f"cannot render unknown manifest fields: {unknown}")
        lines.append("[[snapshots]]")
        for key in _MANIFEST_FIELD_ORDER:
            if key not in record:
                continue
            value = record[key]
            if not isinstance(value, str):
                raise SnapshotError(f"manifest field {key!r} is not a string")
            lines.append(f"{key} = {_toml_string(value)}")
        lines.append("")
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _update_snapshots() -> None:
    downloads: dict[str, Download] = {}
    upstream_metadata: dict[str, dict[str, str]] = {}

    for source in SOURCES:
        print(f"Fetching {source.id}: {source.url}")
        download = _download(source.url, source.content_types)
        upstream = source.validator(download.payload)
        downloads[source.id] = download
        upstream_metadata[source.id] = upstream

    psl_commit = upstream_metadata["psl"]["upstream_commit"]
    license_source_url = PSL_LICENSE_URL_TEMPLATE.format(commit=psl_commit)
    print(f"Fetching psl_license: {license_source_url}")
    license_download = _download(license_source_url, ("text/plain",))
    _validate_psl_license(license_download.payload)

    records = [
        _record_for_download(source, downloads[source.id], upstream_metadata[source.id])
        for source in SOURCES
    ]
    psl_record = next(record for record in records if record["id"] == "psl")
    psl_record.update(
        {
            "license_path": "data/snapshots/LICENSE.publicsuffix",
            "license_source_url": license_source_url,
            "license_retrieved_at": license_download.retrieved_at,
            "license_sha256": _sha256(license_download.payload),
        }
    )
    if license_download.http_etag is not None:
        psl_record["license_http_etag"] = license_download.http_etag

    manifest = _render_manifest(_now(), records)

    for source in SOURCES:
        _write_atomic(source.filesystem_path, downloads[source.id].payload)
    _write_atomic(PSL_LICENSE_PATH, license_download.payload)
    _write_atomic(MANIFEST_PATH, manifest)
    print(
        f"Updated {len(SOURCES)} snapshots and {MANIFEST_PATH.relative_to(REPOSITORY_ROOT)}"
    )


def _parse_simple_manifest(text: str) -> dict[str, Any]:
    """Parse the intentionally small generated TOML subset on Python 3.10."""
    document: dict[str, Any] = {"snapshots": []}
    current: dict[str, Any] | None = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[snapshots]]":
            current = {}
            document["snapshots"].append(current)
            continue
        if "=" not in line:
            raise SnapshotError(f"invalid manifest syntax on line {line_number}")
        key, raw_value = (part.strip() for part in line.split("=", 1))
        target = document if current is None else current
        if key in target:
            raise SnapshotError(f"duplicate manifest key {key!r} on line {line_number}")
        if raw_value.isdigit():
            value: Any = int(raw_value)
        else:
            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError as error:
                raise SnapshotError(
                    f"invalid manifest value on line {line_number}: {error}"
                ) from error
        target[key] = value
    return document


def _load_manifest() -> dict[str, Any]:
    try:
        payload = MANIFEST_PATH.read_bytes()
    except FileNotFoundError as error:
        raise SnapshotError(f"missing manifest: {MANIFEST_PATH}") from error
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SnapshotError(f"manifest is not UTF-8: {error}") from error

    try:
        import tomllib
    except ModuleNotFoundError:
        document = _parse_simple_manifest(text)
    else:
        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            raise SnapshotError(f"manifest is invalid TOML: {error}") from error
    if not isinstance(document, dict):
        raise SnapshotError("manifest root is not a table")
    return document


def _load_policy_document(path: Path, description: str) -> dict[str, Any]:
    """Load policy TOML for the dependency-aware release checks."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise SnapshotError(f"missing {description}: {path}") from error
    except UnicodeDecodeError as error:
        raise SnapshotError(f"{description} are not UTF-8: {error}") from error

    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[import-not-found,no-redef]
        except ModuleNotFoundError as error:
            raise SnapshotError(
                "dependency-aware policy freshness checks require Python 3.11+ "
                "or the 'tomli' package"
            ) from error
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise SnapshotError(f"{description} are invalid TOML: {error}") from error
    if not isinstance(document, dict):
        raise SnapshotError(f"{description} root is not a table")
    return document


def _policy_table_array(
    document: dict[str, Any], field: str, description: str
) -> list[dict[str, Any]]:
    records = document.get(field)
    if not isinstance(records, list) or not all(
        isinstance(record, dict) for record in records
    ):
        raise SnapshotError(f"{description} contain no {field} table array")
    return records


def _flatten_policy_profiles(
    authored: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve profile inheritance using the compiler's replacement rules."""
    by_id: dict[str, dict[str, Any]] = {}
    for profile in authored:
        profile_id = _require_string(profile, "id", "<unknown-profile>")
        if profile_id in by_id:
            raise SnapshotError(f"policy profiles repeat id {profile_id!r}")
        by_id[profile_id] = profile

    cache: dict[str, dict[str, Any]] = {}
    visiting: set[str] = set()

    def resolve(profile_id: str) -> dict[str, Any]:
        if profile_id in cache:
            return cache[profile_id]
        if profile_id in visiting:
            raise SnapshotError(f"policy profile inheritance cycle at {profile_id!r}")
        profile = by_id.get(profile_id)
        if profile is None:
            raise SnapshotError(
                f"policy profile refers to unknown parent {profile_id!r}"
            )
        visiting.add(profile_id)
        parent_id = profile.get("extends")
        if parent_id is None:
            flattened: dict[str, Any] = {}
        elif isinstance(parent_id, str) and parent_id:
            flattened = dict(resolve(parent_id))
        else:
            raise SnapshotError(f"policy profile {profile_id!r} has invalid 'extends'")
        flattened["id"] = profile_id
        for field in (
            "offering_state",
            "public_access",
            "application_channel",
            "eligibility",
            "label_policy",
        ):
            if field in profile:
                flattened[field] = profile[field]
        visiting.remove(profile_id)
        cache[profile_id] = flattened
        return flattened

    return [resolve(profile_id) for profile_id in sorted(by_id)]


def _claim_is_verified(claim: Any) -> bool:
    if not isinstance(claim, dict):
        return False
    status = claim.get("status")
    if status is None:
        status = "verified" if "value" in claim else "unknown"
    return status == "verified"


def _evidence_ids(value: Any, description: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise SnapshotError(f"{description} has invalid evidence IDs")
    return value


def _required_current_evidence(
    profiles: list[dict[str, Any]],
) -> dict[str, set[str]]:
    """Map evidence IDs to flattened, active claim uses."""
    uses: dict[str, set[str]] = {}

    def record(profile_id: str, predicate: str, raw_ids: Any) -> None:
        for evidence_id in _evidence_ids(
            raw_ids, f"profile {profile_id!r} {predicate}"
        ):
            uses.setdefault(evidence_id, set()).add(f"{profile_id}.{predicate}")

    for profile in profiles:
        profile_id = _require_string(profile, "id", "<unknown-profile>")
        for predicate in (
            "offering_state",
            "public_access",
            "application_channel",
        ):
            claim = profile.get(predicate)
            if _claim_is_verified(claim):
                assert isinstance(claim, dict)
                record(profile_id, predicate, claim.get("evidence", []))

        eligibility = profile.get("eligibility")
        if eligibility is not None and _claim_is_verified(profile.get("public_access")):
            if not isinstance(eligibility, dict):
                raise SnapshotError(f"profile {profile_id!r} has invalid eligibility")
            requirements = eligibility.get("requirements")
            if not isinstance(requirements, list):
                raise SnapshotError(
                    f"profile {profile_id!r} eligibility has invalid requirements"
                )
            for requirement in requirements:
                if not isinstance(requirement, dict):
                    raise SnapshotError(
                        f"profile {profile_id!r} eligibility has invalid requirement"
                    )
                record(profile_id, "eligibility", requirement.get("evidence", []))

        policy = profile.get("label_policy")
        if policy is None:
            continue
        if not isinstance(policy, dict):
            raise SnapshotError(f"profile {profile_id!r} has invalid label_policy")
        if policy.get("completeness") == "verified":
            record(
                profile_id,
                "label_policy",
                policy.get("completeness_evidence", []),
            )
        length = policy.get("length")
        if length is not None:
            if not isinstance(length, dict):
                raise SnapshotError(f"profile {profile_id!r} has invalid label length")
            record(profile_id, "label_length", length.get("evidence", []))
        idn_support = policy.get("idn_support")
        if _claim_is_verified(idn_support):
            assert isinstance(idn_support, dict)
            record(profile_id, "idn_support", idn_support.get("evidence", []))
            idn_profile = policy.get("idn_profile")
            if idn_profile is not None:
                if not isinstance(idn_profile, dict):
                    raise SnapshotError(
                        f"profile {profile_id!r} has invalid IDN profile"
                    )
                record(profile_id, "idn_profile", idn_profile.get("evidence", []))
        if policy.get("reserved_status") == "verified":
            record(
                profile_id,
                "reserved_labels",
                policy.get("reserved_set_evidence", []),
            )
            reserved_labels = policy.get("reserved_labels", [])
            if not isinstance(reserved_labels, list):
                raise SnapshotError(
                    f"profile {profile_id!r} has invalid reserved labels"
                )
            for reserved in reserved_labels:
                if not isinstance(reserved, dict):
                    raise SnapshotError(
                        f"profile {profile_id!r} has invalid reserved label"
                    )
                record(profile_id, "reserved_labels", reserved.get("evidence", []))
    return uses


def _parse_policy_timestamp(value: str, description: str) -> datetime:
    if re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        value,
    ) is None or value.endswith("-00:00"):
        raise SnapshotError(f"{description} is not RFC 3339: {value!r}")
    try:
        return _parse_datetime(value)
    except SnapshotError as error:
        raise SnapshotError(f"{description} is not RFC 3339: {value!r}") from error


def _parse_policy_date(value: str, description: str) -> date:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
        raise SnapshotError(f"{description} is not an ISO date: {value!r}")
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as error:
        raise SnapshotError(f"{description} is not an ISO date: {value!r}") from error


def _check_policy_source_freshness(
    catalog_generated_at: datetime,
    release_time: datetime | None = None,
) -> None:
    """Require current evidence only for flattened active claim dependencies."""
    if release_time is None:
        release_time = datetime.now(timezone.utc)
    sources_document = _load_policy_document(POLICY_SOURCES_PATH, "policy sources")
    profiles_document = _load_policy_document(POLICY_PROFILES_PATH, "policy profiles")
    source_records = _policy_table_array(sources_document, "sources", "policy sources")
    evidence_records = _policy_table_array(
        sources_document, "evidence", "policy sources"
    )
    profile_records = _policy_table_array(
        profiles_document, "profiles", "policy profiles"
    )

    sources: dict[str, tuple[datetime, date]] = {}
    for record in source_records:
        source_id = _require_string(record, "id", "<unknown-policy-source>")
        if source_id in sources:
            raise SnapshotError(f"policy sources repeat id {source_id!r}")
        retrieved_at = _parse_policy_timestamp(
            _require_string(record, "retrieved_at", source_id),
            f"policy source {source_id!r} retrieved_at",
        )
        if retrieved_at > catalog_generated_at:
            raise SnapshotError(
                f"policy source {source_id!r} was retrieved after catalog generation"
            )
        if retrieved_at > release_time:
            raise SnapshotError(
                f"policy source {source_id!r} has a future retrieval timestamp"
            )
        review_after = _parse_policy_date(
            _require_string(record, "review_after", source_id),
            f"policy source {source_id!r} review_after",
        )
        if review_after < retrieved_at.astimezone(timezone.utc).date():
            raise SnapshotError(
                f"policy source {source_id!r} has review_after before its retrieval date"
            )
        sources[source_id] = (retrieved_at, review_after)

    evidence_sources: dict[str, str] = {}
    for record in evidence_records:
        evidence_id = _require_string(record, "id", "<unknown-evidence>")
        if evidence_id in evidence_sources:
            raise SnapshotError(f"policy evidence repeats id {evidence_id!r}")
        source_id = _require_string(record, "source", evidence_id)
        if source_id not in sources:
            raise SnapshotError(
                f"policy evidence {evidence_id!r} refers to unknown source {source_id!r}"
            )
        evidence_sources[evidence_id] = source_id

    required = _required_current_evidence(_flatten_policy_profiles(profile_records))
    for evidence_id, dependent_claims in sorted(required.items()):
        active_source_id = evidence_sources.get(evidence_id)
        if active_source_id is None:
            raise SnapshotError(
                f"active policy claim refers to unknown evidence {evidence_id!r}"
            )
        review_after = sources[active_source_id][1]
        if review_after < release_time.astimezone(timezone.utc).date():
            uses = ", ".join(sorted(dependent_claims))
            raise SnapshotError(
                f"policy source {active_source_id!r} expired on "
                f"{review_after.isoformat()} "
                f"but still supports active claim(s): {uses}"
            )

    if not sources:
        raise SnapshotError("policy sources contain no records")


def _require_string(record: dict[str, Any], field: str, source_id: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise SnapshotError(f"snapshot {source_id!r} has invalid {field!r}")
    return value


def _validate_rfc3339(value: str, description: str) -> datetime:
    try:
        parsed = _parse_datetime(value)
    except SnapshotError as error:
        raise SnapshotError(f"{description} is not RFC 3339: {value!r}") from error
    if _format_datetime(parsed) != value:
        raise SnapshotError(f"{description} is not normalized UTC: {value!r}")
    return parsed


def _safe_repository_path(value: str, description: str) -> Path:
    relative = Path(value)
    if relative.is_absolute():
        raise SnapshotError(f"{description} must be repository-relative")
    resolved = (REPOSITORY_ROOT / relative).resolve()
    try:
        resolved.relative_to(REPOSITORY_ROOT.resolve())
    except ValueError as error:
        raise SnapshotError(f"{description} escapes the repository") from error
    return resolved


def _check_snapshots() -> None:
    document = _load_manifest()
    if document.get("schema_version") != SCHEMA_VERSION:
        raise SnapshotError(
            f"unsupported manifest schema_version {document.get('schema_version')!r}"
        )
    generated_at = document.get("generated_at")
    if not isinstance(generated_at, str):
        raise SnapshotError("manifest has no generated_at timestamp")
    generated_time = _validate_rfc3339(generated_at, "manifest generated_at")
    release_time = datetime.now(timezone.utc)
    if generated_time > release_time:
        raise SnapshotError("manifest generation timestamp is in the future")

    records = document.get("snapshots")
    if not isinstance(records, list):
        raise SnapshotError("manifest snapshots is not an array of tables")
    if len(records) != len(SOURCES):
        raise SnapshotError(
            f"manifest has {len(records)} snapshots; expected {len(SOURCES)}"
        )

    by_id: dict[str, dict[str, Any]] = {}
    for raw_record in records:
        if not isinstance(raw_record, dict):
            raise SnapshotError("manifest contains a non-table snapshot record")
        source_id = _require_string(raw_record, "id", "<unknown>")
        if source_id in by_id:
            raise SnapshotError(f"manifest repeats snapshot id {source_id!r}")
        by_id[source_id] = raw_record

    expected_ids = {source.id for source in SOURCES}
    if set(by_id) != expected_ids:
        missing = sorted(expected_ids.difference(by_id))
        unexpected = sorted(set(by_id).difference(expected_ids))
        raise SnapshotError(
            f"manifest snapshot IDs differ (missing={missing}, unexpected={unexpected})"
        )

    for source in SOURCES:
        record = by_id[source.id]
        expected_static = {
            "kind": source.kind,
            "path": source.repository_path,
            "url": source.url,
            "parser_version": source.parser_version,
            "license_spdx": source.license_spdx,
            "license_name": source.license_name,
            "license_url": source.license_url,
        }
        for field, expected in expected_static.items():
            actual = _require_string(record, field, source.id)
            if actual != expected:
                raise SnapshotError(
                    f"snapshot {source.id!r} has {field}={actual!r}; expected {expected!r}"
                )

        retrieved_at = _require_string(record, "retrieved_at", source.id)
        retrieved_time = _validate_rfc3339(
            retrieved_at, f"snapshot {source.id!r} retrieved_at"
        )
        if retrieved_time > generated_time:
            raise SnapshotError(
                f"snapshot {source.id!r} was retrieved after manifest generation"
            )
        last_modified = record.get("http_last_modified")
        if last_modified is not None:
            if not isinstance(last_modified, str):
                raise SnapshotError(
                    f"snapshot {source.id!r} has invalid http_last_modified"
                )
            last_modified_time = _validate_rfc3339(
                last_modified, f"snapshot {source.id!r} http_last_modified"
            )
            if last_modified_time > retrieved_time:
                raise SnapshotError(
                    f"snapshot {source.id!r} was retrieved before its Last-Modified time"
                )
        upstream_updated_at = record.get("upstream_updated_at")
        if upstream_updated_at is not None:
            if not isinstance(upstream_updated_at, str):
                raise SnapshotError(
                    f"snapshot {source.id!r} has invalid upstream_updated_at"
                )
            upstream_updated_time = _validate_rfc3339(
                upstream_updated_at,
                f"snapshot {source.id!r} upstream_updated_at",
            )
            if upstream_updated_time > retrieved_time:
                raise SnapshotError(
                    f"snapshot {source.id!r} predates its upstream update"
                )
        content_type = _require_string(record, "content_type", source.id)
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type not in source.content_types:
            raise SnapshotError(
                f"snapshot {source.id!r} has unexpected content_type {content_type!r}"
            )
        for optional_string in ("http_etag",):
            if optional_string in record:
                _require_string(record, optional_string, source.id)

        snapshot_path = _safe_repository_path(
            _require_string(record, "path", source.id),
            f"snapshot {source.id!r} path",
        )
        try:
            payload = snapshot_path.read_bytes()
        except FileNotFoundError as error:
            raise SnapshotError(
                f"snapshot {source.id!r} file is missing: {snapshot_path}"
            ) from error

        expected_hash = _require_string(record, "sha256", source.id)
        if re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
            raise SnapshotError(f"snapshot {source.id!r} has invalid SHA-256 metadata")
        actual_hash = _sha256(payload)
        if actual_hash != expected_hash:
            raise SnapshotError(
                f"snapshot {source.id!r} SHA-256 mismatch: "
                f"manifest={expected_hash}, actual={actual_hash}"
            )

        extracted = source.validator(payload)
        upstream_fields = {
            key: value for key, value in record.items() if key.startswith("upstream_")
        }
        if upstream_fields != extracted:
            raise SnapshotError(
                f"snapshot {source.id!r} upstream metadata differs: "
                f"manifest={upstream_fields}, extracted={extracted}"
            )

    psl_record = by_id["psl"]
    license_path_value = _require_string(psl_record, "license_path", "psl")
    if license_path_value != "data/snapshots/LICENSE.publicsuffix":
        raise SnapshotError("PSL license_path does not name the vendored license")
    license_path = _safe_repository_path(license_path_value, "PSL license_path")
    try:
        license_payload = license_path.read_bytes()
    except FileNotFoundError as error:
        raise SnapshotError(f"PSL license file is missing: {license_path}") from error
    _validate_psl_license(license_payload)

    license_hash = _require_string(psl_record, "license_sha256", "psl")
    if re.fullmatch(r"[0-9a-f]{64}", license_hash) is None:
        raise SnapshotError("PSL license has invalid SHA-256 metadata")
    actual_license_hash = _sha256(license_payload)
    if actual_license_hash != license_hash:
        raise SnapshotError(
            "PSL license SHA-256 mismatch: "
            f"manifest={license_hash}, actual={actual_license_hash}"
        )

    psl_commit = _require_string(psl_record, "upstream_commit", "psl")
    expected_license_source = PSL_LICENSE_URL_TEMPLATE.format(commit=psl_commit)
    license_source = _require_string(psl_record, "license_source_url", "psl")
    if license_source != expected_license_source:
        raise SnapshotError(
            f"PSL license source {license_source!r} does not match commit {psl_commit}"
        )
    license_retrieved_at = _require_string(psl_record, "license_retrieved_at", "psl")
    license_retrieved_time = _validate_rfc3339(
        license_retrieved_at, "PSL license_retrieved_at"
    )
    if license_retrieved_time > generated_time:
        raise SnapshotError("PSL license was retrieved after manifest generation")
    if "license_http_etag" in psl_record:
        _require_string(psl_record, "license_http_etag", "psl")

    _check_policy_source_freshness(generated_time, release_time)

    print(
        f"Snapshot check passed: {len(SOURCES)} snapshots and "
        f"{PSL_LICENSE_PATH.relative_to(REPOSITORY_ROOT)}; "
        "active policy evidence is within its review window"
    )


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate checked-in snapshots without accessing the network",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the updater or its offline validation mode."""
    arguments = _build_argument_parser().parse_args(argv)
    try:
        if arguments.check:
            _check_snapshots()
        else:
            _update_snapshots()
    except (OSError, SnapshotError) as error:
        print(f"snapshot update failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
