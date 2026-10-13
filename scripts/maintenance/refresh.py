"""Observe upstream drift with bounded public GETs; never promote snapshots."""

from __future__ import annotations

import hashlib
import http.client
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from scripts.data.fetch import fetch
from scripts.data.reconcile import changes, verify

from .report import date, records


def inventory(root: Path, staging: Path, as_of: str) -> dict:
    """Fetch a new verified tree while retaining the approved evaluation date."""
    date(as_of)
    pinned = verify(root)
    if as_of < pinned["evaluation_date"]:
        raise ValueError("refresh date precedes pinned evaluation")
    try:
        fetch(staging, pinned["evaluation_date"], as_of)
    except http.client.HTTPException as exc:
        raise OSError("incomplete inventory HTTP response") from exc
    return {
        "staging_directory": str(staging),
        "changes": changes(root, staging),
        "approval_status": "review_required",
    }


def download(url: str, *, timeout: float = 15, max_bytes: int = 5_000_000) -> bytes:
    """Read one reviewed source URL with finite transfer limits and no credentials."""
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or timeout <= 0
        or max_bytes <= 0
    ):
        raise ValueError("invalid public HTTPS source or download bounds")
    request = urllib.request.Request(
        url, headers={"User-Agent": "tldhax-source-review/1"}
    )
    started = time.monotonic()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        redirected = urllib.parse.urlsplit(response.geturl())
        if redirected.scheme != "https" or redirected.hostname != parsed.hostname:
            raise ValueError("source redirected outside its pinned HTTPS host")
        content, size = [], 0
        while True:
            if time.monotonic() - started > timeout:
                raise TimeoutError("source transfer deadline exceeded")
            chunk = response.read(min(65_536, max_bytes + 1 - size))
            if not chunk:
                break
            content.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("source exceeds download byte limit")
    if not size:
        raise ValueError("empty source response")
    return b"".join(content)


def policies(root: Path, as_of: str) -> list[dict]:
    """Compare exact original bytes, preserving inaccessible/extracted-text gaps."""
    date(as_of)
    observations = []
    assertions = records(root, "assertions")
    for source in sorted(records(root, "sources"), key=lambda s: s["id"]):
        result = {
            "source_id": source["id"],
            "checked_on": as_of,
            "pinned_sha256": source["sha256"],
            "hash_representation": source.get("hash_representation", "original_bytes"),
            "affected_assertion_ids": sorted(
                a["id"] for a in assertions if a.get("source_id") == source["id"]
            ),
        }
        if result["hash_representation"] != "original_bytes":
            result["status"] = "manual_representation_check_required"
        else:
            try:
                observed = hashlib.sha256(
                    download(source.get("fetched_url", source["url"]))
                ).hexdigest()
                result["observed_sha256"] = observed
                result["status"] = (
                    "unchanged"
                    if observed == source["sha256"]
                    else "changed_review_required"
                )
            except urllib.error.HTTPError as exc:
                result.update(status="inaccessible", http_status=exc.code)
            except (
                OSError,
                ValueError,
                urllib.error.URLError,
                http.client.HTTPException,
            ):
                result["status"] = "check_failed"
        observations.append(result)
    return observations
