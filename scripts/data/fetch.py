"""Bounded downloads to a fresh staging tree; publishing requires review."""

from __future__ import annotations

import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .reconcile import reconcile, verify
from .sources import PARSERS, SOURCES


def download(
    url: str, *, timeout: float = 20, max_bytes: int = 5_000_000, attempts: int = 3
) -> bytes:
    """Fetch one public source with finite retries, deadlines and byte limits."""
    if timeout <= 0 or max_bytes <= 0 or not 1 <= attempts <= 5:
        raise ValueError("invalid download limits")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname
        not in {"data.iana.org", "www.iana.org", "www.icann.org", "publicsuffix.org"}
        or parsed.username
        or parsed.password
    ):
        raise ValueError("only supported public HTTPS sources may be fetched")
    for attempt in range(attempts):
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 tldhax-inventory/2", "Accept": "*/*"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                final = urllib.parse.urlsplit(response.geturl())
                if final.scheme != "https" or final.hostname != parsed.hostname:
                    raise ValueError("upstream redirected outside its HTTPS host")
                length = response.headers.get("Content-Length")
                expected = int(length) if length is not None else None
                if expected is not None and (expected < 0 or expected > max_bytes):
                    raise ValueError("snapshot exceeds byte limit")
                chunks, total = [], 0
                deadline = time.monotonic() + timeout
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError("snapshot transfer deadline exceeded")
                    chunk = response.read(min(65_536, max_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("snapshot exceeds byte limit")
                    chunks.append(chunk)
                content = b"".join(chunks)
                if not content or expected is not None and total != expected:
                    raise ValueError("empty or truncated snapshot")
                return content
        except urllib.error.HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt + 1 == attempts:
                raise
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt + 1 == attempts:
                raise
        time.sleep(min(2**attempt, 4))
    raise AssertionError("unreachable retry state")


def fetch(
    destination: Path,
    evaluation_date: str,
    retrieved_on: str,
    *,
    timeout: float = 20,
    max_bytes: int = 5_000_000,
) -> dict:
    """Stage a complete verified dataset in a new directory without promotion."""
    if destination.exists():
        raise ValueError("staging destination must not exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".tldhax-fetch-", dir=destination.parent))
    try:
        for source_id, (path, url) in SOURCES.items():
            content = download(url, timeout=timeout, max_bytes=max_bytes)
            PARSERS[source_id](content.decode("utf-8"))
            target = temporary / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        record = reconcile(temporary, evaluation_date, retrieved_on)
        verify(temporary)
        if destination.exists():
            raise ValueError("staging destination appeared during download")
        temporary.rename(destination)
        return record
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
