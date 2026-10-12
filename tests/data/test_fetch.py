"""Inventory importer and reconciliation regression tests."""

import io
import urllib.error
from pathlib import Path

import pytest
from scripts.data import fetch as fetching
from scripts.data.reconcile import verify
from scripts.data.sources import SOURCES

from .samples import RAW

URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"


class Response(io.BytesIO):
    """Response."""

    def __init__(
        self, content: bytes, length: str | None = None, url: str = URL
    ) -> None:
        """Init."""
        super().__init__(content)
        self.headers = {} if length is None else {"Content-Length": length}
        self.url = url

    def geturl(self) -> str:
        """Geturl."""
        return self.url


def test_bounded_download(monkeypatch) -> None:
    """Bounded download."""
    monkeypatch.setattr(
        fetching.urllib.request,
        "urlopen",
        lambda request, timeout: Response(b"abc", "3"),
    )
    assert fetching.download(URL, max_bytes=3) == b"abc"


@pytest.mark.parametrize(
    "content,length,url,limit",
    [
        (b"abc", "4", URL, 5),
        (b"", "0", URL, 5),
        (b"abc", None, URL, 2),
        (b"abc", "100", URL, 5),
        (b"abc", "3", "http://data.iana.org/insecure", 5),
        (b"abc", "3", "https://example.org/snapshot", 5),
    ],
)
def test_truncation_limits_and_untrusted_redirects_fail(
    monkeypatch, content, length, url, limit
) -> None:
    """Truncation limits and untrusted redirects fail."""
    monkeypatch.setattr(
        fetching.urllib.request,
        "urlopen",
        lambda request, timeout: Response(content, length, url),
    )
    with pytest.raises(ValueError):
        fetching.download(URL, max_bytes=limit)


def test_retry_is_bounded_and_auth_errors_are_not_retried(monkeypatch) -> None:
    """Retry is bounded and auth errors are not retried."""
    calls = []

    def fail(request, timeout):
        """Fail."""
        calls.append(request)
        raise urllib.error.HTTPError(URL, 503, "Unavailable", {}, None)

    monkeypatch.setattr(fetching.urllib.request, "urlopen", fail)
    monkeypatch.setattr(fetching.time, "sleep", lambda seconds: None)
    with pytest.raises(urllib.error.HTTPError):
        fetching.download(URL, attempts=3)
    assert len(calls) == 3
    calls.clear()

    def forbidden(request, timeout):
        """Forbidden."""
        calls.append(request)
        raise urllib.error.HTTPError(URL, 403, "Forbidden", {}, None)

    monkeypatch.setattr(fetching.urllib.request, "urlopen", forbidden)
    with pytest.raises(urllib.error.HTTPError):
        fetching.download(URL, attempts=3)
    assert len(calls) == 1


def test_staging_does_not_publish_malformed_source(monkeypatch, tmp_path: Path) -> None:
    """Staging does not publish malformed source."""
    monkeypatch.setattr(fetching, "download", lambda url, **kwargs: b"malformed")
    destination = tmp_path / "candidate"
    with pytest.raises(ValueError):
        fetching.fetch(destination, "2026-10-12", "2026-10-12")
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_successful_staging_is_verified_and_never_overwrites(
    monkeypatch, tmp_path: Path
) -> None:
    """Successful staging is verified and never overwrites."""
    bodies = {url: RAW[source].encode() for source, (_, url) in SOURCES.items()}
    monkeypatch.setattr(fetching, "download", lambda url, **kwargs: bodies[url])
    destination = tmp_path / "candidate"
    record = fetching.fetch(destination, "2026-10-12", "2026-10-12")
    assert verify(destination) == record
    with pytest.raises(ValueError, match="must not exist"):
        fetching.fetch(destination, "2026-10-12", "2026-10-12")
