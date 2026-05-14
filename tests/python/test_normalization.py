"""Normalization and structure invariants for registry checks."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from tldhax import Registry

REGISTERABLE_SUFFIXES = ("ai", "com", "co.uk", "com.ai", "net.ai", "off.ai", "org.ai")
ASCII_LABELS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
    min_size=3,
    max_size=20,
).filter(
    lambda label: label[0] != "-" and label[-1] != "-" and not label.startswith("xn--")
)


def test_uppercase_is_normalized(registry) -> None:
    """Uppercase input should normalize to the same result as lowercase input."""
    assert registry.check("FOO.CO.UK").status == registry.check("foo.co.uk").status


def test_trailing_dot_is_ignored(registry) -> None:
    """A trailing dot should not affect the computed registerability result."""
    assert registry.check("example.com.").status == registry.check("example.com").status


def test_bare_tld_is_rejected(registry) -> None:
    """A bare suffix should be rejected because it has no registrable label."""
    result = registry.check("co.uk")
    assert result.status == "no"
    assert "TLD" in result.reasons[0]


def test_subdomain_is_rejected(registry) -> None:
    """Subdomains should be rejected in favor of the registrable domain."""
    result = registry.check("foo.bar.co.uk")
    assert result.status == "no"
    assert "subdomain" in result.reasons[0]


@given(label=ASCII_LABELS, suffix=st.sampled_from(REGISTERABLE_SUFFIXES))
def test_uppercase_normalization_property(label: str, suffix: str) -> None:
    """Uppercasing a valid domain should preserve the full check result."""
    registry = Registry()
    domain = f"{label}.{suffix}"
    normalized = registry.check(domain)
    uppercased = registry.check(domain.upper())

    assert uppercased.status == normalized.status
    assert uppercased.reasons == normalized.reasons


@given(label=ASCII_LABELS, suffix=st.sampled_from(REGISTERABLE_SUFFIXES))
def test_trailing_dot_normalization_property(label: str, suffix: str) -> None:
    """Appending a trailing dot should preserve the full check result."""
    registry = Registry()
    domain = f"{label}.{suffix}"
    normalized = registry.check(domain)
    with_trailing_dot = registry.check(f"{domain}.")

    assert with_trailing_dot.status == normalized.status
    assert with_trailing_dot.reasons == normalized.reasons


@given(suffix=st.sampled_from(REGISTERABLE_SUFFIXES))
def test_bare_tld_rejection_property(suffix: str) -> None:
    """Known registrable suffixes alone should still be rejected as bare TLDs."""
    registry = Registry()
    result = registry.check(suffix)

    assert result.status == "no"
    assert "TLD" in result.reasons[0]


@given(label=ASCII_LABELS, suffix=st.sampled_from(REGISTERABLE_SUFFIXES))
def test_subdomain_rejection_property(label: str, suffix: str) -> None:
    """Adding one more label should turn a registrable domain into a subdomain."""
    registry = Registry()
    result = registry.check(f"sub.{label}.{suffix}")

    assert result.status == "no"
    assert "subdomain" in result.reasons[0]
