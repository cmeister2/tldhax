"""Normalization and structure invariants for registry checks."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from tldhax import Registry

UNRESEARCHED_SUFFIXES = ("xyz", "ai", "com.ai", "net.ai", "off.ai", "org.ai")
KNOWN_ROOTS = ("xyz", "ai")
ASCII_LABELS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
    min_size=3,
    max_size=20,
).filter(
    lambda label: (
        label[0] != "-"
        and label[-1] != "-"
        and label[2:4] != "--"
        and not label.startswith("xn--")
    )
)


def test_uppercase_is_normalized(registry) -> None:
    """Uppercase input should normalize to the same result as lowercase input."""
    assert registry.check("FOO.CO.UK").status == registry.check("foo.co.uk").status


def test_trailing_dot_is_ignored(registry) -> None:
    """A trailing dot should not affect the computed registerability result."""
    assert registry.check("example.com.").status == registry.check("example.com").status


def test_bare_tld_is_rejected(registry) -> None:
    """The candidate API requires an applicant beneath a known IANA root."""
    result = registry.check("xyz")
    assert result.status == "no"
    assert "applicant label" in result.reasons[0]


def test_discovered_namespace_and_deeper_candidates_need_policy_evidence(
    registry,
) -> None:
    """PSL discovery alone establishes no prohibited registration shape."""
    assert registry.check("com.ai").status == "unknown"
    assert registry.check("foo.bar.com.ai").status == "unknown"


@given(label=ASCII_LABELS, suffix=st.sampled_from(UNRESEARCHED_SUFFIXES))
def test_uppercase_normalization_property(label: str, suffix: str) -> None:
    """Uppercasing a valid domain should preserve the full check result."""
    registry = Registry()
    domain = f"{label}.{suffix}"
    normalized = registry.check(domain)
    uppercased = registry.check(domain.upper())

    assert uppercased.status == normalized.status
    assert uppercased.reasons == normalized.reasons


@given(label=ASCII_LABELS, suffix=st.sampled_from(UNRESEARCHED_SUFFIXES))
def test_trailing_dot_normalization_property(label: str, suffix: str) -> None:
    """Appending a trailing dot should preserve the full check result."""
    registry = Registry()
    domain = f"{label}.{suffix}"
    normalized = registry.check(domain)
    with_trailing_dot = registry.check(f"{domain}.")

    assert with_trailing_dot.status == normalized.status
    assert with_trailing_dot.reasons == normalized.reasons


@given(suffix=st.sampled_from(KNOWN_ROOTS))
def test_bare_tld_rejection_property(suffix: str) -> None:
    """Known roots require applicant labels independently of policy research."""
    registry = Registry()
    result = registry.check(suffix)

    assert result.status == "no"
    assert "applicant label" in result.reasons[0]


@given(label=ASCII_LABELS, suffix=st.sampled_from(UNRESEARCHED_SUFFIXES))
def test_unresearched_deeper_name_property(label: str, suffix: str) -> None:
    """Valid deeper names cannot be prohibited using discovery data alone."""
    registry = Registry()
    result = registry.check(f"sub.{label}.{suffix}")

    assert result.status == "unknown"
