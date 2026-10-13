"""Normalization and structure invariants for registry checks."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from tldhax import Registry

KNOWN_SUFFIXES = ("ai", "com", "co.uk", "com.ai", "net.ai", "off.ai", "org.ai")
ROOT_SUFFIXES = ("ai", "com", "de", "net", "org", "uk", "name")
REVIEWED_SINGLE_LABEL_NAMESPACES = ("co.uk", "de")
ASCII_LABELS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
    min_size=3,
    max_size=20,
).filter(lambda label: label[0] != "-" and label[-1] != "-" and label[2:4] != "--")


def test_uppercase_is_normalized(registry) -> None:
    """Uppercase input should normalize to the same result as lowercase input."""
    assert registry.check("FOO.CO.UK").status == registry.check("foo.co.uk").status


def test_trailing_dot_is_ignored(registry) -> None:
    """A trailing dot should not affect the computed registerability result."""
    assert registry.check("example.com.").status == registry.check("example.com").status


def test_bare_tld_is_rejected(registry) -> None:
    """A bare delegated root fails the prospective-candidate input contract."""
    result = registry.check("com")
    assert result.status == "no"
    assert registry.assess("com").to_dict()["findings"][0]["code"] == "bare_root"


def test_subdomain_is_rejected(registry) -> None:
    """A reviewed complete single-label form rejects an extra applicant label."""
    result = registry.check("foo.bar.co.uk")
    assert result.status == "no"
    assert any(
        finding["code"] == "unsupported_registration_form"
        for finding in registry.assess("foo.bar.co.uk").to_dict()["findings"]
    )


@given(label=ASCII_LABELS, suffix=st.sampled_from(KNOWN_SUFFIXES))
def test_uppercase_normalization_property(label: str, suffix: str) -> None:
    """Uppercasing a valid domain should preserve the full check result."""
    registry = Registry()
    domain = f"{label}.{suffix}"
    normalized = registry.check(domain)
    uppercased = registry.check(domain.upper())

    assert uppercased.status == normalized.status
    assert uppercased.reasons == normalized.reasons


@given(label=ASCII_LABELS, suffix=st.sampled_from(KNOWN_SUFFIXES))
def test_trailing_dot_normalization_property(label: str, suffix: str) -> None:
    """Appending a trailing dot should preserve the full check result."""
    registry = Registry()
    domain = f"{label}.{suffix}"
    normalized = registry.check(domain)
    with_trailing_dot = registry.check(f"{domain}.")

    assert with_trailing_dot.status == normalized.status
    assert with_trailing_dot.reasons == normalized.reasons


@given(suffix=st.sampled_from(ROOT_SUFFIXES))
def test_bare_tld_rejection_property(suffix: str) -> None:
    """Every known root needs an applicant label under the candidate contract."""
    registry = Registry()
    result = registry.check(suffix)

    assert result.status == "no"
    assert registry.assess(suffix).to_dict()["findings"][0]["code"] == "bare_root"


@given(label=ASCII_LABELS, suffix=st.sampled_from(REVIEWED_SINGLE_LABEL_NAMESPACES))
def test_subdomain_rejection_property(label: str, suffix: str) -> None:
    """Complete reviewed form sets, rather than PSL discovery, reject extra labels."""
    registry = Registry()
    result = registry.check(f"sub.{label}.{suffix}")

    assert result.status == "no"
    assert any(
        finding["code"] == "unsupported_registration_form"
        for finding in registry.assess(f"sub.{label}.{suffix}").to_dict()["findings"]
    )


@given(label=ASCII_LABELS)
def test_unresearched_extra_labels_remain_unknown(label: str) -> None:
    """An inventory boundary does not establish an exhaustive form prohibition."""
    assert Registry().assess(f"sub.{label}.aaa").status == "unknown"
