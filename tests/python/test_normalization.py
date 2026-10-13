"""Canonical identity and DNS structure invariants through the public interface."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tldhax import Registry

ASCII_LABELS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=3, max_size=20
)


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "example.com..",
        "example.com.。",
        "ab--cd.com",
        "xn--0.com",
        "a\u200db.com",
        "_bad.com",
    ],
)
def test_malformed_input_is_rejected(registry: Registry, domain: str) -> None:
    """IDNA and DNS failures remain useful negative registration decisions."""
    result = registry.assess(domain)
    assert result.decision == "no"
    assert result.reasons and all(reason.message for reason in result.reasons)


@given(label=ASCII_LABELS, suffix=st.sampled_from(["com", "de", "co.uk", "aaa"]))
def test_case_and_root_dot_preserve_full_assessment(label: str, suffix: str) -> None:
    """Canonical input transformations preserve all observable decision fields."""
    registry = Registry()
    domain = f"{label}.{suffix}"
    expected = registry.assess(domain).to_dict()
    assert registry.assess(domain.upper()).to_dict() == expected
    assert registry.assess(domain + ".").to_dict() == expected


def test_bare_root_and_registration_form(registry: Registry) -> None:
    """A missing applicant label and an unimplemented registration form differ."""
    bare = registry.assess("com")
    assert bare.decision == "no"
    assert any(reason.code == "missing_registration_label" for reason in bare.reasons)
    deeper = registry.assess("foo.bar.co.uk")
    assert deeper.decision == "unknown"
    assert any(
        reason.code == "unsupported_registration_form" for reason in deeper.reasons
    )
    assert registry.assess("sub.name.aaa").decision == "unknown"


@given(length=st.integers(min_value=64, max_value=200))
def test_dns_label_limit_is_conclusive_even_for_unknown_policy(length: int) -> None:
    """Protocol violations cannot be mistaken for mere missing policy."""
    assert Registry().assess("a" * length + ".aaa").decision == "no"


def test_mapped_terminal_root_dot_and_raw_input_budget(registry: Registry) -> None:
    """The boundary normalizes one root dot after checking raw byte limits."""
    assert (
        registry.assess("sunflower。com。").to_dict()
        == registry.assess("sunflower.com").to_dict()
    )
    with pytest.raises(ValueError, match="^input_limit$"):
        registry.assess(" " * 4097)
