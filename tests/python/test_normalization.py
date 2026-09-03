"""Normalization and Public Suffix List topology invariants."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from tldhax import Registry

SUFFIXES = ("de", "com", "co.uk", "gov.uk", "中国", "xn--fiqs8s")
ASCII_LABELS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
    min_size=3,
    max_size=20,
).filter(
    lambda label: label[0] != "-" and label[-1] != "-" and not label.startswith("xn--")
)


def comparable_assessment(result) -> tuple[object, ...]:
    """Return fields that must be stable across spelling normalization."""
    return (
        result.ascii_domain,
        result.registrable_domain,
        result.candidate_status,
        result.public_suffix,
        result.suffix_rule,
        result.suffix_rule_kind,
        result.suffix_evidence,
        result.root_state,
        result.namespace_state,
        result.product_id,
        result.product_suffix,
        result.verdict,
        [(finding.code, finding.message) for finding in result.findings],
        result.evidence,
    )


def test_unicode_domain_is_normalized_to_an_a_label(registry) -> None:
    """Unicode and A-label spellings resolve to the same policy record."""
    unicode_result = registry.assess("例子.中国")
    ascii_result = registry.assess("xn--fsqu00a.xn--fiqs8s")

    assert unicode_result.ascii_domain == "xn--fsqu00a.xn--fiqs8s"
    assert comparable_assessment(unicode_result) == comparable_assessment(ascii_result)


def test_unicode_terminal_dot_is_normalized_after_idna(registry) -> None:
    """An IDNA dot-equivalent at the end is treated as an absolute-name dot."""
    absolute = registry.assess("例子.中国。")
    relative = registry.assess("例子.中国")

    assert absolute.ascii_domain == "xn--fsqu00a.xn--fiqs8s"
    assert comparable_assessment(absolute) == comparable_assessment(relative)


def test_bare_suffix_is_impossible(registry) -> None:
    """A suffix alone has no candidate registration label."""
    result = registry.assess("co.uk")

    assert result.candidate_status == "bare_suffix"
    assert result.verdict == "impossible"
    assert any(finding.code == "bare_suffix" for finding in result.findings)


def test_subdomain_is_impossible(registry) -> None:
    """The assessor distinguishes an existing registrable name's child."""
    result = registry.assess("foo.example.co.uk")

    assert result.candidate_status == "subdomain"
    assert result.registrable_domain == "example.co.uk"
    assert result.verdict == "impossible"
    assert any(finding.code == "subdomain" for finding in result.findings)


def test_reserved_r_ldh_label_is_invalid(registry) -> None:
    """Non-A-label double hyphens in positions three and four are reserved."""
    result = registry.assess("ab--cd.de")

    assert result.syntax == "invalid"
    assert result.verdict == "impossible"


def test_psl_wildcard_rule_is_preserved(registry) -> None:
    """A wildcard match retains both its effective suffix and source syntax."""
    result = registry.assess("name.foo.ck")

    assert result.public_suffix == "foo.ck"
    assert result.suffix_rule == "*.ck"
    assert result.suffix_rule_kind == "wildcard"
    assert result.suffix_section == "icann"
    assert result.suffix_role == "registry_boundary"
    assert result.suffix_evidence is not None
    evidence = registry.evidence(result.suffix_evidence)
    assert evidence is not None
    assert evidence.kind == "public_suffix_list"
    assert result.candidate_status == "registrable_domain"


def test_psl_exception_rule_is_preserved(registry) -> None:
    """An exception shortens the effective suffix without losing provenance."""
    result = registry.assess("www.ck")

    assert result.public_suffix == "ck"
    assert result.suffix_rule == "!www.ck"
    assert result.suffix_rule_kind == "exception"
    assert result.suffix_section == "icann"
    assert result.candidate_status == "registrable_domain"


@given(label=ASCII_LABELS, suffix=st.sampled_from(SUFFIXES))
def test_case_and_trailing_dot_normalization(label: str, suffix: str) -> None:
    """Case and an absolute-name dot do not change an assessment."""
    registry = Registry()
    domain = f"{label}.{suffix}"
    normalized = registry.assess(domain)

    assert comparable_assessment(
        registry.assess(domain.upper())
    ) == comparable_assessment(normalized)
    assert comparable_assessment(
        registry.assess(f"{domain}.")
    ) == comparable_assessment(normalized)
