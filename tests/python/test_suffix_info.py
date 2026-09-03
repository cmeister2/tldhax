"""Tests for namespace topology and policy-product lookup."""

from __future__ import annotations


def test_suffix_info_returns_independent_topology_and_policy(registry) -> None:
    """A suffix record separates its namespace facts from product claims."""
    info = registry.suffix_info("de")

    assert info is not None
    assert info.canonical_suffix == "de"
    assert info.root == "de"
    assert info.public_suffix == "de"
    assert info.root_state == "delegated"
    assert info.root_state_status == "verified"
    assert info.namespace_state == "ordinary"
    assert info.namespace_state_status == "verified"
    assert info.product_id == "de-direct"
    assert info.product_suffix == "de"
    assert info.public_access == "open"
    assert info.suffix_evidence is not None
    assert registry.evidence(info.suffix_evidence).kind == "public_suffix_list"
    assert info.root_state_evidence
    assert info.namespace_state_evidence
    assert info.offering_state_evidence == ["denic-public-applicants"]
    assert info.public_access_evidence == ["denic-public-applicants"]
    for evidence_id in (
        info.root_state_evidence
        + info.namespace_state_evidence
        + info.offering_state_evidence
        + info.public_access_evidence
    ):
        assert registry.evidence(evidence_id) is not None


def test_unicode_suffix_is_canonicalized_to_an_a_label(registry) -> None:
    """Unicode lookup reaches the same root record as its A-label form."""
    unicode_info = registry.suffix_info("中国")
    ascii_info = registry.suffix_info("xn--fiqs8s")

    assert unicode_info is not None
    assert ascii_info is not None
    assert unicode_info.canonical_suffix == "xn--fiqs8s"
    assert unicode_info.canonical_suffix == ascii_info.canonical_suffix
    assert unicode_info.display_suffix == "中国"

    absolute_info = registry.suffix_info("中国。")
    assert absolute_info is not None
    assert absolute_info.canonical_suffix == unicode_info.canonical_suffix


def test_unknown_root_is_verified_absent(registry) -> None:
    """The exhaustive root snapshot can prove absence without inventing a product."""
    info = registry.suffix_info("definitely-not-a-real-tld")

    assert info is not None
    assert info.root_state == "absent"
    assert info.root_state_status == "verified"
    assert info.product_id is None
    assert info.public_access is None


def test_suffix_info_reports_special_use_below_a_delegated_root(registry) -> None:
    """Multi-label special use remains visible beside its PSL topology."""
    info = registry.suffix_info("example.com")

    assert info is not None
    assert info.canonical_suffix == "com"
    assert info.public_suffix == "com"
    assert info.root_state == "delegated"
    assert info.namespace_state == "special_use"


def test_evidence_lookup_is_auditable(registry) -> None:
    """Assessment evidence identifiers resolve to provenance records."""
    evidence = registry.evidence("denic-public-applicants")

    assert evidence is not None
    assert evidence.kind == "registry_policy"
    assert evidence.publisher == "DENIC eG"
    assert evidence.url.startswith("https://")
    assert evidence.review_after == "2027-03-02"
    assert len(evidence.sha256) == 64


def test_unknown_evidence_id_returns_none(registry) -> None:
    """Unknown evidence identifiers do not manufacture provenance."""
    assert registry.evidence("missing-evidence") is None
