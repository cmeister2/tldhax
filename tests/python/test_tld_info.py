"""Tests for TLD metadata lookup."""

from __future__ import annotations


def test_tld_info_known_suffix(registry) -> None:
    """Conflicting policy cannot be flattened into a faithful legacy summary."""
    info = registry.tld_info("co.uk")
    assert info is None
    namespace = registry.namespace_info("co.uk")
    assert namespace is not None and namespace.namespace == "co.uk"
    coverage = namespace.to_dict()["policy"]["coverage"]
    assert any(
        row["family"] == "length" and row["ascii"] == "conflicting"
        for row in coverage
    )


def test_tld_info_unknown_suffix(registry) -> None:
    """Unknown suffixes should not return compiled metadata."""
    assert registry.tld_info("unknowntld") is None
