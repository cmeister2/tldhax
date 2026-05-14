"""Tests for TLD metadata lookup."""

from __future__ import annotations


def test_tld_info_known_suffix(registry) -> None:
    """Known suffixes should return their compiled metadata."""
    info = registry.tld_info("co.uk")
    assert info is not None
    assert info.tld == "co.uk"
    assert info.registerable == "yes"
    assert info.min_length == 3


def test_tld_info_unknown_suffix(registry) -> None:
    """Unknown suffixes should not return compiled metadata."""
    assert registry.tld_info("unknowntld") is None