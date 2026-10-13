"""Tests for TLD metadata lookup."""

from __future__ import annotations


def test_tld_info_known_suffix(registry) -> None:
    """Discovery alone cannot supply a complete legacy policy summary."""
    assert registry.tld_info("co.uk") is None


def test_tld_info_unknown_suffix(registry) -> None:
    """Unknown suffixes should not return compiled metadata."""
    assert registry.tld_info("unknowntld") is None
