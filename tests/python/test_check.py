"""Example-based tests for registry check outcomes."""

from __future__ import annotations


def test_known_domains(registry) -> None:
    """Unreviewed legacy claims cannot approve or prohibit valid candidates."""
    for name in ("vanity.xyz", "vanity.ai", "vanity.com.ai", "za.sk"):
        assert registry.check(name).status == "unknown"
    assert registry.check("example.test").status == "no"


def test_unknown_tld(registry) -> None:
    """Unknown suffixes should return the unknown status with reasons."""
    result = registry.check("example.unknowntld")
    assert result.status == "unknown"
    assert result.reasons
