"""Example-based tests for registry check outcomes."""

from __future__ import annotations


def test_known_domains(registry) -> None:
    """Check a representative set of known registerability outcomes."""
    assert registry.check("foo.co.uk").status == "yes"
    assert registry.check("ab.co.uk").status == "no"
    assert registry.check("za.sk").status == "no"
    assert registry.check("example.google").status == "no"
    assert registry.check("example.com").status == "yes"
    assert registry.check("example.test").status == "no"
    assert registry.check("something.mo.us").status == "no"
    assert registry.check("max.de").status == "restricted"


def test_unknown_tld(registry) -> None:
    """Unknown suffixes should return the unknown status with reasons."""
    result = registry.check("example.unknowntld")
    assert result.status == "unknown"
    assert result.reasons
