"""Example-based tests for registry check outcomes."""

from __future__ import annotations


def test_known_domains(registry) -> None:
    """Legacy shapes retain proven denial and explicit incomplete research."""
    for domain in [
        "foo.co.uk",
        "ab.co.uk",
        "za.sk",
        "example.google",
        "vanity.com",
        "something.mo.us",
        "max.de",
    ]:
        result = registry.check(domain)
        assert result.status == "unknown"
        assert isinstance(result.reasons, list)
        assert all(isinstance(reason, str) for reason in result.reasons)
    assert registry.check("example.test").status == "no"
    assert registry.check("example.com").status == "no"
    assert registry.check("uk.co.uk").status == "no"


def test_unknown_tld(registry) -> None:
    """Unknown suffixes should return the unknown status with reasons."""
    result = registry.check("example.unknowntld")
    assert result.status == "unknown"
    assert result.reasons
