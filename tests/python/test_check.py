"""Example-based tests for the original registry check interface."""

from __future__ import annotations

from tldhax import CheckResult, Registry


def test_known_domains(registry: Registry) -> None:
    """Keep original examples while correcting unsupported historical guesses."""
    assert registry.check("foo.co.uk").status == "unknown"
    assert (
        registry.check("ab.co.uk").status == "unknown"
    )  # No invented three-character minimum.
    assert (
        registry.check("za.sk").status == "unknown"
    )  # Legacy inventory is not a prohibition.
    assert (
        registry.check("example.google").status == "unknown"
    )  # Applicant declarations are absent.
    assert registry.check("example.com").status == "no"  # Special-use reservation.
    assert registry.check("example.test").status == "no"
    assert (
        registry.check("something.mo.us").status == "unknown"
    )  # Unimplemented registration scope.
    assert (
        registry.check("max.de").status == "unknown"
    )  # Capacity declarations are absent.


def test_unknown_tld(registry: Registry) -> None:
    """Unknown suffixes preserve the original result class and explanation list."""
    result = registry.check("example.unknowntld")
    assert isinstance(result, CheckResult)
    assert result.status == "unknown"
    assert result.reasons and all(isinstance(reason, str) for reason in result.reasons)
