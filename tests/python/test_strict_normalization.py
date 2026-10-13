"""Exercise the same strict input contract through the native binding."""

import pytest


@pytest.mark.parametrize(
    "domain",
    ["example.com..", "example.com.。", "ab--cd.com", "xn--0.com", "a\u200db.com"],
)
def test_malformed_input_is_rejected(registry, domain: str) -> None:
    """Trailing roots and malformed IDNA must not be silently repaired."""
    assert registry.check(domain).status == "no"


def test_equivalent_input_forms_have_identical_results(registry) -> None:
    """Canonical Unicode and A-label forms must follow the same policy."""
    values = ["bücher.de", "BÜCHER.DE", "bu\u0308cher.de", "xn--bcher-kva.de"]
    results = [registry.check(value) for value in values]
    assert len({(result.status, tuple(result.reasons)) for result in results}) == 1


def test_root_dot_mapping_and_input_budget(registry) -> None:
    """One mapped root dot is permitted; preprocessing limits remain explicit."""
    assert registry.check("example。com。").status == registry.check("example.com").status
    result = registry.check(" " * 4097)
    assert result.status == "no"
    assert result.reasons[0].startswith("Input limit:")
