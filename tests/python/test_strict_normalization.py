"""Exercise the strict input contract through the original native checker."""

import pytest

from tldhax import Registry


@pytest.mark.parametrize(
    "domain",
    ["example.com..", "example.com.。", "ab--cd.com", "xn--0.com", "a\u200db.com"],
)
def test_malformed_input_is_rejected(registry: Registry, domain: str) -> None:
    """Malformed IDNA is rejected without silently repairing the candidate."""
    assert registry.check(domain).status == "no"


def test_equivalent_input_forms_have_identical_results(registry: Registry) -> None:
    """Unicode and Punycode use the same policy and canonical identity."""
    values = ["bücher.de", "BÜCHER.DE", "bu\u0308cher.de", "xn--bcher-kva.de"]
    results = [registry.check(value) for value in values]
    assert len({(result.status, tuple(result.reasons)) for result in results}) == 1


def test_root_dot_mapping_and_input_budget(registry: Registry) -> None:
    """The legacy checker returns a structured unknown for its input budget."""
    assert (
        registry.check("example。com。").status == registry.check("example.com").status
    )
    result = registry.check(" " * 4097)
    assert result.status == "unknown"
    assert "4096" in result.reasons[0]
