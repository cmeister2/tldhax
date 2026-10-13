"""Original metadata methods remain available before authored policy data lands."""

from tldhax import Registry, TldInfo


def test_original_metadata_api_before_policy_data(registry: Registry) -> None:
    """Discovery data does not fabricate a policy summary or approval count."""
    assert isinstance(TldInfo, type)
    assert registry.tld_info("co.uk") is None
    assert registry.tld_info("unknowntld") is None
    assert registry.rule_count() == 0
    stats = registry.stats()
    assert set(stats) == {
        "compiled_rules",
        "total_known_suffixes",
        "registerable",
        "not_registerable",
        "restricted",
        "coverage_percent",
    }
    assert stats["compiled_rules"] == 0
    assert (
        stats["registerable"] == stats["not_registerable"] == stats["restricted"] == 0
    )
    assert stats["total_known_suffixes"] > 0
