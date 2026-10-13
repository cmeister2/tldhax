"""The original Python metadata API exposes only faithfully represented facts."""

from __future__ import annotations

from tldhax import Registry, TldInfo, _native


def test_tld_info_known_suffix(registry: Registry) -> None:
    """Known namespaces keep their record shape without unsupported length guesses."""
    info = registry.tld_info(".CO.UK")
    assert isinstance(info, TldInfo)
    assert info.tld == "co.uk"
    assert info.min_length is None  # Historical default three was unsupported.
    assert info.max_length is None
    assert info.note and "assess" in info.note
    assert isinstance(info.sources, dict)
    assert isinstance(info.banned, list)
    assert isinstance(info.restrictions, list)
    denic = registry.tld_info("de")
    assert denic is not None
    assert (
        denic.min_length is None
    )  # Unicode minimum and ASCII maximum use different bases.
    assert denic.max_length is None
    assert denic.length_basis is None
    australian = registry.tld_info("au")
    assert australian is not None
    assert australian.min_length == 2
    assert australian.length_basis == "ascii"


def test_tld_info_unknown_suffix(registry: Registry) -> None:
    """Unreviewed legacy and absent namespaces cannot acquire synthetic summaries."""
    assert registry.tld_info("unknowntld") is None
    assert registry.tld_info("sk") is None
    assert _native.Registry().tld_info("sk") is None


def test_original_registry_methods_and_statistics(registry: Registry) -> None:
    """Existing imports and all original methods remain usable alongside assess."""
    stats = registry.stats()
    assert set(stats) == {
        "compiled_rules",
        "total_known_suffixes",
        "registerable",
        "not_registerable",
        "restricted",
        "coverage_percent",
    }
    assert stats["compiled_rules"] == registry.rule_count()
    assert stats["total_known_suffixes"] >= registry.rule_count() > 0
    assert 0.0 <= stats["coverage_percent"] <= 100.0
    native = _native.Registry()
    assert native.rule_count() == registry.rule_count()
    assert native.stats() == stats
    assert isinstance(native.tld_info("com"), TldInfo)
