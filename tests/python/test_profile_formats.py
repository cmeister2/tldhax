"""Declared country encodings fail preparation before eligibility evaluation."""

from __future__ import annotations

import json

import pytest

from tldhax import PreparedRegistrant, Registry, _native

COUNTRY_FIELDS = ["citizenships", "domicile_country", "incorporation_country"]


@pytest.mark.parametrize("field", COUNTRY_FIELDS)
@pytest.mark.parametrize(
    "value", ["us", "United States", " US", "US ", "", "ＵＳ", "UЅ", "U1", "USA"]
)
def test_country_format_rejects_malformed_mapping_and_native_json(field, value):
    """Aliases, whitespace and Unicode lookalikes are never negative facts."""
    profile = {field: [value] if field == "citizenships" else value}
    registry = Registry()
    with pytest.raises(ValueError, match="^invalid_profile_value$"):
        registry.prepare_registrant(profile)
    with pytest.raises(ValueError, match="^invalid_profile_value$"):
        _native.Registry().prepare_registrant(json.dumps(profile))


@pytest.mark.parametrize("field", COUNTRY_FIELDS)
@pytest.mark.parametrize("value", ["PR", "GB", "US"])
def test_country_format_preserves_uppercase_declarations(field, value):
    """Formatting does not restrict declarations to US/AU qualifying codes."""
    profile = {field: [value] if field == "citizenships" else value}
    assert isinstance(Registry().prepare_registrant(profile), PreparedRegistrant)
    assert isinstance(
        _native.Registry().prepare_registrant(json.dumps(profile)), PreparedRegistrant
    )


def test_country_format_schema_and_missing_empty_set_distinction():
    """Discoverable encoding preserves unknown versus explicit no citizenship."""
    registry = Registry()
    schema = registry.profile_schema()
    assert all(
        schema[field]["string_format"] == "uppercase_alpha2"
        for field in COUNTRY_FIELDS
    )
    assert schema["entity_kind"]["string_format"] is None
    alternatives = {
        "entity_kind": "individual",
        "us_permanent_resident": False,
        "domicile_country": "GB",
        "us_primary_domicile_in_possession": False,
        "proxy_registration": False,
    }
    missing = registry.prepare_registrant(alternatives)
    empty = registry.prepare_registrant({**alternatives, "citizenships": []})
    for profile, expected in [(missing, "unknown"), (empty, "false")]:
        result = registry.assess("vanity.us", profile).to_dict()
        nexus = next(rule for rule in result["rules"] if rule["rule_id"] == "us.nexus")
        assert nexus["truth"] == expected


def test_country_format_error_omits_declared_value():
    """Both public and native preparation return a fixed value-free error."""
    marker = "private-country-declaration-639128"
    profile = {"domicile_country": marker}
    with pytest.raises(ValueError) as public_error:
        Registry().prepare_registrant(profile)
    with pytest.raises(ValueError) as native_error:
        _native.Registry().prepare_registrant(json.dumps(profile))
    for error in [public_error.value, native_error.value]:
        assert str(error) == "invalid_profile_value"
        assert marker not in repr(error)
