"""Malformed profile values are input errors before policy evaluation."""

from __future__ import annotations

import json

import pytest

from tldhax import PreparedRegistrant, Registry, _native

COUNTRY_FIELDS = ["citizenships", "domicile_country", "incorporation_country"]


@pytest.mark.parametrize("field", COUNTRY_FIELDS)
@pytest.mark.parametrize(
    "value", ["us", "United States", " US", "US ", "", "ＵＳ", "UЅ", "U1", "USA"]
)
def test_country_format_rejects_malformed_mapping_and_json(
    field: str, value: str
) -> None:
    """An invalid declaration must not masquerade as a disqualifying country."""
    profile = {field: [value] if field == "citizenships" else value}
    with pytest.raises(ValueError, match="^invalid_profile_value$"):
        Registry().prepare_registrant(profile)
    with pytest.raises(ValueError, match="^invalid_profile_value$"):
        _native.Registry().prepare_registrant(json.dumps(profile))


@pytest.mark.parametrize("field", COUNTRY_FIELDS)
@pytest.mark.parametrize("value", ["PR", "GB", "US"])
def test_country_format_preserves_uppercase_declarations(
    field: str, value: str
) -> None:
    """The declared encoding does not impose an invented eligibility list."""
    profile = {field: [value] if field == "citizenships" else value}
    assert isinstance(Registry().prepare_registrant(profile), PreparedRegistrant)
    assert isinstance(
        _native.Registry().prepare_registrant(json.dumps(profile)), PreparedRegistrant
    )


def test_country_value_errors_omit_values(registry: Registry) -> None:
    """Preparation errors never echo an applicant's supplied declaration."""
    marker = "private-country-declaration-639128"
    with pytest.raises(ValueError) as error:
        registry.prepare_registrant({"domicile_country": marker})
    assert str(error.value) == "invalid_profile_value"
    assert marker not in repr(error.value)
