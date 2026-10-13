"""Positive and malformed-source adapter fixtures."""

import json

import pytest
from scripts.data.policies import gtlds, reserved, special_csv, special_use

from .samples import RAW, XML_NS


def test_special_scope_and_deprecation() -> None:
    """Special scope and deprecation."""
    text = RAW["iana.special-use.xml"].replace("onion.", "onion. (DEPRECATED)")
    names, version = special_use(text)
    assert version == "2026-10-12"
    assert names[0]["name"] == "example.com"
    assert names[0]["descendants"] is True
    assert names[1]["deprecated"] is True
    assert names[1]["references"] == ["rfc7686"]


def test_reserved_categories_retain_applicability_gap() -> None:
    """Reserved categories retain applicability gap."""
    sets, _ = reserved(RAW["icann.reserved-names"])
    assert sets[0]["labels"] == ["olympic"]
    assert sets[0]["applicability"] == "requires_review"
    assert "exceptions" in sets[0]["description"]


@pytest.mark.parametrize(
    "adapter,text",
    [
        (special_csv, "NewName,Reference\nonion.,[RFC7686]\n"),
        (special_csv, "Name,Reference\nonion.\n"),
        (special_csv, 'Name,Reference\n"onion.,[RFC7686]\n'),
        (special_use, RAW["iana.special-use.xml"].replace("subdomains", "other names")),
        (
            special_use,
            RAW["iana.special-use.xml"].replace('data="rfc7686"', 'data="invalid"'),
        ),
        (reserved, RAW["icann.reserved-names"].replace("<label1>olympic</label1>", "")),
        (reserved, "<registry"),
        (
            reserved,
            RAW["icann.reserved-names"].replace(
                "olympic</label1>", "two.labels</label1>"
            ),
        ),
        (
            reserved,
            f'<!DOCTYPE registry [<!ENTITY x "value">]><registry {XML_NS} id="reservedNames"/>',
        ),
        (gtlds, '{"version":3,"gTLDs":[]}'),
        (
            gtlds,
            RAW["icann.gtlds"].replace(
                '"specification13":false', '"specification13":"false"'
            ),
        ),
        (
            gtlds,
            json.dumps({"version": 2, "updatedOn": "now", "gTLDs": [{"gTLD": "com"}]}),
        ),
    ],
)
def test_upstream_shape_changes_fail_closed(adapter, text: str) -> None:
    """Upstream shape changes fail closed."""
    with pytest.raises(ValueError):
        adapter(text)
