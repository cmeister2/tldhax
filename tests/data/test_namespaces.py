"""Positive and malformed-source adapter fixtures."""

import pytest
from scripts.data.namespaces import active_roots, canonical, psl, root_database

from .samples import RAW


def test_nontransitional_canonicalisation() -> None:
    """Nontransitional canonicalisation."""
    assert canonical("faß.de") == "xn--fa-hia.de"
    assert canonical("FAẞ.DE") == "xn--fa-hia.de"
    assert canonical(canonical("e\u0301.uk")) == canonical("é.uk")


def test_psl_types_and_sections_are_preserved() -> None:
    """Psl types and sections are preserved."""
    rows, version = psl(RAW["psl.list"])
    assert version == "fixture-v1"
    assert {
        tuple(x[k] for k in ("rule", "suffix", "kind", "section")) for x in rows
    } >= {
        ("*.ck", "ck", "wildcard", "ICANN"),
        ("!www.ck", "www.ck", "exception", "ICANN"),
        ("blogspot.com", "blogspot.com", "exact", "PRIVATE"),
    }


def test_root_link_and_bidi_display_are_consistent() -> None:
    """Root link and bidi display are consistent."""
    text = '<table id="tld-table"><tr><td><a href="/domains/root/db/xn--4dbrk0ce.html">\u200f.ישראל\u200e</a></td><td>country-code</td><td>registry</td></tr></table>'
    roots, _ = root_database(text)
    assert "xn--4dbrk0ce" in roots
    with pytest.raises(ValueError, match="disagrees"):
        root_database(text.replace("xn--4dbrk0ce", "uk"))


@pytest.mark.parametrize(
    "adapter,text",
    [
        (active_roots, "COM\n"),
        (active_roots, RAW["iana.active-roots"] + "COM\n"),
        (active_roots, "# Version 2026101200, Last Updated fixture UTC\n"),
        (psl, RAW["psl.list"].replace("!www.ck", "www.ck\n!www.ck\n!www.ck")),
        (psl, RAW["psl.list"].replace("// ===END ICANN DOMAINS===", "")),
        (psl, RAW["psl.list"] + "outside.uk\n"),
        (psl, RAW["psl.list"].replace("co.uk", "é.uk\nxn--9ca.uk")),
        (root_database, "<table></table>"),
        (root_database, RAW["iana.root-database"].replace("country-code", "new-type")),
    ],
)
def test_upstream_shape_changes_fail_closed(adapter, text: str) -> None:
    """Upstream shape changes fail closed."""
    with pytest.raises(ValueError):
        adapter(text)
