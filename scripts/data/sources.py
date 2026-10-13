"""Strict authoritative inventory adapters preserving upstream scopes."""

from __future__ import annotations

from .namespaces import active_roots, psl, root_database
from .policies import gtlds, reserved, special_csv, special_use

SOURCES = {
    "iana.active-roots": (
        "data/root/tlds-alpha-by-domain.txt",
        "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
    ),
    "iana.root-database": (
        "data/root/root-db.html",
        "https://www.iana.org/domains/root/db",
    ),
    "psl.list": (
        "data/psl/public_suffix_list.dat",
        "https://publicsuffix.org/list/public_suffix_list.dat",
    ),
    "iana.special-use.csv": (
        "data/special-use/special-use-domain-names.csv",
        "https://www.iana.org/assignments/special-use-domain-names/special-use-domain.csv",
    ),
    "iana.special-use.xml": (
        "data/special-use/special-use-domain-names.xml",
        "https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xml",
    ),
    "icann.gtlds": (
        "data/root/gtlds.json",
        "https://www.icann.org/resources/registries/gtlds/v2/gtlds.json",
    ),
    "icann.reserved-names": (
        "data/reserved/ReservedNames.xml",
        "https://www.icann.org/sites/default/files/packages/reserved-names/ReservedNames.xml",
    ),
}

PARSERS = {
    "iana.active-roots": active_roots,
    "iana.root-database": root_database,
    "psl.list": psl,
    "iana.special-use.csv": special_csv,
    "iana.special-use.xml": special_use,
    "icann.gtlds": gtlds,
    "icann.reserved-names": reserved,
}
