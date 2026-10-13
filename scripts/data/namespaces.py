"""Strict authoritative inventory adapters preserving upstream scopes."""

from __future__ import annotations

import re
from datetime import date
from html.parser import HTMLParser

import idna


def canonical(name: str) -> str:
    """Canonicalise inventory names with the runtime's nontransitional contract."""
    if not isinstance(name, str) or not name or name != name.strip():
        raise ValueError("empty or padded inventory name")
    value = idna.encode(name, uts46=True, transitional=False, std3_rules=True).decode(
        "ascii"
    )
    if value.endswith(".") or len(value) > 253:
        raise ValueError("inventory names must omit the root dot")
    return value.lower()


def active_roots(text: str) -> tuple[dict, str]:
    """Parse delegated ASCII roots, retaining the source's version header."""
    lines = text.splitlines()
    match = re.fullmatch(
        r"# Version (\d{10}), Last Updated .+", lines[0] if lines else ""
    )
    if not match:
        raise ValueError("IANA version header missing")
    date.fromisoformat(match[1][:4] + "-" + match[1][4:6] + "-" + match[1][6:8])
    roots = {}
    for line in lines[1:]:
        if not line or re.fullmatch(r"[A-Z0-9-]+", line) is None:
            raise ValueError("malformed IANA root label")
        name = canonical(line)
        if "." in name or name in roots:
            raise ValueError("duplicate or non-root IANA label")
        roots[name] = {"tld": name, "active": True}
    if not roots:
        raise ValueError("empty active root inventory")
    return roots, match[1]


class RootDatabase(HTMLParser):
    """Read only the labelled IANA root table, rejecting shape changes."""

    def __init__(self) -> None:
        """Initialise table-local parsing state."""
        super().__init__(convert_charrefs=True)
        self.rows: list[tuple[list[str], str | None]] = []
        self.in_table = False
        self.in_cell = False
        self.cells: list[str] = []
        self.cell = ""
        self.href: str | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        """Recognise root-table cells and delegation-record links."""
        values = dict(attrs)
        if tag == "table" and values.get("id") == "tld-table":
            self.in_table = True
        elif self.in_table and tag == "tr":
            self.cells, self.href = [], None
        elif self.in_table and tag == "td":
            self.in_cell, self.cell = True, ""
        elif (
            self.in_cell
            and tag == "a"
            and values.get("href", "").startswith("/domains/root/db/")
        ):
            self.href = values["href"]

    def handle_endtag(self, tag: str) -> None:
        """Close cells and retain complete table rows."""
        if self.in_table and tag == "td":
            self.cells.append(" ".join(self.cell.split()))
            self.in_cell = False
        elif self.in_table and tag == "tr" and self.cells:
            self.rows.append((self.cells, self.href))
        elif tag == "table":
            self.in_table = False

    def handle_data(self, data: str) -> None:
        """Accumulate display text only inside a table cell."""
        if self.in_cell:
            self.cell += data


def root_database(text: str) -> tuple[dict, str]:
    """Read root manager/type identity without inferring registration access."""
    parser = RootDatabase()
    parser.feed(text)
    roots = {}
    for cells, href in parser.rows:
        cells[0] = cells[0].replace("\u200e", "").replace("\u200f", "")
        if len(cells) != 3 or not href or not cells[0].startswith("."):
            raise ValueError("IANA root database row shape changed")
        name = canonical(href.rsplit("/", 1)[1].removesuffix(".html"))
        display = cells[0][1:]
        if canonical(display) != name:
            raise ValueError("IANA root link disagrees with its display label")
        if name in roots or cells[1] not in {
            "generic",
            "generic-restricted",
            "country-code",
            "sponsored",
            "infrastructure",
            "test",
        }:
            raise ValueError("duplicate root or unknown root type")
        roots[name] = {
            "type": cells[1],
            "operator": cells[2],
            "delegation_url": "https://www.iana.org" + href,
        }
    if not roots:
        raise ValueError("IANA root database table missing")
    return roots, "unversioned"


def psl(text: str) -> tuple[list[dict], str]:
    """Preserve ICANN/PRIVATE sections and exact/wildcard/exception routing."""
    rules, seen, section = [], set(), None
    sections = set()
    version = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("// VERSION: "):
            version = line.removeprefix("// VERSION: ")
        if line in {"// ===BEGIN ICANN DOMAINS===", "// ===BEGIN PRIVATE DOMAINS==="}:
            if section is not None:
                raise ValueError("nested PSL sections")
            section = "ICANN" if "ICANN" in line else "PRIVATE"
            if section in sections:
                raise ValueError("repeated PSL section")
            sections.add(section)
        elif line in {"// ===END ICANN DOMAINS===", "// ===END PRIVATE DOMAINS==="}:
            expected = "ICANN" if "ICANN" in line else "PRIVATE"
            if section != expected:
                raise ValueError("unmatched PSL section end")
            section = None
        elif line and not line.startswith("//"):
            if section is None:
                raise ValueError("PSL rule outside recognised section")
            kind = (
                "exception"
                if line.startswith("!")
                else "wildcard"
                if line.startswith("*.")
                else "exact"
            )
            name = (
                line[1:]
                if kind == "exception"
                else line[2:]
                if kind == "wildcard"
                else line
            )
            suffix = canonical(name)
            key = (section, kind, suffix)
            if key in seen:
                raise ValueError("duplicate canonical PSL rule")
            seen.add(key)
            rules.append(
                {"rule": line, "suffix": suffix, "kind": kind, "section": section}
            )
    if (
        section is not None
        or sections != {"ICANN", "PRIVATE"}
        or not rules
        or not version
    ):
        raise ValueError("incomplete or unversioned PSL")
    return sorted(rules, key=lambda x: (x["section"], x["suffix"], x["kind"])), version
