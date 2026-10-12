"""Strict authoritative inventory adapters preserving upstream scopes."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import date, datetime
from xml.etree import ElementTree as ET

from .namespaces import canonical

NS = {"i": "http://www.iana.org/assignments"}


def gtlds(text: str) -> tuple[dict, str]:
    """Import contract metadata without interpreting policy applicability."""
    document = json.loads(text)
    if (
        not isinstance(document, dict)
        or document.get("version") != 2
        or not isinstance(document.get("gTLDs"), list)
    ):
        raise ValueError("unsupported ICANN gTLD metadata schema")
    records = {}
    for item in document["gTLDs"]:
        if not isinstance(item, dict) or not all(
            k in item
            for k in (
                "gTLD",
                "registryOperator",
                "specification13",
                "contractTerminated",
            )
        ):
            raise ValueError("incomplete ICANN gTLD row")
        name = canonical(item["gTLD"])
        if "." in name or name in records:
            raise ValueError("duplicate or non-root ICANN gTLD")
        for key in (
            "specification13",
            "contractTerminated",
            "thirdOrLowerLevelRegistration",
        ):
            if item.get(key) is not None and not isinstance(item[key], bool):
                raise ValueError("nonboolean ICANN metadata")
        if item["registryOperator"] is not None and not isinstance(
            item["registryOperator"], str
        ):
            raise ValueError("nontext ICANN operator")
        if not isinstance(item["contractTerminated"], bool):
            raise ValueError("missing contract lifecycle flag")
        for key in ("delegationDate", "removalDate", "dateOfContractSignature"):
            if item.get(key) is not None:
                if not isinstance(item[key], str):
                    raise ValueError("nontext ICANN lifecycle date")
                date.fromisoformat(item[key])
        records[name] = {
            "icann_operator": item["registryOperator"],
            "specification13": item["specification13"],
            "contract_terminated": item["contractTerminated"],
            "delegation_date": item.get("delegationDate"),
            "removal_date": item.get("removalDate"),
            "third_or_lower_level_registration": item.get(
                "thirdOrLowerLevelRegistration"
            ),
        }
    if not records or not isinstance(document.get("updatedOn"), str):
        raise ValueError("empty or unversioned ICANN metadata")
    datetime.fromisoformat(document["updatedOn"].replace("Z", "+00:00"))
    return records, document["updatedOn"]


def xml_document(text: str, expected_id: str) -> ET.Element:
    """Validate the named registry and reject entity-bearing XML."""
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("XML entities are unsupported")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("malformed registry XML") from exc
    if (
        root.tag != "{http://www.iana.org/assignments}registry"
        or root.get("id") != expected_id
    ):
        raise ValueError("unexpected XML registry identity")
    return root


def special_use(text: str) -> tuple[list[dict], str]:
    """Preserve special-use descendant scope, deprecation and RFC references."""
    root = xml_document(text, "special-use-domain-names")
    registry = root.find("i:registry[@id='special-use-domain']", NS)
    if registry is None or "subdomains" not in registry.findtext("i:note", "", NS):
        raise ValueError("special-use scope declaration missing")
    names, seen = [], set()
    for item in registry.findall("i:record", NS):
        raw = item.findtext("i:name", "", NS)
        deprecated = raw.endswith(" (DEPRECATED)")
        name = canonical(raw.removesuffix(" (DEPRECATED)").removesuffix("."))
        references = sorted(
            x.get("data", "")
            for x in item.findall("i:xref", NS)
            if x.get("type") == "rfc"
        )
        if (
            name in seen
            or not references
            or any(not re.fullmatch(r"rfc\d+", x) for x in references)
        ):
            raise ValueError("duplicate special-use name or missing RFC")
        seen.add(name)
        names.append(
            {
                "name": name,
                "descendants": True,
                "deprecated": deprecated,
                "references": references,
                "source_id": "iana.special-use.xml",
            }
        )
    version = root.findtext("i:updated", "", NS)
    if not names or not version:
        raise ValueError("empty or unversioned special-use registry")
    date.fromisoformat(version)
    return sorted(names, key=lambda x: x["name"]), version


def special_csv(text: str) -> tuple[list[dict], str]:
    """Validate the independent CSV representation before cross-checking XML."""
    reader = csv.DictReader(io.StringIO(text), strict=True)
    try:
        if reader.fieldnames != ["Name", "Reference"]:
            raise ValueError("special-use CSV schema changed")
        rows = list(reader)
    except csv.Error as exc:
        raise ValueError("malformed special-use CSV") from exc
    if not rows or any(
        None in row or not row["Name"] or not row["Reference"] for row in rows
    ):
        raise ValueError("invalid special-use CSV row")
    if any(not re.fullmatch(r"(?:\[RFC\d+\])+", row["Reference"]) for row in rows):
        raise ValueError("unexpected special-use CSV reference format")
    return rows, "unversioned"


def reserved(text: str) -> tuple[list[dict], str]:
    """Import separate reserved sets with their upstream scope/exception text."""
    root = xml_document(text, "reservedNames")
    sets, seen = [], set()
    for category in root.findall("i:registry", NS):
        labels = set()
        for record in category.findall("i:record", NS):
            if not record.findtext("i:name", "", NS) or not any(
                child.text
                for child in record
                if child.tag
                in {
                    "{http://www.iana.org/assignments}label1",
                    "{http://www.iana.org/assignments}label2",
                }
            ):
                raise ValueError("reserved record missing name or labels")
            for item in record:
                if (
                    re.fullmatch(
                        r"\{http://www.iana.org/assignments\}label\d+", item.tag
                    )
                    and item.text
                ):
                    label = canonical(item.text)
                    if "." in label:
                        raise ValueError("reserved list contains a non-label")
                    labels.add(label)
        refs = sorted(x.get("data", "") for x in category.findall("i:xref", NS))
        description = " ".join(category.findtext("i:description", "", NS).split())
        if (
            not category.get("id")
            or category.get("id") in seen
            or not labels
            or not description
            or not refs
        ):
            raise ValueError("reserved category missing labels, scope or references")
        seen.add(category.get("id"))
        sets.append(
            {
                "id": category.get("id"),
                "title": category.findtext("i:title", "", NS),
                "description": description,
                "references": refs,
                "labels": sorted(labels),
                "applicability": "requires_review",
                "source_id": "icann.reserved-names",
            }
        )
    version = root.findtext("i:updated", "", NS)
    if not sets or not version:
        raise ValueError("empty or unversioned reserved registry")
    date.fromisoformat(version)
    return sorted(sets, key=lambda x: x["id"]), version
