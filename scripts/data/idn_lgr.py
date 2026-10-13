"""Parse a finite LGR XML subset; unsupported expressions remain coverage gaps.

Recognised contexts are one-code-point look-behind/look-ahead sets, and negative
start/end anchors. Whole-label actions, script properties, ordering expressions,
tag-based classes and contextual variant disposition are intentionally unresolved.
"""

from __future__ import annotations

from bisect import bisect_right
from typing import Any
from xml.etree import ElementTree as ET

from .idn import (
    MAX_CONTEXT_SET,
    MAX_RECORDS,
    artifact,
    interval,
    intervals,
    sequence,
    text_and_hash,
)

LGR_NAMESPACE = "urn:ietf:params:xml:ns:lgr-1.0"


def parse_lgr(content: str | bytes) -> dict[str, Any]:
    """Preserve repertoire, literal variants and supported context predicates."""
    text, sha = text_and_hash(content)
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("entity-bearing LGR XML is unsupported")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise ValueError("malformed LGR XML") from error
    if root.tag not in {"lgr", f"{{{LGR_NAMESPACE}}}lgr"}:
        raise ValueError("unrecognised LGR XML root")
    prefix = f"{{{LGR_NAMESPACE}}}" if root.tag.startswith("{") else ""

    def tag(element: ET.Element) -> str:
        """Strip only the document's approved namespace, never a foreign one."""
        return element.tag.removeprefix(prefix) if prefix else element.tag

    unsupported: set[str] = set()
    stack, nodes = [(root, 0)], 0
    while stack:
        element, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > MAX_RECORDS:
            raise ValueError("LGR XML exceeds element/depth budget")
        stack.extend((child, depth + 1) for child in element)
    children = {
        name: [child for child in root if tag(child) == name]
        for name in ("meta", "data", "rules")
    }
    if (
        len(children["meta"]) != 1
        or len(children["data"]) != 1
        or len(children["rules"]) > 1
    ):
        raise ValueError("LGR requires one metadata and repertoire block")
    for child in root:
        if tag(child) not in children:
            unsupported.add("root_element:" + tag(child))
    if root.attrib:
        unsupported.update("root_attribute:" + name for name in root.attrib)
    metadata: dict[str, Any] = {
        tag(child): "".join(child.itertext()).strip() for child in children["meta"][0]
    }
    version_nodes = [child for child in children["meta"][0] if tag(child) == "version"]
    if len(version_nodes) != 1:
        raise ValueError("LGR requires one table version")
    for child in children["meta"][0]:
        unsupported.update(
            f"metadata_attribute:{tag(child)}:{name}"
            for name in child.attrib.keys() - {"comment", "ref"}
        )
        if tag(child) not in {
            "version",
            "date",
            "unicode-version",
            "language",
            "description",
            "references",
        }:
            unsupported.add("metadata_element:" + tag(child))
    for name, blocks in children.items():
        for block in blocks:
            unsupported.update(f"attribute:{name}:{key}" for key in block.attrib)
    if metadata.get("description"):
        unsupported.add("uninterpreted_prose_metadata:description")
    definitions: dict[str, dict[str, ET.Element]] = {"class": {}, "rule": {}}
    if children["rules"]:
        for child in children["rules"][0]:
            kind, name = tag(child), child.get("name", "")
            if kind in definitions:
                if (
                    not name
                    or name.strip() != name
                    or len(name) > 256
                    or name in definitions[kind]
                ):
                    raise ValueError("missing or duplicate LGR definition name")
                definitions[kind][name] = child
            else:
                unsupported.add(f"rules_element:{kind}:{child.get('disp', '')}")

    def attributes(element: ET.Element, allowed: set[str]) -> bool:
        """Flag unhandled attributes before interpreting an expression."""
        extra = element.attrib.keys() - allowed
        unsupported.update(f"attribute:{tag(element)}:{name}" for name in extra)
        return not extra

    used: dict[str, set[str]] = {"class": set(), "rule": set()}
    for element in root.iter():
        # Validate scalars even inside definitions that are not used by a binding.
        if tag(element) in {"char", "var"}:
            sequence(element.get("cp", ""))
        if tag(element) == "range":
            interval(element.get("first-cp", ""), element.get("last-cp", ""))

    def members(
        element: ET.Element, visiting: tuple[str, ...] = ()
    ) -> list[int] | None:
        """Expand only small literal context sets, with bounded acyclic references."""
        kind = tag(element)
        if (
            kind == "char"
            and attributes(element, {"cp", "comment", "ref"})
            and not len(element)
        ):
            value = sequence(element.get("cp", ""))
            return [ord(value)] if len(value) == 1 else None
        if (
            kind == "range"
            and attributes(element, {"first-cp", "last-cp", "comment", "ref"})
            and not len(element)
        ):
            first, last = interval(
                element.get("first-cp", ""), element.get("last-cp", "")
            )
            if last - first + 1 <= MAX_CONTEXT_SET:
                return list(range(first, last + 1))
            unsupported.add("context_set_exceeds_budget")
            return None
        if (
            kind == "class"
            and attributes(element, {"by-ref", "comment", "ref"})
            and not len(element)
        ):
            name = element.get("by-ref", "")
            if name not in definitions["class"]:
                raise ValueError("missing LGR class reference")
            if name in visiting or len(visiting) >= 32:
                raise ValueError("cyclic or excessive LGR class references")
            used["class"].add(name)
            definition = definitions["class"][name]
            if not attributes(definition, {"name", "comment", "ref"}):
                return None
            values = []
            for child in definition:
                parsed = members(child, (*visiting, name))
                if parsed is None:
                    return None
                values.extend(parsed)
                if len(values) > MAX_CONTEXT_SET:
                    unsupported.add("context_set_exceeds_budget")
                    return None
            return sorted(set(values)) or None
        unsupported.add("context_expression:" + kind)
        return None

    def condition(name: str, negative: bool) -> dict[str, Any] | None:
        """Translate only expressions equivalent to the compiler's finite predicates."""
        if name not in definitions["rule"]:
            raise ValueError("missing LGR context rule")
        used["rule"].add(name)
        rule = definitions["rule"][name]
        if not attributes(rule, {"name", "comment", "ref"}):
            return None
        if negative and len(rule) == 1 and tag(rule[0]) in {"start", "end"}:
            if not rule[0].attrib and not len(rule[0]):
                return {"kind": "not_start" if tag(rule[0]) == "start" else "not_end"}
        if negative:
            unsupported.add("negative_context_expression:" + name)
            return None
        adjacent: dict[str, list[int]] = {}
        for child in rule:
            kind = tag(child)
            if (
                kind not in {"look-behind", "look-ahead"}
                or kind in adjacent
                or child.attrib
                or len(child) != 1
            ):
                unsupported.add("context_rule:" + name)
                return None
            if tag(child[0]) == "any" and not child[0].attrib and not len(child[0]):
                if len(rule) == 1:
                    return {"kind": "not_start" if kind == "look-behind" else "not_end"}
                unsupported.add("combined_any_context:" + name)
                return None
            parsed = members(child[0])
            if parsed is None:
                unsupported.add("context_rule:" + name)
                return None
            adjacent[kind] = parsed
        if len(adjacent) == 2:
            return {
                "kind": "between",
                "left": adjacent["look-behind"],
                "right": adjacent["look-ahead"],
            }
        if adjacent:
            kind, values = next(iter(adjacent.items()))
            return {
                "kind": "preceded_by" if kind == "look-behind" else "followed_by",
                "values": values,
            }
        unsupported.add("empty_context_rule:" + name)
        return None

    ranges: list[list[int]] = []
    contexts: list[dict[str, Any]] = []
    variants: list[dict[str, str]] = []
    sequences: set[int] = set()
    metadata["repertoire_sequences"] = []
    metadata["variant_types"] = []
    for item in children["data"][0]:
        kind = tag(item)
        if kind not in {"char", "range"}:
            unsupported.add("repertoire_element:" + kind)
            continue
        attributes(
            item,
            ({"cp"} if kind == "char" else {"first-cp", "last-cp"})
            | {"when", "not-when", "comment", "ref"},
        )
        if kind == "char":
            value = sequence(item.get("cp", ""))
            if len(value) == 1:
                ranges.append([ord(value), ord(value)])
            else:
                unsupported.add("repertoire_sequence")
                metadata["repertoire_sequences"].append(value)
                sequences.update(map(ord, value))
        else:
            bounds = interval(item.get("first-cp", ""), item.get("last-cp", ""))
            ranges.append(bounds)
            value = chr(bounds[0]) if bounds[0] == bounds[1] else ""
        for key in ("when", "not-when"):
            if key in item.attrib:
                if len(value) != 1:
                    unsupported.add("nonscalar_context_binding")
                    continue
                parsed = condition(item.attrib[key], key == "not-when")
                if parsed is not None:
                    contexts.append({"codepoint": ord(value), "condition": parsed})
        for child in item:
            if tag(child) != "var":
                unsupported.add("char_element:" + tag(child))
                continue
            replacement = sequence(child.get("cp", ""))
            native = child.get("type", "")
            attributes(child, {"cp", "type", "comment", "ref"})
            metadata["variant_types"].append(
                {"sequence": value, "replacement": replacement, "type": native}
            )
            disposition = {"blocked": "blocked", "allocatable": "conditional"}.get(
                native, "unresolved"
            )
            if disposition == "unresolved":
                unsupported.add("variant_disposition:" + native)
            if len(child) or "when" in child.attrib or "not-when" in child.attrib:
                unsupported.add("contextual_variant_disposition")
                disposition = "unresolved"
            if value:
                variants.append(
                    {
                        "sequence": value,
                        "replacement": replacement,
                        "disposition": disposition,
                    }
                )
            else:
                unsupported.add("range_variant_relationship")
    direct = intervals(ranges)
    starts = [first for first, _ in direct]
    ranges = direct.copy()
    for cp in sorted(sequences):
        index = bisect_right(starts, cp) - 1
        if index < 0 or cp > direct[index][1]:
            ranges.append([cp, cp])
    for kind in definitions:
        unsupported.update(
            f"unapplied_{kind}:{name}" for name in definitions[kind].keys() - used[kind]
        )
    return artifact(
        format_name="lgr-xml-subset",
        version=metadata.get("version", ""),
        sha256=sha,
        ranges=ranges,
        contexts=contexts,
        variants=variants,
        unsupported=unsupported,
        metadata=metadata,
    )
