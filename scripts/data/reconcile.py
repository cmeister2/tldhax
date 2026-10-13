"""Deterministic offline derivation, integrity checks and inventory diffs."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path

from .sources import PARSERS, SOURCES


def encode(value: object) -> bytes:
    """Serialize canonical human-readable UTF-8 JSON bytes."""
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()


def digest(content: bytes) -> str:
    """Hash the original bytes rather than a parsed approximation."""
    return hashlib.sha256(content).hexdigest()


def _date(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("dates must use YYYY-MM-DD")
    date.fromisoformat(value)


def dataset_version(evaluation_date: str, inputs: list[dict]) -> str:
    """Bind a release date to every pinned raw source identity/hash."""
    _date(evaluation_date)
    identities = sorted((x["source_id"], x["sha256"]) for x in inputs)
    return evaluation_date + "+" + digest(encode(identities))[:16]


def derive(root: Path) -> tuple[dict[str, bytes], dict[str, str]]:
    """Generate inventories and a research queue from validated snapshots."""
    parsed, versions = {}, {}
    for source_id, (path, _) in SOURCES.items():
        parsed[source_id], versions[source_id] = PARSERS[source_id](
            (root / path).read_text(encoding="utf-8")
        )
    active, managers, contracts = (
        parsed["iana.active-roots"],
        parsed["iana.root-database"],
        parsed["icann.gtlds"],
    )
    if active.keys() - managers.keys():
        raise ValueError("active root missing from IANA root database")
    roots = []
    for name in sorted(active):
        row = {
            **active[name],
            **managers[name],
            "inventory_state": "delegated",
            "policy_state": "unknown",
            "source_ids": ["iana.active-roots", "iana.root-database"],
        }
        if name in contracts:
            row.update(contracts[name])
            row["source_ids"].append("icann.gtlds")
        roots.append(row)
    special = parsed["iana.special-use.xml"]
    csv_rows = parsed["iana.special-use.csv"]
    xml_names = {x["name"] for x in special}
    from .namespaces import canonical

    csv_names = {
        canonical(x["Name"].removesuffix(" (DEPRECATED)").removesuffix("."))
        for x in csv_rows
    }
    if xml_names != csv_names or len(csv_rows) != len(special):
        raise ValueError("special-use CSV/XML disagree")
    xml_records = {x["name"]: (x["references"], x["deprecated"]) for x in special}
    for row in csv_rows:
        name = canonical(row["Name"].removesuffix(" (DEPRECATED)").removesuffix("."))
        refs = sorted(
            "rfc" + number for number in re.findall(r"\[RFC(\d+)\]", row["Reference"])
        )
        if xml_records[name] != (refs, row["Name"].endswith(" (DEPRECATED)")):
            raise ValueError("special-use CSV/XML references disagree")
    groups: dict[str, dict] = {}
    namespaces = {
        name: {
            "selector": name,
            "root": name,
            "kind": "exact",
            "source_ids": ["iana.active-roots"],
        }
        for name in active
    }
    for row in parsed["psl.list"]:
        if row["section"] != "ICANN" or row["kind"] == "exception":
            continue
        selector = ("*." if row["kind"] == "wildcard" else "") + row["suffix"]
        tld = row["suffix"].rsplit(".", 1)[-1]
        namespaces.setdefault(
            selector,
            {"selector": selector, "root": tld, "kind": row["kind"], "source_ids": []},
        )
        namespaces[selector]["source_ids"].append("psl.list")
    for selector in sorted(namespaces):
        row = namespaces[selector]
        tld = row["root"]
        row["disposition"] = (
            "requires_policy_research"
            if tld in active
            else "outside_active_root_inventory"
        )
        operator = managers.get(tld, {}).get("operator", "unassigned")
        groups.setdefault(operator, {"operator": operator, "namespaces": []})[
            "namespaces"
        ].append(row)
    outputs = {
        "data/root/inventory.json": {"schema_version": 2, "roots": roots},
        "data/psl/rules.json": {"schema_version": 2, "rules": parsed["psl.list"]},
        "data/special-use/names.json": {"schema_version": 2, "names": special},
        "data/reserved/sets.json": {
            "schema_version": 2,
            "sets": parsed["icann.reserved-names"],
        },
        "data/research-queue.json": {
            "schema_version": 2,
            "groups": [groups[x] for x in sorted(groups)],
        },
    }
    return {path: encode(value) for path, value in outputs.items()}, versions


def manifest(
    root: Path,
    evaluation_date: str,
    retrieved_on: str,
    outputs: dict[str, bytes],
    versions: dict[str, str],
) -> dict:
    """Record raw and generated hashes, preserving unchanged retrieval dates."""
    _date(retrieved_on)
    existing_path = root / "data/manifest.json"
    existing = (
        json.loads(existing_path.read_text(encoding="utf-8"))
        if existing_path.exists()
        else {}
    )
    old = {x["source_id"]: x for x in existing.get("inputs", [])}
    inputs = []
    for source_id, (path, url) in sorted(SOURCES.items()):
        sha = digest((root / path).read_bytes())
        retrieval = (
            old[source_id]["retrieved_on"]
            if source_id in old and old[source_id]["sha256"] == sha
            else retrieved_on
        )
        inputs.append(
            {
                "source_id": source_id,
                "path": path,
                "url": url,
                "sha256": sha,
                "retrieved_on": retrieval,
                "upstream_version": versions[source_id],
            }
        )
    return {
        "schema_version": 2,
        "evaluation_date": evaluation_date,
        "dataset_version": dataset_version(evaluation_date, inputs),
        "inputs": inputs,
        "outputs": [
            {"path": path, "sha256": digest(content)}
            for path, content in sorted(outputs.items())
        ],
    }


def reconcile(root: Path, evaluation_date: str, retrieved_on: str) -> dict:
    """Write deterministic derived artifacts after validating all raw sources."""
    outputs, versions = derive(root)
    record = manifest(root, evaluation_date, retrieved_on, outputs, versions)
    for path, content in outputs.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    (root / "data/manifest.json").write_bytes(encode(record))
    return record


def verify(root: Path) -> dict:
    """Recompute and verify every packaged source and derived artifact offline."""
    record = json.loads((root / "data/manifest.json").read_text(encoding="utf-8"))
    if (
        not isinstance(record, dict)
        or record.get("schema_version") != 2
        or not isinstance(record.get("inputs"), list)
    ):
        raise ValueError("unsupported manifest schema")
    if any(
        not isinstance(x, dict)
        or set(x)
        != {"source_id", "path", "url", "sha256", "retrieved_on", "upstream_version"}
        for x in record["inputs"]
    ):
        raise ValueError("malformed manifest source record")
    actual = {x["source_id"]: x for x in record["inputs"]}
    if len(actual) != len(record["inputs"]) or actual.keys() != SOURCES.keys():
        raise ValueError("missing or duplicate manifest source")
    outputs, versions = derive(root)
    for source_id, (path, url) in SOURCES.items():
        row = actual[source_id]
        _date(row["retrieved_on"])
        if (
            row["path"] != path
            or row["url"] != url
            or row["sha256"] != digest((root / path).read_bytes())
            or row["upstream_version"] != versions[source_id]
        ):
            raise ValueError("manifest source integrity mismatch: " + source_id)
    if record["dataset_version"] != dataset_version(
        record["evaluation_date"], record["inputs"]
    ):
        raise ValueError("dataset version mismatch")
    expected_outputs = [
        {"path": path, "sha256": digest(content)}
        for path, content in sorted(outputs.items())
    ]
    if record.get("outputs") != expected_outputs:
        raise ValueError("manifest generated output hashes disagree")
    for path, content in outputs.items():
        if (root / path).read_bytes() != content:
            raise ValueError("stale generated artifact: " + path)
    return record


def changes(previous_root: Path, current_root: Path) -> dict:
    """Diff verified snapshots; no inventory change approves name policy."""
    before, after = verify(previous_root), verify(current_root)

    def rows(root: Path, path: str, key: str) -> list[dict]:
        return json.loads((root / path).read_text(encoding="utf-8"))[key]

    old = {
        x["tld"]: x for x in rows(previous_root, "data/root/inventory.json", "roots")
    }
    new = {x["tld"]: x for x in rows(current_root, "data/root/inventory.json", "roots")}
    fields = (
        "operator",
        "icann_operator",
        "specification13",
        "contract_terminated",
        "type",
        "delegation_date",
        "removal_date",
        "third_or_lower_level_registration",
    )
    metadata = []
    for name in sorted(old.keys() & new.keys()):
        changed = {
            key: {"before": old[name].get(key), "after": new[name].get(key)}
            for key in fields
            if old[name].get(key) != new[name].get(key)
        }
        if changed:
            metadata.append({"tld": name, "changes": changed})
    lists = {}
    for path, key, identity in [
        ("data/psl/rules.json", "rules", ("section", "kind", "suffix")),
        ("data/special-use/names.json", "names", ("name",)),
    ]:
        a = {tuple(x[k] for k in identity): x for x in rows(previous_root, path, key)}
        b = {tuple(x[k] for k in identity): x for x in rows(current_root, path, key)}
        lists[key] = {
            "added": [b[x] for x in sorted(b.keys() - a.keys())],
            "removed": [a[x] for x in sorted(a.keys() - b.keys())],
            "changed": [
                {"before": a[x], "after": b[x]}
                for x in sorted(a.keys() & b.keys())
                if a[x] != b[x]
            ],
        }
    a = {x["id"]: x for x in rows(previous_root, "data/reserved/sets.json", "sets")}
    b = {x["id"]: x for x in rows(current_root, "data/reserved/sets.json", "sets")}
    lists["reserved_sets"] = {
        "added": sorted(b.keys() - a.keys()),
        "removed": sorted(a.keys() - b.keys()),
        "changed": [
            {
                "id": key,
                "labels_added": sorted(set(b[key]["labels"]) - set(a[key]["labels"])),
                "labels_removed": sorted(set(a[key]["labels"]) - set(b[key]["labels"])),
                "metadata_changed": {
                    k: {"before": a[key].get(k), "after": b[key].get(k)}
                    for k in sorted(a[key].keys() | b[key].keys())
                    if k != "labels" and a[key].get(k) != b[key].get(k)
                },
            }
            for key in sorted(a.keys() & b.keys())
            if a[key] != b[key]
        ],
    }
    return {
        "schema_version": 2,
        "before": before["dataset_version"],
        "after": after["dataset_version"],
        "roots_added": sorted(new.keys() - old.keys()),
        "roots_withdrawn": sorted(old.keys() - new.keys()),
        "root_metadata_changes": metadata,
        **lists,
    }
