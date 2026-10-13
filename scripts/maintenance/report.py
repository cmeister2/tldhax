"""Report pinned dataset age and review boundaries without changing evaluation."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

from scripts.data.reconcile import verify


def date(value: str) -> dt.date:
    """Require exact ISO calendar spelling on every maintenance boundary."""
    parsed = dt.date.fromisoformat(value)
    if parsed.isoformat() != value:
        raise ValueError("expected YYYY-MM-DD date")
    return parsed


def records(root: Path, name: str) -> list[dict]:
    """Read optional evidence authoring as UTF-8, including on Python 3.10."""
    path = root / "evidence" / (name + ".toml")
    if not path.exists():
        return []
    return tomllib.loads(path.read_text(encoding="utf-8")).get(name, [])


def freshness(
    root: Path,
    as_of: str,
    *,
    inventory_days: int = 7,
    policy_days: int = 30,
) -> dict:
    """Assess current freshness separately from immutable published outcomes."""
    today = date(as_of)
    if inventory_days < 0 or policy_days < 0:
        raise ValueError("freshness intervals must be nonnegative")
    manifest = verify(root)
    evaluation = date(manifest["evaluation_date"])
    if evaluation > today:
        raise ValueError("as-of date precedes pinned evaluation")
    sources = []
    for kind, rows, interval in [
        ("inventory", manifest["inputs"], inventory_days),
        ("policy", records(root, "sources"), policy_days),
    ]:
        for row in rows:
            retrieved = date(row["retrieved_on"])
            if retrieved > today:
                raise ValueError("source retrieval is after as-of date")
            age = (today - retrieved).days
            sources.append(
                {
                    "source_id": row.get("source_id", row.get("id")),
                    "kind": kind,
                    "retrieved_on": retrieved.isoformat(),
                    "age_days": age,
                    "check_interval_days": interval,
                    "check_due": age > interval,
                    "pinned_sha256": row["sha256"],
                    "pinned_version": row.get("upstream_version", row.get("version")),
                }
            )
    tasks = []
    for assertion in records(root, "assertions"):
        identity = assertion["id"]
        deadline = date(assertion["review_due"])
        if deadline < today:
            tasks.append(
                {
                    "assertion_id": identity,
                    "reason": "review_expired",
                    "date": deadline.isoformat(),
                }
            )
        for field in ("effective_from", "effective_until"):
            if field in assertion:
                boundary = date(assertion[field])
                if evaluation < boundary <= today:
                    tasks.append(
                        {
                            "assertion_id": identity,
                            "reason": field + "_reached",
                            "date": boundary.isoformat(),
                        }
                    )
    return {
        "schema_version": 1,
        "as_of": today.isoformat(),
        "pinned_evaluation_date": evaluation.isoformat(),
        "inventory_dataset_version": manifest["dataset_version"],
        "dataset_age_days": (today - evaluation).days,
        "sources": sorted(sources, key=lambda s: (s["kind"], s["source_id"])),
        "review_tasks": sorted(tasks, key=lambda t: (t["assertion_id"], t["reason"])),
        "approval_status": "review_required",
    }


def write(report: dict, destination: Path) -> None:
    """Write a stable report; it is an observation rather than policy authoring."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
