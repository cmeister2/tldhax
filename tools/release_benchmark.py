"""Measure release compact/detailed calls, formatting, startup and true batches.

Build the extension with `maturin develop --release` before running this tool.
The new API is mandatory: an old extension fails instead of supplying substitutes.
This tool never loads .env, queries providers or prints environment credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.benchmark import measure


def corpus(path: Path) -> list[tuple[str, str, dict[str, Any] | None]]:
    """Read independently authored cases with an optional synthetic profile."""
    cases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or not fields[0] or not fields[1]:
            raise ValueError("assessment corpus requires tag, domain, JSON profile")
        profile = json.loads(fields[2])
        if profile is not None and not isinstance(profile, dict):
            raise ValueError("benchmark profile must be an object or null")
        cases.append((fields[0], fields[1], profile))
    if not cases or len({case[0] for case in cases}) != len(cases):
        raise ValueError("assessment corpus requires unique nonempty case tags")
    return cases


def checkout_hash(root: Path) -> str:
    """Fingerprint explicit build inputs without reading hidden files or secrets."""
    paths = [root / name for name in ("Cargo.toml", "Cargo.lock", "build.rs")]
    paths += [
        path
        for directory in ("src", "build_support", "rules", "evidence", "data")
        for path in (root / directory).rglob("*")
        if path.is_file()
        and path.suffix in {".rs", ".toml", ".json", ".xml", ".txt"}
        and not any(part.startswith(".") for part in path.relative_to(root).parts)
        and path.resolve().is_relative_to(root.resolve())
    ]
    digest = hashlib.sha256()
    for path in sorted(paths):
        name = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        for value in (name, content):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
    return digest.hexdigest()


def require_api(registry: Any) -> None:
    """Reject installed APIs that cannot measure the actual compact/batch path."""
    for name in ("assess", "assess_many", "prepare_registrant", "dataset_info"):
        if not callable(getattr(registry, name, None)):
            raise RuntimeError(
                f"release benchmark requires Registry.{name}; rebuild extension"
            )


def ascii_domains(
    cases: list[tuple[str, str, dict[str, Any] | None]],
) -> list[str]:
    """Select ordinary ASCII inputs without internationalised A-labels or profiles."""
    return [
        domain
        for _, domain, profile in cases
        if domain.isascii()
        and profile is None
        and not any(label.lower().startswith("xn--") for label in domain.split("."))
    ]


def main() -> None:
    """Emit a reproducible report for the loaded extension and pinned release."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true")
    parser.add_argument("--samples", type=int, default=10_000)
    parser.add_argument("--warmup", type=int, default=1_000)
    parser.add_argument("--batch-samples", type=int, default=100)
    args = parser.parse_args()
    if min(args.samples, args.batch_samples) < 100 or args.warmup < 0:
        parser.error("samples/batch-samples must be >=100; warmup must be >=0")
    root = Path(__file__).resolve().parents[1]
    corpus_path = root / "benches/assessment_domains.txt"
    cases = corpus(corpus_path)
    corpus_sha = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
    from time import perf_counter_ns

    started = perf_counter_ns()
    imported = subprocess.run(
        [
            sys.executable,
            "-c",
            "from time import perf_counter_ns; t=perf_counter_ns(); import tldhax; print(perf_counter_ns()-t)",
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=root,
    )
    subprocess_ns = perf_counter_ns() - started
    import tldhax
    from tldhax import _native

    registry: Any = tldhax.Registry()
    require_api(registry)
    started = perf_counter_ns()
    first = registry.assess(cases[0][1], detailed=False)
    first_call_ns = perf_counter_ns() - started
    dataset_info = registry.dataset_info()
    if dataset_info["dataset_version"] != first.dataset_version:
        raise RuntimeError("registry and assessment release fingerprints differ")
    cli_command = [sys.executable, "-m", "tldhax.cli", "check", cases[0][1], "--json"]
    started = perf_counter_ns()
    cli = subprocess.run(cli_command, capture_output=True, text=True, cwd=root)
    cli_subprocess_ns = perf_counter_ns() - started
    cli_payload = json.loads(cli.stdout)
    if cli_payload["dataset_version"] != first.dataset_version:
        raise RuntimeError("CLI and Python release fingerprints differ")
    if cli_payload["status"] != first.status:
        raise RuntimeError("CLI and Python summary outcomes differ")
    prepared = {}
    preparation = {}
    for tag, _, profile in cases:
        if profile is not None:
            started = perf_counter_ns()
            prepared[tag] = registry.prepare_registrant(profile)
            preparation[tag] = perf_counter_ns() - started
    scalar = []
    for tag, domain, _ in cases:
        profile = prepared.get(tag)
        include_private = tag == "private_classification"
        value = registry.assess(
            domain, profile, detailed=False, include_private=include_private
        )
        scalar.append(
            {
                "case": tag,
                "domain": domain,
                "prepared_profile": profile is not None,
                "include_private": include_private,
                "observed": {
                    name: getattr(value, name)
                    for name in (
                        "name_validity",
                        "status",
                        "policy_coverage",
                        "eligibility",
                    )
                },
                "compact_call": measure(
                    lambda arg: registry.assess(
                        arg, profile, detailed=False, include_private=include_private
                    ),
                    domain,
                    args.samples,
                    args.warmup,
                ),
                "detailed_call": measure(
                    lambda arg: registry.assess(
                        arg, profile, detailed=True, include_private=include_private
                    ),
                    domain,
                    args.samples,
                    args.warmup,
                ),
                "scalar_getters": measure(
                    lambda _: (
                        value.name_validity,
                        value.status,
                        value.policy_coverage,
                        value.eligibility,
                    ),
                    None,
                    args.samples,
                    args.warmup,
                ),
                "to_dict_formatting": measure(
                    lambda _: value.to_dict(), None, args.samples, args.warmup
                ),
            }
        )
    ordinary_ascii = ascii_domains(cases)
    if not ordinary_ascii:
        raise ValueError("benchmark corpus has no ordinary ASCII batch candidates")
    batch = [ordinary_ascii[index % len(ordinary_ascii)] for index in range(10_000)]
    batches = {}
    for name, domains, profile in (
        ("ascii_mixed", batch, None),
        (
            "prepared_profile",
            ["vanity.me.uk"] * 10_000,
            prepared["declared_eligibility"],
        ),
    ):
        if len(registry.assess_many(domains, profile, detailed=False)) != len(domains):
            raise RuntimeError("batch API returned the wrong result count")
        timing = measure(
            lambda arg: registry.assess_many(arg, profile, detailed=False),
            domains,
            args.batch_samples,
            10,
        )
        batches[name] = {
            "api": "Registry.assess_many(detailed=False)",
            "candidates": len(domains),
            **timing,
            "candidates_per_second_at_median": len(domains) * 1e9 / timing["p50_ns"],
        }
    extension = Path(_native.__file__)
    cpu = (
        next(
            (
                line.split(":", 1)[1].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")
            ),
            platform.processor(),
        )
        if Path("/proc/cpuinfo").exists()
        else platform.processor()
    )
    report = {
        "report_schema": 2,
        "api": "Registry.assess(detailed=False)",
        "dataset_version": first.dataset_version,
        "dataset_info": dataset_info,
        "checkout_build_inputs_sha256": checkout_hash(root),
        "corpus_sha256": corpus_sha,
        "python": sys.version,
        "platform": platform.platform(),
        "cpu": cpu,
        "package_version": importlib.metadata.version("tldhax"),
        "extension_path": str(extension),
        "extension_sha256": hashlib.sha256(extension.read_bytes()).hexdigest(),
        "extension_build_flags": "not exposed; build release extension explicitly",
        "requested_build_flags": {
            key: os.environ.get(key, "")
            for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET")
        },
        "import_in_child_ns": int(imported.stdout),
        "import_subprocess_total_ns": subprocess_ns,
        "first_call_ns": first_call_ns,
        "cli_subprocess_total_ns": cli_subprocess_ns,
        "cli_status_code": cli.returncode,
        "cli_api": "python -m tldhax.cli check --json",
        "profile_preparation_ns": preparation,
        "scalar": scalar,
        "batches": batches,
        "measurement": "Individual monotonic-clock calls through return exclude result destruction. Detailed calls evaluate and format explanations; getters and to_dict reuse compact results. Batches call the real API with 10000 candidates. Profile preparation, import and CLI startup are separate single samples.",
        "dataset_binding": "Compiled dataset_version identifies the loaded release; checkout hash independently fingerprints local inputs, not the compiler's release-fingerprint algorithm.",
    }
    if args.native:
        environment = os.environ.copy()
        environment.update(
            TLDHAX_CORPUS_SHA256=corpus_sha,
            TLDHAX_BENCH_SAMPLES=str(args.samples),
            TLDHAX_BENCH_WARMUP=str(args.warmup),
        )
        native = subprocess.run(
            ["cargo", "bench", "--bench", "assessment", "--offline", "--locked"],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        report["native"] = json.loads(native.stdout)
        if report["native"]["dataset_version"] != first.dataset_version:
            raise RuntimeError(
                "native and Python release fingerprints differ; rebuild extension"
            )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
