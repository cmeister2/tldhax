"""Measure actual Python calls and optionally native calls against one corpus.

Run `python tools/benchmark.py --native > /tmp/tldhax-benchmark.json` after
building the installed extension from this checkout with `maturin develop -r`.
Sources and the loaded extension are hashed separately to expose stale installs.
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
from collections.abc import Callable
from pathlib import Path
from time import perf_counter_ns
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.corpus_audit import audit


def distribution(durations: list[int]) -> dict[str, int]:
    """Summarise individual call times using nearest-rank percentiles."""
    if not durations:
        raise ValueError("at least one duration is required")
    ordered = sorted(durations)
    return {
        "samples": len(ordered),
        "p50_ns": ordered[(len(ordered) * 50 + 99) // 100 - 1],
        "p99_ns": ordered[(len(ordered) * 99 + 99) // 100 - 1],
        "min_ns": ordered[0],
        "max_ns": ordered[-1],
    }


def timed_call(method: Callable[[Any], Any], argument: Any) -> int:
    """Measure the call through return, excluding destruction of its result."""
    started = perf_counter_ns()
    result = method(argument)
    elapsed = perf_counter_ns() - started
    del result
    return elapsed


def measure(
    method: Callable[[Any], Any], argument: Any, samples: int, warmup: int
) -> dict[str, int]:
    """Record first invocation separately before warming and sampling an API."""
    first = timed_call(method, argument)
    for _ in range(warmup):
        method(argument)
    return {
        "first_invocation_ns": first,
        "warmup_calls": warmup,
        **distribution([timed_call(method, argument) for _ in range(samples)]),
    }


def main() -> None:
    """Run credential-free offline benchmarks and emit a single JSON report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true")
    parser.add_argument("--samples", type=int, default=10_000)
    parser.add_argument("--warmup", type=int, default=1_000)
    parser.add_argument("--batch-samples", type=int, default=100)
    arguments = parser.parse_args()
    if min(arguments.samples, arguments.batch_samples) < 100 or arguments.warmup < 0:
        parser.error("samples and batch-samples must be >=100; warmup must be >=0")
    root = Path(__file__).resolve().parents[1]
    corpus_file = root / "benches/domains.txt"
    corpus = [line.split("\t", 1) for line in corpus_file.read_text().splitlines()]
    corpus_hash = hashlib.sha256(corpus_file.read_bytes()).hexdigest()
    inventory = audit(root / "rules")
    import_code = (
        "from time import perf_counter_ns; t=perf_counter_ns(); "
        "import tldhax; print(perf_counter_ns()-t)"
    )
    started = perf_counter_ns()
    imported = subprocess.run(
        [sys.executable, "-c", import_code],
        capture_output=True,
        text=True,
        check=True,
        cwd=root,
    )
    startup_ns = perf_counter_ns() - started
    import tldhax
    from tldhax import _native

    registry = tldhax.Registry()
    scalar_names = ("check", "assess", "check_compact", "assess_compact")
    batch_names = ("assess_many", "check_many", "assess_many_compact")
    scalar = {}
    for name in scalar_names:
        method = getattr(registry, name, None)
        if callable(method):
            scalar[f"Registry.{name}"] = [
                {
                    "case": tag,
                    "domain": domain,
                    **measure(method, domain, arguments.samples, arguments.warmup),
                }
                for tag, domain in corpus
            ]
    ascii_domains = [domain for _, domain in corpus if domain.isascii()]
    batch = [ascii_domains[i % len(ascii_domains)] for i in range(10_000)]
    batches = {}
    for name in batch_names:
        method = getattr(registry, name, None)
        if callable(method):
            timing = measure(method, batch, arguments.batch_samples, 10)
            batches[f"Registry.{name}"] = {
                "candidates_per_call": len(batch),
                **timing,
                "candidates_per_second_at_median": len(batch) * 1e9 / timing["p50_ns"],
            }
    started = perf_counter_ns()
    cli = subprocess.run(
        [sys.executable, "-m", "tldhax.cli", "check", corpus[0][1], "--json"],
        capture_output=True,
        text=True,
        cwd=root,
        check=False,
    )
    cli_startup_ns = perf_counter_ns() - started
    if cli.returncode not in (0, 1, 2, 3):
        raise RuntimeError("CLI benchmark failed")
    extension = Path(_native.__file__)
    cpu_info = Path("/proc/cpuinfo")
    cpu = (
        next(
            (
                line.split(":", 1)[1].strip()
                for line in cpu_info.read_text().splitlines()
                if line.startswith("model name")
            ),
            platform.processor(),
        )
        if cpu_info.exists()
        else platform.processor()
    )
    report = {
        "report_schema": 1,
        "python": sys.version,
        "platform": platform.platform(),
        "cpu": cpu,
        "package_version": importlib.metadata.version("tldhax"),
        "extension_path": str(extension),
        "extension_sha256": hashlib.sha256(extension.read_bytes()).hexdigest(),
        "extension_build_flags": "not exposed by installed extension",
        "requested_build_flags": {
            name: os.environ.get(name, "")
            for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET")
        },
        "dataset_sha256": inventory["corpus_sha256"],
        "corpus_sha256": corpus_hash,
        "dataset_binding": "Source authoring hash; rebuild the installed extension from this checkout before comparing results.",
        "inventory": inventory["inventory"],
        "scalar_apis": scalar,
        "batch_apis": batches,
        "unavailable_apis": [
            name
            for name in (*scalar_names, *batch_names)
            if not callable(getattr(registry, name, None))
        ],
        "import_in_child_ns": int(imported.stdout),
        "import_subprocess_total_ns": startup_ns,
        "cli_subprocess_total_ns": cli_startup_ns,
        "cli_status_code": cli.returncode,
        "measurement": "Per-call monotonic timings exclude result destruction; first invocation is per case/API, and prior cases may have warmed shared state. Startup is one sample and includes process overhead. Batches use real native batch methods only.",
    }
    if arguments.native:
        environment = os.environ.copy()
        environment.update(
            {
                "TLDHAX_DATASET_SHA256": inventory["corpus_sha256"],
                "TLDHAX_CORPUS_SHA256": corpus_hash,
                "TLDHAX_BENCH_SAMPLES": str(arguments.samples),
                "TLDHAX_BENCH_WARMUP": str(arguments.warmup),
            }
        )
        native = subprocess.run(
            ["cargo", "bench", "--bench", "lookup", "--offline"],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        report["native"] = json.loads(native.stdout)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
