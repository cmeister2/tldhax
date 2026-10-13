# Release performance measurement

The measured release meets the initial latency and batch-throughput targets on
this host. This is one warmed run of the 19-case
[assessment corpus](assessment_domains.txt), measured on 2026-10-12.

| Measurement | Observed | Target |
| --- | ---: | ---: |
| Worst native ASCII compact p99, including prepared profiles | 1.793 µs | ≤10 µs |
| Worst native IDNA-work compact p99 | 4.658 µs | ≤100 µs |
| Worst Python ASCII detailed-call p99 | 3.456 µs | ≤100 µs |
| Python mixed ASCII batch, median throughput | 982,399 candidates/s | ≥100,000 candidates/s |

ASCII here excludes every input containing a Unicode label or `xn--` A-label.
The six IDNA-work cases include Unicode applicant labels, equivalent A-labels,
an invalid ContextO sequence, and IDN suffixes. This performance grouping is
independent of the policy evaluator's applicant-label `InputClass`.

## Build and workload identity

- Reachable source commit: `06136d86cfb841238897c4e151bdceb96bce92c4`.
- Recorded measured revision: `4b533c23e14241a3eb2957f476dda29aba011168`,
  before a test-only commit restack. Both revisions have the identical Git tree
  `0c112cdc1595d7177ec6e45216ce928ed3aa02b1`; the recorded artifacts and
  measurements remain unchanged.
- Package: `tldhax 0.0.0`; x86-64 release wheel for CPython 3.12.
- CPU: AMD Ryzen 7 PRO 7840U with Radeon 780M Graphics.
- Host: Linux 6.6.114.1, WSL2, glibc 2.39.
- Python: CPython 3.12.3; Rust: `rustc 1.99.0 (b940084d7 2026-09-28)`.
- Build: `maturin build --release --offline --locked`; no added Rust flags or
  target override. Native benchmark has `debug_assertions=false`.
- Other build/test work finished before timing. This was not an isolated or
  CPU-pinned scheduler experiment.
- Compiled release: 1,437 roots, 25 authored namespaces, 44 predicate rules,
  108 assertions, 47 sources and one IDN profile. Policy gaps remain explicit.

```text
dataset_version:
2026-10-12+907a3c2b1caa5e82d9f249c88adf80fa2a16c5866c6f5fea33abad137e92aac5
normalization_profile:
uts46-nontransitional-std3-hyphens-contexto-v2/idna-1.1.0/idna-adapter-1.2.2/icu-normalizer-2.2.0/icu-normalizer-data-2.2.0/icu-properties-2.2.0/icu-properties-data-2.2.0
corpus_sha256:
866b296fc80619078d0cb1d0834f4c5be5934bd26582b90688c51c74f1c2f5b0
checkout_build_inputs_sha256:
af7e956854cbf868726eb1822edde50c6705842da5e278c43cee7e8159c6e550
native_extension_sha256:
03ad2dda23a99eed0dc6c537fac578c90043a906714a071831dc1de0910ec6bd
wheel_sha256:
e71c835b1944bec79b9291bde4b623ba0d8348c5e2018cb384de6102ec848cd0
```

The compiled dataset identity agrees across Rust, Python and CLI results. The
checkout hash independently records local build inputs; it is a different
algorithm from the compiler's release fingerprint.

## Individual calls

Each cell is **p50 / p99 in microseconds**. Native calls use
`Registry.assess_with_private`; Python uses `Registry.assess` with the indicated
`detailed` flag. Profiles are prepared before these measurements. PRIVATE
classification is enabled for the blogspot case and records `blogspot.com`.

| Candidate / case | Native compact | Python compact | Python detailed |
| --- | ---: | ---: | ---: |
| `sunflower.com` | 0.941 / 1.663 | 1.130 / 2.287 | 1.166 / 1.598 |
| `sunflower.co.uk` | 0.772 / 1.363 | 1.011 / 1.681 | 1.029 / 3.021 |
| `_bad.com` | 0.120 / 0.331 | 0.257 / 0.441 | 0.579 / 1.231 |
| `sunflower..com` | 0.080 / 0.200 | 0.257 / 0.414 | 0.404 / 0.744 |
| `com.co.uk` | 0.751 / 1.332 | 1.386 / 2.186 | 1.213 / 3.408 |
| `sunflower.unknown-tldhax` | 0.411 / 0.772 | 0.606 / 1.047 | 0.753 / 1.194 |
| `sunflower.b.ck` | 0.651 / 1.252 | 0.845 / 1.378 | 0.864 / 1.470 |
| `www.ck` | 0.481 / 0.872 | 0.744 / 0.945 | 0.771 / 1.405 |
| `sunflower.blogspot.com`, PRIVATE | 0.791 / 1.423 | 1.038 / 1.304 | 1.341 / 2.553 |
| `bücher.de` | 1.853 / 4.658 | 1.993 / 3.601 | 2.241 / 3.940 |
| `xn--bcher-kva.de` | 1.723 / 3.326 | 2.144 / 3.647 | 2.424 / 3.036 |
| `日本語.de` | 1.874 / 3.737 | 2.244 / 3.717 | 2.695 / 2.896 |
| `a·b.com` | 0.411 / 0.841 | 0.651 / 0.921 | 0.882 / 1.022 |
| `sunflower.中国` | 1.353 / 2.555 | 1.664 / 2.535 | 1.703 / 3.256 |
| `sunflower.xn--fiqs8s` | 1.243 / 2.224 | 1.653 / 4.759 | 1.673 / 6.832 |
| `vanity.example.com` | 0.541 / 0.982 | 0.752 / 1.182 | 0.912 / 1.623 |
| `1.in-addr.arpa` | 0.811 / 1.512 | 1.092 / 1.904 | 1.342 / 1.983 |
| `vanity.me.uk`, individual | 0.902 / 1.793 | 1.172 / 1.653 | 1.192 / 1.874 |
| `vanity.me.uk`, organization | 0.761 / 1.362 | 1.172 / 2.074 | 1.433 / 3.456 |

The me.uk profiles also declare `organizational_proxy=false`. The individual
matches declared eligibility while the overall name outcome remains unknown;
the organization fails eligibility without making the name itself invalid.
The corpus contains seven summary denials and twelve unknown outcomes. It does
not establish comprehensive policy acceptance or registrar availability.

Worst case p99 for reading **four scalar getters together** was 0.461 µs;
compact-result `to_dict()` formatting peaked at 56.015 µs. These are separate
measurements. Detailed calls format explanation records during assessment;
converting either result to Python dictionaries is additional optional work.

## Batches, startup and allocations

| Python batch of 10,000 | p50 | p99 | Candidates/s at p50 |
| --- | ---: | ---: | ---: |
| Mixed ordinary ASCII, no profile | 10.179 ms | 15.439 ms | 982,399 |
| Repeated `vanity.me.uk`, prepared individual profile | 10.078 ms | 16.426 ms | 992,267 |

These call the actual `Registry.assess_many(detailed=False)` batch API and
include creation of the returned Python result objects. The mixed batch cycles
through corpus ASCII cases, including failures and unresolved policies. The
prepared-profile batch reuses one profile and one candidate, so its throughput
does not characterize all possible profile/candidate mixes.

Startup and profile preparation are **single observations**, separate from warm
latency distributions:

- First native compact call: 52.318 µs; first Python compact call: 49.059 µs.
- Import inside a child interpreter: 11.986 ms; whole import subprocess:
  25.226 ms.
- CLI subprocess, `check sunflower.com --json`: 40.283 ms, exit code 2 for the
  observed unknown policy outcome.
- Python profile preparation: 94.217 µs for the first individual profile,
  11.104 µs for the subsequent organization profile. Native preparation:
  6.753 µs and 0.491 µs respectively.

Native ASCII cases made 1–3 allocation/reallocation requests per call, requesting
512–1,184 bytes in total. IDNA-work cases made 4–16 requests, totaling 544–1,880
bytes; early ContextO rejection is the four-request case. These counters run in
a separate untimed pass and report requested capacity, not peak or live memory.

## Artifact size

| Final artifact measurement | Bytes |
| --- | ---: |
| Compressed wheel | 1,277,353 |
| Entire native extension file | 7,914,720 |
| All allocated ELF section payload | 4,684,847 |
| `.rodata` | 798,092 |
| `.data.rel.ro` | 1,659,584 |
| Combined candidate constant sections | 2,457,676 |
| Dynamic relocation metadata | 1,443,816 |
| Namespace/rule/source/assertion struct payload lower bound | 41,560 |

The whole allocated image is below 10 MiB, conservatively bounding its contained
static policy/evidence tables. The constant sections also contain Unicode,
stdlib, PyO3 and other dependency data; an isolated incremental policy-data
footprint was not measured. The struct lower bound omits strings, predicate
children, other tables and routing. Section payload excludes alignment gaps and
does not measure RSS, heap usage or touched pages. `.data.rel.ro` is covered by
GNU RELRO and becomes read-only after loader relocations.

The exact saved historical Python baseline has 1,512,748 bytes in the same two
constant sections; the descriptive increase is 944,928 bytes. Its build profile
was unattested and it contains 16,634,823 bytes of DWARF. Changes in optimization,
dependencies and generated routing code prevent attributing that difference to
TLD tables alone or claiming a controlled release-file size improvement. The
older legacy-detailed latency reports likewise do not supply a controlled
compact-API speed comparison.

## Reproduction and limits

Use an isolated checkout of the reachable source commit and the development
environment described in the README. Build and extract the wheel without
replacing an installed extension; run from the repository root:

```sh
CARGO_TARGET_DIR=/tmp/tldhax-perf-target \
  maturin build --release --offline --locked --interpreter python \
  --out /tmp/tldhax-perf-wheels
python - <<'PY'
from pathlib import Path
from zipfile import ZipFile
wheels = list(Path('/tmp/tldhax-perf-wheels').glob('*.whl'))
assert len(wheels) == 1, 'Select one current wheel explicitly'
with ZipFile(wheels[0]) as archive:
    archive.extractall('/tmp/tldhax-perf-installed')
PY
PYTHONPATH=/tmp/tldhax-perf-installed CARGO_TARGET_DIR=/tmp/tldhax-perf-target \
  python tools/release_benchmark.py --native > /tmp/tldhax-release-benchmark.json
python tools/artifact_size.py \
  /tmp/tldhax-perf-installed/tldhax/_native.cpython-312-x86_64-linux-gnu.so \
  > /tmp/tldhax-artifact-sections.json
```

The [native harness](assessment.rs) and
[Python driver](../tools/release_benchmark.py) collect 10,000 per-call samples
after 1,000 warmups per case/mode. Native cases rotate their order; Python modes
are measured separately. Batch distributions use 100 samples after 10 warmups.
Percentiles use nearest rank. Timers include the call through return and exclude
result destruction; allocation-instrumentation branches remain in the native
timing build. Mode/case distributions are independent and should not be added
to estimate a combined p99. Observed maxima were sometimes larger than p99;
these measurements are not worst-case latency guarantees.

The driver records the loaded extension hash and rejects differing compiled
dataset identities across native, Python and CLI paths. The
[artifact tool](../tools/artifact_size.py) reads ELF bytes without loading or
executing the library. Raw reports for this run are retained locally as
`/tmp/tldhax-final-release-benchmark.json` and
`/tmp/tldhax-final-artifact-sections.json`.
