# Source review and reproducible packages

Offline freshness is separate from the library's pinned evaluation:

```sh
python -m scripts.maintenance --as-of 2026-10-12 --report freshness.json
```

The report contains dataset age, each source's retrieval age, review deadlines,
and documented effective-date boundaries crossed since the published evaluation.
It does not change runtime policy outcomes. Check intervals default to seven days
for inventories and thirty days for policy sources; flags can change those
reporting thresholds.
The report's `inventory_dataset_version` identifies the pinned inventory manifest;
the library's full release fingerprint also includes compiled policy and evidence.

An explicit refresh stages a new verified inventory and reports additions,
withdrawals, operator/Spec 13 changes and routing changes:

```sh
python -m scripts.maintenance --as-of 2026-10-20 --report inventory-review.json \
  --refresh-inventory /tmp/tldhax-candidate-2026-10-20
python -m scripts.maintenance --as-of 2026-10-20 --report policy-review.json \
  --check-policies
```

The staging directory must be new. Refresh retains the existing evaluation date
and never replaces approved data, writes policy authoring, creates commits, or
marks evidence reviewed. A changed source hash needs review of its affected
assertions and independent outcome fixtures. Original-byte policy checks use
bounded public GETs and discard downloaded content after hashing it. HTTP denial
or transfer failure leaves a check gap. An `extracted_text/v1` fingerprint needs
the documented extraction procedure and manual review; original PDF bytes cannot
be compared to that fingerprint.

The source workflow publishes only JSON review reports. It schedules inventories
weekly and policy observations monthly. Quarterly human review remains a research
task, especially for partial coverage and upcoming policy transitions. A failure
report never establishes that a source is unchanged. The workflow has read-only
repository permissions and does not publish updated datasets.

Parser property tests run with 80 deterministic examples per property in ordinary
CI. Set `TLDHAX_FUZZ_EXAMPLES=1000` for the periodic campaign, bounded at 5,000.
They exercise corrupted source bodies, scope separation, normalized identities,
native syntax negatives and batch equivalence. Minimized failures should become
explicit regression fixtures. They supplement the independent policy examples;
they do not establish policy completeness.

Prepare maturin, Python tooling and the pinned Cargo dependency cache first. Then:

```sh
python scripts/package_check.py --work-directory /tmp/tldhax-package-check
```

All packaging commands use Cargo offline mode, a locked dependency graph and
index-free wheel installation. The check verifies every manifest artifact,
compiler module, namespace/profile source, retained evidence snapshot and IDN
input in the source archive. It rebuilds from that unpacked archive, installs both
wheels into fresh virtual environments, and compares their assessments and full
dataset fingerprints outside the checkout. The probe disables socket connections.
The wheel must contain the PSL MPL license and inventory redistribution notices;
the raw inventory is needed in source distributions rather than at runtime.

Cargo's include list must cover `build_support/**`, `data/**`, `evidence/**`,
`rules/**` and compiler fixtures in addition to ordinary source files. The Python
source distribution also needs `pyproject.toml`. Declare
`license-files = ["LICENSE", "data/psl/LICENSE", "data/NOTICES.md"]` under
`[project]` so notices ship under wheel distribution metadata without raw tables.
This also works with maturin 1.9.4, whose wheel include patterns are relative to
the Python source directory rather than the project root.
Generated tables belong in Cargo's `OUT_DIR` and compile into the extension; they
are not additional runtime parsing inputs. Missing build tools/dependency caches
are setup errors, not permission to fetch during an ordinary offline build.

To compare outcomes across releases, save compact assessments as UTF-8 JSONL under
both installed versions. Each row contains only `request_id` (a stable fixture ID)
and `assessment` (the result of `Assessment.to_dict()`). IDs must identify the same
candidate and registrant scenario; profiles remain with the fixture generator.

```sh
python -m scripts.maintenance.outcomes before.jsonl after.jsonl \
  --report outcome-review.json
```

The comparator retains both release identities and reports changed status, name
validity, eligibility, coverage, gap scopes/evidence and failed rule IDs. It ignores
record ordering and formatting/prose, and emits no profile facts or finding params.
Inputs are limited to 10,000 rows, 64 KiB per row and 64 MiB per file. Mismatched
request sets/canonical identities, mixed releases and truncated diagnostics fail
validation; they cannot establish unchanged outcomes. Outcome reports support
human review and never alter policy approvals or advance the evaluation date.
