# tldhax

`tldhax` is a safety-first Rust library, Python package, and command-line tool
for assessing proposed domain registrations against pinned namespace data and
explicitly sourced registry policy.

It answers whether a registration is statically `plausible`, `conditional`,
`impossible`, or `indeterminate`. It does not check live availability, prices,
trademarks, or whether a registrar will complete an order. In particular, a
delegated root or Public Suffix List entry is never treated as proof that public
registration is open.

The project is pre-1.0. The former `check()`/`tld_info()` API and its
`yes`/`no`/`restricted` classification were removed because that model produced
unsupported positive answers. Missing policy now remains unknown and yields an
`indeterminate` verdict.

## What an assessment contains

An `Assessment` exposes the decision instead of hiding it behind one Boolean:

- normalized IDNA A-label and protocol syntax status;
- the registrable domain and exact, wildcard, or exception suffix match;
- ICANN versus PRIVATE PSL topology and its pinned evidence ID;
- current root state, ordinary versus special-use namespace state, and assigned
  registration product suffix;
- offering state, public-access class, application channel, and eligibility;
- discoverable eligibility requirement IDs, metadata, evidence, and outcomes;
- registry-specific label-policy status;
- stable finding codes, readable explanations, per-axis evidence IDs, and a
  de-duplicated aggregate evidence list.

The verdicts mean:

| Verdict | Meaning |
|---|---|
| `plausible` | Static checks pass for a verified open, accepting product; live availability remains unknown |
| `conditional` | Static checks pass, but verified eligibility, approval, or controlled allocation applies |
| `impossible` | A verified protocol, namespace, product, eligibility, or label-policy rule fails |
| `indeterminate` | A decision-critical policy fact is unknown, stale, conflicting, or incomplete |

## Rust API

```rust
use tldhax::{Registry, Verdict};

let registry = Registry::new();
let assessment = registry.assess("ordinary-candidate.com");

// A standards-reserved namespace has a decisive negative result.
let reserved = registry.assess("example.com");
assert_eq!(reserved.verdict, Verdict::Impossible);
assert_eq!(reserved.offering_state.value, None);

// Other assessments may remain indeterminate until every critical policy
// dimension has capable evidence.
assert!(matches!(assessment.verdict, Verdict::Indeterminate));

// Topology and registration products can select different boundaries.
let suffix = registry
    .suffix_info("service.gov.uk")
    .expect("known suffix");
assert_eq!(suffix.topology.suffix, "service.gov.uk");
assert_eq!(suffix.product_suffix.as_deref(), Some("gov.uk"));
assert_eq!(suffix.canonical_suffix, "gov.uk");

// Assessments carry stable evidence IDs; retrieve full provenance explicitly.
for evidence_id in &assessment.evidence {
    let evidence = registry.evidence(evidence_id).expect("compiled evidence");
    println!("{}: {}", evidence.id, evidence.url);
}
```

The PSL-derived suffix is a topology boundary. `product_suffix` is the suffix
at which the selected registration product allocates names. When a product is
known, `registrable_domain` and `candidate_status` are evaluated at that product
boundary; otherwise they fall back to the PSL boundary. `SuffixInfo` keeps both:
`canonical_suffix` selects the product boundary when present, while
`topology.suffix` always reports the PSL result.

Eligibility-aware evaluation accepts facts by stable requirement ID:

```rust
use tldhax::{RegistrantContext, Registry};

let registry = Registry::new();
let mut context = RegistrantContext::default();
context
    .satisfied_requirements
    .insert("govuk-public-sector".to_owned());
context
    .satisfied_requirements
    .insert("govuk-name-approval".to_owned());

let assessment = registry.assess_for("service.gov.uk", &context);
println!("{}", assessment.verdict.as_str());
for requirement in &assessment.eligibility_requirements {
    println!("{}: {:?}", requirement.id, requirement.outcome);
}
```

`Registry::stats()` splits roots by namespace state, topology by ICANN/PRIVATE
section, and product selectors by exact/one-label-below form. Each policy
dimension reports verified/unknown/stale/conflicting counts both per product
and weighted by selector. It does not collapse those axes into a misleading
single coverage percentage.

## Python API

```python
from tldhax import Registry

registry = Registry()
assessment = registry.assess("ordinary-candidate.com")

assert assessment.verdict == "indeterminate"
reserved = registry.assess("example.com")
assert reserved.verdict == "impossible"
assert reserved.namespace_state == "special_use"
assert reserved.offering_state is None  # no fabricated product-policy claim

suffix = registry.suffix_info("gov.uk")
assert suffix is not None
assert suffix.canonical_suffix == "gov.uk"

# Every flattened claim retains its own evidence IDs as well as status/value.
assert assessment.root_state_evidence
assert set(assessment.root_state_evidence) <= set(assessment.evidence)

for evidence_id in assessment.evidence:
    evidence = registry.evidence(evidence_id)
    assert evidence is not None
    print(evidence.id, evidence.url)
```

For a gated product, pass known facts as stable requirement IDs. A requirement
not listed as satisfied or unsatisfied remains unknown. A supplied ID that does
not belong to the selected product does not count as partial context: the
assessment preserves missing-context semantics and adds an
`unknown_eligibility_requirement` finding so typos are visible.

```python
assessment = registry.assess_for(
    "service.gov.uk",
    satisfied=["govuk-public-sector", "govuk-name-approval"],
    unsatisfied=[],
)
print(assessment.verdict, assessment.eligibility)
for requirement in assessment.eligibility_requirements:
    print(requirement.id, requirement.kind, requirement.outcome)
```

## Command line

After installing the Python package, assess a candidate or inspect a suffix:

```bash
tldhax assess candidate.de
tldhax suffix-info gov.uk
tldhax evidence denic-public-applicants
tldhax stats
```

The `assess` command exits with status `0` for `plausible`, `1` for
`impossible`, `2` for `indeterminate`, and `3` for `conditional`. Use `--json`
when another program will consume the result; it includes suffix evidence,
product suffix, namespace state, per-axis claim evidence, and per-requirement
outcomes. Human-readable messages are not a stable data interface.

Failed `suffix-info` and `evidence` lookups exit nonzero. Human-mode diagnostics
go to standard error; JSON mode keeps standard output machine-readable with a
stable error code and the failed lookup key. The two codes are
`suffix_not_found` with `suffix` and `evidence_not_found` with `evidence_id`;
both exit with status `2`:

```json
{
  "error": {
    "code": "evidence_not_found",
    "evidence_id": "missing-id",
    "message": "No evidence record with id 'missing-id'"
  }
}
```

## Data and evidence

The source model has four independent layers: root namespace, suffix topology,
registration products, and policy/evidence. Policy is authored as reusable
profiles explicitly assigned to products, rather than copied onto every PSL
row. Each decision-critical claim records an evidence state and is validated
against the source's capability and product scope. Curated evidence has a
`review_after` date; the offline checker fails once that date has passed so
policy cannot silently age into authority.

Authoritative topology and namespace inputs are checked into `data/snapshots/`
with URL, version, retrieval time, parser version, and SHA-256 provenance in
`data/manifest.toml`. Normal builds are deterministic and do not use the
network. Curated policy records contain a URL, locator, review date, and digest,
but their source payloads are not vendored snapshots and are not reproduced by
a normal build. See [the data-model guide](docs/data-model.md) for the schemas,
evidence rules, unknown semantics, and policy-curation workflow.

The vendored Public Suffix List remains MPL-2.0 material; its notice, complete
license text, and snapshot provenance are checked in. Python wheels include the
third-party notice and PSL license in their standard distribution metadata.
For other snapshots, `data/manifest.toml` records the upstream terms identified
during retrieval; `NOASSERTION` is metadata, not a licence grant or a project
conclusion about redistribution rights.

## Updating pinned snapshots

Check the committed data without network access:

```bash
python3 tools/update_snapshots.py --check
```

Refreshing is an explicit, networked maintenance operation:

```bash
python3 tools/update_snapshots.py
python3 tools/update_snapshots.py --check
cargo test --locked --all-targets
```

Review all snapshot, manifest, and generated behavior changes before committing
an update. `cargo build` never refreshes data implicitly.

## Development

The same checks run in CI:

```bash
python3 tools/update_snapshots.py --check
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets

python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[dev]'
pytest
mypy
ruff check .
ruff format --check .
```

The Python package requires CPython 3.10 or newer. Binary distributions use the
CPython stable ABI beginning at 3.10 (`abi3-py310`), so each platform wheel is
forward-compatible with newer supported CPython releases. CI exercises Python
3.10 and 3.12.

Release jobs build ABI3 wheels for Linux, musllinux, Windows, and macOS, plus a
source distribution, from the same checked-in data. Before publication or tag
creation, the workflow checks required wheel notices, smoke-tests a
representative Linux wheel and the source distribution in clean environments,
and dry-runs both PyPI and crates.io publication. Those build and validation
steps remain usable now. Production publication is intentionally gated by
`tools/check_distribution_rights.py`: while the three bundled IANA/ICANN
snapshots remain `NOASSERTION`, the workflow stops before publishing or tagging.
Once redistribution rights have been reviewed and asserted, or the unresolved
payloads are no longer bundled, it publishes the packages and creates the Git
tag and GitHub release last.
