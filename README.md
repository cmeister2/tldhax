# tldhax

`tldhax` determines whether a domain meets supported static registration rules
given a declared applicant profile. Its offline Rust evaluator returns **yes**,
**no**, or **unknown**, with useful explanations of failed or missing conditions.
Python and a command-line interface expose the same decision.

A `yes` means the applicable implemented policy passes. `no` identifies a known
failed requirement. `unknown` identifies missing declarations or an unsupported
policy condition. A known mandatory failure remains conclusive even when another
condition is unresolved. Matching an alternative eligibility route does not
require declarations for unused routes.

Availability, pricing, proof submission and transaction approval belong to the
application that performs registration. Applicant facts are declarations;
`tldhax` does not verify them.

## Python

```python
from tldhax import Registry

registry = Registry()
assert registry.assess("sunflower.com").decision == "yes"

result = registry.assess("a.au")
assert result.decision == "no"
for reason in result.reasons:
    print(reason.code, reason.message)  # explains the minimum and observed length

profile = registry.prepare_registrant({"de_contract_capacity": True})
assert registry.assess("bücher.de", profile).decision == "yes"
results = registry.assess_many(["bücher.de", "xn--bcher-kva.de", "_bad.com"], profile)
```

`assess()` accepts a mapping or an opaque `PreparedRegistrant`. Prepare once for
repeated calls or batches of up to 10,000 candidates. Batches preserve input order
and evaluate in Rust with the Python GIL released. `profile_schema()` lists
accepted fields, types and any constrained values.

The assessment contains:

```text
decision: yes | no | unknown
canonical_domain: normalized ASCII name, or None for malformed input
namespace: selected registration namespace, if known
reasons: objects with stable code and human-readable message
missing_profile_fields: absent facts still needed for the decision
```

`result.to_dict()` produces JSON-compatible output. `status` aliases `decision`;
`check(domain)` retains the small `status`/list-of-explanation-strings adapter.
Prepared-profile representations, assessment reasons and profile validation
errors omit supplied profile values.

Missing fields differ from explicit `false` or empty sets. Unknown fields, wrong
types, duplicate JSON keys and malformed values are input errors. Country fields
use exactly two uppercase ASCII letters; this validates the declared encoding,
not membership in a country-code inventory. Raw names have a 4,096 UTF-8 byte
limit. Profiles allow 65,536 JSON bytes, 128 fields, 256 values per string set and
1,024 UTF-8 bytes per string fact. Exceeded limits raise `ValueError`.

Canonicalization uses strict nontransitional IDNA processing and DNS size checks.
Equivalent Unicode/Punycode, case variants and one terminal root dot receive the
same decision. Malformed names return `no` with a reason. An inventory or public
suffix entry alone never establishes permission to register: unsupported
namespaces, registration forms and applicable policy conditions remain visible
as `unknown`.

## Command line

```sh
tldhax check a.au
tldhax assess bücher.de --profile registrant.json --json
tldhax batch candidates.jsonl --profile registrant.json
tldhax info com
tldhax stats --json
```

Default single-name output gives the decision and its actual reasons. Profiles
are local JSON objects. Batch input is JSONL strings or `{"domain":"name.com"}`
records; `-` reads stdin. Batch output is JSONL, or a JSON array with `--json`.
`--quiet` prints only decisions. Exit codes are 0 for `yes`, 1 for `no`, and 2 for
`unknown` or input errors. In a batch, any denial takes precedence over unknowns.
The CLI uses UTF-8 regardless of the process locale.

## Policy data and development

Direct policy files in [rules/](rules/) describe registration forms, name and
applicant requirements, IDN support and explicit limitations. Ordinary maintainer
notes record the policy interpretation. Adopted IDN tables and required identity
inputs remain checked in. Schema-checked immutable tables compile into the
library; evaluation needs no network, credentials or runtime policy-file parsing.

`dataset_version()` identifies the packaged release. `supported_namespaces()`
lists authored selectors; individual unsupported scopes still return unknown.

```sh
python -m pip install -e '.[dev]'
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
python -m pytest tests/python
```

Tests cover positive and negative policy cases, incomplete profiles, decisive
alternatives, Unicode/Punycode equivalence, routing, useful explanations and
bounded batch/profile interfaces. Rust documentation lints remain strict.
