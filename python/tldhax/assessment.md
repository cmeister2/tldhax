# Offline assessment API

```python
from tldhax import Registry

registry = Registry()
profile = registry.prepare_registrant({
    "entity_kind": "individual",
    "organizational_proxy": False,
})
result = registry.assess("vanity.me.uk", profile)
print(result.name_validity, result.eligibility, result.status)
results = registry.assess_many(["vanity.me.uk", "bücher.de"], profile)
detailed = registry.assess("vanity.me.uk", profile, detailed=True)
payload = detailed.to_dict()
```

`assess` accepts a flat mapping or an opaque `PreparedRegistrant`. Preparing a
mapping validates its typed facts once; reusing the object or supplying one
mapping to `assess_many` avoids repeated JSON transport. Facts are declared, and
the library does not verify identities or documents. Prepared objects, results
and errors omit profile values from their representations and explanations.

`name_validity`, `eligibility`, `policy_coverage` and combined `status` remain
separate. A supplied-profile failure can produce status `no` while name validity
remains `unknown`: another qualified applicant may meet the same conditional
rule. Partial coverage does not silently become permission.

The result exposes canonical ASCII/Unicode identities, selected namespace and
release metadata as read-only attributes. `to_dict()` allocates JSON-ready rule
traces, findings, coverage gaps and provenance. Compact assessments contain
finding codes; `detailed=True` adds prose and resolved source/assertion records
without changing outcomes. `include_private=True` adds hosting-boundary metadata
without changing registration assessment.

`namespace_info()` includes factual inventory metadata for unresearched known
namespaces. Its absent policy is explicit. `source()` and `assertion()` look up
stable provenance IDs. `dataset_info()` identifies the immutable release;
`dataset_stats()` reports factual denominators and coverage by class/family.
`profile_schema()` lists accepted profile fields with `type` (`boolean`,
`string`, `string_set`), `allowed_values` and `string_format`; an empty list means
no finite enum is specified. Country fields declare `uppercase_alpha2`: exactly
two uppercase ASCII letters. Malformed values fail preparation with
`invalid_profile_value`; they do not imply failed eligibility. This format checks
encoding, not membership in an ISO country-code inventory. Other fields have
`string_format=None`. The schema contains no supplied facts.
Legacy `check()` and `tld_info()` retain their result shapes; a legacy summary is
absent when reviewed policy cannot be represented faithfully.

Each Python batch accepts at most 10,000 candidates. Raw name input is bounded
to 4,096 UTF-8 bytes; excessive input yields an input-limit finding. Profiles
are bounded to 65,536 JSON bytes, 128 fields, 256 values per string set and
1,024 UTF-8 bytes per string fact. Larger batches can be chunked by the caller.

A prospective registration candidate must contain an applicant label beneath
a known delegated root. A bare known root yields `no`/`invalid` under that input
contract; the finding does not claim DNS syntax failure or a registry policy
prohibition. Additional applicant-label forms require their own reviewed policy.

```sh
tldhax check vanity.me.uk --profile registrant.json --json --details
tldhax batch candidates.jsonl --profile registrant.json
tldhax info aaa --json
tldhax stats --json
```

The batch command accepts JSON strings or `{"domain":"vanity.me.uk"}` records,
one per line; `-` reads stdin. Output is JSONL by default and a bounded JSON array
with `--json`. The profile file is local JSON; duplicate fields, unknown keys,
invalid types and input-budget errors produce stable diagnostics without values.
Exit codes remain 0 for `yes`, 1 for `no`, 2 for `unknown`/input errors and 3 for
`restricted`. Batch exit status gives known denial precedence, followed by
unknown and restricted outcomes.
CLI text input/output uses UTF-8 independently of the process locale.
