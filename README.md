# tldhax

`tldhax` is a fast, offline Rust library with Python bindings for filtering
prospective public-registration domain names, including vanity URLs. It checks
name rules and optional declared registrant eligibility against a compiled,
source-backed dataset. Availability, pricing, purchases and registry verification
belong to the application that performs registration.

Policy, factual inventory and evidence compile into the binary. Normal lookup
does no networking, credential loading or policy-file parsing. Unresearched
policy remains an explicit gap; an active TLD or PSL entry never implies open
registration.

## Python API

```python
from tldhax import Registry

registry = Registry()
result = registry.assess("ß.com")       # compact result; no prose formatting
assert result.name_validity == "invalid"
assert result.status == "no"

detailed = registry.assess("ß.com", detailed=True)
payload = detailed.to_dict()            # allocate JSON-ready output on request
assert any(rule["rule_id"] == "com.idn-no-sharp-s"
           and rule["truth"] == "true" for rule in payload["rules"])

# A passed rule does not imply complete name-policy coverage.
german = registry.assess("bücher.de").to_dict()
assert any(rule["rule_id"] == "de.idn-repertoire"
           and rule["truth"] == "true" for rule in german["rules"])
assert german["status"] == "unknown"
```

The sharp-s prohibition comes from
[Verisign IDN Registration Rules §5](https://www.verisign.com/resources/internationalized-domain-names/idn-registration-rules/).
DENIC's reviewed repertoire comes from
[Domainrichtlinien V(1)–(2) and Annex](https://www.denic.de/domainrichtlinien/).
Detailed findings resolve assertion IDs, source URLs, content hashes, locators
and review dates. `source(id)` and `assertion(id)` also query those records.
Compact and detailed assessment produce the same decisions.

| Result | Meaning |
| --- | --- |
| `name_validity`: `valid`, `invalid`, `unknown` | The candidate satisfies fully reviewed applicable name policy, fails a proven constraint/input contract, or lacks enough evidence. |
| `eligibility`: `not_required`, `declared_match`, `does_not_match`, `needs_profile`, `unknown_policy` | Applicant conditions are absent, declared facts match/fail, facts are missing, or applicant policy is incomplete. |
| `policy_coverage`: `complete`, `partial`, `unknown`, `conflicting` | How much applicable policy is established, independently of a decisive prohibition. |
| `status`: `yes`, `no`, `restricted`, `unknown` | Combined candidate/profile assessment. `yes` requires complete support; `restricted` identifies an otherwise valid name requiring applicant facts. |

A supplied profile can produce `status="no"` with `name_validity="unknown"`:
another qualifying applicant could satisfy the same conditional rule. Facts are
self-declared; matching them is not identity, residency or document verification.
Missing facts differ from explicit `false` or an empty set. A known denial
remains decisive even when other policy families have gaps.

Discover accepted fields, types and finite enums, then prepare once for reuse:

```python
schema = registry.profile_schema()
assert schema["citizenships"]["type"] == "string_set"
assert schema["google_qualifying_trademark_licensee"]["type"] == "boolean"

profile = registry.prepare_registrant({
    "entity_kind": "individual",
    "organizational_proxy": False,
})
matching = registry.assess("vanity.me.uk", profile)
assert matching.eligibility == "declared_match"
assert matching.status == "unknown"     # independent name/access gaps remain

results = registry.assess_many(
    ["vanity.me.uk", "bücher.de", "_bad.com"], profile
)
```

`assess()` also accepts a mapping. `assess_many()` prepares one mapping once,
preserves order and runs a native batch of at most **10,000** names with the GIL
released during Rust evaluation. Prepared profiles are opaque; result formatting,
representations and validation messages omit supplied facts. Unknown fields,
wrong types, duplicate JSON keys and excessive input are rejected. Profile
budgets are 65,536 JSON bytes, 128 fields, 256 values per string set and 1,024
UTF-8 bytes per string fact. Empty schema `allowed_values` means no finite enum.
Country fields expose `string_format="uppercase_alpha2"` and require exactly two
uppercase ASCII letters. Malformed declarations fail preparation with
`invalid_profile_value` before eligibility evaluation. This checks encoding,
not membership in an ISO country-code inventory.

## Input and namespace contract

Raw domain input is capped at **4,096 UTF-8 bytes before preprocessing**; excess
produces `unknown` with `input_limit`. Case, equivalent U-/A-labels and one
terminal root dot share canonical identity. Strict nontransitional UTS46, STD3,
hyphen, contextual and DNS wire checks reject malformed candidates.

The prospective-candidate API requires an applicant label beneath a known
delegated root: bare `com` produces `no`/`invalid` with `bare_root`. This is an
API shape requirement supported by root inventory, not a registry prohibition
or a claim that bare-root DNS syntax is invalid. An unknown root produces
`unknown`. Additional applicant-label forms require separate reviewed evidence;
there is no universal “everything deeper is a subdomain” ban.

`registration` identifies the selected registration route; `icann` separately
records PSL discovery. A reviewed route approves only its evidenced component
counts. PSL exact, wildcard and exception boundaries alone do not approve a
registration form or registrant. `include_private=True` adds the independent
hosting boundary in `private`; it does not change registration outcomes.

```python
info = registry.namespace_info("aaa")
assert info is not None
assert info.to_dict()["root_inventory"]["tld"] == "aaa"
assert info.to_dict()["policy"] is None   # inventory-only information
```

`namespace_info()` exposes inventory, reviewed rules/evidence and family gaps.
Legacy `check()` keeps its `status`/`reasons` shape, but decisions now use reviewed
policy. `tld_info()` keeps its old shape only where the summary is faithful:
`tld_info("co.uk")` is `None` because conflicting length evidence cannot fit one
unconditional minimum/maximum.

Migration corrects earlier unsupported assumptions:

- `.de` has no blanket German-residence gate. Contract capacity is necessary;
  a German service recipient is appointed following a DENIC request. See
  [DENICdirect FAQ](https://www.denic-services.de/en/denic-direct/frequently-asked-questions)
  and [Domainbedingungen §3(4)](https://www.denic.de/domainbedingungen/).
- `ab.co.uk` is not rejected by an invented three-character minimum. Current
  [Nominet Rules §§5.2–5.7](https://nominet.uk/wp-content/uploads/2025/03/UK-rules-of-registration.pdf)
  and field documentation leave a recorded length-wording conflict. The revised
  policy commencing 9 February 2027 is inactive in the October 2026 dataset.
- `za.sk` has no reviewed current prohibition in this corpus and stays unknown.
  Historical entries are research inputs, not active approvals or denials.
- A Spec13 inventory flag alone does not prohibit a name. For `.google`, the
  [2017 Global Amendment §32, Specification13 §§9.3(ii), 9.5](https://newgtlds.icann.org/sites/default/files/agreements/agreement-approved-global-amendment-31jul17-en.html)
  establishes operator, qualifying Affiliate and organizational Trademark Licensee
  alternatives; [the applicable 2023 amendment, Schedule A](https://itp.cdn.icann.org/en/files/registry-agreements/specification-13-global-amendment-07-08-2023-en.html)
  includes `.google`. The license concerns the Brand trademark, not a literal
  candidate-label grant. DNS setup and future-use purpose remain context.

## Dataset and command line

```python
release = registry.dataset_info()
print(release["dataset_version"], release["evaluation_date"])
print(release["inventory_date"], release["normalization_profile"])
coverage = registry.dataset_stats()
```

The immutable fingerprint covers pinned inputs and compilation context.
`evaluation_date` determines active policy; `inventory_date` dates factual
snapshots. Source retrieval is not policy commencement. The normalization
profile includes the selected contract, pinned `idna-1.1.0` and
`idna-adapter-1.2.2`, and ICU normalization/property libraries and data at `2.2.0`.
See [evidence provenance](evidence/README.md) and [inventory inputs](data/README.md).

`dataset_stats()` reports active roots, known inventory namespaces, authored
namespace policies, rules, assertions, sources, IDN profiles and ASCII/IDN
coverage by family. Those denominators describe different things. Deprecated
legacy `stats()` remains compatible and its faithful-summary counts can all be
zero; the compiled inventory and policy corpus can still contain substantial data.

```sh
tldhax check 'ß.com' --json --details
tldhax check vanity.me.uk --profile registrant.json --json
tldhax batch candidates.jsonl --profile registrant.json
tldhax info aaa --json
tldhax stats --json
```

Profiles are local JSON objects. Batch input is JSONL strings or
`{"domain":"vanity.me.uk"}` objects, at most 10,000 records; `-` reads stdin.
Batch output is JSONL by default, or a JSON array with `--json`. `--details`
adds prose/provenance and `--include-private` adds hosting metadata. Exit codes
are 0=`yes`, 1=`no`, 2=`unknown`/input error, 3=`restricted`; batch status prioritizes
known denial, then unknown, then restricted.
CLI text streams use UTF-8 independently of the process locale.

## Development

```sh
python -m pip install -e '.[dev]'
cargo test
python -m pytest
```

Tests include independent source-derived positive/negative policy cases,
normalization properties, optional-profile privacy, synthetic complete policies
and namespace isolation. Fake HTTP/clock tests exercise the optional registrar
oracle without credentials or networking. Its API dependencies belong only to
the [developer oracle](tools/README.md), not normal library operation.

Release benchmarks measure compact lookup separately from getters, formatting,
prepared profiles and true batches. Performance targets and development
measurements are provisional until repeated against the final release artifact
and its recorded dataset/backend identity.
