# Data model

`tldhax` answers a narrow question: given a proposed domain and the facts that
have been verified about its registration product, what can static analysis say
about a new registration?

It deliberately does not treat delegation, appearance in the Public Suffix
List (PSL), or the existence of an IANA record as proof that a domain is sold to
the public. It also does not perform a live availability search. The strongest
positive verdict, `plausible`, still means only that the static checks and the
verified public policy pass.

## Normalized layers

The compiled registry keeps facts with different meanings in different types:

| Layer | Type | What it describes |
|---|---|---|
| DNS root | `RootTld` | Canonical A-label, optional display U-label, IANA family, current root state, operator IDs, and designations |
| Suffix topology | `SuffixRule` / `SuffixMatch` | The prevailing PSL exact, wildcard, or exception rule; its ICANN or PRIVATE section, boundary role, and pinned evidence ID |
| Allocation path | `RegistrationProduct` | A concrete product at a root or child suffix, its operator, offering state, access class, application channel, and eligibility |
| Reused policy | `PolicyProfile` | A versioned set of claims shared by explicitly assigned products and flattened at build time |
| Label rules | `LabelPolicy` / `IdnProfile` | Registry-specific length, IDN repertoire, and reserved-name policy, distinct from DNS and IDNA protocol validity |
| Provenance | `Evidence` | A reusable source identity plus a precise locator, retrieval date, optional review deadline, digest, and capability class; predicate and product scope are checked in the authoring model |

This separation matters. `gov.uk` is an allocation product below a PSL
boundary; `.bank` is delegated but eligibility-gated; `.arpa` is protocol
infrastructure; and a PRIVATE PSL rule such as `github.io` is a tenant security
boundary rather than a registry product. None can be represented safely by a
single `registerable = yes/no` field.

There are consequently two suffix boundaries in some results. The PSL-derived
`public_suffix` is a topology boundary: it can describe a registry boundary or
a PRIVATE tenant boundary. `product_suffix` is the allocation boundary of the
selected `RegistrationProduct`. For `service.gov.uk`, for example, the PSL
result may be `service.gov.uk` while the researched product allocates at
`gov.uk`. `Assessment.registrable_domain` and `candidate_status` use the product
boundary when a product is selected and otherwise use the PSL result.
`SuffixInfo.canonical_suffix` follows the same product-first rule while retaining
the PSL result separately in `topology` (Rust) or `public_suffix` (Python).

All domain and suffix keys are canonical lowercase IDNA A-labels internally.
Unicode forms are retained only for display. The resolver consumes the pinned
PSL syntax directly, including wildcard and exception rules, rather than
pretending that those rules are literal suffix keys.

### Migration from the legacy corpus

The old `rules/*.toml` files are no longer the runtime classification source.
A migration cross-check found 6,570 of its 6,577 non-brand rows in the current
pinned PSL; all eight exception rules that had previously lost their `!`
syntax were recoverable. The remaining seven rows were explainable by upstream
drift or special-use handling. This comparison is a migration audit, not a
reason to preserve the old policy assertions.

Topology is now generated directly from one pinned PSL, while current-root and
contractual facts come from their respective pinned inputs. The active ICANN
Specification 13 set is generated from the current feed (367 records in this
snapshot), replacing 369 copied brand entries that had already drifted. Policy
research therefore operates on shared profiles and products instead of
maintaining thousands of near-identical per-suffix files.

## Claims and unknown values

Decision-critical facts are `Claim<T>` values. Every claim has one of four
audit states:

- `verified`: capable, in-scope evidence supports the value;
- `unknown`: no supported value is known;
- `stale`: the last-known value is older than its review policy;
- `conflicting`: current capable sources disagree.

A stale value may be retained for inspection, but only a verified value can
authorize a positive or negative policy conclusion. Omission is unknown; it is
never interpreted as public access, ASCII-only support, a `1..63` registry
limit, or an empty reserved-name set. DNS and IDNA protocol constraints are the
only implicit defaults.

The Rust API retains the supporting IDs on every `Claim<T>::evidence` slice.
The flattened Python objects expose equivalent `<axis>_evidence` lists next to
`<axis>` and `<axis>_status`: root state, namespace state, offering state,
public access, and application channel on `Assessment`, and every corresponding
claim present on `SuffixInfo`. `Assessment.evidence` remains the de-duplicated
aggregate for callers that want to enumerate all provenance used by a result.

Eligibility is a typed expression over requirements such as residence, entity
type, regulated-sector credentials, community membership, naming entitlement,
intended use, and authority approval. Callers can supply a
`RegistrantContext` containing requirement IDs known to be satisfied or
unsatisfied. Without enough context, an otherwise valid gated product remains
`conditional` or `indeterminate`; it is not silently treated as open.
Every assessment exposes the atomic requirements with their stable IDs, typed
kind, explanation, evidence, and caller-specific `satisfied`, `unsatisfied`, or
`unknown` outcome. An explicitly empty context has the same missing-context
semantics as no context. Supplied IDs outside the selected product's expression
are ignored when deciding whether useful context exists and produce an
`UnknownEligibilityRequirement` / `unknown_eligibility_requirement` finding.
This makes misspellings auditable without changing `required` into `unknown`.

## Verdicts

`Registry::assess` returns all decision axes in an `Assessment`, plus stable
finding codes, human-readable findings, and the de-duplicated evidence IDs used
for the decision.

| Verdict | Meaning |
|---|---|
| `impossible` | A verified protocol, namespace, product, eligibility, or label-policy rule fails |
| `conditional` | Static checks pass, but verified eligibility, approval, or controlled allocation applies |
| `plausible` | Static checks pass and current evidence verifies an open, accepting product; live availability is unknown |
| `indeterminate` | A decision-critical claim is unknown, stale, conflicting, or only partially researched |

A verified hard failure takes precedence over unknown facts. Unknown or stale
facts can never produce `plausible` or authorize a negative policy assertion.
The result also distinguishes an exact registrable-domain candidate from a bare
suffix, a deeper subdomain, and an unresolved boundary.

Special use is a namespace claim, not an offering or access claim. For example,
`example.com` is decisively impossible because it is in the pinned special-use
registry, while its `.com` root remains delegated and its unresearched product
offering/access claims remain unknown. The result separately reports the PSL
public suffix and the suffix at which a selected registration product allocates
names.

The top-level verdict is intentionally not a Boolean. Applications should
branch on the enum and retain the structured axes and finding codes for audit
or user-facing explanations.

## Source capabilities

Build-time validation limits what a source is allowed to prove. Scope is also
checked against the product named by the evidence record.

| Source kind | May establish | Cannot establish by itself |
|---|---|---|
| IANA current-root list | Current root presence | Offering state or public access |
| IANA Root Zone Database | Delegation record, manager, and IANA type | Eligibility or retail policy |
| Public Suffix List | ICANN/PRIVATE topology and exact/wildcard/exception boundaries | Root validity or registration access |
| ICANN registry-agreement data | Contract, lifecycle, and contractual designations | Complete retail policy |
| IANA special-use registry or standards document | Standards-defined special handling within its scope | Unrelated registry reservations |
| Registry or IANA IDN table | Repertoire, variants, and contextual label rules | Registrant eligibility |
| Current registry/government policy | Offering, access, eligibility, and label rules within its stated product scope | Policy for other products |
| Secondary material | Research leads | Decision-critical enforcement facts |

The authoring files under `data/policy/` use stable IDs to connect these layers:

- `sources.toml` defines sources and scoped evidence locators;
- `profiles.toml` defines reusable, versioned claim sets;
- `products.toml` assigns profiles to explicit registration products and suffix
  selectors.

The build rejects missing references, duplicate IDs, incapable evidence,
out-of-scope evidence, invalid claim combinations, and ambiguous assignments.
Profiles are flattened into compact generated tables, so runtime assessment
does not fetch sources or merge policy. These checks validate authored
relationships and declared source capabilities; they do not inspect remote
prose and should not be read as semantic verification of a cited source.

## Pinned upstream data

Authoritative topology and namespace inputs live in `data/snapshots/`.
`data/manifest.toml` records each URL, parser version, retrieval time, upstream
version where available, content type, and SHA-256 digest. Builds consume only
these checked-in files and therefore require no network access.

Curated policy evidence in `data/policy/sources.toml` instead records a URL,
locator, retrieval and review dates, and digest without vendoring the cited
payload. A normal build therefore cannot reproduce or inspect that remote
policy content; source review remains a curation responsibility.

Validate the exact checked-in bytes, their embedded structure, and curated
source review dates offline. The check fails when `review_after` is earlier
than the actual UTC date:

```bash
python3 tools/update_snapshots.py --check
```

Refresh all upstream snapshots explicitly:

```bash
python3 tools/update_snapshots.py
python3 tools/update_snapshots.py --check
cargo test --locked --all-targets
```

The update command uses the network, validates each response before replacing
files, writes atomically, and regenerates the manifest. Review the resulting
snapshot and normalized-data diff before committing it. Never edit generated
manifest metadata or snapshot content by hand.

The vendored PSL is distributed under MPL-2.0; its complete license and exact
provenance are checked in. IANA's Special-Use Domain Names registry is a
protocol registry covered by IANA's CC0 statement. The other three bundled IANA
and ICANN snapshots currently have `NOASSERTION` license metadata. That status
and the upstream terms links are disclosure, not a grant of redistribution
rights. The production release gate fails while any bundled snapshot remains
unresolved; a reviewed redistribution license must be asserted, or the payload
must stop being bundled, before publication. See
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) and `data/manifest.toml` for
details.

## Adding or changing policy

Policy curation starts with a registration product, not every row that happens
to share a TLD or PSL source:

1. Add or update the authoritative source and record an exact locator,
   retrieval time, digest, review date, supported predicates, and product
   scope.
2. Encode atomic claims in a versioned profile. Preserve an omitted fact as
   unknown rather than inferring it from topology or a related product.
3. Assign the profile to explicit product selectors. A shared operator is a
   research clue, not an implicit assignment.
4. Add assessment fixtures for positive, conditional, negative, missing-context,
   IDN, wildcard, and exception behavior as applicable.
5. Run the offline snapshot check and the complete Rust and Python validation
   suite.

The primary quality invariant is zero unsupported decisive verdicts. Increasing
the number of researched products is useful, but reducing unknowns is never a
reason to manufacture policy defaults.
