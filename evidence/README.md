# Initial policy evidence

The authoring files describe **new registration** policy as reviewed on
2026-10-12. They support an offline name filter and optional declared registrant
checks. They do not describe current registration availability. Every assertion
has a publisher, source URL, content fingerprint, clause locator, interpretation,
scope, input class, review date and review deadline.

`sources.toml` records acquisition provenance; `assertions.toml` records reviewed
claims. `rules/namespaces/` attaches claims only to their stated namespace and
registration form. `rules/profiles/` contains the DENIC repertoire and typed
registrant facts. The compiler checks references, scope, dates and coverage before
emitting static runtime tables.

An assertion marked `reviewed` establishes that specific claim. It does not prove
that the entire rule family is complete. `attests_completeness` is a separate
claim and is used sparingly. Reviewed denials can coexist with partial or unknown
coverage. Missing tables, exceptions, allocation relations and unpublished
reservations remain visible gaps.

## Source fingerprints

No complete registry policy publications are redistributed in this initial corpus.
Publications downloaded for review stay in a temporary local cache. Packaged
records contain metadata, hashes and paraphrased interpretations with precise
locators. A hash identifies reviewed content; it does not provide a license to
redistribute it or prove that a later version is unchanged.

The catalog also references the seven factual IANA/ICANN/PSL inputs already
packaged by the inventory pipeline under `data/`; their hashes, published
versions and retrieval dates come from that pinned manifest. These source-only
records do not approve any registration policy.

`hash_representation = "original_bytes"` means SHA-256 of the exact successful
HTTP response body, including the original HTML or PDF encoding. The helper can
recompute it from a saved acquisition:

```sh
python tools/evidence_fingerprint.py --representation original_bytes source.pdf
```

Direct requests for the Nominet and fTLD PDFs returned HTTP 403 during acquisition.
Those sources use the explicit `extracted_text/v1` representation. Their hashes
identify captured browser-extracted text, **not original PDF bytes**. To reproduce
this representation, save the complete text returned by the browser's `open`
operation for one source, including its `Total lines: N` header and numbered line
markers. Then run:

```sh
python tools/evidence_fingerprint.py --representation extracted_text/v1 capture.txt
```

The helper requires all source line numbers in order, exactly once, from zero to
N minus one. It removes only the numbered `L<number>:` or
`L<number>@P<page-or-range>:` markers and their optional separating space. It
keeps the displayed text of browser citation wrappers while removing their
machine citation IDs. It joins the captured logical lines with LF and appends one
terminal LF. Wording, Unicode, spaces, extracted page footers and extraction
artifacts remain unchanged. When two tool markers share one physical line, one
separating space immediately before the next marker is removed. Tool headers and unrelated tool boilerplate are
excluded. Partial, reordered, duplicate or mixed captures are rejected. These
steps are tested in `tests/evidence/test_fingerprint.py`.

A refresh must compare the same representation. Switching from extracted text
to original PDF bytes, or changing extraction output, requires a new fingerprint
and manual source review; it must not be presented as an unchanged source.

## Dates and authority

`effective_from` records a known commencement from the controlling publication.
For an undated current publication, `applicable_on = "2026-10-12"` records the
reviewer's current applicability attestation. It does not invent a historical
commencement date. `retrieved_on` is acquisition metadata and never activates a
policy. The next review deadline is 2027-01-10.

DENIC's German wording controls; the English publications are identified as
translations. FAQs are separately attributed supplementary sources. The
Nominet policy index identifies the current document; the revised policy with
commencement **2027-02-09** is retained as inactive evidence. auDA's IDN section
has no announced commencement in the reviewed licensing rules and provides no
current allowance.

## Decisions and remaining gaps

| Scope | Source-backed behavior | Explicit remaining gap |
| --- | --- | --- |
| `.de` | German guidelines V(1)–(2) define syntax, Unicode minimum and ACE maximum; the Annex includes 93 additional characters, including sharp-s. Foreign holders are permitted. | Reservations and rights/allocation completeness are unknown. Contract capacity is declared; a German service recipient is required only following a DENIC request. |
| `.com`, `.net` | Appendix 6 identifies named reservations with an express authorization exception and independently permits qualifying Registry Operator use of `nic`, `whois` and `www`. Current Verisign IDN Rules §5 excludes sharp-s and Greek final sigma. | Released short labels, exceptional authorizations, language tables, script mixing and variants are incomplete. Historical two-character reservation is not a current blanket minimum. |
| `.org` | PIR explicitly allows individuals and organizations without nonprofit status. | Current reserved-name releases and adopted IDN tables need further curation; the contract's phased short-name releases do not establish a three-character minimum. |
| `.uk`, managed third levels | Current Nominet rules identify ASCII-only names and reservations in exact namespaces. `me.uk` requires a natural person without an organizational proxy. `co.uk` and `org.uk` charters are expressly unenforced. | §5.7's total-name limit conflicts with current technical field documentation. Company name derivation and ISP requirements are partial. Delegated operators receive independent unknown policy. |
| `sch.uk`, `*.sch.uk` | Current school rules explicitly use `school-name.area.sch.uk`. | Geographic area assignment, prior holdings, consortium qualifications and name allocation need further modeling. |
| `.au`, `com.au` | Active §2.7.1 requires at least two ASCII characters and specified hyphen placements. Australian Presence and Commercial Entity conditions have necessary declared-fact checks. | Proposed IDN policy is inactive. Reserved-name exceptions, related-body conditions and broader permitted name correspondence are partial. |
| `.us` | The registry disallows IDNs and proxy registration. Nexus covers qualifying individuals and organizations, including the relevant US possessions and territories. | Documentary certification, infrastructure requirements, complete reservation lists and separate locality registrations remain incomplete. |
| `.bank` | The eligibility policy requires charter, supervision, membership or board qualification for stated classes and prohibits proxy registration. Explicit exceptional Board approval is preserved. | Verification, sanctions, class exclusions and discretion remain partial. Broader permitted name correspondence is not reduced to exact equality. Current complete reservation lists are unpublished here. |
| `.name` | Appendix 11 §1(a)(2) supports the one-label second-level form independently of PSL discovery. | ICANN approved third-level service withdrawal in 2026; the reviewed request and approval require prior notice but supply no implementation date. Two-label acceptance remains unknown. Operator exceptions prevent treating the public form list as a universal closed set. |
| `.google` | Operative Specification 13 permits the Registry Operator, qualifying Affiliates and qualifying organizational Trademark Licensees as registrants. | No accepted form is inferred from Brand inventory. DNS control and future use are operational context; a trademark license concerns the Brand string and does not imply a candidate-label authorization rule. Allocation remains partial. |

The current `.name` supplement approves only the supported one-label form.
For `firstname.lastname.name`, the pinned PSL exact `name` route remains
discovery metadata; the `.name` policy scope records the pending form gap.
Historical PSL wildcards are not substituted for the reviewed current snapshot.
Historical third-level wording and withdrawal authorization are separately
fingerprinted and do not become a current allowance or prohibition.

The initial corpus does not reassert the legacy `za.sk` prohibition: no reviewed
current primary clause establishing it was found. SK-NIC's short-name auction
program also prevents deriving a blanket restriction from historical short-name
reservation. Absence of evidence remains a research gap.

## Declared facts and tests

Profile fields are assertions by the caller, not registry verification. Missing
facts remain unknown, while `false` and empty sets are explicit declarations.
Citizenship and country fields require two uppercase ASCII letters, such as `AU`
and `US`. Profile preparation rejects malformed encoding instead of treating it
as an explicit nonqualifying declaration. The schema enforces this encoding;
it does not claim to validate membership in an ISO country-code inventory.
`domicile_country` means the applicant's **primary** domicile for the US Nexus
check. `us_permanent_resident`, `us_constituted_entity` and
`us_bona_fide_presence` include the policy's applicable possessions and
territories. The separate territorial domicile/incorporation booleans avoid
requiring a territorial applicant to misstate its country as `US`.

Enum values for Australian and banking classes refer to the complete legal
definition cited by the applicable assertion, rather than a casual occupation or
industry description. `bank_board_approved` qualifies the ordinary Board-approved
classes; `bank_board_exception_approved` is explicit exceptional approval under
the current implementation guidelines. No exceptional approval is inferred.

`au_trademark_exact_labels`, `com_icann_authorized_labels` and
`net_icann_authorized_labels` contain qualifying canonical applicant labels for
the current candidate. A grant for one label cannot authorize another. The
auDA exact-label declaration includes the policy's defined removals and does not
impose literal equality to an unprocessed trademark string.

`com_registry_operational_labels` and `net_registry_operational_labels` declare
qualifying Registry Operator use of each candidate in connection with operation
of that registry. These exceptions apply only to the three operational names
identified in Appendix 6 D; they cannot authorize the distinct ICANN/IANA names
in Appendix 6 A. An absent operational-use declaration remains unknown.

`google_qualifying_trademark_licensee` declares the organizational licensee role
under Specification 13 §9.5, including its continuing substantive business use
conditions. It is scoped to the `.google` Brand trademark. It does not declare
a grant for a particular applicant label. DNS setup and future domain-use
purpose remain context and incomplete allocation research.

Independent positive and negative examples are in `tests/fixtures/policy/`.
Their expectations come from the cited clauses and include A-/U-label
equivalence, boundaries, necessary eligibility conditions, explicit exceptions,
namespace isolation, inactive policy and unresolved coverage. Broad successful
name-validity claims are omitted where the corpus is incomplete.
