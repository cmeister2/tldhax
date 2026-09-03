"""Type stubs for the native tldhax extension module."""

from typing import Literal, TypeAlias, TypedDict

ClaimStatus: TypeAlias = Literal["verified", "unknown", "stale", "conflicting"]

class Finding:
    code: Literal[
        "invalid_idna",
        "invalid_dns_syntax",
        "root_absent",
        "special_use_namespace",
        "bare_suffix",
        "subdomain",
        "no_registration_product",
        "offering_not_accepting",
        "public_access_unavailable",
        "eligibility_required",
        "eligibility_failed",
        "eligibility_unknown",
        "unknown_eligibility_requirement",
        "label_policy_failed",
        "label_policy_incomplete",
        "claim_unknown",
        "claim_stale",
        "claim_conflicting",
    ]
    message: str

class EligibilityRequirement:
    id: str
    kind: Literal[
        "residence",
        "citizenship",
        "legal_presence",
        "entity_type",
        "regulated_sector_credential",
        "community_membership",
        "naming_entitlement",
        "intended_use",
        "authority_approval",
    ]
    value: str
    explanation: str
    evidence: list[str]
    outcome: Literal["satisfied", "unsatisfied", "unknown"]

class Assessment:
    input: str
    ascii_domain: str | None
    registrable_domain: str | None
    syntax: Literal["valid", "invalid"]
    candidate_status: Literal[
        "registrable_domain", "bare_suffix", "subdomain", "unresolved"
    ]
    public_suffix: str | None
    suffix_rule: str | None
    suffix_rule_kind: Literal["exact", "wildcard", "exception", "default"] | None
    suffix_section: Literal["icann", "private"] | None
    suffix_role: Literal["registry_boundary", "private_service_boundary"] | None
    suffix_evidence: str | None
    root_state: Literal["delegated", "special_use", "absent"] | None
    root_state_status: ClaimStatus
    root_state_evidence: list[str]
    namespace_state: Literal["ordinary", "special_use"] | None
    namespace_state_status: ClaimStatus
    namespace_state_evidence: list[str]
    offering_state: (
        Literal["accepting", "paused", "renewal_only", "not_launched", "closed"] | None
    )
    offering_state_status: ClaimStatus
    offering_state_evidence: list[str]
    public_access: (
        Literal["open", "conditional", "controlled_group", "unavailable"] | None
    )
    public_access_status: ClaimStatus
    public_access_evidence: list[str]
    application_channel: (
        Literal[
            "registrar",
            "registry_direct",
            "approval_workflow",
            "delegated_authority",
            "internal",
        ]
        | None
    )
    application_channel_status: ClaimStatus
    application_channel_evidence: list[str]
    eligibility: Literal[
        "satisfied", "unsatisfied", "required", "unknown", "not_applicable"
    ]
    eligibility_requirements: list[EligibilityRequirement]
    label_policy: Literal["pass", "fail", "partial", "unknown"]
    product_id: str | None
    product_suffix: str | None
    verdict: Literal["plausible", "conditional", "impossible", "indeterminate"]
    findings: list[Finding]
    evidence: list[str]

class SuffixInfo:
    canonical_suffix: str
    display_suffix: str | None
    root: str
    public_suffix: str
    suffix_rule: str | None
    suffix_rule_kind: Literal["exact", "wildcard", "exception", "default"]
    suffix_section: Literal["icann", "private"] | None
    suffix_role: Literal["registry_boundary", "private_service_boundary"] | None
    suffix_evidence: str | None
    root_state: Literal["delegated", "special_use", "absent"] | None
    root_state_status: ClaimStatus
    root_state_evidence: list[str]
    namespace_state: Literal["ordinary", "special_use"] | None
    namespace_state_status: ClaimStatus
    namespace_state_evidence: list[str]
    product_id: str | None
    product_suffix: str | None
    offering_state: (
        Literal["accepting", "paused", "renewal_only", "not_launched", "closed"] | None
    )
    offering_state_status: ClaimStatus
    offering_state_evidence: list[str]
    public_access: (
        Literal["open", "conditional", "controlled_group", "unavailable"] | None
    )
    public_access_status: ClaimStatus
    public_access_evidence: list[str]
    designations: list[
        Literal[
            "brand_spec13",
            "community_spec12",
            "geographic",
            "sponsored_legacy",
            "non_sponsored",
            "exclusive_use",
            "idn_tld",
        ]
    ]

class Evidence:
    id: str
    kind: Literal[
        "iana_current_root",
        "iana_root_database",
        "public_suffix_list",
        "registry_agreement",
        "registry_policy",
        "government_policy",
        "special_use_registry",
        "standards_document",
        "registry_idn_table",
        "iana_idn_table",
        "secondary",
    ]
    publisher: str
    url: str
    locator: str
    retrieved_at: str
    review_after: str | None
    sha256: str

class _ClaimCounts(TypedDict):
    verified: int
    unknown: int
    stale: int
    conflicting: int

class _RootCounts(TypedDict):
    current: int
    special_use: int
    absent: int
    unresolved: int

class _TopologyCounts(TypedDict):
    icann: int
    private: int

class _SelectorCounts(TypedDict):
    exact: int
    one_label_below: int

class _PolicyCoverage(TypedDict):
    by_product: _ClaimCounts
    by_selector: _ClaimCounts

class _RegistryStats(TypedDict):
    roots: _RootCounts
    topology: _TopologyCounts
    products: int
    policy_profiles: int
    selectors: _SelectorCounts
    offering_state: _PolicyCoverage
    public_access: _PolicyCoverage
    eligibility: _PolicyCoverage
    label_policy: _PolicyCoverage
    idn_policy: _PolicyCoverage
    reserved_labels: _PolicyCoverage

class Registry:
    def __init__(self) -> None: ...
    def assess(self, domain: str) -> Assessment: ...
    def assess_for(
        self,
        domain: str,
        *,
        satisfied: list[str] | None = None,
        unsatisfied: list[str] | None = None,
    ) -> Assessment: ...
    def suffix_info(self, suffix: str) -> SuffixInfo | None: ...
    def evidence(self, evidence_id: str) -> Evidence | None: ...
    def stats(self) -> _RegistryStats: ...
