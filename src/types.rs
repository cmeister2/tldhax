//! Public value types for registration-product assessment.
//!
//! Namespace topology, registry policy, and evidence quality are deliberately
//! independent. A public suffix or delegated root never implies that public
//! registration is open.

use std::collections::BTreeSet;

/// The top-level assessment for a proposed new registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Protocol and verified registry policy pass for a public product.
    Plausible,
    /// Static checks pass, but eligibility or a controlled allocation path applies.
    Conditional,
    /// A verified protocol, namespace, or policy rule prevents registration.
    Impossible,
    /// At least one decision-critical fact is unresolved.
    Indeterminate,
}

impl Verdict {
    /// Returns the stable lowercase machine representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plausible => "plausible",
            Self::Conditional => "conditional",
            Self::Impossible => "impossible",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// Returns the conventional command-line exit code.
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Plausible => 0,
            Self::Impossible => 1,
            Self::Indeterminate => 2,
            Self::Conditional => 3,
        }
    }
}

/// Whether protocol-level IDNA and DNS syntax checks passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyntaxStatus {
    /// The normalized domain satisfies protocol syntax.
    Valid,
    /// The input is not a valid DNS name after IDNA processing.
    Invalid,
}

/// The input's relationship to its resolved registration boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateStatus {
    /// The input is exactly one label below its suffix.
    RegistrableDomain,
    /// The input is itself a suffix and has no registrable label.
    BareSuffix,
    /// The input is below an already registrable domain.
    Subdomain,
    /// A registration boundary could not be resolved.
    Unresolved,
}

/// The evidence state of one atomic claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimStatus {
    /// Current, capable evidence supports the claim.
    Verified,
    /// No sufficiently supported value is known.
    Unknown,
    /// The last-known value is older than its freshness policy.
    Stale,
    /// Current capable sources disagree.
    Conflicting,
}

/// A compact compiled fact and its supporting evidence identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Claim<T> {
    /// The audit state of the claim.
    pub status: ClaimStatus,
    /// The verified value, or the last-known value for a stale claim.
    pub value: Option<T>,
    /// Stable evidence identifiers relevant to the claim.
    pub evidence: &'static [&'static str],
}

impl<T> Claim<T> {
    /// Constructs a verified claim.
    pub const fn verified(value: T, evidence: &'static [&'static str]) -> Self {
        Self {
            status: ClaimStatus::Verified,
            value: Some(value),
            evidence,
        }
    }

    /// Constructs a claim for which no supported value is known.
    pub const fn unknown() -> Self {
        Self {
            status: ClaimStatus::Unknown,
            value: None,
            evidence: &[],
        }
    }

    /// Constructs a stale claim while retaining its last-known value.
    pub const fn stale(value: T, evidence: &'static [&'static str]) -> Self {
        Self {
            status: ClaimStatus::Stale,
            value: Some(value),
            evidence,
        }
    }

    /// Constructs a claim whose capable sources conflict.
    pub const fn conflicting(evidence: &'static [&'static str]) -> Self {
        Self {
            status: ClaimStatus::Conflicting,
            value: None,
            evidence,
        }
    }

    /// Returns the value only when the claim is verified.
    pub const fn verified_value(&self) -> Option<&T> {
        if matches!(self.status, ClaimStatus::Verified) {
            self.value.as_ref()
        } else {
            None
        }
    }
}

/// Current state of a root namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootState {
    /// The root label is present in the current DNS root.
    Delegated,
    /// The label has special protocol semantics instead of a DNS-root product.
    SpecialUse,
    /// The label is absent from an authoritative current-root snapshot.
    Absent,
}

/// Whether a candidate is inside a standards-defined special-use namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceState {
    /// The candidate is not at or below a name in the pinned special-use registry.
    Ordinary,
    /// The candidate is at or below a standards-defined special-use name.
    SpecialUse,
}

/// Normalized family of an IANA root-zone type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootFamily {
    /// A country-code root.
    CountryCode,
    /// A generic, restricted-generic, or sponsored root.
    Generic,
    /// A protocol infrastructure root.
    Infrastructure,
    /// A test root.
    Test,
}

/// Contractual or descriptive designation independent of public access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Designation {
    /// ICANN Specification 13 brand status.
    BrandSpec13,
    /// ICANN Specification 12 community status.
    CommunitySpec12,
    /// Geographic-string designation.
    Geographic,
    /// Legacy sponsored-TLD designation.
    SponsoredLegacy,
    /// Non-sponsored generic designation.
    NonSponsored,
    /// Contractual exclusive-use designation.
    ExclusiveUse,
    /// Internationalized top-level-domain designation.
    IdnTld,
}

/// One compiled root-label record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootTld {
    /// Canonical lowercase A-label.
    pub ascii_label: &'static str,
    /// Optional normalized Unicode display label.
    pub unicode_label: Option<&'static str>,
    /// Raw IANA type string without lossy normalization.
    pub raw_iana_type: Option<&'static str>,
    /// Normalized root family.
    pub family: Option<RootFamily>,
    /// Current namespace state.
    pub state: Claim<RootState>,
    /// Stable identifiers for current or historical operators.
    pub operator_ids: &'static [&'static str],
    /// Independent contractual or descriptive tags.
    pub designations: &'static [Designation],
}

/// The section of the Public Suffix List containing a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PslSection {
    /// Registry-controlled topology in the ICANN section.
    Icann,
    /// Service or tenant topology in the PRIVATE section.
    Private,
}

/// The syntax of a Public Suffix List rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuffixRuleKind {
    /// A literal rule.
    Exact,
    /// A one-label wildcard rule.
    Wildcard,
    /// An exception to an exact or wildcard rule.
    Exception,
    /// The implicit fallback for an otherwise unknown root.
    Default,
}

/// The semantic role of an explicit suffix rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuffixRole {
    /// A registry-controlled registration boundary.
    RegistryBoundary,
    /// A private-service or tenant security boundary.
    PrivateServiceBoundary,
}

/// One compiled exact, wildcard, or exception topology rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SuffixRule {
    /// Canonical A-label rule with wildcard and exception markers removed.
    pub labels: &'static str,
    /// Original rule syntax.
    pub kind: SuffixRuleKind,
    /// Source PSL section.
    pub section: PslSection,
    /// Semantic role derived from the source section.
    pub role: SuffixRole,
    /// Stable evidence identifier for the pinned PSL snapshot.
    pub evidence: &'static str,
}

/// An owned result from resolving one suffix boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SuffixMatch {
    /// Canonical A-label suffix without a leading or trailing dot.
    pub suffix: String,
    /// Canonical source rule; exception matches retain their exception label.
    pub matched_rule: Option<String>,
    /// Form of the prevailing rule.
    pub rule_kind: SuffixRuleKind,
    /// Source-list section, absent for the implicit default rule.
    pub section: Option<PslSection>,
    /// Rule role, absent for the implicit default rule.
    pub role: Option<SuffixRole>,
    /// Stable evidence identifier for the matched topology rule.
    pub evidence: Option<&'static str>,
}

/// Whether a registration product accepts new allocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OfferingState {
    /// Applications for new allocations are accepted.
    Accepting,
    /// New applications are temporarily paused.
    Paused,
    /// Existing registrations may renew but new ones are unavailable.
    RenewalOnly,
    /// The product has not begun accepting registrations.
    NotLaunched,
    /// The product is closed to new registrations.
    Closed,
}

/// Who may receive an allocation from a registration product.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicAccess {
    /// Any member of the public may apply under ordinary product rules.
    Open,
    /// Applicants must satisfy explicit eligibility requirements.
    Conditional,
    /// Allocations are limited to an operator or another defined group.
    ControlledGroup,
    /// No allocation path is available to the general public.
    Unavailable,
}

/// The channel through which a product accepts allocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplicationChannel {
    /// Applications are submitted through accredited registrars.
    Registrar,
    /// Applications are submitted directly to the registry.
    RegistryDirect,
    /// Applications require explicit approval.
    ApprovalWorkflow,
    /// An authority below the registry controls allocation.
    DelegatedAuthority,
    /// The operator allocates names internally.
    Internal,
}

/// The result of evaluating a product's eligibility expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EligibilityStatus {
    /// Supplied registrant facts satisfy the expression.
    Satisfied,
    /// Supplied registrant facts disprove the expression.
    Unsatisfied,
    /// Eligibility applies but no registrant context was supplied.
    Required,
    /// The expression or supplied context is incomplete.
    Unknown,
    /// The verified-open product has no eligibility expression.
    NotApplicable,
}

/// A typed class of registrant eligibility requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EligibilityKind {
    /// Residence in a jurisdiction.
    Residence,
    /// Citizenship of a jurisdiction.
    Citizenship,
    /// Legal presence or incorporation in a jurisdiction.
    LegalPresence,
    /// A legal or organizational entity type.
    EntityType,
    /// A credential issued to a regulated sector.
    RegulatedSectorCredential,
    /// Membership of a defined community.
    CommunityMembership,
    /// A legal name, trademark, or other naming entitlement.
    NamingEntitlement,
    /// A required purpose or intended use.
    IntendedUse,
    /// Approval or sponsorship by a named authority.
    AuthorityApproval,
}

/// One atomic typed eligibility requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EligibilityRequirement {
    /// Stable identifier used by registrant context.
    pub id: &'static str,
    /// Typed requirement category.
    pub kind: EligibilityKind,
    /// Jurisdiction, credential, entity type, or other parameter.
    pub value: &'static str,
    /// Human-readable explanation.
    pub explanation: &'static str,
    /// Supporting evidence identifiers.
    pub evidence: &'static [&'static str],
}

/// A composable registrant eligibility expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EligibilityExpression {
    /// One atomic requirement.
    Requirement(&'static EligibilityRequirement),
    /// Every nested expression must be satisfied.
    All(&'static [EligibilityExpression]),
    /// At least one nested expression must be satisfied.
    Any(&'static [EligibilityExpression]),
}

/// Caller-supplied facts used to evaluate eligibility requirements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrantContext {
    /// Requirement identifiers known to be satisfied.
    pub satisfied_requirements: BTreeSet<String>,
    /// Requirement identifiers known not to be satisfied.
    pub unsatisfied_requirements: BTreeSet<String>,
}

/// Caller-specific outcome for one atomic eligibility requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EligibilityRequirementOutcome {
    /// Caller facts establish that the requirement is met.
    Satisfied,
    /// Caller facts establish that the requirement is not met.
    Unsatisfied,
    /// No supplied fact decides the requirement.
    Unknown,
}

/// Discoverable metadata and caller-specific state for one eligibility requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EligibilityRequirementAssessment {
    /// Stable identifier accepted by [`RegistrantContext`].
    pub id: &'static str,
    /// Typed requirement category.
    pub kind: EligibilityKind,
    /// Jurisdiction, credential, entity type, or other parameter.
    pub value: &'static str,
    /// Human-readable explanation.
    pub explanation: &'static str,
    /// Supporting evidence identifiers.
    pub evidence: &'static [&'static str],
    /// Result of applying caller-supplied facts to this requirement.
    pub outcome: EligibilityRequirementOutcome,
}

/// The result of applying registry-specific label policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelPolicyStatus {
    /// Every applicable, decision-critical facet is verified and passes.
    Pass,
    /// A verified registry-specific rule fails.
    Fail,
    /// Some facets pass, but at least one is unresolved.
    Partial,
    /// No applicable registry-specific policy is established.
    Unknown,
}

/// Unit used by a registry-specific label-length constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LengthUnit {
    /// Bytes in the normalized ASCII A-label.
    ALabelOctets,
    /// Unicode scalar values in the normalized U-label.
    UnicodeCodePoints,
    /// User-perceived grapheme clusters in the normalized U-label.
    GraphemeClusters,
}

/// An inclusive registry-specific label-length range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LengthConstraint {
    /// Inclusive minimum length.
    pub minimum: u16,
    /// Inclusive maximum length.
    pub maximum: u16,
    /// Unit for both bounds.
    pub unit: LengthUnit,
}

/// Whether a product supports internationalized labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdnSupport {
    /// IDNs are supported subject to a referenced repertoire.
    Supported,
    /// IDNs are prohibited by registry policy.
    Unsupported,
}

/// Treatment of a label reserved by registry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReservedDisposition {
    /// The label cannot be allocated.
    Prohibited,
    /// The label is withheld from ordinary allocation.
    Held,
    /// The label is allocatable under non-standard commercial terms.
    Premium,
    /// The label requires a defined special-allocation path.
    SpecialAllocation,
}

/// One registry-specific reserved-label rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReservedLabel {
    /// Canonical A-label.
    pub label: &'static str,
    /// Registry treatment of the label.
    pub disposition: ReservedDisposition,
    /// Supporting evidence identifiers.
    pub evidence: &'static [&'static str],
}

/// Metadata for a versioned registry IDN repertoire or LGR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdnProfile {
    /// Stable profile identifier.
    pub id: &'static str,
    /// Registry or IANA table version.
    pub version: &'static str,
    /// Evidence identifiers for the source table.
    pub evidence: &'static [&'static str],
}

/// A compiled registry-specific label policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LabelPolicy {
    /// Stable policy identifier.
    pub id: &'static str,
    /// Audit state of the policy's decision-critical completeness.
    pub completeness: ClaimStatus,
    /// Evidence supporting the policy-completeness assessment.
    pub completeness_evidence: &'static [&'static str],
    /// Optional verified registry length constraint.
    pub length: Option<LengthConstraint>,
    /// Evidence for the length constraint.
    pub length_evidence: &'static [&'static str],
    /// Registry support for IDNs.
    pub idn_support: Claim<IdnSupport>,
    /// Versioned repertoire used when IDNs are supported.
    pub idn_profile: Option<&'static IdnProfile>,
    /// Audit state of the reserved-label set; verified empty is meaningful.
    pub reserved_status: ClaimStatus,
    /// Evidence supporting the reserved-label-set assessment.
    pub reserved_set_evidence: &'static [&'static str],
    /// Explicit reserved-label dispositions.
    pub reserved_labels: &'static [ReservedLabel],
}

/// An allocation product governed by one registry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegistrationProduct {
    /// Stable product identifier.
    pub id: &'static str,
    /// Stable registry-operator identifier.
    pub operator_id: &'static str,
    /// Current new-registration offering state.
    pub offering_state: Claim<OfferingState>,
    /// Product access class.
    pub public_access: Claim<PublicAccess>,
    /// Product application channel.
    pub application_channel: Claim<ApplicationChannel>,
    /// Typed eligibility expression, when one applies.
    pub eligibility: Option<&'static EligibilityExpression>,
    /// Registry-specific label policy, when researched.
    pub label_policy: Option<&'static LabelPolicy>,
    /// Independent product designations.
    pub designations: &'static [Designation],
}

/// A reusable profile from which product facts are flattened at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyProfile {
    /// Stable profile identifier.
    pub id: &'static str,
    /// Optional parent profile used only for authoring lineage.
    pub extends: Option<&'static str>,
    /// Flattened offering-state claim.
    pub offering_state: Claim<OfferingState>,
    /// Flattened public-access claim.
    pub public_access: Claim<PublicAccess>,
    /// Flattened application-channel claim.
    pub application_channel: Claim<ApplicationChannel>,
    /// Flattened eligibility expression.
    pub eligibility: Option<&'static EligibilityExpression>,
    /// Flattened label policy.
    pub label_policy: Option<&'static LabelPolicy>,
}

/// The capability class of an evidence document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// IANA's exhaustive current root-label list.
    IanaCurrentRoot,
    /// An IANA root-zone delegation record.
    IanaRootDatabase,
    /// A canonical Public Suffix List snapshot.
    PublicSuffixList,
    /// An ICANN registry agreement or contractual dataset.
    RegistryAgreement,
    /// Current policy published by a registry operator.
    RegistryPolicy,
    /// Eligibility or namespace policy published by a government authority.
    GovernmentPolicy,
    /// IANA's special-use domain-name registry.
    SpecialUseRegistry,
    /// An RFC or another authoritative technical standards document.
    StandardsDocument,
    /// A registry-operator IDN repertoire or label-generation-rules table.
    RegistryIdnTable,
    /// An IDN repertoire or label-generation-rules table published by IANA.
    IanaIdnTable,
    /// A non-authoritative research lead.
    Secondary,
}

/// A reusable source record for one or more atomic claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Evidence {
    /// Stable evidence identifier.
    pub id: &'static str,
    /// Capability class used by build-time validation.
    pub kind: SourceKind,
    /// Publishing organization.
    pub publisher: &'static str,
    /// Source URL.
    pub url: &'static str,
    /// Precise section, heading, rule, or other locator.
    pub locator: &'static str,
    /// RFC 3339 retrieval timestamp.
    pub retrieved_at: &'static str,
    /// Optional RFC 3339 date after which curated evidence must be reviewed.
    pub review_after: Option<&'static str>,
    /// Lowercase hexadecimal SHA-256 content digest.
    pub sha256: &'static str,
}

/// Stable machine-readable explanation for an assessment finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingCode {
    /// IDNA conversion failed.
    InvalidIdna,
    /// Protocol-level DNS syntax failed.
    InvalidDnsSyntax,
    /// The root is verified absent.
    RootAbsent,
    /// The root has special protocol semantics.
    SpecialUseNamespace,
    /// The input is itself a suffix.
    BareSuffix,
    /// The input is a subdomain of the registrable domain.
    Subdomain,
    /// No registration product is known for the suffix.
    NoRegistrationProduct,
    /// New allocations are not currently accepted.
    OfferingNotAccepting,
    /// The product is unavailable to the public.
    PublicAccessUnavailable,
    /// Eligibility applies without registrant context.
    EligibilityRequired,
    /// Registrant facts fail a requirement.
    EligibilityFailed,
    /// Eligibility facts or policy are incomplete.
    EligibilityUnknown,
    /// A supplied registrant fact does not name a requirement for the selected product.
    UnknownEligibilityRequirement,
    /// A verified label-policy rule failed.
    LabelPolicyFailed,
    /// Registry-specific label policy is incomplete.
    LabelPolicyIncomplete,
    /// A decision-critical claim has no supported value.
    ClaimUnknown,
    /// A decision-critical claim is stale.
    ClaimStale,
    /// Decision-critical sources conflict.
    ClaimConflicting,
}

/// One structured and human-readable assessment explanation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Finding {
    /// Stable reason code.
    pub code: FindingCode,
    /// Human-readable rendering.
    pub message: String,
}

/// Detailed assessment of a proposed new registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// Original caller input.
    pub input: String,
    /// Canonical lowercase A-label domain after IDNA processing.
    pub ascii_domain: Option<String>,
    /// Canonical registrable domain at the selected product or topology boundary.
    pub registrable_domain: Option<String>,
    /// Protocol syntax result.
    pub syntax: SyntaxStatus,
    /// Relationship to the selected product boundary, or topology when no product is known.
    pub candidate_status: CandidateStatus,
    /// Resolved suffix topology.
    pub suffix: Option<SuffixMatch>,
    /// Current root state.
    pub root_state: Claim<RootState>,
    /// Whether the candidate is within a special-use namespace.
    pub namespace_state: Claim<NamespaceState>,
    /// Assigned registration-product identifier.
    pub product_id: Option<&'static str>,
    /// Suffix at which the selected registration product allocates names.
    pub product_suffix: Option<String>,
    /// Current product offering state.
    pub offering_state: Claim<OfferingState>,
    /// Product access class.
    pub public_access: Claim<PublicAccess>,
    /// Product application channel.
    pub application_channel: Claim<ApplicationChannel>,
    /// Eligibility result.
    pub eligibility: EligibilityStatus,
    /// Discoverable atomic eligibility requirements and their caller-specific outcomes.
    pub eligibility_requirements: Vec<EligibilityRequirementAssessment>,
    /// Registry-specific label-policy result.
    pub label_policy: LabelPolicyStatus,
    /// Overall safety-first conclusion.
    pub verdict: Verdict,
    /// Structured explanations in evaluation order.
    pub findings: Vec<Finding>,
    /// De-duplicated evidence identifiers used by the assessment.
    pub evidence: Vec<&'static str>,
}

/// Owned metadata about a suffix and its assigned product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuffixInfo {
    /// Canonical product boundary, falling back to the prevailing public suffix.
    pub canonical_suffix: String,
    /// Optional normalized Unicode display form.
    pub display_suffix: Option<String>,
    /// Canonical lowercase A-label root.
    pub root: String,
    /// Resolved PSL topology.
    pub topology: SuffixMatch,
    /// Current root state.
    pub root_state: Claim<RootState>,
    /// Whether the requested name is within a special-use namespace.
    pub namespace_state: Claim<NamespaceState>,
    /// Assigned registration-product identifier.
    pub product_id: Option<&'static str>,
    /// Suffix at which the selected registration product allocates names.
    pub product_suffix: Option<String>,
    /// Current product offering state.
    pub offering_state: Claim<OfferingState>,
    /// Product access class.
    pub public_access: Claim<PublicAccess>,
    /// De-duplicated namespace and product designations.
    pub designations: Vec<Designation>,
}

/// Counts of evidence states for one fact dimension.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ClaimCounts {
    /// Number of verified claims.
    pub verified: usize,
    /// Number of unknown claims.
    pub unknown: usize,
    /// Number of stale claims.
    pub stale: usize,
    /// Number of conflicting claims.
    pub conflicting: usize,
}

impl ClaimCounts {
    /// Returns the number of claims represented by all evidence-state buckets.
    #[must_use]
    pub const fn total(self) -> usize {
        self.verified + self.unknown + self.stale + self.conflicting
    }
}

/// Root-record counts split by current namespace state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RootCounts {
    /// Records verified as currently delegated in the DNS root.
    pub current: usize,
    /// Records representing standards-defined special-use root labels.
    pub special_use: usize,
    /// Historical records verified as absent from the current DNS root.
    pub absent: usize,
    /// Records whose current state is unknown, stale, or conflicting.
    pub unresolved: usize,
}

impl RootCounts {
    /// Returns the total number of compiled root records.
    #[must_use]
    pub const fn total(self) -> usize {
        self.current + self.special_use + self.absent + self.unresolved
    }
}

/// Public Suffix List rule counts split by source section.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct TopologyCounts {
    /// Rules in the ICANN section.
    pub icann: usize,
    /// Rules in the PRIVATE section.
    pub private: usize,
}

impl TopologyCounts {
    /// Returns the total number of explicit topology rules.
    #[must_use]
    pub const fn total(self) -> usize {
        self.icann + self.private
    }
}

/// Registration-product selector counts by selector syntax.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SelectorCounts {
    /// Exact suffix assignments.
    pub exact: usize,
    /// One-label-below family assignments.
    pub one_label_below: usize,
}

impl SelectorCounts {
    /// Returns the total number of explicit product selectors.
    #[must_use]
    pub const fn total(self) -> usize {
        self.exact + self.one_label_below
    }
}

/// Evidence-state coverage measured consistently by product and selector.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct PolicyCoverage {
    /// One claim-state observation per registration product.
    pub by_product: ClaimCounts,
    /// Product claim states weighted by each explicit selector assignment.
    pub by_selector: ClaimCounts,
}

/// Multidimensional coverage and quality statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RegistryStats {
    /// Compiled root records split into current, special-use, and other states.
    pub roots: RootCounts,
    /// Explicit suffix topology split into ICANN and PRIVATE rules.
    pub topology: TopologyCounts,
    /// Distinct registration products.
    pub products: usize,
    /// Distinct shared policy profiles.
    pub policy_profiles: usize,
    /// Exact and one-label-below registration-product assignments.
    pub selectors: SelectorCounts,
    /// Offering-state evidence coverage.
    pub offering_state: PolicyCoverage,
    /// Public-access evidence coverage.
    pub public_access: PolicyCoverage,
    /// Eligibility-policy evidence coverage.
    pub eligibility: PolicyCoverage,
    /// Overall label-policy completeness coverage.
    pub label_policy: PolicyCoverage,
    /// IDN support and required-profile coverage per product and selector.
    pub idn_policy: PolicyCoverage,
    /// Reserved-label-set completeness coverage per product and selector.
    pub reserved_labels: PolicyCoverage,
}
