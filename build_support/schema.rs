//! Versioned evidence and namespace authoring, separate from legacy claims.

use serde::Deserialize;

use super::idn_schema::IdnProfile;
use super::predicates::{Fact, Predicate};

/// Reviewed knowledge state for one assertion or rule-family coverage claim.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Knowledge {
    /// Current reviewed evidence supports the stated claim.
    Reviewed,
    /// Some policy is known but the claim has explicit gaps.
    Partial,
    /// The claim has no sufficient current applicable evidence.
    Unknown,
    /// Evidence contains unresolved contradictory claims.
    Conflicting,
    /// Reviewed evidence establishes that this family does not apply.
    NotApplicable,
}

/// Independent policy dimensions whose coverage is reviewed separately.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// Permitted namespace and registration-form structure.
    Namespace,
    /// Minimum and maximum applicant-label lengths.
    Length,
    /// Character and literal-pattern restrictions.
    Characters,
    /// Adopted internationalized-label repertoire and context rules.
    Idn,
    /// Labels reserved or otherwise unavailable by policy.
    Reserved,
    /// Allocation procedures and name-specific restrictions.
    Allocation,
    /// Access conditions for the registration namespace.
    Access,
    /// Applicant facts and eligibility requirements.
    Eligibility,
}

/// Stable iteration order covering every independently reviewed rule family.
pub const FAMILIES: [Family; 8] = [
    Family::Namespace,
    Family::Length,
    Family::Characters,
    Family::Idn,
    Family::Reserved,
    Family::Allocation,
    Family::Access,
    Family::Eligibility,
];

/// Input representation class covered by an evidence assertion.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// ASCII registration names only.
    Ascii,
    /// Internationalized registration names only.
    Idn,
    /// Both ASCII and internationalized registration names.
    Any,
}

/// How a predicate participates in registration assessment.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// The predicate must hold for registration.
    Require,
    /// Registration is denied when the predicate holds.
    Deny,
    /// The assertion provides context without enforcing a predicate.
    Context,
}

/// Versioned publisher evidence with a stable identity and verifiable snapshot hash.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Stable machine-readable identity used by references in authoring records.
    pub id: String,
    /// Organization responsible for the source material.
    pub publisher: String,
    /// Human-readable title identifying the source document.
    pub title: String,
    /// Canonical HTTPS address identifying the evidence source.
    pub url: String,
    /// HTTPS address from which the retained snapshot was retrieved.
    pub fetched_url: String,
    /// Hexadecimal SHA-256 digest of the declared hash representation.
    pub sha256: String,
    /// Snapshot representation hashed, such as original bytes or extracted text.
    #[serde(default = "original_bytes")]
    pub hash_representation: String,
    /// Publisher version or other identifier distinguishing this evidence edition.
    pub version: String,
    /// Language of the retained source document.
    pub language: String,
    /// ISO calendar date on which the source snapshot was retrieved.
    pub retrieved_on: String,
    /// Optional repository-relative path to bytes verified against the source digest.
    pub snapshot_path: Option<String>,
    /// Optional source identity whose original this record translates.
    pub translation_of: Option<String>,
}

/// Default source hash representation for unchanged publisher bytes.
fn original_bytes() -> String {
    "original_bytes".into()
}

/// Reviewed interpretation of a source clause, with explicit scope and applicability.
///
/// An enforceable predicate does not imply complete coverage of its rule family.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    /// Stable machine-readable identity used by references in authoring records.
    pub id: String,
    /// Identity of the source containing the interpreted clause.
    pub source_id: String,
    /// Clause, section or other precise position of the source evidence.
    pub locator: String,
    /// Registration operation covered by the assertion; currently new registration.
    pub operation: String,
    /// Namespace selectors to which the assertion or asset explicitly applies.
    pub namespaces: Vec<String>,
    /// Applicant-label counts to which this assertion applies.
    pub forms: Vec<u8>,
    /// ASCII, IDN or universal input class covered by this assertion.
    pub input_class: Class,
    /// Rule family whose policy or completeness is described.
    pub family: Family,
    /// Whether the predicate is required, denied, or supplied only as context.
    pub effect: Effect,
    /// Authored evidence state, subject to applicability and review expiry.
    pub knowledge: Knowledge,
    /// Explicit whole-family completeness attestation, independent of predicate truth.
    #[serde(default)]
    pub attests_completeness: bool,
    /// Reviewer explanation connecting the cited clause to the authored rule.
    pub interpretation: String,
    /// Identity of the person or process that reviewed the interpretation.
    pub reviewer: String,
    /// ISO calendar date on which the interpretation was reviewed.
    pub reviewed_on: String,
    /// Last ISO date on which the review remains current.
    pub review_due: String,
    /// Optional inclusive commencement date of the asserted policy.
    pub effective_from: Option<String>,
    /// Optional date explicitly attesting that the policy was applicable.
    pub applicable_on: Option<String>,
    /// Optional exclusive end date of policy applicability.
    pub effective_until: Option<String>,
    /// Optional finite typed expression; context and completeness may omit enforcement.
    pub predicate: Option<Predicate>,
    /// Optional stable diagnostic code overriding the family default.
    pub code: Option<String>,
}

/// Authored completeness claim for one family, tracked separately for ASCII and IDN.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    /// Rule family whose policy or completeness is described.
    pub family: Family,
    /// Completeness knowledge for ASCII registration names.
    pub ascii: Knowledge,
    /// Completeness knowledge for internationalized registration names.
    pub idn: Knowledge,
    /// Assertions attesting completeness or non-applicability for this rule family.
    #[serde(default)]
    pub assertion_ids: Vec<String>,
    /// Optional explanation of missing or unresolved family coverage.
    pub gap: Option<String>,
}

/// Explicit replacement of an inherited rule backed by a rationale and evidence.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    /// Identity of the inherited rule removed by this override.
    pub replaces: String,
    /// Identity of the rule that replaces the inherited rule.
    pub with: String,
    /// Reviewer rationale for the replacement and its scope.
    pub reason: String,
    /// Assertions establishing that the explicit replacement is supported by evidence.
    pub assertion_ids: Vec<String>,
}

/// Authored namespace policy before inheritance and evidence activation are resolved.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    /// Exact or single-wildcard namespace key, canonicalized before compilation.
    pub selector: String,
    /// Registration shapes, listing each applicant-controlled label role in order.
    #[serde(default)]
    pub forms: Vec<Vec<String>>,
    /// Assertions explicitly approving the authored registration shapes.
    #[serde(default)]
    pub form_assertion_ids: Vec<String>,
    /// Identities of reusable profiles inherited by this namespace.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Assertion identities selected for predicate enforcement.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Evidence-backed replacements applied after inherited rules are collected.
    #[serde(default)]
    pub overrides: Vec<Override>,
    /// Explicit per-family completeness claims resolved against active evidence.
    #[serde(default)]
    pub coverage: Vec<Coverage>,
    /// Non-enforcing contextual explanations retained in the compiled policy.
    #[serde(default)]
    pub context: Vec<String>,
}

/// Reusable policy fragment that needs namespace-specific applicability evidence.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Stable machine-readable identity used by references in authoring records.
    pub id: String,
    /// Namespace selectors to which the shared profile may be applied.
    pub applicability: Vec<String>,
    /// Assertions proving the profile applies to the relevant registration forms.
    pub applicability_assertions: Vec<String>,
    /// Parent profile identities, expanded before the profile with cycle checks.
    #[serde(default)]
    pub extends: Vec<String>,
    /// Assertion identities selected for predicate enforcement.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Explicit per-family completeness claims resolved against active evidence.
    #[serde(default)]
    pub coverage: Vec<Coverage>,
    /// Non-enforcing contextual explanations retained in the compiled policy.
    #[serde(default)]
    pub context: Vec<String>,
}

/// Finite named labels backed by assertions defining their namespace and form scope.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelSet {
    /// Stable machine-readable identity used by references in authoring records.
    pub id: String,
    /// Finite label literals; absence of a list does not imply an empty set.
    pub labels: Vec<String>,
    /// Assertions proving the finite label list and its applicable namespace/form scope.
    pub assertion_ids: Vec<String>,
}

/// Collected authoring inputs; validation canonicalizes keys before resolution.
#[derive(Debug, Default)]
pub struct Document {
    /// Publisher evidence records used by the collected assertions.
    pub sources: Vec<Source>,
    /// Reviewed source interpretations and completeness attestations.
    pub assertions: Vec<Assertion>,
    /// Authored namespace policies whose forms, profiles and references are validated.
    pub namespaces: Vec<Namespace>,
    /// Reusable authored policy profiles expanded during namespace resolution.
    pub profiles: Vec<Profile>,
    /// Evidence-backed finite label sets used by membership predicates.
    pub label_sets: Vec<LabelSet>,
    /// Adopted finite IDN repertoires and explicit unsupported features.
    pub idn_profiles: Vec<IdnProfile>,
    /// Typed applicant-profile fields referenced by predicates.
    pub facts: Vec<Fact>,
    /// Unapproved historical claims retained only as research provenance.
    pub legacy: Vec<LegacyResearch>,
}

/// Unreviewed legacy source leads retained without supplying enforceable policy.
#[derive(Debug, Clone)]
pub struct LegacyResearch {
    /// Legacy suffix identity, canonicalized when normalization of the authored key succeeds.
    pub selector: String,
    /// Legacy evidence URLs retained as leads for future review.
    pub source_links: Vec<String>,
    /// Repository-relative path of the legacy authoring file.
    pub provenance: String,
}

/// Versioned TOML container for publisher evidence records.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    /// Authoring schema version; loading accepts the supported version only.
    pub schema_version: u16,
    /// Publisher evidence records used by the collected assertions.
    pub sources: Vec<Source>,
}

/// Versioned TOML container for interpreted source assertions.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionFile {
    /// Authoring schema version; loading accepts the supported version only.
    pub schema_version: u16,
    /// Reviewed source interpretations and completeness attestations.
    pub assertions: Vec<Assertion>,
}

/// Versioned TOML container for namespace policies and their reusable assets.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringFile {
    /// Authoring schema version; loading accepts the supported version only.
    pub schema_version: u16,
    /// Namespace policy definitions contained in this authoring file.
    #[serde(default)]
    pub namespaces: Vec<Namespace>,
    /// Reusable policy profile definitions contained in this authoring file.
    #[serde(default)]
    pub profiles: Vec<Profile>,
    /// Evidence-backed finite label sets used by membership predicates.
    #[serde(default)]
    pub label_sets: Vec<LabelSet>,
    /// Adopted finite IDN repertoires and explicit unsupported features.
    #[serde(default)]
    pub idn_profiles: Vec<IdnProfile>,
    /// Typed applicant-profile fields referenced by predicates.
    #[serde(default)]
    pub facts: Vec<Fact>,
}
