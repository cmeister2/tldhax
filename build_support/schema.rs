//! Small authoring records for direct static requirements.

use super::predicates::{Fact, Predicate};
use serde::Deserialize;

/// Implemented scope for one form and input class.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// All identified applicable static requirements are implemented.
    Supported,
    /// Applicable requirements remain unimplemented.
    Partial,
    /// This input class has no supported policy.
    Unsupported,
}

/// Applicant-label class to which a condition applies.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Only ASCII applicant components.
    Ascii,
    /// At least one internationalised applicant component.
    Idn,
    /// Both applicant input classes.
    Any,
}

/// Whether a predicate must or must not hold.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// False establishes a requirement failure.
    Require,
    /// True establishes a prohibition failure.
    Deny,
}

/// Direct executable requirement with its own explanation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    /// Stable interface reason code.
    pub code: String,
    /// Human-readable unmet condition.
    pub message: String,
    /// Whether a true or false predicate rejects.
    pub effect: Effect,
    /// Candidate class selected for this requirement.
    pub input_class: Class,
    /// Finite typed expression to evaluate.
    pub predicate: Predicate,
    /// Ordinary maintainer notes, omitted from runtime tables.
    #[serde(default)]
    pub source_notes: Vec<String>,
}

/// Real policy or implementation limitation scoped to affected candidates.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    /// Stable unresolved-condition code.
    pub code: String,
    /// Explanation of the missing policy or functionality.
    pub message: String,
    /// Candidate input class selected for this gap.
    pub input_class: Class,
    /// Optional expression identifying affected candidates.
    #[serde(default)]
    pub predicate: Option<Predicate>,
}

/// Policy for a single namespace and applicant-component form.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Unique authoring identity.
    pub id: String,
    /// Exact namespace or a single leading wildcard selector.
    pub selector: String,
    /// Applicant-component roles in input order.
    pub form: Vec<String>,
    /// Implemented scope for ASCII components.
    pub ascii: Support,
    /// Implemented scope for IDN components.
    pub idn: Support,
    /// Direct enforceable requirements.
    #[serde(default)]
    pub requirements: Vec<Requirement>,
    /// Unimplemented applicable conditions.
    #[serde(default)]
    pub gaps: Vec<Gap>,
    /// Optional ordinary maintainer notes; omitted from generated tables.
    #[serde(default)]
    pub source_notes: Vec<String>,
}

/// Shared exact canonical label set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelSet {
    /// Stable set identity.
    pub id: String,
    /// Exact labels, canonicalized and sorted during compilation.
    pub labels: Vec<String>,
}

/// One packaged authoring file; only its relevant record collection is populated.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    /// Supported direct input schema version.
    pub schema_version: u32,
    /// Direct namespace records.
    #[serde(default)]
    pub policies: Vec<Policy>,
    /// Accepted typed applicant declarations.
    #[serde(default)]
    pub facts: Vec<Fact>,
    /// Adopted finite IDN tables.
    #[serde(default)]
    pub idn_profiles: Vec<super::idn::IdnProfile>,
    /// Shared exact-label sets.
    #[serde(default)]
    pub label_sets: Vec<LabelSet>,
}

/// A non-public special-use name.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecialUse {
    /// Canonical designated identity.
    pub name: String,
    /// Whether its descendants are also excluded.
    pub descendants: bool,
}

/// Minimal special-use input file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecialUses {
    /// Designations excluding public registrations.
    pub names: Vec<SpecialUse>,
}
