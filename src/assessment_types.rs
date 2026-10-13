//! Compact assessment records; profile values and formatted prose are excluded.

use crate::inventory_types::{RootInventory, SpecialUse};
use crate::normalization::{CanonicalName, NormalizationError};
use crate::policy_types::{InputClass, Knowledge, RuleEffect, RuleFamily};
use crate::predicate_eval::{PredicateIssue, Truth};
use crate::resolver::{RouteKind, RouteSection};

/// Define an outcome with a stable language-independent spelling.
macro_rules! outcome {
    ($name:ident, $description:literal, {$($variant:ident => $value:literal),+}) => {
        #[doc = $description]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $(#[doc = $value] $variant),+ }
        impl $name {
            /// Stable spelling for serialization and compatibility wrappers.
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
        }
    };
}

outcome!(NameValidity, "Static candidate-name outcome, independent of applicant failure.", {
    Valid => "valid", Invalid => "invalid", Unknown => "unknown"
});
outcome!(Summary, "Combined name, access and declared-applicant outcome.", {
    Yes => "yes", No => "no", Restricted => "restricted", Unknown => "unknown"
});
outcome!(Coverage, "Completeness of the applicable static name-policy dimensions.", {
    Complete => "complete", Partial => "partial", Unknown => "unknown", Conflicting => "conflicting"
});
outcome!(Eligibility, "Declared applicant assessment; this never verifies documentation.", {
    NotRequired => "not_required", DeclaredMatch => "declared_match", DoesNotMatch => "does_not_match",
    NeedsProfile => "needs_profile", UnknownPolicy => "unknown_policy"
});
outcome!(Severity, "Finding importance without changing the independent outcome enums.", {
    Error => "error", Warning => "warning", Info => "info"
});

/// Selected routing identity with byte offsets into the owned canonical name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSelection {
    /// First byte of the canonical ASCII namespace suffix.
    pub suffix_start: usize,
    /// Number of applicant components before the suffix.
    pub applicant_labels: usize,
    /// Exact originating route identity.
    pub rule_id: &'static str,
    /// Original exact, wildcard or exception selector.
    pub selector: &'static str,
    /// Pinned discovery source or reviewed-policy marker.
    pub source_id: &'static str,
    /// Exact, wildcard or exception matching semantics.
    pub kind: RouteKind,
    /// Registration, discovery or optional hosting classification.
    pub section: RouteSection,
    /// Assertions approving reviewed registration forms, if any.
    pub evidence_ids: &'static [&'static str],
}

/// Diagnostic parameters drawn solely from the candidate or static policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingParams {
    /// No parameters are necessary.
    None,
    /// Protocol or API-budget failure.
    Normalization(NormalizationError),
    /// Bounded predicate failure or missing-field name, never a profile value.
    Predicate(PredicateIssue),
    /// Applicant-label count at a reviewed but unsupported registration shape.
    ApplicantLabels(usize),
}

/// A traceable finding whose prose is produced only in detailed mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    /// Stable diagnostic code.
    pub code: &'static str,
    /// Applied compiled rule, when this finding originates from one.
    pub rule_id: Option<&'static str>,
    /// Exact reviewed assertion identities.
    pub evidence_ids: &'static [&'static str],
    /// Factual inventory source identities, independent of policy assertions.
    pub source_ids: &'static [&'static str],
    /// Governing protocol references or source URLs for built-in findings.
    pub references: &'static [&'static str],
    /// Static namespace selector, special-use name or protocol/input scope.
    pub scope: &'static str,
    /// Explanation severity, independent of aggregation.
    pub severity: Severity,
    /// Candidate-derived or static bounded diagnostic parameters.
    pub params: FindingParams,
}

/// Evaluation of one applicable rule, before require/deny aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleEvaluation {
    /// Stable compiled rule identity.
    pub rule_id: &'static str,
    /// Applied policy dimension.
    pub family: RuleFamily,
    /// Interpretation of the predicate's truth value.
    pub effect: RuleEffect,
    /// Three-valued predicate result.
    pub truth: Truth,
    /// Explicitly scoped evidence, even for passing predicates.
    pub evidence_ids: &'static [&'static str],
    /// Canonical policy namespace selector.
    pub scope: &'static str,
    /// Bounded candidate or missing-field diagnostic.
    pub issue: Option<PredicateIssue>,
    /// A missing declared fact made the name predicate conditional.
    pub profile_dependent: bool,
}

/// An unresolved policy dimension for this input class and registration form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageGap {
    /// Policy dimension that prevents a comprehensive claim.
    pub family: RuleFamily,
    /// Applicant class, independent of suffix encoding.
    pub input_class: InputClass,
    /// Partial, unknown or conflicting reviewed research state.
    pub knowledge: Knowledge,
    /// Supporting research assertions; empty means no reviewed evidence.
    pub evidence_ids: &'static [&'static str],
    /// Authoring selector, or the inventory fallback scope.
    pub scope: &'static str,
    /// Static research explanation; no profile values are interpolated.
    pub reason: Option<&'static str>,
}

/// Canonical candidate and compact outcome without self-referential borrows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactAssessment<'a> {
    /// Validated canonical identity, absent for rejected input.
    pub canonical: Option<CanonicalName<'a>>,
    /// Decoded Unicode only when it differs from the ASCII identity.
    pub decoded_unicode: Option<String>,
    /// Independent static name result.
    pub name_validity: NameValidity,
    /// Combined compatibility status.
    pub summary: Summary,
    /// Completeness of applicable name dimensions.
    pub policy_coverage: Coverage,
    /// Declared applicant result, independent of name validity.
    pub eligibility: Eligibility,
    /// Registration route selected using accepted reviewed forms.
    pub registration: Option<RouteSelection>,
    /// Prevailing pinned ICANN discovery match.
    pub icann: Option<RouteSelection>,
    /// Optional PRIVATE classification, separate from registration.
    pub private: Option<RouteSelection>,
    /// Root membership as of the pinned inventory date.
    pub root_known: bool,
    /// Matched factual root metadata, when available.
    pub root_inventory: Option<&'static RootInventory>,
    /// Longest matching special-use designation, independent of delegation.
    pub special_use: Option<&'static SpecialUse>,
    /// Selected authored policy selector, distinct from discovery routing.
    pub policy_selector: Option<&'static str>,
    /// Applicable rule truth and evidence records.
    pub rules: Vec<RuleEvaluation>,
    /// Bounded diagnostic records.
    pub findings: Vec<Finding>,
    /// Missing applicable name or eligibility policy dimensions.
    pub gaps: Vec<CoverageGap>,
    /// True when diagnostic limits omitted records; outcomes still use all rules.
    pub diagnostics_truncated: bool,
    /// Full release fingerprint, including reviewed policy and evidence.
    pub dataset_version: &'static str,
    /// Pinned date used to activate reviewed assertions.
    pub evaluation_date: &'static str,
    /// Date of the pinned factual root snapshot.
    pub inventory_date: &'static str,
    /// Versioned shared normalization contract.
    pub normalization_profile: &'static str,
}

impl CompactAssessment<'_> {
    /// Preserve spans and static records while owning the candidate's identity.
    pub fn into_owned(self) -> CompactAssessment<'static> {
        CompactAssessment {
            canonical: self.canonical.map(CanonicalName::into_owned),
            ..self
        }
    }

    /// Borrow the validated A-label identity.
    pub fn ascii(&self) -> Option<&str> {
        self.canonical.as_ref().map(CanonicalName::ascii)
    }

    /// Borrow canonical Unicode; plain ASCII requires no second allocation.
    pub fn unicode(&self) -> Option<&str> {
        self.decoded_unicode.as_deref().or_else(|| self.ascii())
    }

    /// Borrow the suffix identified by a stored route span.
    pub fn route_suffix(&self, route: RouteSelection) -> Option<&str> {
        self.ascii()?.get(route.suffix_start..)
    }

    /// Borrow the selected registration namespace without copying its labels.
    pub fn namespace(&self) -> Option<&str> {
        self.registration.and_then(|route| self.route_suffix(route))
    }
}
