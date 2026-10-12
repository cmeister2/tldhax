//! Immutable evidence and policy tables generated during an offline build.

/// Research status for an applicable rule family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Knowledge {
    /// Reviewed evidence supports the scoped claim.
    Reviewed,
    /// Some applicable conditions remain unreviewed.
    Partial,
    /// No reviewed decision-critical coverage is established.
    Unknown,
    /// Disputed evidence cannot justify enforcement.
    Conflicting,
    /// Evidence explicitly establishes inapplicability.
    NotApplicable,
}

/// Independent policy dimensions; applicant eligibility is not name validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleFamily {
    /// Accepted registration boundaries and forms.
    Namespace,
    /// Additional registry label-length constraints.
    Length,
    /// Published character and literal pattern restrictions.
    Characters,
    /// Adopted internationalised-name policy.
    Idn,
    /// Exact published reservations and exceptions.
    Reserved,
    /// Relationship between the candidate and declared rights.
    Allocation,
    /// Public or conditional namespace access.
    Access,
    /// Declared applicant qualification.
    Eligibility,
}

/// Class of applicant-supplied labels, independent of suffix encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputClass {
    /// ASCII representation or ASCII applicant-label class.
    Ascii,
    /// Adopted internationalised-name policy.
    Idn,
    /// Any applicable class or a satisfied alternative.
    Any,
}

/// Canonical namespace selector; wildcards match a single resolved component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorKind {
    /// Exact canonical namespace selector.
    Exact,
    /// Single-label wildcard namespace selector.
    Wildcard,
}

/// Meaning of a true/false predicate, with unknown preserved by the evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEffect {
    /// A false predicate establishes a scoped failure.
    Require,
    /// A true predicate establishes a scoped failure.
    Deny,
    /// Explanatory information without a validity prerequisite.
    Context,
}

/// Additional registry length measurement after independent DNS wire checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthMeasure {
    /// ASCII representation or ASCII applicant-label class.
    Ascii,
    /// Decoded canonical Unicode representation.
    Unicode,
}

/// Bounded literal operations; arbitrary regular expressions are unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    /// Match a literal at the beginning.
    Prefix,
    /// Match a literal at the end.
    Suffix,
    /// Match a literal contiguous sequence.
    Contains,
}

/// Declared profile fact type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactKind {
    /// A string scalar.
    String,
    /// A Boolean scalar.
    Boolean,
    /// A finite set of string values.
    StringSet,
}

/// Scalar comparison value; set-valued facts support membership/intersection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactValue {
    /// A string scalar.
    String(&'static str),
    /// A Boolean scalar.
    Boolean(bool),
}

/// A named typed field accepted in an optional applicant profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactSchema {
    /// Declared applicant-profile field name.
    pub field: &'static str,
    /// The typed interpretation of this record.
    pub kind: FactKind,
    /// Optional finite permitted string values.
    pub allowed_values: &'static [&'static str],
}

/// Finite typed predicates compiled into static data, without runtime parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Predicate {
    /// An explicit constant truth value.
    Constant(bool),
    /// Conjunction with three-valued logic.
    All(&'static [Predicate]),
    /// Any applicable class or a satisfied alternative.
    Any(&'static [Predicate]),
    /// Negation preserving unknown.
    Not(&'static Predicate),
    /// Registry-specific label length after DNS checks.
    LabelLength {
        /// Zero-based applicant label index in input order.
        component: u8,
        /// Inclusive minimum length.
        min: u16,
        /// Inclusive maximum length.
        max: u16,
        /// Canonical representation used for comparison.
        basis: LengthMeasure,
    },
    /// An independently documented registry minimum, without an invented maximum.
    LabelMinimum {
        /// Zero-based applicant component index.
        component: u8,
        /// Inclusive evidenced minimum.
        min: u16,
        /// Canonical representation used for measurement.
        basis: LengthMeasure,
    },
    /// An independently documented registry maximum, without an invented minimum.
    LabelMaximum {
        /// Zero-based applicant component index.
        component: u8,
        /// Inclusive evidenced maximum.
        max: u16,
        /// Canonical representation used for measurement.
        basis: LengthMeasure,
    },
    /// Exact canonical reserved-label membership.
    LabelInSet {
        /// Zero-based applicant label index in input order.
        component: u8,
        /// Identifier of the shared exact label set.
        set_id: &'static str,
    },
    /// Require the canonical decoded label to be ASCII.
    AsciiOnly {
        /// Zero-based applicant label index in input order.
        component: u8,
    },
    /// Bounded literal pattern on the selected representation.
    LabelPattern {
        /// Zero-based applicant label index in input order.
        component: u8,
        /// Finite literal matching operation.
        pattern: PatternKind,
        /// Literal or typed comparison value.
        value: &'static str,
        /// Canonical representation used for comparison.
        basis: LengthMeasure,
    },
    /// Finite literal character positions.
    LabelPositions {
        /// Zero-based applicant label index in input order.
        component: u8,
        /// Sorted zero-based character positions.
        positions: &'static [u16],
        /// Literal or typed comparison value.
        value: &'static str,
        /// Canonical representation used for comparison.
        basis: LengthMeasure,
    },
    /// Adopted internationalised-name policy.
    Idn {
        /// Zero-based applicant label index in input order.
        component: u8,
        /// Identifier of the adopted registry IDN profile.
        profile_id: &'static str,
    },
    /// Typed scalar or string-set membership equality.
    FieldEquals {
        /// Declared applicant-profile field name.
        field: &'static str,
        /// Literal or typed comparison value.
        value: FactValue,
    },
    /// Typed scalar membership or string-set intersection.
    FieldIn {
        /// Declared applicant-profile field name.
        field: &'static str,
        /// Finite scalar values for set membership.
        values: &'static [FactValue],
    },
    /// Canonical candidate label equals a declared qualifying label.
    NameEqualsField {
        /// Zero-based applicant label index in input order.
        component: u8,
        /// Declared applicant-profile field name.
        field: &'static str,
    },
}

/// Publisher identity and exact reviewed document version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceSource {
    /// Stable record identifier.
    pub id: &'static str,
    /// Organisation publishing the controlling source.
    pub publisher: &'static str,
    /// Published document title.
    pub title: &'static str,
    /// Canonical controlling source URL.
    pub url: &'static str,
    /// URL used to retrieve the reviewed representation.
    pub fetched_url: &'static str,
    /// SHA-256 hash of the explicitly identified representation.
    pub sha256: &'static str,
    /// Original bytes or versioned extracted-text representation.
    pub hash_representation: &'static str,
    /// Published version or explicitly identified undated snapshot.
    pub version: &'static str,
    /// Language of the reviewed source.
    pub language: &'static str,
    /// Date this representation was retrieved; not a commencement date.
    pub retrieved_on: &'static str,
    /// Optional identifier of the original-language source.
    pub translation_of: Option<&'static str>,
}

/// Clause interpretation, temporal status and explicit applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceAssertion {
    /// Stable record identifier.
    pub id: &'static str,
    /// Identifier of the source containing the cited clause.
    pub source_id: &'static str,
    /// Precise clause, section or page locator.
    pub locator: &'static str,
    /// Reviewed interpretation of the controlling clause.
    pub interpretation: &'static str,
    /// Operation to which the source clause applies.
    pub operation: &'static str,
    /// Canonical exact or wildcard namespace scope.
    pub namespaces: &'static [&'static str],
    /// Applicable applicant-label counts or accepted registration shapes.
    pub forms: &'static [u8],
    /// ASCII/IDN applicability of applicant labels.
    pub input_class: InputClass,
    /// Independent policy dimension addressed by the record.
    pub family: RuleFamily,
    /// Effective research status on the pinned evaluation date.
    pub knowledge: Knowledge,
    /// Explicit attestation of the entire scoped family, independent of a rule.
    pub attests_completeness: bool,
    /// Documented policy commencement, when published.
    pub effective_from: Option<&'static str>,
    /// Attested current applicability without inventing historical commencement.
    pub applicable_on: Option<&'static str>,
    /// Exclusive end of the documented applicability interval.
    pub effective_until: Option<&'static str>,
    /// Identity of the reviewer responsible for this interpretation.
    pub reviewer: &'static str,
    /// Date the assertion was reviewed.
    pub reviewed_on: &'static str,
    /// Date after which comprehensive current claims require renewed review.
    pub review_due: &'static str,
    /// Whether reviewed temporal applicability permits enforcement.
    pub active: bool,
    /// Stable explanation of unresolved or inactive applicability.
    pub inactive_reason: Option<&'static str>,
}

/// An enforceable active assertion or explanatory context rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledRule {
    /// Stable record identifier.
    pub id: &'static str,
    /// Independent policy dimension addressed by the record.
    pub family: RuleFamily,
    /// ASCII/IDN applicability of applicant labels.
    pub input_class: InputClass,
    /// Applicable applicant-label counts or accepted registration shapes.
    pub forms: &'static [u8],
    /// Interpretation of predicate truth for this rule.
    pub effect: RuleEffect,
    /// Precompiled finite constraint.
    pub predicate: Predicate,
    /// Assertion identifiers that justify this record.
    pub evidence_ids: &'static [&'static str],
    /// Canonical namespace scope for explanations.
    pub scope: &'static str,
    /// Stable diagnostic code used without formatting prose.
    pub code: &'static str,
}

/// Reviewed additional registration shape, with components in input order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationForm {
    /// Applicant component roles in input order.
    pub roles: &'static [&'static str],
}

/// Coverage differs between ASCII and internationalised applicant labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyCoverage {
    /// Independent policy dimension addressed by the record.
    pub family: RuleFamily,
    /// Coverage for ASCII applicant labels.
    pub ascii: Knowledge,
    /// Coverage for internationalised applicant labels.
    pub idn: Knowledge,
    /// Assertion identifiers that justify this record.
    pub evidence_ids: &'static [&'static str],
    /// Reason the scoped coverage is unresolved.
    pub gap: Option<&'static str>,
}

/// Sorted namespace policy entry, independent of registration resolver rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespacePolicy {
    /// Canonical namespace selector, preserving wildcard notation.
    pub selector: &'static str,
    /// The typed interpretation of this record.
    pub kind: SelectorKind,
    /// Applicable applicant-label counts or accepted registration shapes.
    pub forms: &'static [RegistrationForm],
    /// Independent family states for each applicant-label class.
    pub coverage: &'static [FamilyCoverage],
    /// Indices into the shared immutable rule table.
    pub rule_indices: &'static [u32],
    /// Assertion identifiers that justify this record.
    pub evidence_ids: &'static [&'static str],
    /// Explanatory information outside static validity prerequisites.
    pub context: &'static [&'static str],
}

/// Canonical sorted label membership; usage is scoped by reviewed assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelSet {
    /// Stable record identifier.
    pub id: &'static str,
    /// Canonical sorted exact labels.
    pub labels: &'static [&'static str],
    /// Assertion identifiers that justify this record.
    pub evidence_ids: &'static [&'static str],
}

/// Finite code point interval in an adopted registry table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodepointRange {
    /// First Unicode scalar in the inclusive interval.
    pub start: u32,
    /// Last Unicode scalar in the inclusive interval.
    pub end: u32,
}

/// Supported finite positional/contextual checks for a specified code point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextKind {
    /// The constrained code point cannot begin the label.
    NotStart,
    /// The constrained code point cannot end the label.
    NotEnd,
    /// A finite permitted immediately preceding code point.
    PrecededBy(&'static [u32]),
    /// A finite permitted immediately following code point.
    FollowedBy(&'static [u32]),
    /// Finite preceding and following code-point conditions.
    Between {
        /// Finite permitted preceding code points.
        left: &'static [u32],
        /// Finite permitted following code points.
        right: &'static [u32],
    },
}

/// One contextual table restriction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdnContext {
    /// Unicode scalar constrained by the contextual rule.
    pub codepoint: u32,
    /// The typed interpretation of this record.
    pub kind: ContextKind,
}

/// Variant relationship disposition; unresolved screening remains a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantDisposition {
    /// A blocked variant relationship; not a generic sequence prohibition.
    Blocked,
    /// Variant allocation requires unresolved conditions.
    Conditional,
    /// Variant allocation remains unresearched.
    Unresolved,
}

/// Literal Unicode sequence relationship from the reviewed table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdnVariant {
    /// Original Unicode sequence in the variant relationship.
    pub sequence: &'static str,
    /// Related Unicode sequence; relationship alone does not deny a label.
    pub replacement: &'static str,
    /// Registry variant relationship disposition.
    pub disposition: VariantDisposition,
}

/// Registry-adopted repertoire, context checks and variant metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdnProfile {
    /// Stable record identifier.
    pub id: &'static str,
    /// Published version or explicitly identified undated snapshot.
    pub version: &'static str,
    /// Effective research status on the pinned evaluation date.
    pub knowledge: Knowledge,
    /// Complete adopted repertoire, independently of contextual/allocation gaps.
    pub repertoire_complete: bool,
    /// Sorted disjoint adopted Unicode repertoire intervals.
    pub ranges: &'static [CodepointRange],
    /// Supported finite positional/contextual restrictions.
    pub contexts: &'static [IdnContext],
    /// Variant relationships retained without inferred prohibitions.
    pub variants: &'static [IdnVariant],
    /// Assertion identifiers that justify this record.
    pub evidence_ids: &'static [&'static str],
    /// Table features that force a scoped completeness gap.
    pub unsupported_features: &'static [&'static str],
}

/// Unsupported legacy claims retained as research leads rather than policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyResearch {
    /// Canonical namespace selector, preserving wildcard notation.
    pub selector: &'static str,
    /// Original source URLs retained as unapproved research leads.
    pub source_links: &'static [&'static str],
    /// Legacy authoring path from which this lead originated.
    pub provenance: &'static str,
}
