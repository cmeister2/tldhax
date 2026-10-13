//! Immutable direct requirements, typed facts and adopted name tables.

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

/// Explicit structural validation for scalar or set-valued string facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactStringFormat {
    /// Exactly two ASCII uppercase letters; country membership is policy-specific.
    UppercaseAlpha2,
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
    /// Optional structural validation applied to each declared string value.
    pub string_format: Option<FactStringFormat>,
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
    /// An independently declared registry minimum, without an invented maximum.
    LabelMinimum {
        /// Zero-based applicant component index.
        component: u8,
        /// Inclusive minimum.
        min: u16,
        /// Canonical representation used for measurement.
        basis: LengthMeasure,
    },
    /// An independently declared registry maximum, without an invented minimum.
    LabelMaximum {
        /// Zero-based applicant component index.
        component: u8,
        /// Inclusive maximum.
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

/// Scope implemented for one registration form and applicant input class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// The identified static requirements are implemented.
    Supported,
    /// Some applicable static requirements remain unimplemented.
    Partial,
    /// The input class has no supported policy.
    Unsupported,
}

/// A direct requirement whose truth can establish a registration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirement {
    /// Stable interface reason code for this check.
    pub code: &'static str,
    /// Human-readable unmet condition, without private profile values.
    pub message: &'static str,
    /// Whether the predicate must hold or must not hold.
    pub effect: RuleEffect,
    /// Applicant input class in which this condition applies.
    pub input_class: InputClass,
    /// Finite precompiled name or profile expression.
    pub predicate: Predicate,
}

/// An unimplemented applicable condition which prevents a positive decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyGap {
    /// Stable interface reason code for the unresolved condition.
    pub code: &'static str,
    /// Actionable description of the implementation or policy gap.
    pub message: &'static str,
    /// Applicant input class to which this limitation applies.
    pub input_class: InputClass,
    /// Optional expression selecting affected candidates; unknown applicability is unresolved.
    pub predicate: Option<Predicate>,
}

/// Direct policy for one exact or wildcard namespace and registration form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespacePolicy {
    /// Stable authoring identifier.
    pub id: &'static str,
    /// Canonical namespace selector, preserving a leading wildcard.
    pub selector: &'static str,
    /// Exact namespace or one-label wildcard.
    pub kind: SelectorKind,
    /// Applicant component roles in input order, for this single form.
    pub form: &'static [&'static str],
    /// Implemented scope for ASCII applicant components.
    pub ascii: Support,
    /// Implemented scope for internationalised applicant components.
    pub idn: Support,
    /// Applicable direct requirements; each failed mandatory check explains itself.
    pub requirements: &'static [Requirement],
    /// Candidate-scoped limitations, independent of unrelated forms.
    pub gaps: &'static [PolicyGap],
}

/// Shared canonical exact-label set used only by explicit requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelSet {
    /// Stable shared set identity.
    pub id: &'static str,
    /// Sorted, unique canonical labels.
    pub labels: &'static [&'static str],
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

/// Registry-adopted repertoire and finite context checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdnProfile {
    /// Stable record identifier.
    pub id: &'static str,
    /// Whether absent code points can be conclusively excluded.
    pub repertoire_complete: bool,
    /// Sorted disjoint adopted Unicode repertoire intervals.
    pub ranges: &'static [CodepointRange],
    /// Supported finite positional/contextual restrictions.
    pub contexts: &'static [IdnContext],
}
