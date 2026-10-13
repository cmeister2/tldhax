//! Typed authoring predicates; arbitrary expressions and regexes are excluded.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Representation used to measure a label or match a literal.
pub enum Basis {
    /// Measure or match the canonical ASCII label, including A-label encoding.
    Ascii,
    /// Measure or match the normalized Unicode label by scalar values.
    Unicode,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Finite literal-matching operations supported by authored predicates.
pub enum Pattern {
    /// Match a literal at the start of the selected label.
    Prefix,
    /// Match a literal at the end of the selected label.
    Suffix,
    /// Match a literal anywhere in the selected label.
    Contains,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
/// Typed scalar literal used in applicant-fact comparisons.
pub enum Value {
    /// Boolean applicant fact literal.
    Boolean(bool),
    /// String applicant fact or string-set membership literal.
    String(String),
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Declared applicant-profile value shape.
pub enum FactKind {
    /// One string value.
    String,
    /// One boolean value.
    Boolean,
    /// A collection of string values.
    StringSet,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Optional string syntax checked independently of finite allowed values.
pub enum FactStringFormat {
    /// Exactly two uppercase ASCII letters, as used by country-code facts.
    UppercaseAlpha2,
}

impl FactStringFormat {
    /// Check the declared syntax against one string literal.
    pub fn matches(self, value: &str) -> bool {
        match self {
            Self::UppercaseAlpha2 => {
                value.len() == 2 && value.bytes().all(|b| b.is_ascii_uppercase())
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Typed applicant-profile field declaration shared by its referencing predicates.
pub struct Fact {
    /// Name of the declared applicant-profile field.
    pub field: String,
    /// Value shape accepted for this applicant-profile field.
    pub kind: FactKind,
    #[serde(default)]
    /// Optional finite string enumeration; an empty vector permits any matching string.
    pub allowed_values: Vec<String>,
    #[serde(default)]
    /// Optional syntax restriction on strings and string-set members.
    pub string_format: Option<FactStringFormat>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Finite policy expression compiled into static runtime predicates.
///
/// Validation bounds nesting, components and literal sizes before emission.
pub enum Predicate {
    /// An explicit unconditional truth value.
    Constant {
        /// Explicit truth value independent of name or applicant facts.
        value: bool,
    },
    /// Require every child expression to hold.
    All {
        /// Child expressions combined in the authored order.
        predicates: Vec<Predicate>,
    },
    /// Require at least one child expression to hold.
    Any {
        /// Child expressions combined in the authored order.
        predicates: Vec<Predicate>,
    },
    /// Negate one child expression.
    Not {
        /// Child expression whose truth value is negated.
        predicate: Box<Predicate>,
    },
    /// Constrain a label to an inclusive length interval.
    LabelLength {
        /// Zero-based applicant-controlled label index in the registration form.
        component: u8,
        /// Inclusive lower bound in the selected representation.
        min: u16,
        /// Inclusive upper bound in the selected representation.
        max: u16,
        /// ASCII representation or Unicode scalar sequence used for evaluation.
        basis: Basis,
    },
    /// Constrain a label with only an inclusive minimum length.
    LabelMinimum {
        /// Zero-based applicant-controlled label index in the registration form.
        component: u8,
        /// Inclusive lower bound in the selected representation.
        min: u16,
        /// ASCII representation or Unicode scalar sequence used for evaluation.
        basis: Basis,
    },
    /// Constrain a label with only an inclusive maximum length.
    LabelMaximum {
        /// Zero-based applicant-controlled label index in the registration form.
        component: u8,
        /// Inclusive upper bound in the selected representation.
        max: u16,
        /// ASCII representation or Unicode scalar sequence used for evaluation.
        basis: Basis,
    },
    /// Test membership in a named finite label set.
    LabelInSet {
        /// Zero-based applicant-controlled label index in the registration form.
        component: u8,
        /// Identity of the finite shared label set.
        set_id: String,
    },
    /// Require the selected label to have no non-ASCII Unicode characters.
    AsciiOnly {
        /// Zero-based applicant-controlled label index in the registration form.
        component: u8,
    },
    /// Match a finite literal prefix, suffix or substring.
    LabelPattern {
        /// Zero-based applicant-controlled label index in the registration form.
        component: u8,
        /// Literal prefix, suffix or containment operation to perform.
        pattern: Pattern,
        /// Literal value compared or matched by this predicate.
        value: String,
        /// ASCII representation or Unicode scalar sequence used for evaluation.
        basis: Basis,
    },
    /// Match literal characters at specified fixed positions.
    LabelPositions {
        /// Zero-based applicant-controlled label index in the registration form.
        component: u8,
        /// Strictly increasing zero-based character positions paired with the literal.
        positions: Vec<u16>,
        /// Literal value compared or matched by this predicate.
        value: String,
        /// ASCII representation or Unicode scalar sequence used for evaluation.
        basis: Basis,
    },
    /// Check a label against its adopted finite IDN profile.
    Idn {
        /// Zero-based applicant-controlled label index in the registration form.
        component: u8,
        /// Identity of the adopted IDN repertoire and context profile.
        profile_id: String,
    },
    /// Compare a declared applicant fact to one typed scalar literal.
    FieldEquals {
        /// Name of the declared applicant-profile field.
        field: String,
        /// Literal value compared or matched by this predicate.
        value: Value,
    },
    /// Test a fact against finite typed alternatives or string-set membership.
    FieldIn {
        /// Name of the declared applicant-profile field.
        field: String,
        /// Finite comparison alternatives with the declared fact type.
        values: Vec<Value>,
    },
    /// Compare the selected label with a string fact or member of a string set.
    NameEqualsField {
        /// Zero-based applicant-controlled label index in the registration form.
        component: u8,
        /// Name of the declared applicant-profile field.
        field: String,
    },
    /// Record policy semantics that cannot be compiled for enforcement.
    Unsupported {
        /// Description of unsupported semantics retained as an explicit policy gap.
        feature: String,
    },
}

impl Predicate {
    /// Return the applicant-label index directly referenced by this expression.
    pub fn component(&self) -> Option<u8> {
        match self {
            Self::LabelLength { component, .. }
            | Self::LabelMinimum { component, .. }
            | Self::LabelMaximum { component, .. }
            | Self::LabelInSet { component, .. }
            | Self::AsciiOnly { component }
            | Self::LabelPattern { component, .. }
            | Self::LabelPositions { component, .. }
            | Self::Idn { component, .. }
            | Self::NameEqualsField { component, .. } => Some(*component),
            _ => None,
        }
    }

    /// Borrow boolean child expressions; scalar predicates have no children.
    pub fn children(&self) -> &[Predicate] {
        match self {
            Self::All { predicates } | Self::Any { predicates } => predicates,
            Self::Not { predicate } => std::slice::from_ref(predicate),
            _ => &[],
        }
    }
}
