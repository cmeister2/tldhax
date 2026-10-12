//! Three-valued finite predicate outcomes and bounded diagnostic parameters.

use crate::policy_types::LengthMeasure;

/// Logical outcome preserving missing facts and unsupported policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truth {
    /// The supplied name and facts establish the predicate.
    True,
    /// The supplied name and facts disprove the predicate.
    False,
    /// A required fact or complete policy interpretation is unavailable.
    Unknown,
}

/// Bounded diagnostics excluding declared profile values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateIssue {
    /// A declared fact is absent, rather than explicitly negative.
    MissingField(&'static str),
    /// No applicant component exists at the selected index.
    MissingComponent(u8),
    /// A static table reference cannot be resolved.
    MissingTable(&'static str),
    /// The adopted IDN profile has an unresolved feature or interpretation.
    IdnIncomplete(&'static str),
    /// A code point is outside a reviewed complete repertoire.
    IdnCharacter(u32),
    /// A code point fails an adopted positional/contextual condition.
    IdnContext {
        /// Offending Unicode scalar.
        codepoint: u32,
        /// Zero-based position in the canonical decoded label.
        position: usize,
    },
    /// Measured registry length falls outside the declared interval.
    Length {
        /// Measured length in the rule's stated representation.
        actual: usize,
        /// Inclusive lower bound.
        min: Option<u16>,
        /// Inclusive upper bound.
        max: Option<u16>,
        /// ASCII bytes or Unicode code points.
        basis: LengthMeasure,
    },
}

/// Compact predicate result; explanations are formatted by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredicateResult {
    /// Three-valued truth independent of the rule's require/deny effect.
    pub truth: Truth,
    /// A bounded failure or missing-information diagnostic.
    pub issue: Option<PredicateIssue>,
}

impl PredicateResult {
    /// Construct a truth value with no additional parameters.
    pub(crate) const fn plain(truth: Truth) -> Self {
        Self { truth, issue: None }
    }

    /// Construct a truth value retaining one precise diagnostic.
    pub const fn issue(truth: Truth, issue: PredicateIssue) -> Self {
        Self {
            truth,
            issue: Some(issue),
        }
    }

    /// Convert an established Boolean proposition.
    pub const fn boolean(value: bool) -> Self {
        Self::plain(if value { Truth::True } else { Truth::False })
    }
}
