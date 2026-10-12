//! Static finite predicates with three-valued declared-profile evaluation.

use crate::normalization::normalize;
use crate::policy_types::{FactValue, IdnProfile, LabelSet, LengthMeasure, PatternKind, Predicate};
use crate::profile::{ProfileFact, RegistrantProfile};

pub use crate::predicate_types::{PredicateIssue, PredicateResult, Truth};

/// Borrowed canonical label context and immutable compiled tables.
pub struct PredicateContext<'a> {
    /// Applicant-supplied components in canonical ASCII form.
    pub ascii: &'a str,
    /// Canonical decoded Unicode components; suffix labels may follow.
    pub unicode: &'a str,
    /// Optional prepared self-declared facts.
    pub profile: Option<&'a RegistrantProfile>,
    /// Sorted shared canonical label sets.
    pub label_sets: &'static [LabelSet],
    /// Sorted adopted IDN profiles.
    pub idn_profiles: &'static [IdnProfile],
}

impl PredicateContext<'_> {
    /// Select an applicant component in the explicitly stated representation.
    fn label(&self, component: u8, basis: LengthMeasure) -> Option<&str> {
        let applicant = self.ascii.split('.').nth(usize::from(component))?;
        if applicant.is_empty() {
            return None;
        }
        let input = match basis {
            LengthMeasure::Ascii => self.ascii,
            LengthMeasure::Unicode => self.unicode,
        };
        input
            .split('.')
            .nth(usize::from(component))
            .filter(|label| !label.is_empty())
    }

    /// Evaluate a compiler-bounded predicate tree using three-valued logic.
    pub fn evaluate(&self, predicate: &Predicate) -> PredicateResult {
        match predicate {
            Predicate::Constant(value) => PredicateResult::boolean(*value),
            Predicate::All(children) => self.logical(children, true),
            Predicate::Any(children) => self.logical(children, false),
            Predicate::Not(child) => {
                let result = self.evaluate(child);
                PredicateResult {
                    truth: match result.truth {
                        Truth::True => Truth::False,
                        Truth::False => Truth::True,
                        Truth::Unknown => Truth::Unknown,
                    },
                    issue: result.issue,
                }
            }
            Predicate::FieldEquals { field, value } => self.field(field, &[*value]),
            Predicate::FieldIn { field, values } => self.field(field, values),
            Predicate::NameEqualsField { component, field } => {
                let Some(label) = self.label(*component, LengthMeasure::Ascii) else {
                    return PredicateResult::issue(
                        Truth::Unknown,
                        PredicateIssue::MissingComponent(*component),
                    );
                };
                let Some(fact) = self.profile.and_then(|profile| profile.get(field)) else {
                    return PredicateResult::issue(
                        Truth::Unknown,
                        PredicateIssue::MissingField(field),
                    );
                };
                let matches =
                    |value: &str| normalize(value).is_ok_and(|name| name.ascii() == label);
                PredicateResult::boolean(match fact {
                    ProfileFact::String(value) => matches(value),
                    ProfileFact::StringSet(values) => values.iter().any(|value| matches(value)),
                    ProfileFact::Boolean(_) => false,
                })
            }
            Predicate::LabelLength {
                component,
                min,
                max,
                basis,
            } => self.length(*component, Some(*min), Some(*max), *basis),
            Predicate::LabelMinimum {
                component,
                min,
                basis,
            } => self.length(*component, Some(*min), None, *basis),
            Predicate::LabelMaximum {
                component,
                max,
                basis,
            } => self.length(*component, None, Some(*max), *basis),
            Predicate::LabelInSet { component, set_id } => {
                self.with_label(*component, LengthMeasure::Ascii, |label| {
                    let Ok(index) = self.label_sets.binary_search_by_key(set_id, |set| set.id)
                    else {
                        return PredicateResult::issue(
                            Truth::Unknown,
                            PredicateIssue::MissingTable(set_id),
                        );
                    };
                    PredicateResult::boolean(
                        self.label_sets[index].labels.binary_search(&label).is_ok(),
                    )
                })
            }
            Predicate::AsciiOnly { component } => {
                self.with_label(*component, LengthMeasure::Unicode, |label| {
                    PredicateResult::boolean(label.is_ascii())
                })
            }
            Predicate::LabelPattern {
                component,
                pattern,
                value,
                basis,
            } => self.with_label(*component, *basis, |label| {
                PredicateResult::boolean(match pattern {
                    PatternKind::Prefix => label.starts_with(value),
                    PatternKind::Suffix => label.ends_with(value),
                    PatternKind::Contains => label.contains(value),
                })
            }),
            Predicate::LabelPositions {
                component,
                positions,
                value,
                basis,
            } => self.with_label(*component, *basis, |label| {
                PredicateResult::boolean(positions.iter().zip(value.chars()).all(
                    |(position, value)| label.chars().nth(usize::from(*position)) == Some(value),
                ))
            }),
            Predicate::Idn {
                component,
                profile_id,
            } => self.with_label(*component, LengthMeasure::Unicode, |label| {
                crate::idn_eval::evaluate(label, profile_id, self.idn_profiles)
            }),
        }
    }

    /// Preserve decisive branches: false AND unknown is false; true OR unknown is true.
    fn logical(&self, children: &[Predicate], all: bool) -> PredicateResult {
        let mut missing = None;
        for child in children {
            let result = self.evaluate(child);
            match (all, result.truth) {
                (true, Truth::False) | (false, Truth::True) => return result,
                (_, Truth::Unknown) if missing.is_none() => missing = Some(result),
                _ => (),
            }
        }
        missing.unwrap_or_else(|| PredicateResult::boolean(all))
    }

    /// Evaluate a typed scalar match or set intersection without coercion.
    fn field(&self, field: &'static str, values: &[FactValue]) -> PredicateResult {
        let Some(fact) = self.profile.and_then(|profile| profile.get(field)) else {
            return PredicateResult::issue(Truth::Unknown, PredicateIssue::MissingField(field));
        };
        PredicateResult::boolean(values.iter().any(|value| {
            match (fact, value) {
                (ProfileFact::String(actual), FactValue::String(expected)) => actual == expected,
                (ProfileFact::Boolean(actual), FactValue::Boolean(expected)) => actual == expected,
                (ProfileFact::StringSet(actual), FactValue::String(expected)) => actual
                    .binary_search_by(|value| value.as_str().cmp(expected))
                    .is_ok(),
                _ => false,
            }
        }))
    }

    /// Apply a finite label operation, preserving an absent component as unknown.
    fn with_label(
        &self,
        component: u8,
        basis: LengthMeasure,
        operation: impl FnOnce(&str) -> PredicateResult,
    ) -> PredicateResult {
        self.label(component, basis).map_or_else(
            || PredicateResult::issue(Truth::Unknown, PredicateIssue::MissingComponent(component)),
            operation,
        )
    }

    /// Apply only the registry bounds actually supported by the source.
    fn length(
        &self,
        component: u8,
        min: Option<u16>,
        max: Option<u16>,
        basis: LengthMeasure,
    ) -> PredicateResult {
        self.with_label(component, basis, |label| {
            let actual = match basis {
                LengthMeasure::Ascii => label.len(),
                LengthMeasure::Unicode => label.chars().count(),
            };
            if min.is_some_and(|min| actual < usize::from(min))
                || max.is_some_and(|max| actual > usize::from(max))
            {
                PredicateResult::issue(
                    Truth::False,
                    PredicateIssue::Length {
                        actual,
                        min,
                        max,
                        basis,
                    },
                )
            } else {
                PredicateResult::plain(Truth::True)
            }
        })
    }
}

#[cfg(test)]
#[path = "predicate_eval_tests.rs"]
mod tests;
