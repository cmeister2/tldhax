//! Direct requirement evaluation with three-valued declared-profile logic.

use crate::assessment_types::{Assessment, Decision, InputError, Reason};
use crate::dataset::PolicyDataset;
use crate::normalization::{CanonicalName, NormalizationError};
use crate::policy_types::{InputClass, Predicate, RuleEffect, Support};
use crate::predicate_eval::PredicateContext;
use crate::predicate_types::{PredicateIssue, PredicateResult, Truth};
use crate::profile::RegistrantProfile;

/// Assess one candidate without network access, wall-clock reads or citation payloads.
///
/// # Errors
/// Returns an input error when the raw domain exceeds the implementation budget.
pub(crate) fn assess(
    dataset: &PolicyDataset,
    input: &str,
    profile: Option<&RegistrantProfile>,
) -> Result<Assessment, InputError> {
    let name = match CanonicalName::new(input) {
        Ok(name) => name,
        Err(NormalizationError::InputLimit) => return Err(InputError::InputLimit),
        Err(error) => {
            return Ok(Assessment {
                decision: Decision::No,
                canonical_domain: None,
                namespace: None,
                reasons: vec![reason(error.code(), error.message())],
                missing_profile_fields: Vec::new(),
            });
        }
    };
    let ascii = name.ascii();
    let resolution = dataset.resolver.resolve(ascii);
    let mut result = Assessment {
        decision: Decision::Unknown,
        canonical_domain: Some(ascii.to_owned()),
        namespace: resolution.namespace.map(str::to_owned),
        reasons: Vec::new(),
        missing_profile_fields: Vec::new(),
    };
    if let Some(special) = dataset.special_use.iter().find(|special| {
        ascii == special.name
            || special.descendants
                && ascii
                    .strip_suffix(special.name)
                    .is_some_and(|prefix| prefix.ends_with('.'))
    }) {
        result.decision = Decision::No;
        result.reasons.push(reason(
            "special_use_name",
            &format!(
                "{} is designated for special use and public registration is unavailable",
                special.name
            ),
        ));
        return Ok(result);
    }
    if !resolution.root_known {
        result.reasons.push(reason(
            "unknown_root",
            "The root is absent from this dataset; its registration policy is unsupported",
        ));
        return Ok(result);
    }
    if resolution.applicant_labels == 0 {
        result.decision = Decision::No;
        result.reasons.push(reason(
            "missing_registration_label",
            "The candidate contains no applicant label under its registration namespace",
        ));
        return Ok(result);
    }
    let Some(policy) = resolution.policy else {
        let known_namespace = dataset.namespaces.iter().any(|policy| {
            result.namespace.as_deref().is_some_and(|namespace| {
                policy.selector == namespace
                    || policy.selector.strip_prefix("*.").is_some_and(|base| {
                        namespace.strip_suffix(base).is_some_and(|prefix| {
                            prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
                        })
                    })
            })
        });
        result.reasons.push(reason(
            if known_namespace { "unsupported_registration_form" } else { "unsupported_namespace" },
            if known_namespace {
                "This registration form is unsupported; additional labels cannot inherit a supported form"
            } else {
                "This namespace has no implemented registration policy"
            },
        ));
        return Ok(result);
    };
    let unicode = match name.unicode() {
        Ok(unicode) => unicode,
        Err(error) => {
            result.decision = Decision::No;
            result.reasons.push(reason(error.code(), error.message()));
            return Ok(result);
        }
    };
    let class = if resolution
        .applicant
        .split('.')
        .any(|label| label.starts_with("xn--"))
    {
        InputClass::Idn
    } else {
        InputClass::Ascii
    };
    let context = PredicateContext {
        ascii: resolution.applicant,
        unicode: &unicode,
        profile,
        label_sets: dataset.label_sets,
        idn_profiles: dataset.idn_profiles,
    };
    let mut failures = Vec::new();
    let mut unresolved = Vec::new();
    let mut missing = Vec::new();
    for requirement in policy.requirements {
        if !applies(requirement.input_class, class) {
            continue;
        }
        let outcome = context.evaluate(&requirement.predicate);
        match (requirement.effect, outcome.truth) {
            (RuleEffect::Require, Truth::False) | (RuleEffect::Deny, Truth::True) => {
                let mut message = explain(requirement.message, outcome);
                if let Some(component) = reserved_component(&requirement.predicate) {
                    if let Some(label) = resolution.applicant.split('.').nth(usize::from(component))
                    {
                        message = message.trim_end_matches(['.', ';', ' ']).to_owned();
                        message.push_str(&format!("; candidate label {label:?}"));
                    }
                }
                failures.push(reason(requirement.code, &message));
            }
            (_, Truth::Unknown) => {
                let fields = context.unresolved_fields(&requirement.predicate);
                let message = if fields.is_empty() {
                    format!(
                        "Cannot determine whether this condition holds: {}",
                        explain(requirement.message, outcome)
                    )
                } else {
                    format!(
                        "{}; missing declared profile fields: {}",
                        requirement.message.trim_end_matches(['.', ';', ' ']),
                        fields.join(", ")
                    )
                };
                unresolved.push(reason(requirement.code, &message));
                missing.extend(fields.into_iter().map(str::to_owned));
            }
            _ => (),
        }
    }
    let mut gap_reported = false;
    for gap in policy.gaps {
        if !applies(gap.input_class, class) {
            continue;
        }
        if let Some(predicate) = &gap.predicate {
            if context.evaluate(predicate).truth == Truth::False {
                continue;
            }
            missing.extend(
                context
                    .unresolved_fields(predicate)
                    .into_iter()
                    .map(str::to_owned),
            );
        }
        unresolved.push(reason(gap.code, gap.message));
        gap_reported = true;
    }
    if !failures.is_empty() {
        result.decision = Decision::No;
        result.reasons = failures;
        return Ok(result);
    }
    let support = match class {
        InputClass::Idn => policy.idn,
        InputClass::Ascii | InputClass::Any => policy.ascii,
    };
    if support != Support::Supported && !gap_reported {
        unresolved.push(reason(
            match (support, class) {
                (Support::Unsupported, InputClass::Idn) => "unsupported_idn_policy",
                (Support::Unsupported, _) => "unsupported_ascii_policy",
                _ => "partial_policy",
            },
            match (support, class) {
                (Support::Unsupported, InputClass::Idn) => {
                    "The registration policy for IDN applicant labels is unsupported"
                }
                (Support::Unsupported, _) => {
                    "The registration policy for ASCII applicant labels is unsupported"
                }
                _ => "Some applicable static registration requirements remain unimplemented",
            },
        ));
    }
    if unresolved.is_empty() {
        result.decision = Decision::Yes;
    } else {
        missing.sort();
        missing.dedup();
        result.reasons = unresolved;
        result.missing_profile_fields = missing;
    }
    Ok(result)
}

/// Find the applicant component whose exact-label membership participates in a reservation check.
fn reserved_component(predicate: &Predicate) -> Option<u8> {
    match predicate {
        Predicate::LabelInSet { component, .. } => Some(*component),
        Predicate::All(children) | Predicate::Any(children) => {
            children.iter().find_map(reserved_component)
        }
        Predicate::Not(child) => reserved_component(child),
        _ => None,
    }
}

/// Select conditions independently of the encoding of the namespace itself.
fn applies(scope: InputClass, class: InputClass) -> bool {
    scope == InputClass::Any || scope == class
}

/// Construct one owned reason at the interface boundary.
fn reason(code: &str, message: &str) -> Reason {
    Reason {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

/// Add meaningful check parameters without disclosing declared applicant values.
fn explain(message: &str, outcome: PredicateResult) -> String {
    let base = message.trim_end_matches(['.', ';', ' ']);
    match outcome.issue {
        Some(PredicateIssue::Length {
            actual,
            min,
            max,
            basis,
        }) => {
            let bounds = match (min, max) {
                (Some(min), Some(max)) => format!("required {min}–{max}"),
                (Some(min), None) => format!("minimum {min}"),
                (None, Some(max)) => format!("maximum {max}"),
                (None, None) => "unspecified bounds".to_owned(),
            };
            format!("{base}; observed length {actual}, {bounds} ({basis:?})")
        }
        Some(PredicateIssue::IdnCharacter(codepoint)) => {
            format!("{base}; U+{codepoint:04X} is outside the adopted character table")
        }
        Some(PredicateIssue::IdnContext {
            codepoint,
            position,
        }) => {
            format!("{base}; U+{codepoint:04X} violates a context condition at position {position}")
        }
        Some(PredicateIssue::IdnIncomplete(profile)) => {
            format!("{base}; IDN table {profile} does not contain a complete adopted repertoire")
        }
        Some(PredicateIssue::MissingTable(table)) => {
            format!("{base}; table {table} is unavailable")
        }
        Some(PredicateIssue::MissingComponent(component)) => {
            format!("{base}; applicant component {component} is unavailable")
        }
        _ => message.to_owned(),
    }
}

#[cfg(test)]
#[path = "evaluator_tests.rs"]
mod tests;
