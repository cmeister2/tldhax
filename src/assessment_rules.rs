//! Applicable rule evaluation separating universal names from declared permissions.

use super::aggregate::State;
use super::policy::has_profile;
use super::{record, PolicyDataset, MAX_RULE_TRACES};
use crate::assessment_types::*;
use crate::policy_types::{
    CompiledRule, InputClass, NamespacePolicy, Predicate, RuleEffect, RuleFamily,
};
use crate::predicate_eval::{PredicateContext, PredicateIssue, PredicateResult, Truth};
use crate::profile::RegistrantProfile;

/// Interpret a compiled rule without discarding unknown truth.
fn failed(rule: &CompiledRule, truth: Truth) -> bool {
    matches!(
        (rule.effect, truth),
        (RuleEffect::Require, Truth::False) | (RuleEffect::Deny, Truth::True)
    )
}

/// Repertoire tables govern internationalised applicant labels, never ASCII ones.
fn has_idn_table(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::Idn { .. } => true,
        Predicate::All(values) | Predicate::Any(values) => values.iter().any(has_idn_table),
        Predicate::Not(value) => has_idn_table(value),
        _ => false,
    }
}

/// Record missing declared information independently of unknown research.
fn missing(state: &mut State, issue: Option<PredicateIssue>, access: bool) {
    if matches!(issue, Some(PredicateIssue::MissingField(_))) {
        state.applicant_missing = true;
    } else if access {
        state.access_policy_unknown = true;
    } else {
        state.applicant_policy_unknown = true;
    }
}

/// Evaluate every applicable rule; retained traces are bounded independently.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate(
    dataset: &PolicyDataset,
    policy: &NamespacePolicy,
    ascii: &str,
    count: usize,
    unicode: &str,
    profile: Option<&RegistrantProfile>,
    class: InputClass,
    result: &mut CompactAssessment<'_>,
    state: &mut State,
) {
    let context = PredicateContext {
        ascii,
        unicode,
        profile,
        label_sets: dataset.label_sets,
        idn_profiles: dataset.idn_profiles,
    };
    let absent = PredicateContext {
        profile: None,
        ..context
    };
    for index in policy.rule_indices {
        let Some(rule) = dataset.rules.get(*index as usize) else {
            state.name_unresolved = true;
            continue;
        };
        if rule.effect == RuleEffect::Context
            || !rule.forms.iter().any(|form| usize::from(*form) == count)
            || rule.input_class != InputClass::Any && rule.input_class != class
            || class == InputClass::Ascii && has_idn_table(&rule.predicate)
        {
            continue;
        }
        let actual = context.evaluate(&rule.predicate);
        let base = if has_profile(&rule.predicate) {
            absent.evaluate(&rule.predicate)
        } else {
            actual
        };
        let conditional = base.truth == Truth::Unknown && has_profile(&rule.predicate);
        let applicant = matches!(rule.family, RuleFamily::Eligibility | RuleFamily::Access);
        if applicant {
            let access = rule.family == RuleFamily::Access;
            state.applicant_conditions |= !access;
            if !matches!(
                super::aggregate::knowledge(Some(policy), rule.family, class),
                crate::policy_types::Knowledge::Reviewed
                    | crate::policy_types::Knowledge::NotApplicable
            ) {
                if access {
                    state.access_policy_unknown = true;
                } else {
                    state.applicant_policy_unknown = true;
                }
            }
            state.applicant_failed |= failed(rule, actual.truth);
            if actual.truth == Truth::Unknown {
                missing(state, actual.issue, access);
            }
        } else if failed(rule, base.truth) {
            state.name_failed = true;
        } else if failed(rule, actual.truth) && conditional {
            // A different qualifying applicant could still use this same name.
            state.applicant_failed = true;
            state.applicant_conditions = true;
            state.name_unresolved = true;
        } else if actual.truth == Truth::Unknown {
            state.name_unresolved = true;
            if conditional {
                state.applicant_conditions = true;
                missing(state, actual.issue, false);
            }
        } else if conditional {
            state.applicant_conditions = true;
        }
        if result.rules.len() < MAX_RULE_TRACES {
            result.rules.push(RuleEvaluation {
                rule_id: rule.id,
                family: rule.family,
                effect: rule.effect,
                truth: actual.truth,
                evidence_ids: rule.evidence_ids,
                scope: policy.selector,
                issue: actual.issue,
                profile_dependent: conditional,
            });
        } else {
            result.diagnostics_truncated = true;
        }
        finding(rule, actual, policy.selector, result);
    }
}

/// Explain failed and unknown predicates without exposing supplied values.
fn finding(
    rule: &CompiledRule,
    actual: PredicateResult,
    scope: &'static str,
    result: &mut CompactAssessment<'_>,
) {
    if !failed(rule, actual.truth) && actual.truth != Truth::Unknown {
        return;
    }
    record(
        result,
        Finding {
            code: if actual.truth == Truth::Unknown {
                if matches!(actual.issue, Some(PredicateIssue::MissingField(_))) {
                    "profile_field_required"
                } else {
                    "policy_predicate_unknown"
                }
            } else {
                rule.code
            },
            rule_id: Some(rule.id),
            evidence_ids: rule.evidence_ids,
            source_ids: &[],
            references: &[],
            scope,
            severity: if actual.truth == Truth::Unknown {
                Severity::Warning
            } else {
                Severity::Error
            },
            params: actual
                .issue
                .map_or(FindingParams::None, FindingParams::Predicate),
        },
    );
}
