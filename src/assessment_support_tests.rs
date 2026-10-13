//! Independent aggregation and applicability assertions before API activation.
#![allow(clippy::missing_docs_in_private_items)]

use super::*;
use crate::compiled;
use crate::normalization::{NormalizationError, NORMALIZATION_PROFILE};
use crate::policy_types::{
    FamilyCoverage, InputClass, Knowledge, NamespacePolicy, Predicate, RuleFamily, SelectorKind,
};
use crate::registration_context::ContextOError;

pub(super) fn dataset() -> PolicyDataset {
    PolicyDataset {
        version: "fixture-v1",
        evaluation_date: "2026-10-12",
        inventory_date: "2026-10-11",
        normalization_profile: NORMALIZATION_PROFILE,
        resolver: &compiled::REGISTRATION_RESOLVER,
        namespaces: &[],
        rules: &[],
        label_sets: &[],
        idn_profiles: &[],
        facts: &[],
        assertions: &[],
        sources: &[],
        roots: &[],
        special_use: &[],
    }
}

#[test]
fn complete_ascii_name_does_not_require_an_idn_attestation() {
    let coverage = [
        RuleFamily::Namespace,
        RuleFamily::Length,
        RuleFamily::Characters,
        RuleFamily::Reserved,
        RuleFamily::Allocation,
        RuleFamily::Eligibility,
        RuleFamily::Access,
    ]
    .map(|family| FamilyCoverage {
        family,
        ascii: Knowledge::Reviewed,
        idn: Knowledge::Unknown,
        evidence_ids: &[],
        gap: None,
    });
    let namespace = Box::leak(Box::new(NamespacePolicy {
        selector: "fixture",
        kind: SelectorKind::Exact,
        forms: &[],
        coverage: Box::leak(Box::new(coverage)),
        rule_indices: &[],
        evidence_ids: &[],
        context: &[],
    }));
    let mut result = empty(&dataset());
    let mut state = aggregate::State::default();
    aggregate::coverage(
        Some(namespace),
        InputClass::Ascii,
        false,
        &mut result,
        &mut state,
    );
    aggregate::finish(state, &mut result);
    assert_eq!(
        (result.name_validity, result.summary),
        (NameValidity::Valid, Summary::Yes)
    );
    assert!(result.gaps.is_empty());
}

#[test]
fn applicant_failure_wins_despite_name_gaps_without_invalidating_the_name() {
    let mut result = empty(&dataset());
    result.policy_coverage = Coverage::Partial;
    aggregate::finish(
        aggregate::State {
            applicant_failed: true,
            ..Default::default()
        },
        &mut result,
    );
    assert_eq!(
        (result.name_validity, result.summary, result.eligibility),
        (
            NameValidity::Unknown,
            Summary::No,
            Eligibility::DoesNotMatch
        )
    );
    assert_eq!(result.inventory_date, "2026-10-11");
}

#[test]
fn suffix_encoding_and_three_valued_conditions_keep_their_own_scope() {
    assert_eq!(policy::input_class("vanity"), InputClass::Ascii);
    assert_eq!(policy::input_class("xn--bcher-kva"), InputClass::Idn);
    assert!(policy::has_profile(&Predicate::Not(
        &Predicate::FieldEquals {
            field: "declared",
            value: crate::policy_types::FactValue::Boolean(false),
        }
    )));
    assert!(!policy::has_profile(&Predicate::AsciiOnly { component: 0 }));
}

#[test]
fn api_budget_is_distinct_from_immutable_contextual_protocol_evidence() {
    assert!(protocol::sources(NormalizationError::InputLimit).is_empty());
    assert!(protocol::references(NormalizationError::InputLimit).is_empty());
    assert_eq!(
        protocol::sources(NormalizationError::ContextO(ContextOError::MiddleDot)),
        &["rfc-5892"]
    );
    assert_eq!(
        protocol::references(NormalizationError::ContextO(ContextOError::MiddleDot)),
        &["https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A.3"]
    );
}
