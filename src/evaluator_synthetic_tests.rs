//! Independent synthetic name and optional-applicant outcomes.
#![allow(clippy::missing_docs_in_private_items)]

use super::*;
#[path = "evaluator_fixtures.rs"]
mod fixture;
use fixture::*;

#[test]
fn complete_name_policy_accepts_positive_and_rejects_independent_failures() {
    let evaluator = Evaluator::new(dataset(policies(vec![POLICY])));
    let valid = evaluator.assess("vanity.fixture", None);
    assert_eq!(
        (
            valid.name_validity,
            valid.summary,
            valid.policy_coverage,
            valid.eligibility
        ),
        (
            NameValidity::Valid,
            Summary::Yes,
            Coverage::Complete,
            Eligibility::NotRequired
        )
    );
    for candidate in [
        "blocked.fixture",
        "ab.fixture",
        "longer-than-twelve.fixture",
    ] {
        let invalid = evaluator.assess(candidate, None);
        assert_eq!(
            (invalid.name_validity, invalid.summary),
            (NameValidity::Invalid, Summary::No)
        );
    }
}

#[test]
fn applicant_alternatives_and_negative_profile_do_not_change_name_validity() {
    let evaluator = Evaluator::new(dataset(&[NamespacePolicy {
        rule_indices: &[0, 1, 2, 6],
        ..POLICY
    }]));
    let citizen = profile(r#"{"citizenships":["US"]}"#);
    let negative = profile(r#"{"citizenships":[],"resident":false}"#);
    let positive = evaluator.assess("vanity.fixture", Some(&citizen));
    assert_eq!(
        (
            positive.name_validity,
            positive.summary,
            positive.eligibility
        ),
        (
            NameValidity::Valid,
            Summary::Yes,
            Eligibility::DeclaredMatch
        )
    );
    assert!(!positive
        .rules
        .iter()
        .any(|rule| rule.rule_id == "external-proof-context"));
    let failure = evaluator.assess("vanity.fixture", Some(&negative));
    assert_eq!(
        (failure.name_validity, failure.summary, failure.eligibility),
        (NameValidity::Valid, Summary::No, Eligibility::DoesNotMatch)
    );
    let missing = evaluator.assess("vanity.fixture", None);
    assert_eq!(
        (missing.name_validity, missing.summary, missing.eligibility),
        (
            NameValidity::Valid,
            Summary::Restricted,
            Eligibility::NeedsProfile
        )
    );
}
