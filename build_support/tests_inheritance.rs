//! Explicit applicability, shared-policy inheritance and completeness fixtures.

use super::{fixtures, inheritance, predicates, schema, validate};
use schema::{Class, Family, Knowledge, Profile};
use std::collections::{BTreeMap, BTreeSet};

/// Verify that family completeness requires whole family scoped attestation.
#[test]
fn family_completeness_requires_whole_family_scoped_attestation() {
    let mut document = fixtures::fixture();
    let statuses = validate::document(&mut document, "2026-10-12", None).unwrap();
    let assertions = document
        .assertions
        .iter()
        .map(|a| (a.id.as_str(), a))
        .collect();
    let namespace = &document.namespaces[0];
    let mut state = namespace.coverage[0].clone();
    assert!(inheritance::coverage(&mut state, namespace, &assertions, &statuses).is_ok());
    assert_eq!(state.ascii, Knowledge::Reviewed);
    state.assertion_ids = vec!["fixture.length".into()];
    assert!(
        inheritance::coverage(&mut state, namespace, &assertions, &statuses)
            .unwrap_err()
            .contains("completeness")
    );
    let mut wrong_family = namespace.coverage[0].clone();
    wrong_family.family = Family::Reserved;
    assert!(inheritance::coverage(&mut wrong_family, namespace, &assertions, &statuses).is_err());
}

/// Verify that expired completeness becomes unknown without erasing supported rules.
#[test]
fn expired_completeness_becomes_unknown_without_erasing_supported_rules() {
    let mut document = fixtures::fixture();
    document.assertions[2].reviewed_on = "2026-01-01".into();
    document.assertions[2].review_due = "2026-10-11".into();
    let statuses = validate::document(&mut document, "2026-10-12", None).unwrap();
    let assertions = document
        .assertions
        .iter()
        .map(|a| (a.id.as_str(), a))
        .collect();
    let namespace = &document.namespaces[0];
    let mut state = namespace.coverage[0].clone();
    inheritance::coverage(&mut state, namespace, &assertions, &statuses).unwrap();
    assert_eq!(state.ascii, Knowledge::Unknown);
    assert_eq!(state.gap.as_deref(), Some("IDN policy not reviewed"));
    assert!(statuses["fixture.length"].active);
    assert!(!statuses["fixture.length.complete"].active);
}

/// Verify that inherited profiles are deduplicated and cycles rejected.
#[test]
fn inherited_profiles_are_deduplicated_and_cycles_rejected() {
    let base = Profile {
        id: "fixture.base".into(),
        applicability: vec!["fixture".into()],
        applicability_assertions: vec!["fixture.form".into()],
        extends: vec![],
        rules: vec!["fixture.length".into()],
        coverage: vec![],
        context: vec![],
    };
    let mut child = base.clone();
    child.id = "fixture.child".into();
    child.extends = vec![base.id.clone(), base.id.clone()];
    let profiles = BTreeMap::from([(base.id.as_str(), &base), (child.id.as_str(), &child)]);
    let mut output = Vec::new();
    inheritance::expand(
        "fixture.child",
        &profiles,
        &mut BTreeSet::new(),
        &mut output,
    )
    .unwrap();
    assert_eq!(
        output.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
        vec!["fixture.base", "fixture.child"]
    );
    child.extends = vec![child.id.clone()];
    let profiles = BTreeMap::from([(child.id.as_str(), &child)]);
    assert!(inheritance::expand(
        "fixture.child",
        &profiles,
        &mut BTreeSet::new(),
        &mut Vec::new()
    )
    .unwrap_err()
    .contains("cycle"));
}

/// Verify that scope and one sided conflicts are precise.
#[test]
fn scope_and_one_sided_conflicts_are_precise() {
    let mut rule = fixtures::assertion(
        "fixture.min",
        Family::Length,
        Some(predicates::Predicate::LabelMinimum {
            component: 0,
            min: 10,
            basis: predicates::Basis::Ascii,
        }),
    );
    assert!(inheritance::scoped(&rule, "fixture", &[1], Class::Ascii));
    assert!(!inheritance::scoped(&rule, "other", &[1], Class::Ascii));
    assert!(!inheritance::scoped(&rule, "fixture", &[2], Class::Ascii));
    let maximum = fixtures::assertion(
        "fixture.max",
        Family::Length,
        Some(predicates::Predicate::LabelMaximum {
            component: 0,
            max: 9,
            basis: predicates::Basis::Ascii,
        }),
    );
    assert!(inheritance::conflict(&rule, &maximum));
    rule.input_class = Class::Idn;
    let mut ascii_maximum = maximum;
    ascii_maximum.input_class = Class::Ascii;
    assert!(!inheritance::conflict(&rule, &ascii_maximum));
}
