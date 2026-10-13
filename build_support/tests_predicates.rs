//! Bounded predicate and simultaneous-rule conflict validation.

use super::{check_predicates, conflicts, fixtures, predicates, schema};
use predicates::{Basis, FactKind, Predicate, Value};
use schema::{Effect, Family};

/// Verify that profile predicates require declared matching types and values.
#[test]
fn profile_predicates_require_declared_matching_types_and_values() {
    let mut document = fixtures::fixture();
    let mut rule = fixtures::assertion("fixture.applicant", Family::Eligibility, None);
    rule.predicate = Some(Predicate::FieldIn {
        field: "citizenships".into(),
        values: vec![Value::String("US".into())],
    });
    assert!(check_predicates::validate(&rule, &document).is_err());
    document.facts.push(predicates::Fact {
        field: "citizenships".into(),
        kind: FactKind::StringSet,
        allowed_values: vec!["US".into(), "GB".into()],
    });
    assert!(check_predicates::validate(&rule, &document).is_ok());
    rule.predicate = Some(Predicate::FieldEquals {
        field: "citizenships".into(),
        value: Value::Boolean(true),
    });
    assert!(check_predicates::validate(&rule, &document).is_err());
    rule.predicate = Some(Predicate::FieldEquals {
        field: "citizenships".into(),
        value: Value::String("unknown-jurisdiction".into()),
    });
    assert!(check_predicates::validate(&rule, &document).is_err());
}

/// Verify that finite components patterns and boolean work have explicit budgets.
#[test]
fn finite_components_patterns_and_boolean_work_have_explicit_budgets() {
    let document = fixtures::fixture();
    let mut rule = fixtures::assertion("fixture.rule", Family::Characters, None);
    let cases = [
        Predicate::AsciiOnly { component: 1 },
        Predicate::LabelPattern {
            component: 0,
            pattern: predicates::Pattern::Contains,
            value: String::new(),
            basis: Basis::Unicode,
        },
        Predicate::LabelPattern {
            component: 0,
            pattern: predicates::Pattern::Contains,
            value: "ß".into(),
            basis: Basis::Ascii,
        },
        Predicate::LabelPositions {
            component: 0,
            positions: vec![3, 2],
            value: "--".into(),
            basis: Basis::Unicode,
        },
        Predicate::All { predicates: vec![] },
        Predicate::Any {
            predicates: vec![Predicate::Constant { value: true }; 129],
        },
    ];
    for predicate in cases {
        rule.predicate = Some(predicate);
        assert!(check_predicates::validate(&rule, &document).is_err());
    }
    let mut nested = Predicate::Constant { value: true };
    for _ in 0..17 {
        nested = Predicate::Not {
            predicate: Box::new(nested),
        };
    }
    rule.predicate = Some(nested);
    assert!(check_predicates::validate(&rule, &document)
        .unwrap_err()
        .contains("budget"));
}

/// Verify that canonical unicode literals and one sided lengths are supported.
#[test]
fn canonical_unicode_literals_and_one_sided_lengths_are_supported() {
    let document = fixtures::fixture();
    for predicate in [
        Predicate::LabelPattern {
            component: 0,
            pattern: predicates::Pattern::Contains,
            value: "ß".into(),
            basis: Basis::Unicode,
        },
        Predicate::LabelPositions {
            component: 0,
            positions: vec![2, 3],
            value: "--".into(),
            basis: Basis::Unicode,
        },
        Predicate::LabelMinimum {
            component: 0,
            min: 3,
            basis: Basis::Ascii,
        },
        Predicate::LabelMaximum {
            component: 0,
            max: 63,
            basis: Basis::Ascii,
        },
    ] {
        let rule = fixtures::assertion("fixture.rule", Family::Characters, Some(predicate));
        assert!(check_predicates::validate(&rule, &document).is_ok());
    }
}

/// Verify that nested contradictions reject but consistent alternatives compile.
#[test]
fn nested_contradictions_reject_but_consistent_alternatives_compile() {
    let atom = Predicate::AsciiOnly { component: 0 };
    let require = fixtures::assertion("fixture.require", Family::Characters, Some(atom.clone()));
    let mut deny = fixtures::assertion(
        "fixture.deny",
        Family::Characters,
        Some(Predicate::All {
            predicates: vec![atom.clone(), Predicate::Constant { value: true }],
        }),
    );
    deny.effect = Effect::Deny;
    assert!(conflicts::check(&[&require, &deny])
        .unwrap_err()
        .contains("conflict"));
    deny.predicate = Some(Predicate::Not {
        predicate: Box::new(atom),
    });
    assert!(conflicts::check(&[&require, &deny]).is_ok());
    let closure = fixtures::assertion(
        "fixture.closed",
        Family::Access,
        Some(Predicate::Constant { value: false }),
    );
    assert!(conflicts::check(&[&closure, &require]).is_ok());
}
