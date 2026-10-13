//! Bounded predicate and simultaneous-rule conflict validation.

use super::{check_predicates, conflicts, fixtures, predicates, schema};
use predicates::{Basis, FactKind, Predicate, Value};
use schema::{Effect, Family};

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
        string_format: None,
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

#[test]
fn formatted_country_literals_enforce_the_declared_code_shape() {
    for kind in [FactKind::String, FactKind::StringSet] {
        let mut document = fixtures::fixture();
        document.facts.push(predicates::Fact {
            field: "country".into(),
            kind,
            allowed_values: vec![],
            string_format: Some(predicates::FactStringFormat::UppercaseAlpha2),
        });
        for value in ["US", "GB", "us", "United States", "USA", "U1", "ＵＳ"] {
            let valid = matches!(value, "US" | "GB");
            for membership in [false, true] {
                let value = Value::String(value.into());
                let predicate = if membership {
                    Predicate::FieldIn {
                        field: "country".into(),
                        values: vec![value],
                    }
                } else {
                    Predicate::FieldEquals {
                        field: "country".into(),
                        value,
                    }
                };
                let rule =
                    fixtures::assertion("fixture.country", Family::Eligibility, Some(predicate));
                assert_eq!(check_predicates::validate(&rule, &document).is_ok(), valid);
            }
        }
    }
}

#[test]
fn country_format_is_string_only_and_validates_enumerations_and_emission() {
    for (kind, allowed, valid) in [
        (FactKind::String, "US", true),
        (FactKind::StringSet, "GB", true),
        (FactKind::String, "us", false),
        (FactKind::StringSet, "United States", false),
        (FactKind::Boolean, "", false),
    ] {
        let mut document = fixtures::fixture();
        document.facts.push(predicates::Fact {
            field: "country".into(),
            kind,
            allowed_values: if allowed.is_empty() {
                vec![]
            } else {
                vec![allowed.into()]
            },
            string_format: Some(predicates::FactStringFormat::UppercaseAlpha2),
        });
        let result = fixtures::run(document);
        assert_eq!(result.is_ok(), valid);
        if valid {
            assert!(result
                .unwrap()
                .rust
                .contains("string_format:Some(FactStringFormat::UppercaseAlpha2)"));
        }
    }
    let untagged: predicates::Fact =
        toml::from_str("field='description'\nkind='string'\nallowed_values=['United States']")
            .unwrap();
    assert_eq!(untagged.string_format, None);
    let mut document = fixtures::fixture();
    document.facts.push(untagged);
    let rule = fixtures::assertion(
        "fixture.description",
        Family::Eligibility,
        Some(Predicate::FieldEquals {
            field: "description".into(),
            value: Value::String("United States".into()),
        }),
    );
    assert!(check_predicates::validate(&rule, &document).is_ok());
    assert!(fixtures::run(document)
        .unwrap()
        .rust
        .contains("string_format:None"));
    let tagged: predicates::Fact =
        toml::from_str("field='country'\nkind='string'\nstring_format='uppercase_alpha2'").unwrap();
    assert_eq!(
        tagged.string_format,
        Some(predicates::FactStringFormat::UppercaseAlpha2)
    );
    assert!(toml::from_str::<predicates::Fact>(
        "field='country'\nkind='string'\nstring_format='lowercase_alpha2'"
    )
    .is_err());
}

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
