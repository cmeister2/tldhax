//! Independent logic, repertoire, scope and name-equivalence fixtures.

use super::*;
use crate::policy_types::{FactKind, FactSchema};

/// Canonical exact set compiled independently of evaluator expectations.
const SETS: &[LabelSet] = &[LabelSet {
    id: "reserved",
    labels: &["com", "xn--bcher-kva"],
    evidence_ids: &["synthetic-reservation"],
}];

/// Make an isolated predicate context using canonical components.
fn context<'a>(
    ascii: &'a str,
    unicode: &'a str,
    profile: Option<&'a RegistrantProfile>,
) -> PredicateContext<'a> {
    PredicateContext {
        ascii,
        unicode,
        profile,
        label_sets: SETS,
        idn_profiles: &[],
    }
}

/// Alternative facts preserve decisive truth, and a false conjunction stays false despite a missing fact.
#[test]
fn alternative_eligibility_preserves_decisive_true_and_false() {
    /// Citizenship and residence declarations used by the independent eligibility alternatives.
    const SCHEMA: &[FactSchema] = &[
        FactSchema {
            field: "citizenships",
            kind: FactKind::StringSet,
            allowed_values: &[],
        },
        FactSchema {
            field: "resident",
            kind: FactKind::Boolean,
            allowed_values: &[],
        },
    ];
    let citizen = RegistrantProfile::from_json(r#"{"citizenships":["US"]}"#, SCHEMA).unwrap();
    let positive = context("candidate", "candidate", Some(&citizen));
    /// Either US citizenship or declared residence independently satisfies eligibility.
    const ALTERNATIVES: &[Predicate] = &[
        Predicate::FieldIn {
            field: "citizenships",
            values: &[FactValue::String("US")],
        },
        Predicate::FieldEquals {
            field: "resident",
            value: FactValue::Boolean(true),
        },
    ];
    assert_eq!(
        positive.evaluate(&Predicate::Any(ALTERNATIVES)).truth,
        Truth::True
    );
    let negative =
        RegistrantProfile::from_json(r#"{"citizenships":[],"resident":false}"#, SCHEMA).unwrap();
    assert_eq!(
        context("candidate", "candidate", Some(&negative))
            .evaluate(&Predicate::Any(ALTERNATIVES))
            .truth,
        Truth::False
    );
    assert_eq!(
        context("candidate", "candidate", None)
            .evaluate(&Predicate::Any(ALTERNATIVES))
            .truth,
        Truth::Unknown
    );
    /// A known false condition paired with a profile condition whose fact may be absent.
    const FALSE_AND_MISSING: &[Predicate] = &[
        Predicate::Constant(false),
        Predicate::FieldEquals {
            field: "resident",
            value: FactValue::Boolean(true),
        },
    ];
    assert_eq!(
        context("candidate", "candidate", None)
            .evaluate(&Predicate::All(FALSE_AND_MISSING))
            .truth,
        Truth::False
    );
}

/// Canonical set, length, and character checks agree across Unicode, A-label, and decomposed inputs.
#[test]
fn canonical_name_policy_is_input_encoding_independent() {
    for input in [
        "BÜCHER.example",
        "xn--bcher-kva.example",
        "bu\u{0308}cher.example",
    ] {
        let name = CanonicalName::new(input).unwrap();
        let unicode = name.unicode().unwrap();
        let ascii = name.ascii().split('.').next().unwrap();
        let ctx = context(ascii, &unicode, None);
        assert_eq!(
            ctx.evaluate(&Predicate::LabelInSet {
                component: 0,
                set_id: "reserved"
            })
            .truth,
            Truth::True
        );
        assert_eq!(
            ctx.evaluate(&Predicate::LabelLength {
                component: 0,
                min: 6,
                max: 6,
                basis: LengthMeasure::Unicode
            })
            .truth,
            Truth::True
        );
        assert_eq!(
            ctx.evaluate(&Predicate::AsciiOnly { component: 0 }).truth,
            Truth::False
        );
    }
    let ctx = context("xn--fa-hia", "faß", None);
    assert_eq!(
        ctx.evaluate(&Predicate::LabelPattern {
            component: 0,
            pattern: PatternKind::Contains,
            value: "ß",
            basis: LengthMeasure::Unicode
        })
        .truth,
        Truth::True
    );
}

/// Missing applicant components produce unknown rather than reading a suffix or unrelated Unicode label.
#[test]
fn missing_component_never_reads_a_suffix_as_an_applicant_label() {
    let ctx = context("a", "a.example", None);
    assert_eq!(
        ctx.evaluate(&Predicate::AsciiOnly { component: 1 }).truth,
        Truth::Unknown
    );
    assert_eq!(
        ctx.evaluate(&Predicate::LabelPositions {
            component: 0,
            positions: &[2, 3],
            value: "--",
            basis: LengthMeasure::Unicode
        })
        .truth,
        Truth::False
    );
}

/// Minimum-only findings omit a maximum, and maximum-only checks do not impose a lower bound.
#[test]
fn one_sided_registry_bounds_do_not_invent_the_other_bound() {
    let ctx = context("a", "a", None);
    assert_eq!(
        ctx.evaluate(&Predicate::LabelMinimum {
            component: 0,
            min: 2,
            basis: LengthMeasure::Ascii
        }),
        PredicateResult::issue(
            Truth::False,
            PredicateIssue::Length {
                actual: 1,
                min: Some(2),
                max: None,
                basis: LengthMeasure::Ascii
            }
        )
    );
    assert_eq!(
        ctx.evaluate(&Predicate::LabelMaximum {
            component: 0,
            max: 2,
            basis: LengthMeasure::Ascii
        })
        .truth,
        Truth::True
    );
}

/// Declared rights compare canonical labels while absent claims remain unknown and unrelated claims fail.
#[test]
fn declared_rights_match_canonical_labels_without_approval_or_proof() {
    /// Arbitrary declared labels whose values are compared after name normalization.
    const SCHEMA: &[FactSchema] = &[FactSchema {
        field: "rights.labels",
        kind: FactKind::StringSet,
        allowed_values: &[],
    }];
    let profile =
        RegistrantProfile::from_json(r#"{"rights.labels":["BÜCHER","unrelated"]}"#, SCHEMA)
            .unwrap();
    let rule = Predicate::NameEqualsField {
        component: 0,
        field: "rights.labels",
    };
    assert_eq!(
        context("xn--bcher-kva", "bücher", Some(&profile))
            .evaluate(&rule)
            .truth,
        Truth::True
    );
    assert_eq!(
        context("other", "other", Some(&profile))
            .evaluate(&rule)
            .truth,
        Truth::False
    );
    assert_eq!(
        context("other", "other", None).evaluate(&rule).truth,
        Truth::Unknown
    );
}
