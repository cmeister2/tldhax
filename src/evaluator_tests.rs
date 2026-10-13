//! Synthetic semantic cases independent of real registry policy coverage.

use super::*;
use crate::inventory_types::SpecialUse;
use crate::policy_types::{
    FactKind, FactSchema, FactValue, LabelSet, LengthMeasure, NamespacePolicy, PolicyGap,
    Predicate, Requirement, SelectorKind,
};
use crate::resolver::{Resolver, Route, RouteKind};

/// Typed alternative eligibility declarations used by the synthetic requirements.
const FACTS: &[FactSchema] = &[
    FactSchema {
        field: "citizen",
        kind: FactKind::Boolean,
        allowed_values: &[],
        string_format: None,
    },
    FactSchema {
        field: "resident",
        kind: FactKind::Boolean,
        allowed_values: &[],
        string_format: None,
    },
];
/// Either independent applicant declaration satisfies the synthetic eligibility route.
const ELIGIBILITY: Predicate = Predicate::Any(&[
    Predicate::FieldEquals {
        field: "citizen",
        value: FactValue::Boolean(true),
    },
    Predicate::FieldEquals {
        field: "resident",
        value: FactValue::Boolean(true),
    },
]);
/// Minimum length, exact reservation and alternative applicant requirements.
const REQUIREMENTS: &[Requirement] = &[
    Requirement {
        code: "label_length",
        message: "The applicant label must contain 3–12 ASCII bytes",
        effect: RuleEffect::Require,
        input_class: InputClass::Any,
        predicate: Predicate::LabelLength {
            component: 0,
            min: 3,
            max: 12,
            basis: LengthMeasure::Ascii,
        },
    },
    Requirement {
        code: "reserved_label",
        message: "This label is reserved",
        effect: RuleEffect::Deny,
        input_class: InputClass::Any,
        predicate: Predicate::LabelInSet {
            component: 0,
            set_id: "reserved",
        },
    },
    Requirement {
        code: "eligible_applicant",
        message: "The applicant must declare citizenship or residence",
        effect: RuleEffect::Require,
        input_class: InputClass::Any,
        predicate: ELIGIBILITY,
    },
];
/// A single supported ASCII form whose IDN scope has no supported policy.
const POLICY: NamespacePolicy = NamespacePolicy {
    id: "fixture",
    selector: "test",
    kind: SelectorKind::Exact,
    form: &["label"],
    ascii: Support::Supported,
    idn: Support::Unsupported,
    requirements: REQUIREMENTS,
    gaps: &[],
};
/// Shared exact reservations.
const SETS: &[LabelSet] = &[LabelSet {
    id: "reserved",
    labels: &["blocked"],
}];
/// Non-public designated namespace, used to test exclusions before unknown-policy handling.
const SPECIAL: &[SpecialUse] = &[SpecialUse {
    name: "excluded.test",
    descendants: true,
}];
/// Synthetic discovery route which does not carry registration permission.
const ROUTES: &[Route] = &[Route {
    selector: "test",
    kind: RouteKind::Exact,
}];

/// Construct isolated semantic tables without real policy records or external sources.
fn dataset(policies: &'static [NamespacePolicy]) -> PolicyDataset {
    PolicyDataset {
        version: "fixture",
        resolver: Resolver::new(policies, &["test"], ROUTES),
        namespaces: policies,
        label_sets: SETS,
        idn_profiles: &[],
        facts: FACTS,
        special_use: SPECIAL,
    }
}

/// Parse only the synthetic typed applicant declaration schema.
fn profile(input: &str) -> RegistrantProfile {
    RegistrantProfile::from_json(input, FACTS).unwrap()
}

/// A successful eligibility alternative needs no declarations from an irrelevant branch.
#[test]
fn successful_alternative_has_no_missing_fields() {
    let result = assess(
        &dataset(&[POLICY]),
        "candidate.test",
        Some(&profile(r#"{"resident":true}"#)),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Yes);
    assert!(result.reasons.is_empty());
    assert!(result.missing_profile_fields.is_empty());
}

/// Missing declarations stay distinct from explicit negative declarations.
#[test]
fn omitted_and_false_declarations_produce_different_decisions() {
    let missing = assess(&dataset(&[POLICY]), "candidate.test", None).unwrap();
    assert_eq!(missing.decision, Decision::Unknown);
    assert_eq!(missing.missing_profile_fields, ["citizen", "resident"]);
    assert!(missing.reasons[0].message.contains("citizen"));
    let negative = assess(
        &dataset(&[POLICY]),
        "candidate.test",
        Some(&profile(r#"{"resident":false,"citizen":false}"#)),
    )
    .unwrap();
    assert_eq!(negative.decision, Decision::No);
    assert_eq!(negative.reasons[0].code, "eligible_applicant");
    assert!(negative.missing_profile_fields.is_empty());
    assert!(!negative.reasons[0].message.contains("false"));
}

/// An established failure decides no despite unrelated unsupported scope and missing facts.
#[test]
fn mandatory_failure_is_decisive_and_explains_actual_length() {
    /// Partial scope whose actual known length requirements remain enforceable.
    const PARTIAL: &[NamespacePolicy] = &[NamespacePolicy {
        ascii: Support::Partial,
        ..POLICY
    }];
    let result = assess(&dataset(PARTIAL), "ab.test", None).unwrap();
    assert_eq!(result.decision, Decision::No);
    assert_eq!(result.reasons.len(), 1);
    assert_eq!(result.reasons[0].code, "label_length");
    assert!(result.reasons[0].message.contains("observed length 2"));
    assert!(result.reasons[0].message.contains("required 3–12"));
    assert!(result.missing_profile_fields.is_empty());
}

/// Exact reservations explain the candidate label without exposing other declarations.
#[test]
fn reservation_failure_identifies_label() {
    let result = assess(&dataset(&[POLICY]), "blocked.test", None).unwrap();
    assert_eq!(result.decision, Decision::No);
    assert_eq!(result.reasons[0].code, "reserved_label");
    assert!(result.reasons[0].message.contains("blocked"));
}

/// Unsupported form or class cannot inherit permission from a supported ASCII form.
#[test]
fn supported_scope_does_not_leak_into_idn_or_extra_components() {
    let prepared = profile(r#"{"citizen":true}"#);
    for domain in ["é.test", "xn--9ca.test", "extra.candidate.test"] {
        let result = assess(&dataset(&[POLICY]), domain, Some(&prepared)).unwrap();
        assert_eq!(result.decision, Decision::Unknown, "{domain}");
        assert!(result.missing_profile_fields.is_empty());
    }
    let unicode = assess(&dataset(&[POLICY]), "é.test", Some(&prepared)).unwrap();
    let punycode = assess(&dataset(&[POLICY]), "xn--9ca.test", Some(&prepared)).unwrap();
    assert_eq!(unicode, punycode);
}

/// An explicit candidate limitation does not invalidate unaffected candidates in the same supported form.
#[test]
fn candidate_gap_is_scoped_and_explains_unknown_once() {
    /// One unresolved candidate length interval, independent of other forms.
    const GAPS: &[PolicyGap] = &[PolicyGap {
        code: "short_label_release",
        message: "Short labels require an unimplemented release condition",
        input_class: InputClass::Ascii,
        predicate: Some(Predicate::LabelMaximum {
            component: 0,
            max: 4,
            basis: LengthMeasure::Ascii,
        }),
    }];
    /// Supported form with a narrow genuine gap.
    const SCOPED: &[NamespacePolicy] = &[NamespacePolicy {
        gaps: GAPS,
        ..POLICY
    }];
    let prepared = profile(r#"{"citizen":true}"#);
    assert_eq!(
        assess(&dataset(SCOPED), "candidate.test", Some(&prepared))
            .unwrap()
            .decision,
        Decision::Yes
    );
    let affected = assess(&dataset(SCOPED), "abc.test", Some(&prepared)).unwrap();
    assert_eq!(affected.decision, Decision::Unknown);
    assert_eq!(affected.reasons.len(), 1);
    assert_eq!(affected.reasons[0].code, "short_label_release");
}

/// Canonical malformed names reject; implementation limits produce an input error instead.
#[test]
fn syntax_exclusions_unknown_roots_and_budgets_are_distinct() {
    for domain in [
        "_bad.test",
        "a..test",
        "excluded.test",
        "candidate.excluded.test",
        "test",
    ] {
        assert_eq!(
            assess(&dataset(&[POLICY]), domain, None).unwrap().decision,
            Decision::No,
            "{domain}"
        );
    }
    assert_eq!(
        assess(&dataset(&[POLICY]), "candidate.unlisted", None)
            .unwrap()
            .decision,
        Decision::Unknown
    );
    assert_eq!(
        assess(&dataset(&[POLICY]), &"x".repeat(4097), None),
        Err(InputError::InputLimit)
    );
}

/// Negating an unresolved condition still requires its missing fact; a decisive conjunction does not.
#[test]
fn negative_and_conjunctive_logic_preserves_unknown_and_decisive_false() {
    let context = PredicateContext {
        ascii: "candidate",
        unicode: "candidate",
        profile: None,
        label_sets: SETS,
        idn_profiles: &[],
    };
    /// Negation cannot invent a negative declaration from an omitted fact.
    const NEGATED: Predicate = Predicate::Not(&Predicate::FieldEquals {
        field: "resident",
        value: FactValue::Boolean(true),
    });
    assert_eq!(context.evaluate(&NEGATED).truth, Truth::Unknown);
    assert_eq!(context.unresolved_fields(&NEGATED), ["resident"]);
    /// A failing conjunct makes other missing declarations immaterial to that expression.
    const CONJUNCTION: Predicate = Predicate::All(&[NEGATED, Predicate::Constant(false)]);
    assert_eq!(context.evaluate(&CONJUNCTION).truth, Truth::False);
    assert!(context.unresolved_fields(&CONJUNCTION).is_empty());
}

/// Unsupported registry IDN conditions are ordinary applicable gaps, separate from character membership.
#[test]
fn unimplemented_idn_condition_uses_direct_gap_without_blocking_ascii() {
    /// Supported character table requirement, limited to IDN applicant components.
    const IDN_REQUIREMENTS: &[Requirement] = &[
        REQUIREMENTS[0],
        REQUIREMENTS[1],
        REQUIREMENTS[2],
        Requirement {
            code: "idn_repertoire",
            message: "The label must use the adopted character table",
            effect: RuleEffect::Require,
            input_class: InputClass::Idn,
            predicate: Predicate::Idn {
                component: 0,
                profile_id: "fixture",
            },
        },
    ];
    /// One genuinely unimplemented IDN allocation condition, expressed directly.
    const GAPS: &[PolicyGap] = &[PolicyGap {
        code: "idn_allocation",
        message: "An adopted IDN allocation condition is unimplemented",
        input_class: InputClass::Idn,
        predicate: None,
    }];
    /// Supported repertoire whose separate IDN allocation condition remains unresolved.
    const SCOPED: &[NamespacePolicy] = &[NamespacePolicy {
        idn: Support::Supported,
        requirements: IDN_REQUIREMENTS,
        gaps: GAPS,
        ..POLICY
    }];
    /// Adopted synthetic complete repertoire sufficient for the tested IDN candidate.
    const TABLES: &[crate::policy_types::IdnProfile] = &[crate::policy_types::IdnProfile {
        id: "fixture",
        repertoire_complete: true,
        ranges: &[
            crate::policy_types::CodepointRange {
                start: 0x61,
                end: 0x7a,
            },
            crate::policy_types::CodepointRange {
                start: 0xe9,
                end: 0xe9,
            },
        ],
        contexts: &[],
    }];
    let mut data = dataset(SCOPED);
    data.idn_profiles = TABLES;
    let prepared = profile(r#"{"citizen":true}"#);
    assert_eq!(
        assess(&data, "candidate.test", Some(&prepared))
            .unwrap()
            .decision,
        Decision::Yes
    );
    let idn = assess(&data, "é.test", Some(&prepared)).unwrap();
    assert_eq!(idn.decision, Decision::Unknown);
    assert_eq!(idn.reasons.len(), 1);
    assert_eq!(idn.reasons[0].code, "idn_allocation");
    let denied = assess(&data, "ø.test", Some(&prepared)).unwrap();
    assert_eq!(denied.decision, Decision::No);
    assert_eq!(denied.reasons[0].code, "idn_repertoire");
}
