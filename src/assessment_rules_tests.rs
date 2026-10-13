//! Necessary-rule semantics with independently declared synthetic permissions.

use super::*;
use crate::policy_types::*;
use crate::predicate_eval::Truth;
use crate::profile::RegistrantProfile;

/// Build a reservation that denies the reserved label unless the profile authorizes it.
fn conditional() -> CompiledRule {
    CompiledRule {
        id: "conditional-nic",
        family: RuleFamily::Reserved,
        effect: RuleEffect::Deny,
        input_class: InputClass::Any,
        forms: &[1],
        evidence_ids: &["fixture.assertion"],
        scope: "fixture",
        code: "conditional-reservation",
        predicate: Predicate::All(&[
            Predicate::LabelInSet {
                component: 0,
                set_id: "reserved",
            },
            Predicate::Not(&Predicate::NameEqualsField {
                component: 0,
                field: "authorized",
            }),
        ]),
    }
}

/// Apply one fixture rule to `nic.fixture` with explicit profile and input-class scope.
fn evaluate(
    rule: CompiledRule,
    profile: Option<&RegistrantProfile>,
    class: InputClass,
) -> CompactAssessment<'static> {
    let mut dataset = super::tests::dataset();
    dataset.rules = Box::leak(Box::new([rule]));
    dataset.label_sets = &[LabelSet {
        id: "reserved",
        labels: &["nic"],
        evidence_ids: &["fixture.assertion"],
    }];
    let policy = NamespacePolicy {
        selector: "fixture",
        kind: SelectorKind::Exact,
        forms: &[],
        coverage: &[],
        rule_indices: &[0],
        evidence_ids: &[],
        context: &[],
    };
    let mut result = empty(&dataset);
    result.policy_coverage = Coverage::Complete;
    let mut state = aggregate::State::default();
    rules::evaluate(
        &dataset,
        &policy,
        "nic",
        1,
        "nic.fixture",
        profile,
        class,
        &mut result,
        &mut state,
    );
    aggregate::finish(state, &mut result);
    result
}

/// A denied authorization rejects this applicant while leaving universal name validity unknown.
#[test]
fn conditional_failure_never_becomes_a_universal_name_prohibition() {
    let schemas = &[FactSchema {
        field: "authorized",
        kind: FactKind::StringSet,
        allowed_values: &[],
        string_format: None,
    }];
    let permitted = RegistrantProfile::from_json(r#"{"authorized":["nic"]}"#, schemas).unwrap();
    let denied = RegistrantProfile::from_json(r#"{"authorized":[]}"#, schemas).unwrap();
    for (profile, name, summary, eligibility) in [
        (
            Some(&permitted),
            NameValidity::Valid,
            Summary::Yes,
            Eligibility::DeclaredMatch,
        ),
        (
            Some(&denied),
            NameValidity::Unknown,
            Summary::No,
            Eligibility::DoesNotMatch,
        ),
        (
            None,
            NameValidity::Unknown,
            Summary::Unknown,
            Eligibility::NeedsProfile,
        ),
    ] {
        let result = evaluate(conditional(), profile, InputClass::Ascii);
        assert_eq!(
            (result.name_validity, result.summary, result.eligibility),
            (name, summary, eligibility)
        );
        assert!(result.rules[0].profile_dependent);
        assert_eq!(result.rules[0].scope, "fixture");
    }
}

/// Rules for another form, another encoding, or contextual guidance leave no executable trace.
#[test]
fn explicit_form_and_input_class_scopes_exclude_unrelated_rules() {
    let form = CompiledRule {
        forms: &[2],
        ..conditional()
    };
    assert!(evaluate(form, None, InputClass::Ascii).rules.is_empty());
    let class = CompiledRule {
        input_class: InputClass::Idn,
        ..conditional()
    };
    assert!(evaluate(class, None, InputClass::Ascii).rules.is_empty());
    let context = CompiledRule {
        effect: RuleEffect::Context,
        ..conditional()
    };
    assert!(evaluate(context, None, InputClass::Idn).rules.is_empty());
}

/// An ASCII-only restriction applies to ASCII applicants, while IDN repertoire checks do not.
#[test]
fn any_class_ascii_constraint_executes_without_applying_an_idn_table() {
    let ascii = CompiledRule {
        family: RuleFamily::Idn,
        effect: RuleEffect::Require,
        predicate: Predicate::AsciiOnly { component: 0 },
        ..conditional()
    };
    assert_eq!(
        evaluate(ascii, None, InputClass::Ascii).rules[0].truth,
        Truth::True
    );
    let table = CompiledRule {
        predicate: Predicate::Idn {
            component: 0,
            profile_id: "idn-only",
        },
        ..ascii
    };
    assert!(evaluate(table, None, InputClass::Ascii).rules.is_empty());
}
