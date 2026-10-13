//! Registration forms, inactive successors and compatible override fixtures.

use super::{check_predicates, fixtures, predicates, resolve, schema, validate};
use schema::{Document, Effect, Family, Knowledge};

/// Validate synthetic authoring before resolving immutable namespace shapes.
fn run(mut document: Document) -> Result<Vec<resolve::ResolvedNamespace>, String> {
    let statuses = validate::document(&mut document, "2026-10-12", None)?;
    for assertion in &document.assertions {
        check_predicates::validate(assertion, &document)?;
    }
    resolve::resolve(&document, &statuses)
}

#[test]
/// Verify that forms require effective reviewed namespace evidence.
fn forms_require_effective_reviewed_namespace_evidence() {
    assert_eq!(run(fixtures::fixture()).unwrap()[0].forms.len(), 1);
    let mut missing = fixtures::fixture();
    missing.namespaces[0].form_assertion_ids.clear();
    assert!(run(missing).unwrap()[0].forms.is_empty());
    let mut inactive = fixtures::fixture();
    inactive.assertions[0].effective_from = Some("2027-02-09".into());
    assert!(run(inactive).unwrap()[0].forms.is_empty());
    let mut not_applicable = fixtures::fixture();
    not_applicable.assertions[0].knowledge = Knowledge::NotApplicable;
    assert!(run(not_applicable).unwrap()[0].forms.is_empty());
}

#[test]
/// Verify that inactive successor does not erase current complete policy.
fn inactive_successor_does_not_erase_current_complete_policy() {
    let mut document = fixtures::fixture();
    let mut successor = document.assertions[1].clone();
    successor.id = "fixture.future".into();
    successor.effective_from = Some("2027-02-09".into());
    document.namespaces[0].rules.push(successor.id.clone());
    document.assertions.push(successor);
    let resolved = run(document).unwrap();
    assert_eq!(resolved[0].rule_ids, vec!["fixture.length"]);
    assert_eq!(
        resolved[0]
            .coverage
            .iter()
            .find(|c| c.family == Family::Length)
            .unwrap()
            .ascii,
        Knowledge::Reviewed
    );
}

#[test]
/// Verify that shared policy requires namespace specific applicability.
fn shared_policy_requires_namespace_specific_applicability() {
    let mut document = fixtures::fixture();
    document.profiles.push(schema::Profile {
        id: "fixture.shared".into(),
        applicability: vec!["other".into()],
        applicability_assertions: vec!["fixture.form".into()],
        extends: vec![],
        rules: vec!["fixture.length".into()],
        coverage: vec![],
        context: vec![],
    });
    document.namespaces[0]
        .profiles
        .push("fixture.shared".into());
    assert!(run(document).unwrap_err().contains("applicability"));
}

#[test]
/// Verify that overrides cannot silently drop input classes forms or enforcement.
fn overrides_cannot_silently_drop_input_classes_forms_or_enforcement() {
    for mutation in 0..4 {
        let mut document = fixtures::fixture();
        document.namespaces[0]
            .forms
            .push(vec!["first".into(), "second".into()]);
        for assertion in &mut document.assertions {
            assertion.forms.push(2);
        }
        let mut replacement = document.assertions[1].clone();
        replacement.id = "fixture.replacement".into();
        replacement.predicate = Some(predicates::Predicate::LabelMaximum {
            component: 0,
            max: 60,
            basis: predicates::Basis::Ascii,
        });
        match mutation {
            1 => replacement.input_class = schema::Class::Ascii,
            2 => replacement.forms = vec![1],
            3 => replacement.effect = Effect::Context,
            _ => (),
        }
        document.namespaces[0].overrides.push(schema::Override {
            replaces: "fixture.length".into(),
            with: replacement.id.clone(),
            reason: "Synthetic explicitly supported replacement".into(),
            assertion_ids: vec!["fixture.form".into()],
        });
        document.assertions.push(replacement);
        let result = run(document);
        if mutation == 0 {
            assert_eq!(result.unwrap()[0].rule_ids, vec!["fixture.replacement"]);
        } else {
            assert!(result.is_err(), "mutation {mutation}");
        }
    }
}
