//! Scope and interpretation tests for named sets, tables and overrides.

use super::fixtures::{assertion, fixture, run};
use super::*;
use predicates::{FactKind, Predicate, Value};
use schema::{Class, Family, Knowledge};

/// Verify that unicode literals and fixed positions survive emission without dns sanitisation.
#[test]
fn unicode_literals_and_fixed_positions_survive_emission_without_dns_sanitisation() {
    let mut document = fixture();
    document.assertions[1].predicate = Some(Predicate::LabelPattern {
        component: 0,
        pattern: predicates::Pattern::Contains,
        value: "ß".into(),
        basis: predicates::Basis::Unicode,
    });
    assert!(run(document)
        .unwrap()
        .rust
        .contains("value:\"ß\",basis:LengthMeasure::Unicode"));
    let mut document = fixture();
    document.assertions[1].predicate = Some(Predicate::LabelPositions {
        component: 0,
        positions: vec![2, 3],
        value: "--".into(),
        basis: predicates::Basis::Unicode,
    });
    assert!(run(document).unwrap().rust.contains("positions:&[2, 3]"));
}

/// Verify that string set membership and name relationships are typed.
#[test]
fn string_set_membership_and_name_relationships_are_typed() {
    let mut document = fixture();
    document.facts.push(predicates::Fact {
        field: "citizenships".into(),
        kind: FactKind::StringSet,
        allowed_values: vec!["US".into(), "GB".into()],
    });
    document.assertions[1].predicate = Some(Predicate::FieldIn {
        field: "citizenships".into(),
        values: vec![Value::String("US".into())],
    });
    assert!(run(document)
        .unwrap()
        .rust
        .contains("FactValue::String(\"US\")"));
    let mut document = fixture();
    document.facts.push(predicates::Fact {
        field: "rights".into(),
        kind: FactKind::Boolean,
        allowed_values: vec![],
    });
    document.assertions[1].predicate = Some(Predicate::NameEqualsField {
        component: 0,
        field: "rights".into(),
    });
    assert!(run(document).unwrap_err().contains("String or StringSet"));
}

/// Verify that scoped reserved sets cannot spill to other namespaces.
#[test]
fn scoped_reserved_sets_cannot_spill_to_other_namespaces() {
    let mut document = fixture();
    let mut list = assertion("fixture.list", Family::Reserved, None);
    list.namespaces = vec!["other".into()];
    document.assertions.push(list);
    document.label_sets.push(schema::LabelSet {
        id: "fixture.list".into(),
        labels: vec!["forbidden".into()],
        assertion_ids: vec!["fixture.list".into()],
    });
    document.assertions[1].predicate = Some(Predicate::LabelInSet {
        component: 0,
        set_id: "fixture.list".into(),
    });
    assert!(run(document)
        .unwrap_err()
        .contains("outside assertion scope"));
}

/// Verify that empty sets do not come from absence of a published list.
#[test]
fn empty_sets_do_not_come_from_absence_of_a_published_list() {
    let mut document = fixture();
    document
        .assertions
        .push(assertion("fixture.list", Family::Reserved, None));
    document.label_sets.push(schema::LabelSet {
        id: "fixture.list".into(),
        labels: vec![],
        assertion_ids: vec!["fixture.list".into()],
    });
    assert!(run(document).unwrap_err().contains("completeness"));
}

/// Extend the synthetic policy with a finite adopted Latin IDN repertoire.
fn idn_fixture() -> schema::Document {
    let mut document = fixture();
    let mut adopted = assertion("fixture.idn.adopted", Family::Idn, None);
    adopted.input_class = Class::Idn;
    adopted.attests_completeness = true;
    document.assertions.push(adopted);
    document.idn_profiles.push(idn::IdnProfile {
        id: "fixture.idn".into(),
        version: "synthetic-1".into(),
        knowledge: Knowledge::Reviewed,
        repertoire_complete: true,
        namespaces: vec!["fixture".into()],
        assertion_ids: vec!["fixture.idn.adopted".into()],
        adoption_assertion_ids: vec!["fixture.idn.adopted".into()],
        effective_from: Some("2020-01-01".into()),
        applicable_on: None,
        effective_until: None,
        ranges: vec![[97, 122], [223, 223]],
        contexts: vec![],
        variants: vec![],
        unsupported_features: vec![],
    });
    document.assertions[1].family = Family::Idn;
    document.assertions[1].input_class = Class::Idn;
    document.assertions[1].predicate = Some(Predicate::Idn {
        component: 0,
        profile_id: "fixture.idn".into(),
    });
    document.namespaces[0].coverage.clear();
    document
}

/// Verify that unsupported idn features and variants are gaps not implicit denials.
#[test]
fn unsupported_idn_features_and_variants_are_gaps_not_implicit_denials() {
    let mut document = idn_fixture();
    document.idn_profiles[0].unsupported_features = vec!["ordering_rule".into()];
    let output = run(document).unwrap();
    assert!(output.rust.contains("knowledge:Knowledge::Partial"));
    assert!(output
        .rust
        .contains("idn_table_features_or_adoption_unresolved"));
    let mut document = idn_fixture();
    document.idn_profiles[0].variants.push(idn::Variant {
        sequence: "ß".into(),
        replacement: "ss".into(),
        disposition: idn::Disposition::Blocked,
    });
    assert!(run(document)
        .unwrap()
        .rust
        .contains("variant_allocation_relationship"));
}

/// Verify that complete repertoire requires reviewed active adopted table evidence.
#[test]
fn complete_repertoire_requires_reviewed_active_adopted_table_evidence() {
    let mut document = idn_fixture();
    document.idn_profiles[0].repertoire_complete = false;
    assert!(run(document)
        .unwrap_err()
        .contains("explicit complete repertoire"));
    let mut document = idn_fixture();
    document.assertions.last_mut().unwrap().attests_completeness = false;
    assert!(run(document)
        .unwrap_err()
        .contains("reviewed table attestation"));
    let mut document = idn_fixture();
    document.assertions.last_mut().unwrap().reviewed_on = "2024-01-01".into();
    document.assertions.last_mut().unwrap().review_due = "2025-01-01".into();
    let output = run(document).unwrap();
    assert!(output.rust.contains("repertoire_complete:false"));
    assert!(output.rust.contains("knowledge:Knowledge::Unknown"));
}

/// Verify that incomplete repertoire syntax cannot claim independently complete ranges.
#[test]
fn incomplete_repertoire_syntax_cannot_claim_independently_complete_ranges() {
    for feature in [
        "repertoire_element:property",
        "repertoire_sequence",
        "repertoire:property",
        "uninterpreted_text_columns:2",
        "new_unknown_feature",
    ] {
        let mut document = idn_fixture();
        document.idn_profiles[0].unsupported_features = vec![feature.into()];
        assert!(run(document)
            .unwrap_err()
            .contains("unsupported definitions"));
    }
    let mut document = idn_fixture();
    document.idn_profiles[0].unsupported_features = vec!["context:script_order".into()];
    let output = run(document).unwrap();
    assert!(output.rust.contains("repertoire_complete:true"));
    assert!(output.rust.contains("knowledge:Knowledge::Partial"));
}

/// Verify that invalid idn ranges and unadopted scope cannot compile.
#[test]
fn invalid_idn_ranges_and_unadopted_scope_cannot_compile() {
    let mut document = idn_fixture();
    document.idn_profiles[0].ranges = vec![[0xd700, 0xe000]];
    assert!(run(document).unwrap_err().contains("code point"));
    let mut document = idn_fixture();
    document.idn_profiles[0].namespaces = vec!["other".into()];
    assert!(run(document).unwrap_err().contains("scope"));
}

/// Verify that overriding requires explicit rationale and compatible evidence.
#[test]
fn overriding_requires_explicit_rationale_and_compatible_evidence() {
    let mut document = fixture();
    let mut replacement = document.assertions[1].clone();
    replacement.id = "fixture.replacement".into();
    replacement.predicate = Some(Predicate::Constant { value: true });
    document.assertions.push(replacement);
    document.namespaces[0].overrides.push(schema::Override {
        replaces: "fixture.length".into(),
        with: "fixture.replacement".into(),
        reason: "Synthetic fixture demonstrates documented supersession".into(),
        assertion_ids: vec!["fixture.length.complete".into()],
    });
    assert!(run(document)
        .unwrap()
        .rust
        .contains("CompiledRule{id:\"fixture.replacement\""));
    let mut document = fixture();
    document.namespaces[0].overrides.push(schema::Override {
        replaces: "fixture.length".into(),
        with: "fixture.form".into(),
        reason: "".into(),
        assertion_ids: vec![],
    });
    assert!(run(document).unwrap_err().contains("override"));
}

/// Verify that whole rule overrides cannot silently narrow input or form scope.
#[test]
fn whole_rule_overrides_cannot_silently_narrow_input_or_form_scope() {
    let scoped_override = || {
        let mut document = fixture();
        document.namespaces[0]
            .forms
            .push(vec!["group".into(), "name".into()]);
        for assertion in &mut document.assertions {
            assertion.forms = vec![1, 2];
        }
        let mut replacement = document.assertions[1].clone();
        replacement.id = "fixture.replacement".into();
        document.assertions.push(replacement);
        document.namespaces[0].overrides.push(schema::Override {
            replaces: "fixture.length".into(),
            with: "fixture.replacement".into(),
            reason: "Synthetic replacement preserves both reviewed input classes and forms".into(),
            assertion_ids: vec!["fixture.length.complete".into()],
        });
        document
    };
    assert!(run(scoped_override())
        .unwrap()
        .rust
        .contains("fixture.replacement"));
    let mut ascii_only = scoped_override();
    ascii_only.assertions.last_mut().unwrap().input_class = Class::Ascii;
    assert!(run(ascii_only)
        .unwrap_err()
        .contains("incompatible override"));
    let mut one_form = scoped_override();
    one_form.assertions.last_mut().unwrap().forms = vec![1];
    assert!(run(one_form).unwrap_err().contains("incompatible override"));
    let mut document = scoped_override();
    let after = document.assertions.last_mut().unwrap();
    after.effect = schema::Effect::Context;
    after.predicate = None;
    assert!(run(document).unwrap_err().contains("incompatible override"));
}

/// Verify that nested boolean contradictions cannot hide behind different shapes.
#[test]
fn nested_boolean_contradictions_cannot_hide_behind_different_shapes() {
    let mut document = fixture();
    let original = document.assertions[1].predicate.clone().unwrap();
    let mut opposite = document.assertions[1].clone();
    opposite.id = "fixture.negation".into();
    opposite.predicate = Some(Predicate::Not {
        predicate: Box::new(Predicate::All {
            predicates: vec![original],
        }),
    });
    document.namespaces[0].rules.push(opposite.id.clone());
    document.assertions.push(opposite);
    assert!(run(document)
        .unwrap_err()
        .contains("propositional conflict"));
}

/// Verify that not applicable metadata cannot enforce or approve registration forms.
#[test]
fn not_applicable_metadata_cannot_enforce_or_approve_registration_forms() {
    let mut document = fixture();
    document.assertions[1].knowledge = Knowledge::NotApplicable;
    document.assertions[1].effect = Effect::Deny;
    document.assertions[1].predicate = Some(Predicate::Constant { value: true });
    assert!(run(document)
        .unwrap_err()
        .contains("not-applicable assertion"));
    let mut document = fixture();
    document.assertions[0].knowledge = Knowledge::NotApplicable;
    assert!(run(document).unwrap().supplements.is_empty());
}

/// Verify that inactive successors do not erase complete current coverage.
#[test]
fn inactive_successors_do_not_erase_complete_current_coverage() {
    let mut document = fixture();
    let mut successor = document.assertions[1].clone();
    successor.id = "fixture.future".into();
    successor.effective_from = Some("2027-02-09".into());
    document.namespaces[0].rules.push(successor.id.clone());
    document.assertions.push(successor);
    let output = run(document).unwrap();
    assert!(output
        .rust
        .contains("ascii:Knowledge::Reviewed,idn:Knowledge::Unknown"));
    assert!(!output.rust.contains("CompiledRule{id:\"fixture.future\""));
    let mut document = fixture();
    document.assertions[2].effective_from = Some("2027-02-09".into());
    assert!(run(document)
        .unwrap()
        .rust
        .contains("ascii:Knowledge::Unknown"));
}

/// Verify that minimum only policy has no fabricated registry maximum.
#[test]
fn minimum_only_policy_has_no_fabricated_registry_maximum() {
    let mut document = fixture();
    document.assertions[1].predicate = Some(Predicate::LabelMinimum {
        component: 0,
        min: 2,
        basis: predicates::Basis::Ascii,
    });
    let output = run(document).unwrap();
    assert!(output
        .rust
        .contains("Predicate::LabelMinimum{component:0,min:2,basis:LengthMeasure::Ascii}"));
}

/// Verify that contradictory minimum and maximum rules are rejected.
#[test]
fn contradictory_minimum_and_maximum_rules_are_rejected() {
    let mut document = fixture();
    document.assertions[1].predicate = Some(Predicate::LabelMinimum {
        component: 0,
        min: 2,
        basis: predicates::Basis::Ascii,
    });
    let mut maximum = document.assertions[1].clone();
    maximum.id = "fixture.maximum".into();
    maximum.predicate = Some(Predicate::LabelMaximum {
        component: 0,
        max: 1,
        basis: predicates::Basis::Ascii,
    });
    document.assertions.push(maximum);
    document.namespaces[0].rules.push("fixture.maximum".into());
    assert!(run(document).unwrap_err().contains("conflict"));
}
