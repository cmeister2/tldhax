//! Scope and interpretation tests for named sets, tables and overrides.

use super::fixtures::{assertion, fixture, run};
use super::*;
use predicates::{FactKind, Predicate, Value};
use schema::{Class, Family, Knowledge};

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

#[test]
fn invalid_idn_ranges_and_unadopted_scope_cannot_compile() {
    let mut document = idn_fixture();
    document.idn_profiles[0].ranges = vec![[0xd700, 0xe000]];
    assert!(run(document).unwrap_err().contains("code point"));
    let mut document = idn_fixture();
    document.idn_profiles[0].namespaces = vec!["other".into()];
    assert!(run(document).unwrap_err().contains("scope"));
}

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

#[test]
fn separately_scoped_form_and_completeness_evidence_combine_without_invented_scope() {
    let mut document = fixture();
    document.namespaces[0]
        .forms
        .push(vec!["group".into(), "name".into()]);
    let mut form = document.assertions[0].clone();
    form.id = "fixture.form.two".into();
    form.forms = vec![2];
    document.namespaces[0]
        .form_assertion_ids
        .push(form.id.clone());
    document.assertions.push(form);
    let mut complete = document.assertions[2].clone();
    complete.id = "fixture.length.two.complete".into();
    complete.forms = vec![2];
    document.namespaces[0].coverage[0]
        .assertion_ids
        .push(complete.id.clone());
    document.assertions.push(complete);
    let output = run(document).unwrap();
    assert_eq!(output.supplements[0].applicant_label_counts, vec![1, 2]);
    assert!(output
        .rust
        .contains("ascii:Knowledge::Reviewed,idn:Knowledge::Unknown"));
}

#[test]
fn a_future_form_does_not_erase_current_form_completeness() {
    let mut document = fixture();
    document.namespaces[0]
        .forms
        .push(vec!["group".into(), "name".into()]);
    let mut future = document.assertions[0].clone();
    future.id = "fixture.future.form".into();
    future.forms = vec![2];
    future.effective_from = Some("2027-01-01".into());
    document.namespaces[0]
        .form_assertion_ids
        .push(future.id.clone());
    document.assertions.push(future);
    let output = run(document).unwrap();
    assert_eq!(output.supplements[0].applicant_label_counts, vec![1]);
    assert!(output
        .rust
        .contains("ascii:Knowledge::Reviewed,idn:Knowledge::Unknown"));
}

#[test]
fn another_active_form_needs_its_own_complete_family_scope() {
    let mut document = fixture();
    document.namespaces[0]
        .forms
        .push(vec!["group".into(), "name".into()]);
    document.assertions[0].forms = vec![1, 2];
    assert!(run(document).unwrap_err().contains("scoped completeness"));
}

#[test]
fn missing_or_expired_form_approval_cannot_infer_a_closed_namespace() {
    for approval in ["missing", "expired", "empty"] {
        let mut document = fixture();
        let mut complete = document.assertions[0].clone();
        complete.id = "fixture.forms.complete".into();
        complete.attests_completeness = true;
        document.assertions.push(complete);
        document.namespaces[0].coverage.push(schema::Coverage {
            family: Family::Namespace,
            ascii: Knowledge::Reviewed,
            idn: Knowledge::Reviewed,
            assertion_ids: vec!["fixture.forms.complete".into()],
            gap: None,
        });
        if approval == "expired" {
            document.assertions[0].reviewed_on = "2024-01-01".into();
            document.assertions[0].review_due = "2025-01-01".into();
        } else {
            document.namespaces[0].form_assertion_ids.clear();
        }
        if approval == "empty" {
            document.namespaces[0].forms.clear();
            document.namespaces[0].rules.clear();
        }
        let output = run(document).unwrap();
        assert!(output.supplements.is_empty());
        assert!(output.rust.contains(
            "family:RuleFamily::Namespace,ascii:Knowledge::Unknown,idn:Knowledge::Unknown"
        ));
        assert!(output.rust.contains("registration_form_approval_missing"));
    }
}

#[test]
fn single_class_form_evidence_cannot_approve_universal_registration_forms() {
    let mut document = fixture();
    document.assertions[0].input_class = Class::Ascii;
    assert!(run(document)
        .unwrap_err()
        .contains("form assertion scope mismatch"));
}

#[test]
fn idn_only_table_adoption_cannot_supply_an_any_class_predicate() {
    let mut document = idn_fixture();
    document.assertions[1].input_class = Class::Any;
    assert!(run(document)
        .unwrap_err()
        .contains("explicit IDN input class"));
}

fn shared_profile(document: &mut schema::Document, evidence: Vec<String>) {
    document.profiles.push(schema::Profile {
        id: "fixture.shared".into(),
        applicability: vec!["fixture".into()],
        applicability_assertions: evidence,
        extends: vec![],
        rules: std::mem::take(&mut document.namespaces[0].rules),
        coverage: std::mem::take(&mut document.namespaces[0].coverage),
        context: vec![],
    });
    document.namespaces[0]
        .profiles
        .push("fixture.shared".into());
}

#[test]
fn future_form_and_profile_references_do_not_block_current_inheritance() {
    let mut document = fixture();
    document.namespaces[0]
        .forms
        .push(vec!["group".into(), "name".into()]);
    let mut future = document.assertions[0].clone();
    future.id = "fixture.future.form".into();
    future.forms = vec![2];
    future.effective_from = Some("2027-01-01".into());
    document.namespaces[0]
        .form_assertion_ids
        .push(future.id.clone());
    document.assertions.push(future);
    shared_profile(
        &mut document,
        vec!["fixture.form".into(), "fixture.future.form".into()],
    );
    let output = run(document).unwrap();
    assert_eq!(output.supplements[0].applicant_label_counts, vec![1]);
    assert!(output.rust.contains("CompiledRule{id:\"fixture.length\""));
}

#[test]
fn distinct_profile_applicability_proofs_combine_and_each_current_form_needs_one() {
    let mut document = fixture();
    document.namespaces[0]
        .forms
        .push(vec!["group".into(), "name".into()]);
    let mut second = document.assertions[0].clone();
    second.id = "fixture.form.two".into();
    second.forms = vec![2];
    document.namespaces[0]
        .form_assertion_ids
        .push(second.id.clone());
    document.assertions.push(second);
    document.namespaces[0].coverage.clear();
    shared_profile(
        &mut document,
        vec!["fixture.form".into(), "fixture.form.two".into()],
    );
    let statuses = validate::document(&mut document, "2026-10-12", None).unwrap();
    let output = resolve::resolve(&document, &statuses).unwrap();
    assert_eq!(
        output[0].forms.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![1, 2]
    );
    document.profiles[0].applicability_assertions.pop();
    assert!(run(document)
        .unwrap_err()
        .contains("applicability evidence"));
}

#[test]
fn necessary_inherited_rules_need_scope_evidence_without_approving_forms() {
    let mut document = fixture();
    document.namespaces[0].form_assertion_ids.clear();
    document.namespaces[0].coverage.clear();
    document.namespaces[0]
        .forms
        .push(vec!["group".into(), "name".into()]);
    document.assertions[1].family = Family::Access;
    document.assertions[1].predicate = Some(Predicate::Constant { value: false });
    let mut future = document.assertions[1].clone();
    future.id = "fixture.future.access".into();
    future.forms = vec![2];
    future.effective_from = Some("2027-01-01".into());
    document.namespaces[0].rules.push(future.id.clone());
    document.assertions.push(future);
    shared_profile(&mut document, vec!["fixture.form".into()]);
    let statuses = validate::document(&mut document, "2026-10-12", None).unwrap();
    let output = resolve::resolve(&document, &statuses).unwrap();
    assert!(output[0].forms.is_empty());
    assert_eq!(output[0].rule_ids, vec!["fixture.length"]);
    document.assertions[0].effective_from = Some("2027-01-01".into());
    assert!(run(document)
        .unwrap_err()
        .contains("applicability evidence"));
}

#[test]
fn shared_profiles_cannot_gain_universal_scope_from_ascii_or_empty_evidence() {
    let mut document = fixture();
    let mut applicability = document.assertions[0].clone();
    applicability.id = "fixture.profile.ascii".into();
    applicability.input_class = Class::Ascii;
    document.assertions.push(applicability);
    shared_profile(&mut document, vec!["fixture.profile.ascii".into()]);
    assert!(run(document)
        .unwrap_err()
        .contains("applicability assertion scope"));
    let mut document = fixture();
    document.namespaces[0].form_assertion_ids.clear();
    document.namespaces[0].rules.clear();
    document.namespaces[0].coverage.clear();
    shared_profile(&mut document, vec!["fixture.form".into()]);
    assert!(run(document)
        .unwrap_err()
        .contains("applicability evidence"));
}
