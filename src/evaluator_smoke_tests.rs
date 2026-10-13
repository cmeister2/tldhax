//! Synthetic complete policy: any ASCII label of length three or greater.
#![allow(clippy::missing_docs_in_private_items)]

use super::*;

pub(super) fn fixture() -> Evaluator {
    let mut dataset = crate::assessment_support::fixture_dataset();
    let coverage = [
        RuleFamily::Namespace,
        RuleFamily::Length,
        RuleFamily::Characters,
        RuleFamily::Reserved,
        RuleFamily::Allocation,
        RuleFamily::Eligibility,
        RuleFamily::Access,
    ]
    .map(|family| FamilyCoverage {
        family,
        ascii: Knowledge::Reviewed,
        idn: Knowledge::Unknown,
        evidence_ids: &[],
        gap: None,
    });
    dataset.namespaces = Box::leak(Box::new([NamespacePolicy {
        selector: "com",
        kind: SelectorKind::Exact,
        forms: &[RegistrationForm { roles: &["label"] }],
        coverage: Box::leak(Box::new(coverage)),
        rule_indices: &[0],
        evidence_ids: &[],
        context: &[],
    }]));
    dataset.rules = &[CompiledRule {
        id: "synthetic-minimum",
        family: RuleFamily::Length,
        effect: RuleEffect::Require,
        predicate: Predicate::LabelMinimum {
            component: 0,
            min: 3,
            basis: LengthMeasure::Ascii,
        },
        input_class: InputClass::Ascii,
        forms: &[1],
        evidence_ids: &[],
        scope: "com",
        code: "too-short",
    }];
    Evaluator::new(Box::leak(Box::new(dataset)))
}

#[test]
fn complete_policy_has_independent_positive_and_negative_names() {
    let evaluator = fixture();
    let positive = evaluator.assess("vanity.com", None);
    assert_eq!(
        (positive.name_validity, positive.summary),
        (NameValidity::Valid, Summary::Yes)
    );
    assert_eq!(positive.namespace(), Some("com"));
    assert_eq!(evaluator.assess("ab.com", None).summary, Summary::No);
    assert_eq!(evaluator.assess("one.two.com", None).summary, Summary::No);
}

#[test]
fn unknown_form_inventory_preserves_an_independent_eligibility_failure() {
    let base = fixture();
    let mut dataset = PolicyDataset { ..*base.dataset() };
    let mut policy = dataset.namespaces[0];
    policy.forms = &[];
    let mut coverage = policy.coverage.to_vec();
    coverage[0].ascii = Knowledge::Unknown;
    policy.coverage = Box::leak(coverage.into_boxed_slice());
    dataset.namespaces = Box::leak(Box::new([policy]));
    dataset.rules = Box::leak(Box::new([CompiledRule {
        id: "declared-eligibility",
        family: RuleFamily::Eligibility,
        predicate: Predicate::FieldEquals {
            field: "qualifies",
            value: FactValue::Boolean(true),
        },
        ..dataset.rules[0]
    }]));
    let evaluator = Evaluator::new(Box::leak(Box::new(dataset)));
    let schema = &[FactSchema {
        field: "qualifies",
        kind: FactKind::Boolean,
        allowed_values: &[],
        string_format: None,
    }];
    let negative = RegistrantProfile::from_json(r#"{"qualifies":false}"#, schema).unwrap();
    let result = evaluator.assess("vanity.com", Some(&negative));
    assert_eq!(
        (result.name_validity, result.summary, result.eligibility),
        (
            NameValidity::Unknown,
            Summary::No,
            Eligibility::DoesNotMatch
        )
    );
}

#[test]
fn discovered_deeper_forms_are_unknown_without_a_reviewed_prohibition() {
    let dataset = Box::leak(Box::new(crate::assessment_support::fixture_dataset()));
    let evaluator = Evaluator::new(dataset);
    for domain in ["one.two.com", "vanity.unknown-tldhax", "co.uk"] {
        assert_eq!(evaluator.assess(domain, None).summary, Summary::Unknown);
    }
    let bare = evaluator.assess("com", None);
    assert_eq!(bare.summary, Summary::No);
    assert_eq!(bare.findings[0].scope, "candidate-input");
    assert!(bare.findings[0].references.is_empty());
    assert_eq!(evaluator.assess("_bad.com", None).summary, Summary::No);
    assert_eq!(
        evaluator
            .assess(&"a".repeat(crate::normalization::MAX_INPUT_BYTES + 1), None)
            .summary,
        Summary::Unknown
    );
}

#[test]
fn owned_results_preserve_spans_and_pinned_metadata_after_input_drops() {
    let evaluator = fixture();
    let input = String::from("VANITY.COM");
    let result = evaluator.assess(&input, None).into_owned();
    drop(input);
    assert_eq!(result.ascii(), Some("vanity.com"));
    assert_eq!(result.namespace(), Some("com"));
    assert_eq!(result.inventory_date, "2026-10-11");
    assert_eq!(result.dataset_version, "fixture-v1");
}

#[test]
fn unsupported_form_cites_the_closed_inventory_attestation() {
    let base = fixture();
    let mut dataset = PolicyDataset { ..*base.dataset() };
    let mut policy = dataset.namespaces[0];
    policy.evidence_ids = &["fixture.accepted-form"];
    let mut coverage = policy.coverage.to_vec();
    coverage[0].evidence_ids = &["fixture.closed-form-inventory"];
    policy.coverage = Box::leak(coverage.into_boxed_slice());
    dataset.namespaces = Box::leak(Box::new([policy]));
    let result = Evaluator::new(Box::leak(Box::new(dataset))).assess("one.two.com", None);
    assert_eq!(result.summary, Summary::No);
    let finding = result
        .findings
        .iter()
        .find(|finding| finding.code == "unsupported_registration_form")
        .unwrap();
    assert_eq!(finding.evidence_ids, &["fixture.closed-form-inventory"]);
    assert!(!finding.evidence_ids.contains(&"fixture.accepted-form"));
}
