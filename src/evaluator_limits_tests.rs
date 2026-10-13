//! Diagnostic-budget and omitted-family regressions with independent outcomes.

use super::*;

/// Build a policy with either every rule failing or a final failure beyond the trace budget.
fn many_rules(count: usize, all_fail: bool) -> Evaluator {
    let rules = (0..count)
        .map(|index| {
            let id = Box::leak(format!("synthetic-clause-{index}").into_boxed_str());
            CompiledRule {
                id,
                code: id,
                family: RuleFamily::Characters,
                effect: RuleEffect::Require,
                predicate: Predicate::Constant(!all_fail && index + 1 < count),
                ..RULES[1]
            }
        })
        .collect::<Vec<_>>();
    let rule_indices = (0..u32::try_from(count).unwrap()).collect::<Vec<_>>();
    let policy = NamespacePolicy {
        rule_indices: Box::leak(rule_indices.into_boxed_slice()),
        ..POLICY
    };
    let base = dataset(policies(vec![policy]));
    Evaluator::new(Box::leak(Box::new(PolicyDataset {
        rules: Box::leak(rules.into_boxed_slice()),
        ..*base
    })))
}

/// A failure after the trace limit still rejects the name and reports diagnostic truncation.
#[test]
fn late_decisive_failure_survives_rule_trace_truncation() {
    let evaluator = many_rules(MAX_RULE_TRACES + 1, false);
    let result = evaluator.assess("vanity.fixture", None);
    assert_eq!(
        (result.name_validity, result.summary),
        (NameValidity::Invalid, Summary::No)
    );
    assert_eq!(result.rules.len(), MAX_RULE_TRACES);
    assert!(result.diagnostics_truncated);
    assert_eq!(result.findings.len(), 1);
}

/// Capping stored findings preserves rejection and marks diagnostics as truncated.
#[test]
fn finding_budget_is_explicit_and_does_not_discard_the_failure() {
    let evaluator = many_rules(MAX_FINDINGS + 1, true);
    let result = evaluator.assess("vanity.fixture", None);
    assert_eq!(result.findings.len(), MAX_FINDINGS);
    assert!(result.diagnostics_truncated);
    assert_eq!(result.summary, Summary::No);
}

/// A passing access rule leaves overall permission unknown when access coverage is absent.
#[test]
fn a_supported_access_condition_does_not_invent_complete_access_coverage() {
    let coverage = COMPLETE
        .iter()
        .copied()
        .filter(|entry| entry.family != RuleFamily::Access)
        .collect::<Vec<_>>();
    let coverage = Box::leak(coverage.into_boxed_slice());
    let base = dataset(policies(vec![NamespacePolicy {
        coverage,
        rule_indices: &[0],
        ..POLICY
    }]));
    let rule = CompiledRule {
        family: RuleFamily::Access,
        predicate: Predicate::FieldEquals {
            field: "resident",
            value: FactValue::Boolean(true),
        },
        ..RULES[2]
    };
    let evaluator = Evaluator::new(Box::leak(Box::new(PolicyDataset {
        rules: Box::leak(vec![rule].into_boxed_slice()),
        ..*base
    })));
    let resident = profile(r#"{"resident":true}"#);
    let result = evaluator.assess("vanity.fixture", Some(&resident));
    assert_eq!(result.name_validity, NameValidity::Valid);
    assert_eq!(
        (result.eligibility, result.summary),
        (Eligibility::NotRequired, Summary::Unknown)
    );
    assert!(result
        .gaps
        .iter()
        .any(|gap| gap.family == RuleFamily::Access));
}

/// Unknown access coverage preserves a reviewed eligibility match and valid name.
#[test]
fn default_unknown_access_keeps_a_reviewed_eligibility_match_independent() {
    let mut coverage = COMPLETE.to_vec();
    let access = coverage
        .iter_mut()
        .find(|entry| entry.family == RuleFamily::Access)
        .unwrap();
    access.ascii = Knowledge::Unknown;
    access.gap = Some("unresearched_family");
    let coverage = Box::leak(coverage.into_boxed_slice());
    let evaluator = Evaluator::new(dataset(policies(vec![NamespacePolicy {
        coverage,
        rule_indices: &[2],
        ..POLICY
    }])));
    let citizen = profile(r#"{"citizenships":["US"]}"#);
    let result = evaluator.assess("vanity.fixture", Some(&citizen));
    assert_eq!(result.name_validity, NameValidity::Valid);
    assert_eq!(result.eligibility, Eligibility::DeclaredMatch);
    assert_eq!(result.summary, Summary::Unknown);
    assert!(result
        .gaps
        .iter()
        .any(|gap| gap.family == RuleFamily::Access));
}

/// Eligibility can match or fail independently while missing form approval leaves name truth unknown.
#[test]
fn independently_scoped_eligibility_survives_missing_approved_form_inventory() {
    let mut coverage = COMPLETE.to_vec();
    let namespace = coverage
        .iter_mut()
        .find(|entry| entry.family == RuleFamily::Namespace)
        .unwrap();
    namespace.ascii = Knowledge::Unknown;
    namespace.idn = Knowledge::Unknown;
    namespace.gap = Some("registration_form_approval_missing");
    let evaluator = Evaluator::new(dataset(policies(vec![NamespacePolicy {
        forms: &[],
        coverage: Box::leak(coverage.into_boxed_slice()),
        rule_indices: &[2],
        ..POLICY
    }])));
    let positive = profile(r#"{"citizenships":["US"]}"#);
    let negative = profile(r#"{"citizenships":[],"resident":false}"#);
    for (profile, eligibility, summary) in [
        (
            Some(&positive),
            Eligibility::DeclaredMatch,
            Summary::Unknown,
        ),
        (Some(&negative), Eligibility::DoesNotMatch, Summary::No),
        (None, Eligibility::NeedsProfile, Summary::Unknown),
    ] {
        let result = evaluator.assess("vanity.fixture", profile);
        assert_eq!(result.name_validity, NameValidity::Unknown);
        assert_eq!(result.eligibility, eligibility);
        assert_eq!(result.summary, summary);
        assert_eq!(result.rules.len(), 1);
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.code == "registration_form_unknown"));
    }
}
