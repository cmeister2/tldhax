//! Independent synthetic name and optional-applicant outcomes.

use super::*;
use crate::normalization::MAX_INPUT_BYTES;
use crate::predicate_eval::Truth;
/// Independently authored namespace policies, routes, evidence, and profile declarations.
#[path = "evaluator_fixtures.rs"]
mod fixture;
use fixture::*;

/// Complete policy accepts an ordinary label and rejects independently chosen reserved and length violations.
#[test]
fn complete_name_policy_accepts_positive_and_rejects_independent_failures() {
    let evaluator = Evaluator::new(dataset(policies(vec![POLICY])));
    let valid = evaluator.assess("vanity.fixture", None);
    assert_eq!(
        (
            valid.name_validity,
            valid.summary,
            valid.policy_coverage,
            valid.eligibility
        ),
        (
            NameValidity::Valid,
            Summary::Yes,
            Coverage::Complete,
            Eligibility::NotRequired
        )
    );
    for candidate in [
        "blocked.fixture",
        "ab.fixture",
        "longer-than-twelve.fixture",
    ] {
        let invalid = evaluator.assess(candidate, None);
        assert_eq!(
            (invalid.name_validity, invalid.summary),
            (NameValidity::Invalid, Summary::No)
        );
    }
}

/// Applicant eligibility changes permission while the valid name remains independent of profile truth.
#[test]
fn applicant_alternatives_and_negative_profile_do_not_change_name_validity() {
    let evaluator = Evaluator::new(dataset(&[NamespacePolicy {
        rule_indices: &[0, 1, 2, 6],
        ..POLICY
    }]));
    let citizen = profile(r#"{"citizenships":["US"]}"#);
    let negative = profile(r#"{"citizenships":[],"resident":false}"#);
    let positive = evaluator.assess("vanity.fixture", Some(&citizen));
    assert_eq!(
        (
            positive.name_validity,
            positive.summary,
            positive.eligibility
        ),
        (
            NameValidity::Valid,
            Summary::Yes,
            Eligibility::DeclaredMatch
        )
    );
    assert!(!positive
        .rules
        .iter()
        .any(|rule| rule.rule_id == "external-proof-context"));
    let failure = evaluator.assess("vanity.fixture", Some(&negative));
    assert_eq!(
        (failure.name_validity, failure.summary, failure.eligibility),
        (NameValidity::Valid, Summary::No, Eligibility::DoesNotMatch)
    );
    let missing = evaluator.assess("vanity.fixture", None);
    assert_eq!(
        (missing.name_validity, missing.summary, missing.eligibility),
        (
            NameValidity::Valid,
            Summary::Restricted,
            Eligibility::NeedsProfile
        )
    );
}

/// Budget and incomplete-policy cases that preserve decisive outcomes.
#[path = "evaluator_limits_tests.rs"]
mod limits;

/// Conditional rights permit authorized applicants, reject negative claims, and leave missing claims unknown.
#[test]
fn conditional_reservation_distinguishes_permission_denial_and_missing_facts() {
    let evaluator = Evaluator::new(dataset(&[NamespacePolicy {
        rule_indices: &[1, 3],
        ..POLICY
    }]));
    let permitted = profile(r#"{"authorized_labels":["CONDITIONAL"]}"#);
    let denied = profile(r#"{"authorized_labels":[]}"#);
    let allow = evaluator.assess("conditional.fixture", Some(&permitted));
    assert_eq!(
        (allow.name_validity, allow.summary, allow.eligibility),
        (
            NameValidity::Valid,
            Summary::Yes,
            Eligibility::DeclaredMatch
        )
    );
    let reject = evaluator.assess("conditional.fixture", Some(&denied));
    assert_eq!(
        (reject.name_validity, reject.summary, reject.eligibility),
        (
            NameValidity::Unknown,
            Summary::No,
            Eligibility::DoesNotMatch
        )
    );
    assert!(
        reject
            .rules
            .iter()
            .find(|rule| rule.rule_id == "conditional-reservation")
            .unwrap()
            .profile_dependent
    );
    let missing = evaluator.assess("conditional.fixture", None);
    assert_eq!(
        (missing.name_validity, missing.summary, missing.eligibility),
        (
            NameValidity::Unknown,
            Summary::Unknown,
            Eligibility::NeedsProfile
        )
    );
}

/// Gaps and conflicts prevent approval while supported name or applicant failures remain decisive.
#[test]
fn research_gaps_conflicts_and_supported_failures_are_independent() {
    let mut coverage = COMPLETE.to_vec();
    coverage
        .iter_mut()
        .find(|entry| entry.family == RuleFamily::Reserved)
        .unwrap()
        .ascii = Knowledge::Partial;
    let coverage = Box::leak(coverage.into_boxed_slice());
    let evaluator = Evaluator::new(dataset(policies(vec![NamespacePolicy {
        coverage,
        rule_indices: &[1, 3],
        ..POLICY
    }])));
    let permitted = profile(r#"{"authorized_labels":["conditional"]}"#);
    assert_eq!(
        evaluator
            .assess("conditional.fixture", Some(&permitted))
            .name_validity,
        NameValidity::Unknown
    );
    assert_eq!(evaluator.assess("ab.fixture", None).summary, Summary::No);
    let mut coverage = COMPLETE.to_vec();
    coverage[1].ascii = Knowledge::Conflicting;
    coverage[6].ascii = Knowledge::Partial;
    let coverage = Box::leak(coverage.into_boxed_slice());
    let evaluator = Evaluator::new(dataset(policies(vec![NamespacePolicy {
        coverage,
        rule_indices: &[2],
        ..POLICY
    }])));
    let matching = profile(r#"{"citizenships":["US"]}"#);
    let result = evaluator.assess("vanity.fixture", Some(&matching));
    assert_eq!(
        (
            result.policy_coverage,
            result.name_validity,
            result.eligibility
        ),
        (
            Coverage::Conflicting,
            NameValidity::Unknown,
            Eligibility::UnknownPolicy
        )
    );
    let negative = profile(r#"{"citizenships":[],"resident":false}"#);
    assert_eq!(
        evaluator.assess("vanity.fixture", Some(&negative)).summary,
        Summary::No
    );
}

/// A reviewed two-label form applies only its second-component rule and rejects unsupported arities.
#[test]
fn reviewed_forms_override_discovery_and_apply_the_right_components() {
    let forms = &[RegistrationForm {
        roles: &["first", "second"],
    }];
    let evaluator = Evaluator::new(dataset(policies(vec![NamespacePolicy {
        forms,
        rule_indices: &[1, 4],
        ..POLICY
    }])));
    let positive = evaluator.assess("ab.long.fixture", None);
    assert_eq!(positive.name_validity, NameValidity::Valid);
    assert_eq!(positive.registration.unwrap().applicant_labels, 2);
    assert_eq!(positive.rules.len(), 1); // The one-component length rule is out of scope.
    assert_eq!(positive.namespace(), Some("fixture"));
    assert_eq!(
        evaluator.assess("long.ab.fixture", None).name_validity,
        NameValidity::Invalid
    );
    assert_eq!(evaluator.assess("one.fixture", None).summary, Summary::No);
}

/// PSL discovery and unresearched child namespaces leave name validity unknown without reviewed prohibitions.
#[test]
fn psl_discovery_and_unknown_children_do_not_invent_name_prohibitions() {
    let evaluator = Evaluator::new(dataset(&[]));
    for candidate in [
        "fixture.child.fixture",
        "child.fixture",
        "deeper.child.fixture",
    ] {
        assert_eq!(
            evaluator.assess(candidate, None).name_validity,
            NameValidity::Unknown
        );
    }
    let child = NamespacePolicy {
        selector: "child.fixture",
        forms: &[],
        coverage: &[],
        rule_indices: &[],
        ..POLICY
    };
    let evaluator = Evaluator::new(dataset(policies(vec![POLICY, child])));
    assert_eq!(
        evaluator.assess("deeper.child.fixture", None).name_validity,
        NameValidity::Unknown
    );
    assert_eq!(evaluator.assess("fixture", None).summary, Summary::No);
    assert_eq!(
        evaluator.assess("vanity.unknown-root", None).summary,
        Summary::Unknown
    );
}

/// Suffix encoding and optional private routes leave the applicant's rule scope and assessment unchanged.
#[test]
fn unicode_suffix_and_private_classification_do_not_change_applicant_rules() {
    let unicode_policy = NamespacePolicy {
        selector: "xn--bcher-kva",
        rule_indices: &[5],
        ..POLICY
    };
    let evaluator = Evaluator::new(dataset(policies(vec![POLICY, unicode_policy])));
    let ascii_applicant = evaluator.assess("vanity.bücher", None);
    assert_eq!(ascii_applicant.name_validity, NameValidity::Valid);
    assert!(ascii_applicant.rules.is_empty());
    let plain = evaluator.assess("vanity.host.fixture", None);
    let private = evaluator.assess_with_private("vanity.host.fixture", None, true);
    assert_eq!(
        (plain.name_validity, plain.summary),
        (private.name_validity, private.summary)
    );
    assert!(plain.private.is_none());
    assert_eq!(
        private.route_suffix(private.private.unwrap()),
        Some("host.fixture")
    );
}

/// ASCII-only restrictions apply to either input class, but IDN table checks skip ASCII applicants.
#[test]
fn ascii_only_any_class_rules_are_traced_without_applying_idn_repertoires() {
    let rules = Box::leak(Box::new([
        CompiledRule {
            id: "explicit-ascii-only",
            family: RuleFamily::Idn,
            effect: RuleEffect::Require,
            predicate: Predicate::AsciiOnly { component: 0 },
            ..RULES[0]
        },
        CompiledRule {
            id: "idn-repertoire",
            family: RuleFamily::Idn,
            effect: RuleEffect::Require,
            predicate: Predicate::Idn {
                component: 0,
                profile_id: "not-an-ascii-policy",
            },
            ..RULES[0]
        },
    ]));
    let dataset = Box::leak(Box::new(PolicyDataset {
        rules,
        ..*dataset(&[POLICY])
    }));
    let evaluator = Evaluator::new(dataset);
    let ascii = evaluator.assess("vanity.fixture", None);
    assert_eq!(ascii.name_validity, NameValidity::Valid);
    assert_eq!(ascii.rules.len(), 1);
    assert_eq!(ascii.rules[0].rule_id, "explicit-ascii-only");
    assert_eq!(ascii.rules[0].truth, Truth::True);
    let idn = evaluator.assess("café.fixture", None);
    assert_eq!(idn.name_validity, NameValidity::Invalid);
    assert_eq!(idn.rules[0].truth, Truth::False);
    assert_eq!(idn.rules[1].truth, Truth::Unknown);
}

/// Special-use matching respects descendants, longest scope, and deprecation while preserving factual sources.
#[test]
fn longest_special_use_scope_deprecation_and_infrastructure_keep_provenance() {
    let evaluator = Evaluator::new(dataset(&[POLICY]));
    let exact = evaluator.assess("exact.fixture", None);
    assert_eq!(exact.summary, Summary::No);
    assert_eq!(
        evaluator.assess("child.exact.fixture", None).special_use,
        None
    );
    let longest = evaluator.assess("nested.local.fixture", None);
    assert_eq!(longest.special_use.unwrap().name, "nested.local.fixture");
    assert_eq!(longest.findings[0].references, &["rfc6761"]);
    let deprecated = evaluator.assess("deprecated.fixture", None);
    assert_ne!(deprecated.summary, Summary::No);
    let infrastructure = evaluator.assess("vanity.arpa", None);
    assert_eq!(infrastructure.summary, Summary::Unknown);
    assert!(infrastructure
        .findings
        .iter()
        .any(|finding| finding.code == "infrastructure_purpose"));
}

/// Local input budgets produce unknown, while malformed DNS and IDNA inputs produce rejection.
#[test]
fn budget_limits_are_unknown_and_protocol_failures_are_invalid() {
    let evaluator = Evaluator::new(dataset(&[POLICY]));
    let large = "a".repeat(MAX_INPUT_BYTES + 1);
    assert_eq!(evaluator.assess(&large, None).summary, Summary::Unknown);
    for name in ["a..fixture", "a·b.fixture", "xn--0.fixture"] {
        assert_eq!(evaluator.assess(name, None).summary, Summary::No);
    }
}

/// Compact, detailed, and owned results agree, and explanation rejects a different pinned release.
#[test]
fn detailed_owned_and_pinned_date_results_preserve_the_same_decision() {
    let dataset = dataset(&[POLICY]);
    let evaluator = Evaluator::new(dataset);
    let input = String::from("blocked.fixture");
    let compact = evaluator.assess(&input, None);
    let detailed = evaluator.assess_detailed(&input, None);
    assert_eq!(compact, detailed.compact);
    assert_eq!(detailed.findings[0].evidence[0].id, "fixture.assertion");
    assert_eq!(detailed.findings[0].sources[0].id, "fixture.source");
    let owned = compact.into_owned();
    drop(input);
    assert_eq!(owned.namespace(), Some("fixture"));
    let other = Box::leak(Box::new(PolicyDataset {
        version: "fixture-v2",
        evaluation_date: "2026-10-13",
        ..*dataset
    }));
    let other = Evaluator::new(other);
    assert_eq!(other.assess("blocked.fixture", None).summary, Summary::No);
    assert_eq!(other.explain(owned), Err(ExplanationError::DatasetMismatch));
}

/// Direct source and clause provenance cases for synthetic assessments.
#[path = "evaluator_evidence_tests.rs"]
mod evidence;
