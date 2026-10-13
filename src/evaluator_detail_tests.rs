//! Assertion identity, source identity and formatting are distinct from truth.
#![allow(clippy::missing_docs_in_private_items)]

use super::*;

fn source(id: &'static str) -> EvidenceSource {
    EvidenceSource {
        id,
        publisher: "Synthetic registry",
        title: "Independent fixture clauses",
        url: "https://example.invalid/fixture",
        fetched_url: "https://example.invalid/fixture",
        sha256: "synthetic-source",
        hash_representation: "fixture",
        version: "1",
        language: "en",
        retrieved_on: "2026-10-12",
        translation_of: None,
    }
}

fn assertion(id: &'static str, source_id: &'static str, complete: bool) -> EvidenceAssertion {
    EvidenceAssertion {
        id,
        source_id,
        locator: "Independent synthetic accepted-shape clause",
        interpretation: "The closed-form clause attests the exhaustive accepted shape list.",
        operation: "new_registration",
        namespaces: &["com"],
        forms: &[1],
        input_class: InputClass::Any,
        family: RuleFamily::Namespace,
        knowledge: Knowledge::Reviewed,
        attests_completeness: complete,
        effective_from: None,
        applicable_on: Some("2026-10-12"),
        effective_until: None,
        reviewer: "fixture author",
        reviewed_on: "2026-10-12",
        review_due: "2027-10-12",
        active: true,
        inactive_reason: None,
    }
}

fn closure() -> Evaluator {
    let base = super::smoke::fixture();
    let mut dataset = PolicyDataset { ..*base.dataset() };
    let mut policy = dataset.namespaces[0];
    policy.evidence_ids = &["fixture.accepted-form"];
    let mut coverage = policy.coverage.to_vec();
    coverage[0].evidence_ids = &["fixture.closed-form-inventory"];
    policy.coverage = Box::leak(coverage.into_boxed_slice());
    dataset.namespaces = Box::leak(Box::new([policy]));
    dataset.assertions = Box::leak(Box::new([
        assertion("fixture.accepted-form", "fixture.source-approval", false),
        assertion(
            "fixture.closed-form-inventory",
            "fixture.source-closure",
            true,
        ),
    ]));
    dataset.sources = Box::leak(Box::new([
        source("fixture.source-approval"),
        source("fixture.source-closure"),
        source("iana.active-roots"),
        source("rfc-5892"),
        source("uts46-rev33"),
    ]));
    Evaluator::new(Box::leak(Box::new(dataset)))
}

#[test]
fn unsupported_form_no_resolves_the_closure_source_and_preserves_compact_truth() {
    let evaluator = closure();
    let compact = evaluator.assess("one.two.com", None);
    let detailed = evaluator.assess_detailed("one.two.com", None);
    assert_eq!(compact, detailed.compact);
    assert_eq!(detailed.compact.summary, Summary::No);
    assert_eq!(
        detailed.findings[0].evidence[0].id,
        "fixture.closed-form-inventory"
    );
    assert_eq!(detailed.findings[0].sources[0].id, "fixture.source-closure");
    assert_eq!(detailed.findings[0].sources.len(), 1);
}

#[test]
fn direct_protocol_and_candidate_contract_sources_resolve_without_policy_assertions() {
    let evaluator = closure();
    let context = evaluator.assess_detailed("a·b.com", None);
    assert!(context.findings[0].message.contains("RFC5892 Appendix A.3"));
    assert_eq!(context.findings[0].sources[0].id, "rfc-5892");
    let bare = evaluator.assess_detailed("com", None);
    assert!(bare.findings[0]
        .message
        .contains("candidate API requires an applicant label"));
    assert_eq!(bare.findings[0].sources[0].id, "iana.active-roots");
    assert!(bare.findings[0].evidence.is_empty());
}

#[test]
fn formatted_evidence_cannot_be_attached_to_another_release_or_date() {
    let evaluator = closure();
    let result = evaluator.assess("one.two.com", None).into_owned();
    let mut other = PolicyDataset {
        ..*evaluator.dataset()
    };
    other.evaluation_date = "2026-10-13";
    let other = Evaluator::new(Box::leak(Box::new(other)));
    assert_eq!(
        other.explain(result),
        Err(ExplanationError::DatasetMismatch)
    );
}
