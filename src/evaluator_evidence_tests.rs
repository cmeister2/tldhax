//! Direct factual and immutable protocol-source linkage regression cases.

use super::*;

/// Build the synthetic evaluator with a sorted table of independently selected source identities.
fn with_sources(ids: &[&'static str]) -> Evaluator {
    let base = dataset(&[POLICY]);
    let mut sources = ids
        .iter()
        .map(|id| EvidenceSource {
            id,
            ..base.sources[0]
        })
        .collect::<Vec<_>>();
    sources.sort_by_key(|source| source.id);
    Evaluator::new(Box::leak(Box::new(PolicyDataset {
        sources: Box::leak(sources.into_boxed_slice()),
        ..*base
    })))
}

/// A shared rule reports the selected namespace rather than its comma-separated authoring scope.
#[test]
fn a_shared_assertion_records_the_applied_namespace_selector() {
    let base = dataset(&[NamespacePolicy {
        rule_indices: &[0],
        ..POLICY
    }]);
    let rule = CompiledRule {
        scope: "fixture,other.fixture",
        ..RULES[0]
    };
    let evaluator = Evaluator::new(Box::leak(Box::new(PolicyDataset {
        rules: Box::leak(vec![rule].into_boxed_slice()),
        ..*base
    })));
    let result = evaluator.assess("blocked.fixture", None);
    assert_eq!(result.rules[0].scope, "fixture");
    assert_eq!(result.findings[0].scope, "fixture");
}

/// Infrastructure and special-use findings resolve direct sources without policy evidence records.
#[test]
fn direct_inventory_and_special_use_source_ids_resolve_without_assertions() {
    let evaluator = with_sources(&["fixture.roots", "fixture.special", "rfc-3172"]);
    let result = evaluator.assess_detailed("vanity.arpa", None);
    let infrastructure = result
        .findings
        .iter()
        .find(|finding| finding.finding.code == "infrastructure_purpose")
        .unwrap();
    assert!(infrastructure.evidence.is_empty());
    assert_eq!(
        infrastructure
            .sources
            .iter()
            .map(|source| source.id)
            .collect::<Vec<_>>(),
        vec!["fixture.roots", "rfc-3172"]
    );
    let special = evaluator.assess_detailed("local.fixture", None);
    assert_eq!(special.findings[0].sources[0].id, "fixture.special");
}

/// IDNA findings cite the pinned Unicode revision and ContextO findings cite their exact RFC clause.
#[test]
fn normalization_uses_pinned_unicode_source_and_exact_contexto_locator() {
    let evaluator = with_sources(&["rfc-5892", "uts46-rev33"]);
    let idna = evaluator.assess_detailed("_bad.fixture", None);
    assert!(idna.findings[0]
        .finding
        .references
        .contains(&"https://www.unicode.org/reports/tr46/tr46-33.html"));
    assert!(idna.findings[0]
        .sources
        .iter()
        .any(|source| source.id == "uts46-rev33"));
    let context = evaluator.assess_detailed("a·b.fixture", None);
    assert_eq!(
        context.findings[0].finding.references,
        &["https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A.3"]
    );
    assert_eq!(context.findings[0].sources[0].id, "rfc-5892");
    assert!(context.findings[0].message.contains("lowercase Latin l"));
    assert!(context.findings[0].message.contains("RFC5892 Appendix A.3"));
}

/// Exceeding the local input budget returns unknown with no registry or protocol citation.
#[test]
fn a_domain_api_budget_is_not_a_registry_or_protocol_prohibition() {
    let evaluator = with_sources(&["rfc-5892", "uts46-rev33"]);
    let input = "a".repeat(MAX_INPUT_BYTES + 1);
    let result = evaluator.assess_detailed(&input, None);
    assert_eq!(result.compact.summary, Summary::Unknown);
    assert!(result.findings[0].sources.is_empty());
    assert!(result.findings[0].finding.source_ids.is_empty());
    assert!(result.findings[0].finding.references.is_empty());
}

/// Bare-root rejection names the candidate contract and inventory date without a policy rule.
#[test]
fn bare_root_rejection_describes_the_candidate_api_without_inventing_registry_policy() {
    let evaluator = with_sources(&["iana.active-roots"]);
    let result = evaluator.assess_detailed("fixture", None);
    assert_eq!(result.compact.summary, Summary::No);
    let finding = &result.findings[0];
    assert_eq!(finding.finding.code, "bare_root");
    assert_eq!(finding.finding.scope, "candidate-input");
    assert!(finding.finding.rule_id.is_none());
    assert!(finding.finding.evidence_ids.is_empty());
    assert!(finding.finding.references.is_empty());
    assert_eq!(finding.sources[0].id, "iana.active-roots");
    assert!(finding
        .message
        .contains("candidate API requires an applicant label"));
    assert!(finding.message.contains(result.compact.inventory_date));
}
