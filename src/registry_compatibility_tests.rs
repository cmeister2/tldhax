//! Legacy results must agree with the same evidence-backed assessment.

use super::Registry;
use crate::assessment_types::Summary;
use crate::types::CheckStatus;

#[test]
fn unreviewed_legacy_claims_cannot_approve_or_prohibit_valid_names() {
    let registry = Registry::new();
    for name in ["vanity.xyz", "vanity.ai", "za.sk"] {
        assert_eq!(registry.check(name).status, CheckStatus::Unknown);
        assert_eq!(registry.assess(name, None).summary, Summary::Unknown);
    }
    assert!(registry.tld_info("co.uk").is_none());
    assert_eq!(registry.rule_count(), 0);
    assert_eq!(registry.stats().coverage_percent, 0.0);
}

#[test]
fn protocol_and_candidate_contract_failures_share_legacy_outcomes() {
    let registry = Registry::new();
    for name in ["under_score.com", "a..com", "com", "example.test"] {
        assert_eq!(registry.check(name).status, CheckStatus::No);
        assert_eq!(registry.assess(name, None).summary, Summary::No);
        assert!(!registry.check(name).reasons.is_empty());
    }
    assert_eq!(
        registry.check(&"a".repeat(crate::normalization::MAX_INPUT_BYTES + 1)).status,
        CheckStatus::Unknown
    );
}
