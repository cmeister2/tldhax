//! Internal assessment foundations, staged before their public entry point.

use crate::assessment_types::*;
use crate::dataset::PolicyDataset;

#[path = "assessment_aggregate.rs"]
pub(crate) mod aggregate;
#[path = "assessment_policy.rs"]
pub(crate) mod policy;
#[path = "assessment_protocol.rs"]
pub(crate) mod protocol;
#[path = "assessment_rules.rs"]
pub(crate) mod rules;

/// Empty result used for unknown input or an unresearched namespace.
pub(crate) fn empty(dataset: &PolicyDataset) -> CompactAssessment<'static> {
    CompactAssessment {
        canonical: None,
        decoded_unicode: None,
        name_validity: NameValidity::Unknown,
        summary: Summary::Unknown,
        policy_coverage: Coverage::Unknown,
        eligibility: Eligibility::UnknownPolicy,
        registration: None,
        icann: None,
        private: None,
        root_known: false,
        root_inventory: None,
        special_use: None,
        policy_selector: None,
        rules: Vec::new(),
        findings: Vec::new(),
        gaps: Vec::new(),
        diagnostics_truncated: false,
        dataset_version: dataset.version,
        evaluation_date: dataset.evaluation_date,
        inventory_date: dataset.inventory_date,
        normalization_profile: dataset.normalization_profile,
    }
}

#[cfg(test)]
#[path = "assessment_support_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "assessment_rules_tests.rs"]
mod rule_tests;

/// Maximum diagnostic findings; evaluation continues after the retention limit.
pub const MAX_FINDINGS: usize = 64;
/// Maximum retained rule traces; later rules still affect the decision.
pub const MAX_RULE_TRACES: usize = 128;

/// Bound stored diagnostics independently of computed policy truth.
pub(crate) fn record(result: &mut CompactAssessment<'_>, finding: Finding) {
    if result.findings.len() < MAX_FINDINGS {
        result.findings.push(finding);
    } else {
        result.diagnostics_truncated = true;
    }
}

#[cfg(test)]
/// Minimal dataset shared by independently declared synthetic runtime fixtures.
pub(crate) fn fixture_dataset() -> PolicyDataset {
    tests::dataset()
}
