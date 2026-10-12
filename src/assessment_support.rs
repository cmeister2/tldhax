//! Internal assessment foundations, staged before their public entry point.

use crate::assessment_types::*;
use crate::dataset::PolicyDataset;

#[path = "assessment_aggregate.rs"]
pub(crate) mod aggregate;
#[path = "assessment_policy.rs"]
pub(crate) mod policy;
#[path = "assessment_protocol.rs"]
pub(crate) mod protocol;

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
