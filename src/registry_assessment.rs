//! Assessment and provenance accessors over one immutable compiled release.

use super::Registry;
use crate::assessment_types::CompactAssessment;
use crate::compiled;
use crate::dataset::PolicyDataset;
use crate::evaluator::{DetailedAssessment, Evaluator};
use crate::normalization::NORMALIZATION_PROFILE;
use crate::policy_types::{EvidenceAssertion, EvidenceSource};
use crate::profile::{ProfileError, RegistrantProfile};
use crate::registry_stats::DatasetStats;

/// Every lookup uses these static tables without parsing or lazy initialization.
static DATASET: PolicyDataset = PolicyDataset {
    version: compiled::RELEASE_FINGERPRINT,
    evaluation_date: compiled::EVALUATION_DATE,
    inventory_date: compiled::INVENTORY_DATE,
    normalization_profile: NORMALIZATION_PROFILE,
    resolver: &compiled::REGISTRATION_RESOLVER,
    namespaces: compiled::NAMESPACE_POLICIES,
    rules: compiled::RULES,
    label_sets: compiled::LABEL_SETS,
    idn_profiles: compiled::IDN_PROFILES,
    facts: compiled::FACT_SCHEMAS,
    assertions: compiled::ASSERTIONS,
    sources: compiled::SOURCES,
    roots: compiled::ROOT_INVENTORY,
    special_use: compiled::SPECIAL_USE,
};

impl Registry {
    /// Inspect immutable release tables and their pinned metadata.
    pub const fn dataset(&self) -> &'static PolicyDataset {
        &DATASET
    }
    /// Evaluate syntax, reviewed name policies and optional declared eligibility.
    pub fn assess<'a>(
        &self,
        input: &'a str,
        profile: Option<&RegistrantProfile>,
    ) -> CompactAssessment<'a> {
        Evaluator::new(self.dataset()).assess(input, profile)
    }
    /// Include PRIVATE hosting metadata without changing registration decisions.
    pub fn assess_with_private<'a>(
        &self,
        input: &'a str,
        profile: Option<&RegistrantProfile>,
        private: bool,
    ) -> CompactAssessment<'a> {
        Evaluator::new(self.dataset()).assess_with_private(input, profile, private)
    }
    /// Format explanations after obtaining the same compact policy result.
    pub fn assess_detailed<'a>(
        &self,
        input: &'a str,
        profile: Option<&RegistrantProfile>,
    ) -> DetailedAssessment<'a> {
        self.assess_detailed_with_private(input, profile, false)
    }
    /// Format detailed evidence while optionally preserving PRIVATE route metadata.
    pub fn assess_detailed_with_private<'a>(
        &self,
        input: &'a str,
        profile: Option<&RegistrantProfile>,
        private: bool,
    ) -> DetailedAssessment<'a> {
        Evaluator::new(self.dataset()).assess_detailed_with_private(input, profile, private)
    }
    /// Prepare bounded declared facts once using this release's compiled schemas.
    ///
    /// # Errors
    /// Returns a stable profile error for invalid JSON, types, fields or budgets.
    pub fn prepare_registrant(&self, input: &str) -> Result<RegistrantProfile, ProfileError> {
        RegistrantProfile::from_json(input, self.dataset().facts)
    }
    /// Retrieve an exact immutable publisher/source record by its stable identifier.
    pub fn source(&self, id: &str) -> Option<&'static EvidenceSource> {
        self.dataset()
            .sources
            .binary_search_by_key(&id, |s| s.id)
            .ok()
            .map(|i| &self.dataset().sources[i])
    }
    /// Retrieve reviewed or inactive evidence without implying current enforcement.
    pub fn assertion(&self, id: &str) -> Option<&'static EvidenceAssertion> {
        self.dataset()
            .assertions
            .binary_search_by_key(&id, |a| a.id)
            .ok()
            .map(|i| &self.dataset().assertions[i])
    }
    /// Precomputed release statistics; this accessor performs no counting loops.
    pub const fn dataset_stats(&self) -> &'static DatasetStats {
        &compiled::DATASET_STATS
    }
}

#[cfg(test)]
#[path = "registry_assessment_tests.rs"]
mod tests;
