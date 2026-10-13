//! Public registry over locally compiled direct policy records.

use crate::assessment_types::{Assessment, Decision, InputError};
use crate::compiled;
use crate::dataset::PolicyDataset;
use crate::policy_types::FactSchema;
use crate::profile::{ProfileError, RegistrantProfile};
use crate::resolver::Resolver;
use crate::types::{CheckResult, CheckStatus};

/// Cheap handle to the packaged offline registration dataset.
#[derive(Debug, Clone, Copy, Default)]
pub struct Registry;

impl Registry {
    /// Create a registry without runtime loading or network access.
    pub const fn new() -> Self {
        Self
    }

    /// Prepare bounded typed declarations once for repeated assessments.
    ///
    /// # Errors
    /// Rejects malformed, duplicate, unknown, wrongly typed or oversized facts.
    pub fn prepare_registrant(&self, input: &str) -> Result<RegistrantProfile, ProfileError> {
        RegistrantProfile::from_json(input, compiled::FACT_SCHEMAS)
    }

    /// Evaluate prospective registration against supported static policy.
    ///
    /// # Errors
    /// Returns an implementation input error for an oversized raw domain.
    pub fn assess(
        &self,
        input: &str,
        profile: Option<&RegistrantProfile>,
    ) -> Result<Assessment, InputError> {
        crate::evaluator::assess(&dataset(), input, profile)
    }

    /// Preserve the original profile-free checker with direct explanation text.
    pub fn check(&self, input: &str) -> CheckResult {
        match self.assess(input, None) {
            Ok(result) => CheckResult {
                status: match result.decision {
                    Decision::Yes => CheckStatus::Yes,
                    Decision::No => CheckStatus::No,
                    Decision::Unknown => CheckStatus::Unknown,
                },
                reasons: result
                    .reasons
                    .into_iter()
                    .map(|reason| reason.message)
                    .collect(),
            },
            Err(error) => CheckResult {
                status: CheckStatus::Unknown,
                reasons: vec![error.to_string()],
            },
        }
    }

    /// Identify the packaged policy release using a simple checked-in version.
    pub const fn dataset_version(&self) -> &'static str {
        compiled::DATASET_VERSION
    }

    /// Enumerate namespaces with at least one authored registration form.
    pub fn supported_namespaces(&self) -> Vec<&'static str> {
        let mut names = compiled::NAMESPACE_POLICIES
            .iter()
            .map(|policy| policy.selector)
            .collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Discover accepted declared facts without exposing applicant values.
    pub const fn profile_schema(&self) -> &'static [FactSchema] {
        compiled::FACT_SCHEMAS
    }
}

/// Assemble borrowed static tables; the resolver contains no mutable state.
fn dataset() -> PolicyDataset {
    PolicyDataset {
        version: compiled::DATASET_VERSION,
        resolver: Resolver::new(
            compiled::NAMESPACE_POLICIES,
            compiled::ACTIVE_ROOTS,
            compiled::ROUTES,
        ),
        namespaces: compiled::NAMESPACE_POLICIES,
        label_sets: compiled::LABEL_SETS,
        idn_profiles: compiled::IDN_PROFILES,
        facts: compiled::FACT_SCHEMAS,
        special_use: compiled::SPECIAL_USE,
    }
}
