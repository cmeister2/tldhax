//! Compiler-validated immutable tables for offline assessment.

use crate::inventory_types::SpecialUse;
use crate::policy_types::{FactSchema, IdnProfile, LabelSet, NamespacePolicy};
use crate::resolver::Resolver;

/// Tables shared by the packaged registry and isolated semantic fixtures.
pub struct PolicyDataset {
    /// Simple packaged policy release identifier.
    pub version: &'static str,
    /// Registration namespace and form selection.
    pub resolver: Resolver,
    /// Direct namespace and form policies.
    pub namespaces: &'static [NamespacePolicy],
    /// Sorted shared exact-label tables.
    pub label_sets: &'static [LabelSet],
    /// Sorted adopted finite IDN tables.
    pub idn_profiles: &'static [IdnProfile],
    /// Typed declarations accepted by this dataset.
    pub facts: &'static [FactSchema],
    /// Non-public namespace exclusions.
    pub special_use: &'static [SpecialUse],
}
