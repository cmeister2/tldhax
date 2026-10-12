//! Immutable compiler-validated release tables for offline assessment.

use crate::inventory_types::{RootInventory, SpecialUse};
use crate::policy_types::{
    CompiledRule, EvidenceAssertion, EvidenceSource, FactSchema, IdnProfile, LabelSet,
    NamespacePolicy,
};
use crate::resolver::Resolver;

/// One compiler-validated release with sorted, immutable lookup tables.
pub struct PolicyDataset {
    /// Full release fingerprint of inventory, policy and evidence inputs.
    pub version: &'static str,
    /// Pinned policy activation date; assessment never reads the wall clock.
    pub evaluation_date: &'static str,
    /// Retrieval date of the root inventory used for this release.
    pub inventory_date: &'static str,
    /// Shared normalizer contract included in the release fingerprint.
    pub normalization_profile: &'static str,
    /// Pinned registration and optional hosting routing tables.
    pub resolver: &'static Resolver,
    /// Sorted exact and wildcard namespace policies.
    pub namespaces: &'static [NamespacePolicy],
    /// Shared enforceable rules; namespace indices reference this table.
    pub rules: &'static [CompiledRule],
    /// Sorted named canonical label sets.
    pub label_sets: &'static [LabelSet],
    /// Sorted registry-adopted IDN profiles.
    pub idn_profiles: &'static [IdnProfile],
    /// Typed schemas used to prepare a profile once for a batch.
    pub facts: &'static [FactSchema],
    /// Sorted reviewed assertion records.
    pub assertions: &'static [EvidenceAssertion],
    /// Sorted reviewed source records.
    pub sources: &'static [EvidenceSource],
    /// Sorted factual active-root records.
    pub roots: &'static [RootInventory],
    /// Sorted factual special-use designations with governing references.
    pub special_use: &'static [SpecialUse],
}
