//! Owned namespace identity with immutable policy and provenance references.

use crate::inventory_types::RootInventory;
use crate::policy_types::{CompiledRule, EvidenceAssertion, EvidenceSource, NamespacePolicy};
use crate::resolver::RouteRule;

/// Inventory and reviewed policy for a queried namespace, including unknown policy.
#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    /// Canonical queried namespace without a terminal root dot.
    pub namespace: String,
    /// Factual root metadata; delegation does not establish registration access.
    pub root_inventory: Option<&'static RootInventory>,
    /// Matching pinned ICANN discovery selector, independent of policy.
    pub icann_route: Option<&'static RouteRule>,
    /// Exact or wildcard authored namespace policy, when present.
    pub policy: Option<&'static NamespacePolicy>,
    /// Applicable inherited and local compiled rules, already resolved.
    pub rules: Vec<&'static CompiledRule>,
    /// Relevant assertions, including inactive evidence and coverage claims.
    pub assertions: Vec<&'static EvidenceAssertion>,
    /// Sources supporting the returned policy and assertions.
    pub sources: Vec<&'static EvidenceSource>,
    /// Full immutable release identity.
    pub dataset_version: &'static str,
    /// Date used to evaluate temporal policy applicability.
    pub evaluation_date: &'static str,
    /// Date of the pinned factual inventory.
    pub inventory_date: &'static str,
    /// Versioned normalization contract for this release.
    pub normalization_profile: &'static str,
}
