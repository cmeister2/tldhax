//! Immutable factual inventory, independent of reviewed registration policies.

/// An active delegated root and its published management/contract metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootInventory {
    /// Canonical ASCII root label.
    pub tld: &'static str,
    /// Published IANA root type; this does not establish public access.
    pub kind: &'static str,
    /// IANA manager name.
    pub operator: &'static str,
    /// Official IANA delegation-record URL.
    pub delegation_url: &'static str,
    /// Independently recorded ICANN operator name when available.
    pub icann_operator: Option<&'static str>,
    /// Contract metadata alone does not approve an access rule.
    pub specification13: Option<bool>,
    /// Published contract lifecycle flag when available.
    pub contract_terminated: Option<bool>,
    /// Published delegation date when available.
    pub delegation_date: Option<&'static str>,
    /// Published removal date when available.
    pub removal_date: Option<&'static str>,
    /// Published registration-depth metadata, independent of reviewed forms.
    pub third_or_lower_level_registration: Option<bool>,
    /// Authoritative inventory source identifiers.
    pub source_ids: &'static [&'static str],
}

/// An IANA special-use designation with governing protocol references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecialUse {
    /// Canonical complete designated name; this may have multiple labels.
    pub name: &'static str,
    /// Whether the governing designation extends to descendants.
    pub descendants: bool,
    /// Whether IANA marks this designation deprecated.
    pub deprecated: bool,
    /// Stable designation purpose; protocol details are in the governing RFCs.
    pub purpose: &'static str,
    /// Governing RFC identifiers in IANA's source representation.
    pub references: &'static [&'static str],
    /// Authoritative special-use registry source identifier.
    pub source_id: &'static str,
}

/// Precomputed factual denominators; none are reviewed-policy coverage counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryCounts {
    /// Number of active root labels in the pinned IANA list.
    pub active_roots: usize,
    /// Root and ICANN namespace research selectors, including wildcard selectors.
    pub discovered_namespaces: usize,
    /// Exact, wildcard and exception rules in the ICANN PSL section.
    pub icann_routes: usize,
    /// Optional PRIVATE classification rules.
    pub private_routes: usize,
    /// Active roots whose source metadata identifies Spec 13 membership.
    pub specification13_roots: usize,
    /// Special-use designations, including deprecated designations.
    pub special_use_names: usize,
}
