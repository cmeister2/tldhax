//! Precomputed knowledge denominators, separate from deprecated legacy summaries.

use crate::policy_types::RuleFamily;

/// Counts over an explicit namespace denominator for one class or family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnowledgeCounts {
    /// Reviewed knowledge; namespace totals include complete NotApplicable families.
    pub reviewed: usize,
    /// Partially established coverage with remaining research gaps.
    pub partial: usize,
    /// Unresearched or inactive knowledge.
    pub unknown: usize,
    /// Unresolved evidence conflicts.
    pub conflicting: usize,
    /// Explicitly evidenced inapplicability, separate in family counts.
    pub not_applicable: usize,
}

/// Knowledge for one rule family across every known namespace selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyStats {
    /// Stable policy family.
    pub family: RuleFamily,
    /// ASCII applicant labels, independent of suffix representation.
    pub ascii: KnowledgeCounts,
    /// IDN applicant labels, independent of suffix representation.
    pub idn: KnowledgeCounts,
}

/// Full immutable release counts; generated at build time without runtime loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatasetStats {
    /// Every root present in the pinned active IANA list.
    pub active_roots: usize,
    /// Union of pinned research selectors and reviewed registration supplements.
    pub known_namespaces: usize,
    /// Namespace policy records, including partial and unresearched records.
    pub published_namespaces: usize,
    /// Active enforceable rules, independent of legacy summary count.
    pub compiled_rules: usize,
    /// All assertion records, including inactive evidence.
    pub compiled_assertions: usize,
    /// Publisher/source records retained for provenance.
    pub sources: usize,
    /// Adopted IDN profiles, including unresolved profiles.
    pub idn_profiles: usize,
    /// Profiles with fully reviewed repertoire/context/allocation features.
    pub reviewed_idn_profiles: usize,
    /// Profiles with incomplete table/context/allocation features.
    pub partial_idn_profiles: usize,
    /// Legacy claims retained as unapproved research leads.
    pub unresolved_legacy_entries: usize,
    /// Aggregate static name-family completeness for ASCII applicants.
    /// Access and eligibility remain separate in the family counts.
    pub ascii_namespaces: KnowledgeCounts,
    /// Aggregate static name-family completeness for IDN applicants.
    pub idn_namespaces: KnowledgeCounts,
    /// Per-family ASCII and IDN counts; each family sums to known_namespaces.
    pub families: &'static [FamilyStats],
    /// Full release fingerprint, including evidence and policy bytes.
    pub dataset_version: &'static str,
    /// Pinned policy activation date.
    pub evaluation_date: &'static str,
    /// Pinned active-root retrieval date.
    pub inventory_date: &'static str,
    /// Exact shared normalization contract.
    pub normalization_profile: &'static str,
}
