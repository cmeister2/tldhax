//! Public registry over one immutable evidence-backed release.

use crate::assessment_types::Summary;
use crate::compiled;
use crate::types::{CheckResult, CheckStatus, RegistryStats, TldRule};

#[path = "registry_assessment.rs"]
mod assessment;
#[path = "registry_namespace.rs"]
mod namespace;

/// Cheap handle to one locally compiled and reproducible policy release.
#[derive(Debug, Clone, Copy, Default)]
pub struct Registry;

impl Registry {
    /// Create a registry without allocation, runtime parsing or network access.
    pub const fn new() -> Self {
        Self
    }
    /// Compatibility assessment; use `assess` for independent outcomes and evidence.
    pub fn check(&self, input: &str) -> CheckResult {
        let result = self.assess_detailed(input, None);
        CheckResult {
            status: match result.compact.summary {
                Summary::Yes => CheckStatus::Yes,
                Summary::No => CheckStatus::No,
                Summary::Restricted => CheckStatus::Restricted,
                Summary::Unknown => CheckStatus::Unknown,
            },
            reasons: result.findings.into_iter().map(|f| f.message).collect(),
        }
    }
    /// Compatibility summary only when a complete policy fits the old shape.
    /// Prefer `namespace_info`; incomplete or richer policies return no summary.
    pub fn tld_info(&self, input: &str) -> Option<&'static TldRule> {
        let input = input.trim().strip_prefix('.').unwrap_or(input.trim());
        let name = crate::normalization::normalize(input).ok()?;
        compiled::TLD_RULES.get(name.ascii())
    }
    /// Number of faithful legacy summaries, rather than executable predicate rules.
    pub fn rule_count(&self) -> usize {
        compiled::TLD_RULES.len()
    }
    /// Compatibility counts for legacy summaries; deprecated as a coverage measure.
    /// Use `dataset_stats` for complete inventory and per-family knowledge counts.
    pub fn stats(&self) -> RegistryStats {
        RegistryStats {
            compiled_rules: self.rule_count(),
            total_known_suffixes: compiled::TOTAL_KNOWN_SUFFIXES,
            registerable: compiled::LEGACY_COUNTS.0,
            not_registerable: compiled::LEGACY_COUNTS.1,
            restricted: compiled::LEGACY_COUNTS.2,
            coverage_percent: compiled::LEGACY_COVERAGE_PERCENT,
        }
    }
}

#[cfg(test)]
#[path = "registry_compatibility_tests.rs"]
mod tests;
