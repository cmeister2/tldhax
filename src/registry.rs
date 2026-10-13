//! Public registry over locally compiled direct policy records.

use crate::assessment_types::{Assessment, Decision, InputError};
use crate::compiled;
use crate::dataset::PolicyDataset;
use crate::policy_types::{
    FactSchema, InputClass, LengthMeasure, NamespacePolicy, Predicate, RuleEffect, Support,
};
use crate::profile::{ProfileError, RegistrantProfile};
use crate::resolver::Resolver;
use crate::types::{CheckResult, CheckStatus, RegistryStats, TldRuleSummary};

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

    /// Describe a single-label direct namespace policy without inventing unknown properties.
    ///
    /// Legacy inventory entries and richer multi-form policies have no faithful scalar summary.
    pub fn tld_info(&self, input: &str) -> Option<TldRuleSummary> {
        let input = input.trim().strip_prefix('.').unwrap_or(input.trim());
        let name = crate::normalization::CanonicalName::new(input).ok()?;
        let mut matching = compiled::NAMESPACE_POLICIES
            .iter()
            .filter(|policy| policy.selector == name.ascii());
        let policy = matching.next()?;
        if matching.next().is_some() || policy.form.len() != 1 {
            return None;
        }
        Some(summary(policy))
    }

    /// Count unique authored direct-policy selectors, excluding unreviewed legacy inventory.
    pub fn rule_count(&self) -> usize {
        self.supported_namespaces().len()
    }

    /// Preserve compatibility counters while distinguishing authored policy from inventory.
    pub fn stats(&self) -> RegistryStats {
        let mut registerable = 0;
        let mut not_registerable = 0;
        let mut restricted = 0;
        let names = self.supported_namespaces();
        for name in &names {
            if let Some(info) = self.tld_info(name) {
                match info.registerable.as_str() {
                    "yes" => registerable += 1,
                    "no" => not_registerable += 1,
                    "restricted" => restricted += 1,
                    _ => (),
                }
            }
        }
        let total_known_suffixes = compiled::KNOWN_SUFFIXES.len();
        RegistryStats {
            compiled_rules: names.len(),
            total_known_suffixes,
            registerable,
            not_registerable,
            restricted,
            coverage_percent: if total_known_suffixes == 0 {
                0.0
            } else {
                100.0 * names.len() as f64 / total_known_suffixes as f64
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

/// Identify applicant-dependent expressions without interpreting or coercing declared values.
fn profile_dependent(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::FieldEquals { .. }
        | Predicate::FieldIn { .. }
        | Predicate::NameEqualsField { .. } => true,
        Predicate::All(children) | Predicate::Any(children) => {
            children.iter().any(profile_dependent)
        }
        Predicate::Not(child) => profile_dependent(child),
        _ => false,
    }
}

/// Describe direct scalar metadata only; complex or candidate-dependent properties remain unknown.
fn summary(policy: &NamespacePolicy) -> TldRuleSummary {
    let applicable = policy
        .requirements
        .iter()
        .filter(|requirement| requirement.input_class != InputClass::Idn)
        .collect::<Vec<_>>();
    let prohibited = applicable.iter().any(|requirement| {
        matches!(
            (requirement.effect, requirement.predicate),
            (RuleEffect::Require, Predicate::Constant(false))
                | (RuleEffect::Deny, Predicate::Constant(true))
        )
    });
    let conditional_denial = applicable.iter().any(|requirement| {
        requirement.effect == RuleEffect::Deny && profile_dependent(&requirement.predicate)
    });
    let profile_required = applicable.iter().any(|requirement| {
        requirement.effect == RuleEffect::Require && profile_dependent(&requirement.predicate)
    });
    let unresolved = policy.ascii != Support::Supported
        || policy
            .gaps
            .iter()
            .any(|gap| gap.input_class != InputClass::Idn)
        || conditional_denial;
    let mode = if prohibited {
        "no"
    } else if unresolved {
        "unknown"
    } else if profile_required {
        "restricted"
    } else {
        "yes"
    };
    let mut min = None;
    let mut max = None;
    let mut basis = None;
    let mut mixed_basis = false;
    let mut banned = Vec::new();
    let mut charset = None;
    let mut idn_chars = None;
    for requirement in policy.requirements {
        match (requirement.effect, requirement.predicate) {
            (
                RuleEffect::Require,
                Predicate::LabelLength {
                    component: 0,
                    min: lower,
                    max: upper,
                    basis: measure,
                },
            ) if requirement.input_class != InputClass::Idn => {
                min = Some(min.map_or(lower, |existing: u16| existing.max(lower)));
                max = Some(max.map_or(upper, |existing: u16| existing.min(upper)));
                mixed_basis |= basis.is_some_and(|previous| previous != measure);
                basis = Some(measure);
            }
            (
                RuleEffect::Require,
                Predicate::LabelMinimum {
                    component: 0,
                    min: lower,
                    basis: measure,
                },
            ) if requirement.input_class != InputClass::Idn => {
                min = Some(min.map_or(lower, |existing: u16| existing.max(lower)));
                mixed_basis |= basis.is_some_and(|previous| previous != measure);
                basis = Some(measure);
            }
            (
                RuleEffect::Require,
                Predicate::LabelMaximum {
                    component: 0,
                    max: upper,
                    basis: measure,
                },
            ) if requirement.input_class != InputClass::Idn => {
                max = Some(max.map_or(upper, |existing: u16| existing.min(upper)));
                mixed_basis |= basis.is_some_and(|previous| previous != measure);
                basis = Some(measure);
            }
            (
                RuleEffect::Deny,
                Predicate::LabelInSet {
                    component: 0,
                    set_id,
                },
            ) if requirement.input_class != InputClass::Idn => {
                if let Some(set) = compiled::LABEL_SETS.iter().find(|set| set.id == set_id) {
                    banned.extend(set.labels.iter().map(|label| (*label).to_owned()));
                }
            }
            (RuleEffect::Require, Predicate::AsciiOnly { component: 0 })
                if requirement.input_class == InputClass::Any =>
            {
                charset = Some("ascii".to_owned())
            }
            (
                RuleEffect::Require,
                Predicate::Idn {
                    component: 0,
                    profile_id,
                },
            ) if policy.idn == Support::Supported => {
                charset = Some("idn".to_owned());
                if let Some(profile) = compiled::IDN_PROFILES
                    .iter()
                    .find(|profile| profile.id == profile_id && profile.repertoire_complete)
                {
                    let count = profile
                        .ranges
                        .iter()
                        .map(|range| u64::from(range.end - range.start) + 1)
                        .sum::<u64>();
                    if count <= 1024 {
                        idn_chars = Some(
                            profile
                                .ranges
                                .iter()
                                .flat_map(|range| range.start..=range.end)
                                .filter(|cp| *cp > 127)
                                .filter_map(char::from_u32)
                                .collect(),
                        );
                    }
                }
            }
            _ => (),
        }
    }
    if mixed_basis {
        min = None;
        max = None;
        basis = None;
    }
    banned.sort();
    banned.dedup();
    TldRuleSummary {
        tld: policy.selector.to_owned(), registerable: mode.to_owned(), reason: None,
        note: Some("Namespace metadata only; use assess for the candidate and declared profile. Inventory membership does not establish approval.".to_owned()),
        restrictions: applicable.iter().filter(|requirement| profile_dependent(&requirement.predicate)).map(|requirement| requirement.message.to_owned()).collect(),
        min_length: min, max_length: max,
        length_basis: basis.map(|measure| match measure { LengthMeasure::Ascii => "ascii".to_owned(), LengthMeasure::Unicode => "unicode".to_owned() }),
        banned, charset, idn_chars, sources: Vec::new(),
    }
}

#[cfg(test)]
/// Compatibility metadata never invents bounds or approves unreviewed inventory.
mod tests {
    use super::*;
    use crate::policy_types::{Requirement, SelectorKind};

    /// A supported single form with one explicitly known minimum and no other scalar defaults.
    const POLICY: NamespacePolicy = NamespacePolicy {
        id: "fixture",
        selector: "fixture",
        kind: SelectorKind::Exact,
        form: &["label"],
        ascii: Support::Supported,
        idn: Support::Unsupported,
        requirements: &[Requirement {
            code: "minimum",
            message: "Minimum two ASCII bytes",
            effect: RuleEffect::Require,
            input_class: InputClass::Any,
            predicate: Predicate::LabelMinimum {
                component: 0,
                min: 2,
                basis: LengthMeasure::Ascii,
            },
        }],
        gaps: &[],
    };

    /// Compatibility metadata exposes authored values while retaining unknown missing properties.
    #[test]
    fn scalar_metadata_preserves_absent_bounds_and_character_policy() {
        let info = summary(&POLICY);
        assert_eq!(info.min_length, Some(2));
        assert_eq!(info.max_length, None);
        assert_eq!(info.charset, None);
        assert_eq!(info.idn_chars, None);
        assert_eq!(info.length_basis.as_deref(), Some("ascii"));
        assert!(info.note.unwrap().contains("use assess"));
    }

    /// Partial scope cannot acquire general registration approval through the compatibility surface.
    #[test]
    fn partial_metadata_and_legacy_inventory_remain_unapproved() {
        let info = summary(&NamespacePolicy {
            ascii: Support::Partial,
            ..POLICY
        });
        assert_eq!(info.registerable, "unknown");
        let registry = Registry::new();
        assert_eq!(registry.check("ordinary.sk").status, CheckStatus::Unknown);
        assert!(registry.tld_info("sk").is_none());
        let stats = registry.stats();
        assert!(stats.total_known_suffixes > stats.compiled_rules);
        assert_eq!(stats.compiled_rules, registry.rule_count());
    }
}
