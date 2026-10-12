//! Offline assessment over immutable compiled policy, evidence and inventory.

use std::borrow::Cow;

use crate::assessment_types::*;
use crate::normalization::{normalize, NormalizationError};
use crate::policy_types::*;
use crate::profile::RegistrantProfile;
use crate::resolver::RouteMatch;

use crate::assessment_support::{aggregate, empty, policy, protocol, record, rules};
pub use crate::assessment_support::{MAX_FINDINGS, MAX_RULE_TRACES};
pub use crate::dataset::PolicyDataset;

#[path = "assessment_detailed.rs"]
mod detailed;
pub use detailed::{DetailedAssessment, DetailedFinding, ExplanationError};

/// Cheap immutable evaluator; construction performs no parsing or dynamic initialization.
pub struct Evaluator {
    /// All decisions derive from the same pinned release.
    dataset: &'static PolicyDataset,
}

impl Evaluator {
    /// Construct from locally compiled and validated tables.
    pub const fn new(dataset: &'static PolicyDataset) -> Self {
        Self { dataset }
    }

    /// Access immutable evidence and metadata for optional explanation formatting.
    pub const fn dataset(&self) -> &'static PolicyDataset {
        self.dataset
    }

    /// Look up an exact canonical authoring selector, including literal wildcards.
    pub fn namespace_policy(&self, selector: &str) -> Option<&'static NamespacePolicy> {
        self.dataset
            .namespaces
            .binary_search_by_key(&selector, |policy| policy.selector)
            .ok()
            .map(|index| &self.dataset.namespaces[index])
    }

    /// Assess a prospective name with optional prepared self-declared facts.
    pub fn assess<'a>(
        &self,
        input: &'a str,
        profile: Option<&RegistrantProfile>,
    ) -> CompactAssessment<'a> {
        self.assess_with_private(input, profile, false)
    }

    /// Assess with optional PRIVATE metadata that never changes registration outcomes.
    pub fn assess_with_private<'a>(
        &self,
        input: &'a str,
        profile: Option<&RegistrantProfile>,
        include_private: bool,
    ) -> CompactAssessment<'a> {
        let canonical = match normalize(input) {
            Ok(name) => name,
            Err(error) => return self.input_failure(error),
        };
        let decoded = match canonical.unicode() {
            Ok(Cow::Owned(unicode)) => Some(unicode),
            Ok(Cow::Borrowed(_)) => None,
            Err(error) => return self.input_failure(error),
        };
        let mut result: CompactAssessment<'a> = self.canonical(
            canonical.ascii(),
            decoded.as_deref().unwrap_or(canonical.ascii()),
            profile,
            include_private,
        );
        result.canonical = Some(canonical);
        result.decoded_unicode = decoded;
        result
    }

    /// Evaluate the canonical candidate before moving its buffers into the result.
    fn canonical(
        &self,
        ascii: &str,
        unicode: &str,
        profile: Option<&RegistrantProfile>,
        private: bool,
    ) -> CompactAssessment<'static> {
        let mut result = empty(self.dataset);
        let resolution = self.dataset.resolver.resolve(ascii, private);
        result.root_known = resolution.root_known;
        result.registration = resolution
            .registration
            .map(|route| route_selection(ascii, route));
        result.icann = resolution.icann.map(|route| route_selection(ascii, route));
        result.private = resolution
            .private
            .map(|route| route_selection(ascii, route));
        result.root_inventory = self
            .dataset
            .roots
            .binary_search_by_key(&resolution.root, |root| root.tld)
            .ok()
            .map(|index| &self.dataset.roots[index]);
        let root_sources = result
            .root_inventory
            .map_or(&["iana.active-roots"][..], |root| root.source_ids);
        result.special_use = policy::special(ascii, self.dataset.special_use);
        if let Some(special) = result.special_use {
            record(
                &mut result,
                Finding {
                    code: if special.deprecated {
                        "special_use_deprecated"
                    } else {
                        "special_use_not_public"
                    },
                    rule_id: None,
                    evidence_ids: &[],
                    source_ids: &[],
                    references: special.references,
                    scope: special.name,
                    severity: if special.deprecated {
                        Severity::Warning
                    } else {
                        Severity::Error
                    },
                    params: FindingParams::None,
                },
            );
            if !special.deprecated {
                result.name_validity = NameValidity::Invalid;
                result.summary = Summary::No;
                result.eligibility = Eligibility::NotRequired;
                return result;
            }
        }
        if !resolution.root_known {
            record(
                &mut result,
                Finding {
                    code: "not_in_root_snapshot",
                    rule_id: None,
                    evidence_ids: &[],
                    source_ids: &["iana.active-roots"],
                    references: &["https://data.iana.org/TLD/tlds-alpha-by-domain.txt"],
                    scope: "root-snapshot",
                    severity: Severity::Warning,
                    params: FindingParams::None,
                },
            );
            return result;
        }
        if !ascii.contains('.') {
            record(
                &mut result,
                Finding {
                    code: "bare_root",
                    rule_id: None,
                    evidence_ids: &[],
                    source_ids: &["iana.active-roots"],
                    references: &[],
                    scope: "candidate-input",
                    severity: Severity::Error,
                    params: FindingParams::ApplicantLabels(0),
                },
            );
            result.name_validity = NameValidity::Invalid;
            result.summary = Summary::No;
            return result;
        }
        if result
            .root_inventory
            .is_some_and(|root| root.kind == "infrastructure")
        {
            record(
                &mut result,
                Finding {
                    code: "infrastructure_purpose",
                    rule_id: None,
                    evidence_ids: &[],
                    source_ids: if resolution.root == "arpa" {
                        &["rfc-3172"]
                    } else {
                        root_sources
                    },
                    references: &[],
                    scope: "root-snapshot",
                    severity: Severity::Info,
                    params: FindingParams::None,
                },
            );
        }
        let selected = policy::select(ascii, &resolution, self.dataset.namespaces);
        let namespace = selected.as_ref().map(|selected| selected.policy);
        result.policy_selector = namespace.map(|policy| policy.selector);
        let class = policy::input_class(selected.as_ref().map_or_else(
            || resolution.registration.map_or("", |route| route.applicant),
            |selected| selected.applicant,
        ));
        let mut state = aggregate::State::default();
        let access_rules = selected.as_ref().is_some_and(|selected| {
            selected
                .policy
                .rule_indices
                .iter()
                .filter_map(|index| self.dataset.rules.get(*index as usize))
                .any(|rule| {
                    rule.family == RuleFamily::Access
                        && rule.effect != RuleEffect::Context
                        && rule
                            .forms
                            .iter()
                            .any(|count| usize::from(*count) == selected.count)
                        && (rule.input_class == InputClass::Any || rule.input_class == class)
                })
        });
        aggregate::coverage(namespace, class, access_rules, &mut result, &mut state);
        if let Some(selected) = selected {
            if !selected
                .policy
                .forms
                .iter()
                .any(|form| form.roles.len() == selected.count)
            {
                let complete = aggregate::knowledge(namespace, RuleFamily::Namespace, class)
                    == Knowledge::Reviewed;
                state.name_failed |= complete;
                state.name_unresolved |= !complete;
                record(
                    &mut result,
                    Finding {
                        code: if complete {
                            "unsupported_registration_form"
                        } else {
                            "registration_form_unknown"
                        },
                        rule_id: None,
                        evidence_ids: if complete {
                            selected
                                .policy
                                .coverage
                                .iter()
                                .find(|entry| entry.family == RuleFamily::Namespace)
                                .map_or(&[], |entry| entry.evidence_ids)
                        } else {
                            selected.policy.evidence_ids
                        },
                        source_ids: &[],
                        references: &[],
                        scope: selected.policy.selector,
                        severity: if complete {
                            Severity::Error
                        } else {
                            Severity::Warning
                        },
                        params: FindingParams::ApplicantLabels(selected.count),
                    },
                );
            }
            // Each compiled rule independently retains its supported form/class scope.
            rules::evaluate(
                self.dataset,
                selected.policy,
                selected.applicant,
                selected.count,
                unicode,
                profile,
                class,
                &mut result,
                &mut state,
            );
        }
        aggregate::finish(state, &mut result);
        result
    }

    /// Input budgets express an API limit, while protocol failures invalidate syntax.
    fn input_failure(&self, error: NormalizationError) -> CompactAssessment<'static> {
        let mut result = empty(self.dataset);
        if error != NormalizationError::InputLimit {
            result.name_validity = NameValidity::Invalid;
            result.summary = Summary::No;
        }
        record(
            &mut result,
            Finding {
                code: error.code(),
                rule_id: None,
                evidence_ids: &[],
                source_ids: protocol::sources(error),
                references: protocol::references(error),
                scope: "input",
                severity: if error == NormalizationError::InputLimit {
                    Severity::Warning
                } else {
                    Severity::Error
                },
                params: FindingParams::Normalization(error),
            },
        );
        result
    }
}

/// Store route identity and candidate-relative spans, never borrowed self references.
fn route_selection(name: &str, route: RouteMatch<'_>) -> RouteSelection {
    RouteSelection {
        suffix_start: name.len() - route.suffix.len(),
        applicant_labels: route.applicant_labels,
        rule_id: route.rule.id,
        selector: route.rule.selector,
        source_id: route.rule.source_id,
        kind: route.rule.kind,
        section: route.rule.section,
        evidence_ids: route.rule.evidence_ids,
    }
}

#[cfg(test)]
#[path = "evaluator_smoke_tests.rs"]
mod smoke;

#[cfg(test)]
#[path = "evaluator_detail_tests.rs"]
mod detail_tests;

#[cfg(test)]
#[path = "evaluator_synthetic_tests.rs"]
mod tests;
