//! Opt-in explanation formatting derived from the same compact decision.

use super::Evaluator;
use crate::assessment_types::{CompactAssessment, Finding, FindingParams};
use crate::policy_types::{EvidenceAssertion, EvidenceSource};
use crate::predicate_eval::PredicateIssue;
use crate::profile::RegistrantProfile;

/// One formatted explanation with its exact reviewed assertions and sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedFinding {
    /// Unchanged compact finding identity and diagnostic parameters.
    pub finding: Finding,
    /// Human-readable explanation without declared profile values.
    pub message: String,
    /// Exact reviewed assertions supporting the finding.
    pub evidence: Vec<&'static EvidenceAssertion>,
    /// Controlling source records linked by those assertions.
    pub sources: Vec<&'static EvidenceSource>,
}

/// Detailed presentation over an unchanged compact assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedAssessment<'a> {
    /// The complete shared decision; formatting cannot change outcomes.
    pub compact: CompactAssessment<'a>,
    /// Requested human-readable finding explanations and evidence.
    pub findings: Vec<DetailedFinding>,
}

/// Refuse to combine decisions and controlling evidence from different releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplanationError {
    /// The result's release metadata differs from this evaluator's dataset.
    DatasetMismatch,
}

impl DetailedAssessment<'_> {
    /// Own candidate buffers while preserving all static evidence and span offsets.
    pub fn into_owned(self) -> DetailedAssessment<'static> {
        DetailedAssessment {
            compact: self.compact.into_owned(),
            findings: self.findings,
        }
    }
}

impl Evaluator {
    /// Assess and format findings only after obtaining the shared compact result.
    pub fn assess_detailed<'a>(
        &self,
        input: &'a str,
        profile: Option<&RegistrantProfile>,
    ) -> DetailedAssessment<'a> {
        self.format(self.assess(input, profile))
    }

    /// Format the shared assessment with separately retained PRIVATE metadata.
    pub fn assess_detailed_with_private<'a>(
        &self,
        input: &'a str,
        profile: Option<&RegistrantProfile>,
        private: bool,
    ) -> DetailedAssessment<'a> {
        self.format(self.assess_with_private(input, profile, private))
    }

    /// Format an existing compact result from this release, including PRIVATE metadata.
    /// # Errors
    /// Rejects a compact result produced using different release metadata.
    pub fn explain<'a>(
        &self,
        compact: CompactAssessment<'a>,
    ) -> Result<DetailedAssessment<'a>, ExplanationError> {
        if compact.dataset_version != self.dataset.version
            || compact.evaluation_date != self.dataset.evaluation_date
            || compact.inventory_date != self.dataset.inventory_date
            || compact.normalization_profile != self.dataset.normalization_profile
        {
            return Err(ExplanationError::DatasetMismatch);
        }
        Ok(self.format(compact))
    }

    /// Resolve the already assessed release's exact evidence after validation.
    fn format<'a>(&self, compact: CompactAssessment<'a>) -> DetailedAssessment<'a> {
        let findings = compact
            .findings
            .iter()
            .map(|finding| {
                let evidence = finding
                    .evidence_ids
                    .iter()
                    .filter_map(|id| {
                        self.dataset
                            .assertions
                            .binary_search_by_key(id, |assertion| assertion.id)
                            .ok()
                            .map(|index| &self.dataset.assertions[index])
                    })
                    .collect::<Vec<_>>();
                let source_ids = finding
                    .source_ids
                    .iter()
                    .copied()
                    .chain(evidence.iter().map(|assertion| assertion.source_id))
                    .chain(
                        compact
                            .special_use
                            .filter(|record| record.name == finding.scope)
                            .map(|record| record.source_id),
                    )
                    .chain(
                        compact
                            .root_inventory
                            .filter(|_| finding.scope == "root-snapshot")
                            .into_iter()
                            .flat_map(|root| root.source_ids.iter().copied()),
                    );
                let mut sources = source_ids
                    .filter_map(|id| {
                        self.dataset
                            .sources
                            .binary_search_by_key(&id, |source| source.id)
                            .ok()
                            .map(|index| &self.dataset.sources[index])
                    })
                    .collect::<Vec<_>>();
                sources.sort_by_key(|source| source.id);
                sources.dedup_by_key(|source| source.id);
                DetailedFinding {
                    finding: *finding,
                    message: message(*finding, compact.inventory_date),
                    evidence,
                    sources,
                }
            })
            .collect();
        DetailedAssessment { compact, findings }
    }
}

/// Format only static policy and candidate-derived parameters.
fn message(finding: Finding, inventory_date: &str) -> String {
    if finding.code == "bare_root" {
        return format!("This candidate API requires an applicant label beneath a delegated root in the {inventory_date} IANA snapshot");
    }
    match finding.params {
        FindingParams::Normalization(crate::normalization::NormalizationError::ContextO(error)) => {
            use crate::registration_context::ContextOError::*;
            let reason = match error {
                MiddleDot => "Middle dot requires a lowercase Latin l immediately on each side",
                GreekNumeralSign => "Greek numeral sign requires a following Greek-script character",
                HebrewGeresh | HebrewGershayim => "Hebrew punctuation requires a preceding Hebrew-script character",
                KatakanaMiddleDot => "Katakana middle dot requires a Hiragana, Katakana or Han character in the same label",
                MixedArabicIndicDigits => "The same label cannot mix the two Arabic-Indic digit sets",
            };
            format!("{reason} ({})", error.locator())
        }
        FindingParams::Normalization(error) => error.message().to_owned(),
        FindingParams::Predicate(PredicateIssue::MissingField(field)) => {
            format!("Declared profile field required: {field}")
        }
        FindingParams::Predicate(PredicateIssue::Length {
            actual,
            min,
            max,
            basis,
        }) => format!(
            "Label length {actual} ({basis:?}) is outside the reviewed bounds {min:?}..{max:?}"
        ),
        FindingParams::Predicate(PredicateIssue::IdnCharacter(cp)) => {
            format!("U+{cp:04X} is outside the adopted complete repertoire")
        }
        FindingParams::Predicate(PredicateIssue::IdnContext {
            codepoint,
            position,
        }) => format!("U+{codepoint:04X} fails the adopted context at position {position}"),
        FindingParams::ApplicantLabels(count) => {
            format!("Applicant-label count {count}: {}", finding.code)
        }
        _ => finding.code.replace('_', " "),
    }
}
