//! Owned assessment objects and bounded, profile-safe Python evaluation.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyString};
use serde_json::{json, Value};

use crate::assessment_types::{CompactAssessment, Finding, FindingParams, RouteSelection};
use crate::evaluator::DetailedFinding;
use crate::normalization::MAX_INPUT_BYTES;
use crate::policy_types::RuleEffect;
use crate::predicate_eval::{PredicateIssue, Truth};
use crate::profile::{RegistrantProfile, MAX_PROFILE_BYTES};
use crate::python_records::{self as records, family, input_class, knowledge};
use crate::registry::Registry;

/// Maximum candidates accepted in one Python batch, before extraction/evaluation.
pub const MAX_BATCH: usize = 10_000;

/// Read the actual Unicode length without invoking a string subclass method.
pub(crate) fn character_count(value: &Bound<'_, PyString>) -> usize {
    // SAFETY: Bound<PyString> guarantees a Unicode object and an attached Python
    // thread. PyUnicode_GetLength reads its size without allocating UTF-8 data.
    unsafe { pyo3::ffi::PyUnicode_GetLength(value.as_ptr()) as usize }
}

#[pyclass(name = "PreparedRegistrant", frozen, skip_from_py_object)]
/// Validated registrant facts reusable across assessments without exposing values.
pub struct NativePreparedProfile {
    /// Rust profile retained for predicate evaluation only.
    pub(crate) inner: RegistrantProfile,
}

#[pymethods]
impl NativePreparedProfile {
    /// Return a representation that does not reveal registrant facts.
    fn __repr__(&self) -> &'static str {
        "PreparedRegistrant()"
    }
}

/// Candidate outcomes own bounded canonical identity and contain no profile values.
#[pyclass(name = "Assessment", frozen, skip_from_py_object)]
pub struct PyAssessment {
    /// Owned canonical identity, independent outcomes and bounded diagnostics.
    inner: CompactAssessment<'static>,
    /// Expanded explanations and provenance, present for detailed assessments.
    details: Option<Vec<DetailedFinding>>,
}

#[pymethods]
impl PyAssessment {
    /// Report whether the candidate satisfies protocol and static name-policy rules.
    #[getter]
    fn name_validity(&self) -> &'static str {
        self.inner.name_validity.as_str()
    }
    /// Return the compatibility summary derived from all independent outcomes.
    #[getter]
    fn status(&self) -> &'static str {
        self.inner.summary.as_str()
    }
    /// Report completeness of the policy knowledge used for this candidate.
    #[getter]
    fn policy_coverage(&self) -> &'static str {
        self.inner.policy_coverage.as_str()
    }
    /// Report whether the supplied registrant facts satisfy eligibility rules.
    #[getter]
    fn eligibility(&self) -> &'static str {
        self.inner.eligibility.as_str()
    }
    /// Return the normalized ASCII name when normalization succeeded.
    #[getter]
    fn canonical_ascii(&self) -> Option<&str> {
        self.inner.ascii()
    }
    /// Return the normalized Unicode name when normalization succeeded.
    #[getter]
    fn canonical_unicode(&self) -> Option<&str> {
        self.inner.unicode()
    }
    /// Return the registration namespace selected for this candidate.
    #[getter]
    fn namespace(&self) -> Option<&str> {
        self.inner.namespace()
    }
    /// Indicate whether the root label occurs in the pinned root inventory.
    #[getter]
    fn root_known(&self) -> bool {
        self.inner.root_known
    }
    /// Return the fingerprint of the immutable release used for evaluation.
    #[getter]
    fn dataset_version(&self) -> &'static str {
        self.inner.dataset_version
    }
    /// Return the date used to decide which evidence assertions are active.
    #[getter]
    fn evaluation_date(&self) -> &'static str {
        self.inner.evaluation_date
    }
    /// Return the date of the pinned namespace-discovery inventories.
    #[getter]
    fn inventory_date(&self) -> &'static str {
        self.inner.inventory_date
    }
    /// Return the identifier of the normalization rules used for this result.
    #[getter]
    fn normalization_profile(&self) -> &'static str {
        self.inner.normalization_profile
    }
    /// Indicate whether explanations and provenance were expanded for this result.
    #[getter]
    fn detailed(&self) -> bool {
        self.details.is_some()
    }
    /// Indicate whether recording limits omitted diagnostic findings or rule traces.
    #[getter]
    fn diagnostics_truncated(&self) -> bool {
        self.inner.diagnostics_truncated
    }

    /// Copy the assessment and optional provenance into ordinary Python objects.
    ///
    /// # Errors
    /// Returns a Python allocation or conversion error while constructing output.
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        records::object(py, &self.payload())
    }
    /// Return the three summary outcomes without including registrant facts.
    fn __repr__(&self) -> String {
        format!(
            "Assessment(status='{}', name_validity='{}', eligibility='{}')",
            self.status(),
            self.name_validity(),
            self.eligibility()
        )
    }
}

impl PyAssessment {
    /// Evaluate one candidate and own the result separately from its input.
    fn evaluate(
        registry: &Registry,
        domain: &str,
        profile: Option<&RegistrantProfile>,
        detailed: bool,
        private: bool,
    ) -> Self {
        if detailed {
            let value = registry
                .assess_detailed_with_private(domain, profile, private)
                .into_owned();
            Self {
                inner: value.compact,
                details: Some(value.findings),
            }
        } else {
            Self {
                inner: registry
                    .assess_with_private(domain, profile, private)
                    .into_owned(),
                details: None,
            }
        }
    }

    /// Serialize outcomes and evidence without including prepared profile values.
    fn payload(&self) -> Value {
        let result = &self.inner;
        let findings = match &self.details {
            Some(details) => details
                .iter()
                .map(|detail| {
                    let mut value = finding(detail.finding);
                    value["message"] = json!(detail.message);
                    value["evidence"] = json!(detail
                        .evidence
                        .iter()
                        .map(|item| records::assertion(item))
                        .collect::<Vec<_>>());
                    value["sources"] = json!(detail
                        .sources
                        .iter()
                        .map(|item| records::source(item))
                        .collect::<Vec<_>>());
                    value
                })
                .collect::<Vec<_>>(),
            None => result.findings.iter().copied().map(finding).collect(),
        };
        let rules = result
            .rules
            .iter()
            .map(|rule| {
                json!({"rule_id":rule.rule_id,
            "family":family(rule.family),"effect":effect(rule.effect),"truth":truth(rule.truth),
            "evidence_ids":rule.evidence_ids,"scope":rule.scope,"issue":rule.issue.map(issue),
            "profile_dependent":rule.profile_dependent})
            })
            .collect::<Vec<_>>();
        let gaps = result
            .gaps
            .iter()
            .map(|gap| {
                json!({"family":family(gap.family),
            "input_class":input_class(gap.input_class),"knowledge":knowledge(gap.knowledge),
            "evidence_ids":gap.evidence_ids,"scope":gap.scope,"reason":gap.reason})
            })
            .collect::<Vec<_>>();
        json!({"name_validity":self.name_validity(),"status":self.status(),
            "policy_coverage":self.policy_coverage(),"eligibility":self.eligibility(),
            "canonical_ascii":result.ascii(),"canonical_unicode":result.unicode(),
            "namespace":result.namespace(),"registration":result.registration.map(|item| route(result,item)),
            "icann":result.icann.map(|item| route(result,item)),"private":result.private.map(|item| route(result,item)),
            "root_known":result.root_known,"root_inventory":result.root_inventory.map(records::root),
            "special_use":result.special_use.map(records::special),"policy_selector":result.policy_selector,
            "rules":rules,"findings":findings,"gaps":gaps,"detailed":self.detailed(),
            "diagnostics_truncated":result.diagnostics_truncated,"dataset_version":result.dataset_version,
            "evaluation_date":result.evaluation_date,"inventory_date":result.inventory_date,
            "normalization_profile":result.normalization_profile})
    }
}

/// Parse a bounded JSON profile without including its values in errors.
///
/// # Errors
/// Returns a value-free validation code for malformed, unsupported or oversized input.
pub fn prepare(
    registry: &Registry,
    input: &Bound<'_, PyString>,
) -> PyResult<NativePreparedProfile> {
    if character_count(input) > MAX_PROFILE_BYTES {
        return Err(PyValueError::new_err("profile_input_limit"));
    }
    let input = input
        .to_str()
        .map_err(|_| PyValueError::new_err("invalid_profile_json"))?;
    registry
        .prepare_registrant(input)
        .map(|inner| NativePreparedProfile { inner })
        .map_err(|error| PyValueError::new_err(error.code()))
}

/// Evaluate one Python string and own its bounded result outside the GIL.
///
/// # Errors
/// This function currently returns no Python errors; invalid names are assessments.
pub fn assess(
    py: Python<'_>,
    registry: &Registry,
    domain: &Bound<'_, PyString>,
    profile: Option<&NativePreparedProfile>,
    detailed: bool,
    private: bool,
) -> PyResult<PyAssessment> {
    let over_limit;
    let domain = if character_count(domain) > MAX_INPUT_BYTES {
        over_limit = "a".repeat(MAX_INPUT_BYTES + 1);
        &over_limit
    } else {
        // A lone surrogate cannot be a Rust UTF-8 string. A fixed disallowed
        // code point retains a structured IDNA failure without transforming
        // candidate labels or retaining the invalid input.
        domain.to_str().unwrap_or("\u{fffd}")
    };
    Ok(py.detach(|| {
        PyAssessment::evaluate(
            registry,
            domain,
            profile.map(|value| &value.inner),
            detailed,
            private,
        )
    }))
}

/// Evaluate an ordered, bounded Python list with one prepared profile.
///
/// # Errors
/// Rejects oversized lists and non-string items.
pub fn assess_many(
    py: Python<'_>,
    registry: &Registry,
    domains: &Bound<'_, PyList>,
    profile: Option<&NativePreparedProfile>,
    detailed: bool,
    private: bool,
) -> PyResult<Vec<PyAssessment>> {
    if domains.len() > MAX_BATCH {
        return Err(PyValueError::new_err("batch_input_limit"));
    }
    // Copy only bounded UTF-8 input before releasing Python references. Oversized
    // candidates retain the same input-limit outcome without cloning their data.
    let inputs = domains
        .iter()
        .map(|item| {
            let value = item.cast::<PyString>()?;
            if character_count(value) > MAX_INPUT_BYTES {
                return Ok(None);
            }
            let value = value.to_str().unwrap_or("\u{fffd}");
            Ok((value.len() <= MAX_INPUT_BYTES).then(|| value.to_owned()))
        })
        .collect::<PyResult<Vec<_>>>()?;
    let over_limit = "a".repeat(MAX_INPUT_BYTES + 1);
    Ok(py.detach(|| {
        inputs
            .iter()
            .map(|input| {
                PyAssessment::evaluate(
                    registry,
                    input.as_deref().unwrap_or(&over_limit),
                    profile.map(|value| &value.inner),
                    detailed,
                    private,
                )
            })
            .collect()
    }))
}

/// Return the stable Python spelling of a rule effect.
fn effect(value: RuleEffect) -> &'static str {
    match value {
        RuleEffect::Require => "require",
        RuleEffect::Deny => "deny",
        RuleEffect::Context => "context",
    }
}
/// Return the stable Python spelling of a three-valued predicate result.
fn truth(value: Truth) -> &'static str {
    match value {
        Truth::True => "true",
        Truth::False => "false",
        Truth::Unknown => "unknown",
    }
}
/// Encode a predicate diagnostic as a tagged record with bounded parameters.
fn issue(value: PredicateIssue) -> Value {
    match value {
        PredicateIssue::MissingField(field) => json!({"kind":"missing_field","field":field}),
        PredicateIssue::MissingComponent(component) => {
            json!({"kind":"missing_component","component":component})
        }
        PredicateIssue::MissingTable(table) => json!({"kind":"missing_table","table":table}),
        PredicateIssue::IdnIncomplete(profile) => {
            json!({"kind":"idn_incomplete","profile":profile})
        }
        PredicateIssue::IdnCharacter(cp) => json!({"kind":"idn_character","codepoint":cp}),
        PredicateIssue::IdnContext {
            codepoint,
            position,
        } => json!({"kind":"idn_context","codepoint":codepoint,"position":position}),
        PredicateIssue::Length {
            actual,
            min,
            max,
            basis,
        } => {
            json!({"kind":"length","actual":actual,"min":min,"max":max,"basis":format!("{basis:?}").to_lowercase()})
        }
    }
}
/// Encode a finding's stable code, provenance references and diagnostic parameters.
fn finding(value: Finding) -> Value {
    let params = match value.params {
        FindingParams::None => Value::Null,
        FindingParams::Normalization(error) => json!({"kind":"normalization","code":error.code()}),
        FindingParams::Predicate(value) => issue(value),
        FindingParams::ApplicantLabels(count) => json!({"kind":"applicant_labels","count":count}),
    };
    json!({"code":value.code,"rule_id":value.rule_id,"evidence_ids":value.evidence_ids,
        "source_ids":value.source_ids,"references":value.references,"scope":value.scope,
        "severity":value.severity.as_str(),"params":params})
}
/// Encode a selected route using the suffix from the assessment's canonical name.
fn route(result: &CompactAssessment<'_>, value: RouteSelection) -> Value {
    json!({"suffix":result.route_suffix(value),"applicant_labels":value.applicant_labels,
        "rule_id":value.rule_id,"selector":value.selector,"source_id":value.source_id,
        "kind":format!("{:?}",value.kind).to_lowercase(),
        "section":format!("{:?}",value.section).to_lowercase(),"evidence_ids":value.evidence_ids})
}
