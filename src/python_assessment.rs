//! Compact, owned Python decisions and reusable declared registrant profiles.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use crate::assessment_types::{Assessment, Reason};
use crate::normalization::MAX_INPUT_BYTES;
use crate::profile::{RegistrantProfile, MAX_PROFILE_BYTES};
use crate::registry::Registry;

/// Maximum number of candidates accepted by one native Python batch.
pub const MAX_BATCH: usize = 10_000;

/// Read builtin Unicode storage before allocating its UTF-8 representation.
pub(crate) fn character_count(value: &Bound<'_, PyString>) -> usize {
    // SAFETY: the typed bound guarantees a Unicode object and an attached thread.
    unsafe { pyo3::ffi::PyUnicode_GetLength(value.as_ptr()) as usize }
}

/// Validated declarations retained for evaluation without exposing their values.
#[pyclass(name = "PreparedRegistrant", frozen, skip_from_py_object)]
pub struct NativePreparedProfile {
    /// Rust declarations reused by single and batch assessments.
    pub(crate) inner: RegistrantProfile,
}

#[pymethods]
impl NativePreparedProfile {
    /// Return an inspectable representation that excludes all supplied facts.
    fn __repr__(&self) -> &'static str {
        "PreparedRegistrant()"
    }
}

/// One actionable explanation from an applicable policy requirement.
#[pyclass(name = "Reason", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyReason {
    /// Stable machine-readable identifier for the failed or unresolved check.
    #[pyo3(get)]
    pub code: String,
    /// Human-readable explanation excluding declared profile values.
    #[pyo3(get)]
    pub message: String,
}

#[pymethods]
impl PyReason {
    /// Show the reason code and actionable explanation.
    fn __repr__(&self) -> String {
        format!("Reason(code={:?}, message={:?})", self.code, self.message)
    }

    /// Render the human-readable explanation directly.
    fn __str__(&self) -> &str {
        &self.message
    }
}

impl From<&Reason> for PyReason {
    /// Copy a Rust reason into independently owned Python fields.
    fn from(value: &Reason) -> Self {
        Self {
            code: value.code.clone(),
            message: value.message.clone(),
        }
    }
}

/// A static registration decision, its candidate identity and useful reasons.
#[pyclass(name = "Assessment", frozen, skip_from_py_object)]
pub struct PyAssessment {
    /// Owned Rust output, independent of the candidate and prepared profile.
    inner: Assessment,
}

#[pymethods]
impl PyAssessment {
    /// Return yes, no or unknown for the supported static registration policy.
    #[getter]
    fn decision(&self) -> &'static str {
        self.inner.decision.as_str()
    }

    /// Preserve the inexpensive status spelling used by existing callers.
    #[getter]
    fn status(&self) -> &'static str {
        self.decision()
    }

    /// Return the canonical ASCII domain when normalization succeeded.
    #[getter]
    fn canonical_domain(&self) -> Option<&str> {
        self.inner.canonical_domain.as_deref()
    }

    /// Return the registration namespace selected for the candidate.
    #[getter]
    fn namespace(&self) -> Option<&str> {
        self.inner.namespace.as_deref()
    }

    /// Return structured, independently owned reasons for this decision.
    #[getter]
    fn reasons(&self) -> Vec<PyReason> {
        self.inner.reasons.iter().map(Into::into).collect()
    }

    /// Return only the absent facts still needed after Boolean alternatives.
    #[getter]
    fn missing_profile_fields(&self) -> Vec<String> {
        self.inner.missing_profile_fields.clone()
    }

    /// Copy the small public contract into ordinary JSON-compatible objects.
    ///
    /// # Errors
    /// Returns a Python allocation or conversion error while constructing output.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        result.set_item("decision", self.decision())?;
        result.set_item("canonical_domain", self.canonical_domain())?;
        result.set_item("namespace", self.namespace())?;
        result.set_item("missing_profile_fields", self.missing_profile_fields())?;
        let reasons = PyList::empty(py);
        for reason in &self.inner.reasons {
            let item = PyDict::new(py);
            item.set_item("code", &reason.code)?;
            item.set_item("message", &reason.message)?;
            reasons.append(item)?;
        }
        result.set_item("reasons", reasons)?;
        Ok(result)
    }

    /// Show the decision and canonical candidate without any profile facts.
    fn __repr__(&self) -> String {
        format!(
            "Assessment(decision={:?}, canonical_domain={:?})",
            self.decision(),
            self.canonical_domain()
        )
    }
}

/// Parse a bounded profile without including values in Python errors.
///
/// # Errors
/// Returns a stable validation code for invalid, unsupported or oversized input.
pub(crate) fn prepare(
    registry: &Registry,
    profile_json: &Bound<'_, PyString>,
) -> PyResult<NativePreparedProfile> {
    if character_count(profile_json) > MAX_PROFILE_BYTES {
        return Err(PyValueError::new_err("profile_input_limit"));
    }
    let value = profile_json
        .to_str()
        .map_err(|_| PyValueError::new_err("invalid_profile_json"))?;
    registry
        .prepare_registrant(value)
        .map(|inner| NativePreparedProfile { inner })
        .map_err(|error| PyValueError::new_err(error.code()))
}

/// Extract a bounded name; lone surrogates become a malformed-name witness.
///
/// # Errors
/// Returns the stable input-limit code before oversized UTF-8 allocation.
pub(crate) fn domain_text(value: &Bound<'_, PyString>) -> PyResult<String> {
    if character_count(value) > MAX_INPUT_BYTES {
        return Err(PyValueError::new_err("input_limit"));
    }
    let text = value.to_str().unwrap_or("\u{fffd}");
    if text.len() > MAX_INPUT_BYTES {
        return Err(PyValueError::new_err("input_limit"));
    }
    Ok(text.to_owned())
}

/// Assess one bounded candidate with Rust evaluation outside the Python GIL.
///
/// # Errors
/// Returns a stable input-limit code for exceeded candidate budgets.
pub(crate) fn assess(
    py: Python<'_>,
    registry: &Registry,
    domain: &Bound<'_, PyString>,
    profile: Option<&NativePreparedProfile>,
) -> PyResult<PyAssessment> {
    let domain = domain_text(domain)?;
    py.detach(|| registry.assess(&domain, profile.map(|value| &value.inner)))
        .map(|inner| PyAssessment { inner })
        .map_err(|error| PyValueError::new_err(error.code()))
}

/// Assess an ordered bounded batch with one profile and the Python GIL released.
///
/// # Errors
/// Returns a type error for non-string items or a stable exceeded-budget code.
pub(crate) fn assess_many(
    py: Python<'_>,
    registry: &Registry,
    domains: &Bound<'_, PyList>,
    profile: Option<&NativePreparedProfile>,
) -> PyResult<Vec<PyAssessment>> {
    if domains.len() > MAX_BATCH {
        return Err(PyValueError::new_err("batch_input_limit"));
    }
    let mut names = Vec::with_capacity(domains.len());
    for domain in domains.iter() {
        names.push(domain_text(domain.cast::<PyString>()?)?);
    }
    py.detach(|| {
        names
            .iter()
            .map(|domain| registry.assess(domain, profile.map(|value| &value.inner)))
            .collect::<Result<Vec<_>, _>>()
    })
    .map(|values| {
        values
            .into_iter()
            .map(|inner| PyAssessment { inner })
            .collect()
    })
    .map_err(|error| PyValueError::new_err(error.code()))
}
