//! Thin Python bindings for the offline static registration evaluator.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use crate::policy_types::{FactKind, FactStringFormat};
use crate::python_assessment::{self, NativePreparedProfile, PyAssessment, PyReason};
use crate::registry::Registry as RustRegistry;

/// Compatibility decision with directly readable explanation strings.
#[pyclass(name = "CheckResult", frozen, skip_from_py_object)]
pub struct PyCheckResult {
    /// Lowercase decision: yes, no or unknown.
    #[pyo3(get)]
    pub status: String,
    /// Useful explanations of failed or unresolved requirements.
    #[pyo3(get)]
    pub reasons: Vec<String>,
}

#[pymethods]
impl PyCheckResult {
    /// Show the decision and explanation strings for inspection.
    fn __repr__(&self) -> String {
        format!(
            "CheckResult(status={:?}, reasons={:?})",
            self.status, self.reasons
        )
    }
}

/// Cheap Python handle to the immutable compiled registry policies.
#[pyclass(name = "Registry")]
pub struct PyRegistry {
    /// Rust evaluator providing every registration decision.
    inner: RustRegistry,
}

#[pymethods]
impl PyRegistry {
    /// Construct a registry without runtime files or networking.
    #[new]
    fn new() -> Self {
        Self {
            inner: RustRegistry::new(),
        }
    }

    /// Check one candidate using the same decision engine as assess.
    ///
    /// # Errors
    /// Returns a stable input-limit error for an oversized domain.
    fn check(&self, py: Python<'_>, domain: &Bound<'_, PyString>) -> PyResult<PyCheckResult> {
        let domain = python_assessment::domain_text(domain)?;
        let value = py
            .detach(|| self.inner.assess(&domain, None))
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.code()))?;
        Ok(PyCheckResult {
            status: value.decision.as_str().to_owned(),
            reasons: value
                .reasons
                .into_iter()
                .map(|reason| reason.message)
                .collect(),
        })
    }

    /// Validate bounded JSON declarations for reuse across candidates.
    ///
    /// # Errors
    /// Returns a stable validation code excluding supplied profile values.
    fn prepare_registrant(
        &self,
        profile_json: &Bound<'_, PyString>,
    ) -> PyResult<NativePreparedProfile> {
        python_assessment::prepare(&self.inner, profile_json)
    }

    /// Evaluate one candidate against static policy and optional declarations.
    ///
    /// # Errors
    /// Returns a stable input-limit error for an oversized domain.
    #[pyo3(signature = (domain, registrant=None))]
    fn assess(
        &self,
        py: Python<'_>,
        domain: &Bound<'_, PyString>,
        registrant: Option<&NativePreparedProfile>,
    ) -> PyResult<PyAssessment> {
        python_assessment::assess(py, &self.inner, domain, registrant)
    }

    /// Evaluate at most ten thousand candidates in order with one profile.
    ///
    /// # Errors
    /// Returns a type error for non-string items or stable exceeded-budget code.
    #[pyo3(signature = (domains, registrant=None))]
    fn assess_many(
        &self,
        py: Python<'_>,
        domains: &Bound<'_, PyList>,
        registrant: Option<&NativePreparedProfile>,
    ) -> PyResult<Vec<PyAssessment>> {
        python_assessment::assess_many(py, &self.inner, domains, registrant)
    }

    /// Return the version of the packaged direct-policy dataset.
    fn dataset_version(&self) -> &str {
        self.inner.dataset_version()
    }

    /// Return selectors with an authored direct registration policy.
    fn supported_namespaces(&self) -> Vec<&'static str> {
        self.inner.supported_namespaces()
    }

    /// Describe accepted declaration fields, types and finite value constraints.
    ///
    /// # Errors
    /// Returns a Python allocation or conversion error while constructing output.
    fn profile_schema<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        for field in self.inner.profile_schema() {
            let value = PyDict::new(py);
            value.set_item(
                "type",
                match field.kind {
                    FactKind::String => "string",
                    FactKind::Boolean => "boolean",
                    FactKind::StringSet => "string_set",
                },
            )?;
            value.set_item("allowed_values", field.allowed_values)?;
            value.set_item(
                "string_format",
                field.string_format.map(|format| match format {
                    FactStringFormat::UppercaseAlpha2 => "uppercase_alpha2",
                }),
            )?;
            result.set_item(field.field, value)?;
        }
        Ok(result)
    }
}

/// Export the small decision API and opaque prepared-profile class.
///
/// # Errors
/// Returns a Python error if a native class cannot be registered.
#[pymodule]
pub fn _native(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyRegistry>()?;
    module.add_class::<PyAssessment>()?;
    module.add_class::<PyReason>()?;
    module.add_class::<NativePreparedProfile>()?;
    module.add_class::<PyCheckResult>()?;
    Ok(())
}
