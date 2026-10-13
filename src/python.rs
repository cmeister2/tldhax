//! Thin Python bindings for the offline static registration evaluator.

use std::collections::BTreeMap;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};

use crate::registry::Registry as RustRegistry;
use crate::types::{CheckResult, RegistryStats, TldRuleSummary};

/// Read builtin Unicode length before allocating an input's UTF-8 representation.
fn character_count(value: &Bound<'_, PyString>) -> usize {
    // SAFETY: the typed bound guarantees an attached thread and Unicode object.
    unsafe { pyo3::ffi::PyUnicode_GetLength(value.as_ptr()) as usize }
}

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

    /// Render the same compatibility status and explanations as the representation.
    fn __str__(&self) -> String {
        self.__repr__()
    }
}

impl From<CheckResult> for PyCheckResult {
    /// Own the Rust compatibility status and explanation strings.
    fn from(value: CheckResult) -> Self {
        Self {
            status: value.status.as_str().to_owned(),
            reasons: value.reasons,
        }
    }
}

/// Original namespace-summary interface populated only by direct policy facts.
#[pyclass(name = "TldInfo", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyTldInfo {
    /// Canonical namespace selector without a leading dot.
    #[pyo3(get)]
    pub tld: String,
    /// Representable availability mode, or unknown for conditional/partial policy.
    #[pyo3(get)]
    pub registerable: String,
    /// Optional category explaining the namespace summary.
    #[pyo3(get)]
    pub reason: Option<String>,
    /// Qualification describing the limits of this namespace summary.
    #[pyo3(get)]
    pub note: Option<String>,
    /// Direct applicant requirements that cannot be collapsed into permission.
    #[pyo3(get)]
    pub restrictions: Vec<String>,
    /// Explicit unconditional minimum, absent when not faithfully representable.
    #[pyo3(get)]
    pub min_length: Option<u16>,
    /// Explicit unconditional maximum, absent when not faithfully representable.
    #[pyo3(get)]
    pub max_length: Option<u16>,
    /// Shared basis for represented lengths, or unknown.
    #[pyo3(get)]
    pub length_basis: Option<String>,
    /// Unconditional exact reservations representable by the original summary.
    #[pyo3(get)]
    pub banned: Vec<String>,
    /// Explicit repertoire class, or unknown for unsupported/conditional scopes.
    #[pyo3(get)]
    pub charset: Option<String>,
    /// Explicit finite additional repertoire, if representable.
    #[pyo3(get)]
    pub idn_chars: Option<String>,
    /// Optional ordinary maintainer URLs, without an evidence catalogue.
    sources: BTreeMap<String, String>,
}

#[pymethods]
impl PyTldInfo {
    /// Copy ordinary source notes into the original mapping shape.
    ///
    /// # Errors
    /// Returns a Python allocation or conversion error while constructing output.
    #[getter]
    fn sources<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        for (field, source) in &self.sources {
            result.set_item(field, source)?;
        }
        Ok(result)
    }

    /// Show the represented namespace and mode without implying a candidate decision.
    fn __repr__(&self) -> String {
        format!(
            "TldInfo(tld={:?}, registerable={:?})",
            self.tld, self.registerable
        )
    }
}

impl From<TldRuleSummary> for PyTldInfo {
    /// Move only faithfully represented Rust metadata into Python fields.
    fn from(value: TldRuleSummary) -> Self {
        Self {
            tld: value.tld,
            registerable: value.registerable,
            reason: value.reason,
            note: value.note,
            restrictions: value.restrictions,
            min_length: value.min_length,
            max_length: value.max_length,
            length_basis: value.length_basis,
            banned: value.banned,
            charset: value.charset,
            idn_chars: value.idn_chars,
            sources: value.sources.into_iter().collect(),
        }
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

    /// Preserve the original profile-free status/reason-strings result.
    fn check(&self, py: Python<'_>, domain: &Bound<'_, PyString>) -> PyCheckResult {
        if character_count(domain) > crate::normalization::MAX_INPUT_BYTES {
            return PyCheckResult {
                status: "unknown".to_owned(),
                reasons: vec!["Domain exceeds 4096 UTF-8 bytes".to_owned()],
            };
        }
        let domain = domain.to_str().unwrap_or("\u{fffd}");
        py.detach(|| self.inner.check(domain)).into()
    }

    /// Return faithful namespace metadata, or none for unreviewed/ambiguous inputs.
    fn tld_info(&self, tld: &str) -> Option<PyTldInfo> {
        self.inner.tld_info(tld).map(Into::into)
    }

    /// Return the number of namespaces with authored direct policies.
    fn rule_count(&self) -> usize {
        self.inner.rule_count()
    }

    /// Retain the original statistics fields with direct-policy summary counts.
    ///
    /// # Errors
    /// Returns a Python allocation or conversion error while constructing output.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        registry_stats_to_dict(py, self.inner.stats())
    }
}

/// Copy the original statistics contract without inventing registration defaults.
///
/// # Errors
/// Returns a Python allocation or conversion error while constructing output.
fn registry_stats_to_dict<'py>(
    py: Python<'py>,
    stats: RegistryStats,
) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new(py);
    result.set_item("compiled_rules", stats.compiled_rules)?;
    result.set_item("total_known_suffixes", stats.total_known_suffixes)?;
    result.set_item("registerable", stats.registerable)?;
    result.set_item("not_registerable", stats.not_registerable)?;
    result.set_item("restricted", stats.restricted)?;
    result.set_item("coverage_percent", stats.coverage_percent)?;
    Ok(result)
}

/// Preserve the original native registry, check-result and namespace-summary API.
///
/// # Errors
/// Returns a Python error if a native class cannot be registered.
#[pymodule]
pub fn _native(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyRegistry>()?;
    module.add_class::<PyCheckResult>()?;
    module.add_class::<PyTldInfo>()?;
    Ok(())
}
