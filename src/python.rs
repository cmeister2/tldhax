//! PyO3 bindings exposing the Rust registry API to Python.

use std::collections::BTreeMap;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::registry::Registry as RustRegistry;
use crate::types::{CheckResult, RegistryStats, TldRuleSummary};

/// Compatibility status and human-readable explanations for one candidate.
#[pyclass(name = "CheckResult", skip_from_py_object)]
#[derive(Clone)]
pub struct PyCheckResult {
    /// Lowercase compatibility outcome: yes, no, restricted or unknown.
    #[pyo3(get)]
    pub status: String,
    /// Explanations of findings used to derive the compatibility outcome.
    #[pyo3(get)]
    pub reasons: Vec<String>,
}

#[pymethods]
impl PyCheckResult {
    /// Return an inspectable representation containing status and reasons.
    fn __repr__(&self) -> String {
        format!(
            "CheckResult(status='{}', reasons={:?})",
            self.status, self.reasons
        )
    }

    /// Render the same status and reasons as the inspectable representation.
    fn __str__(&self) -> String {
        self.__repr__()
    }
}

impl From<CheckResult> for PyCheckResult {
    /// Copy a Rust compatibility result into Python-facing owned fields.
    fn from(value: CheckResult) -> Self {
        Self {
            status: value.status.as_str().to_string(),
            reasons: value.reasons,
        }
    }
}

/// Legacy policy summary available only when a policy fits the original API.
#[pyclass(name = "TldInfo", skip_from_py_object)]
#[derive(Clone)]
pub struct PyTldInfo {
    /// Normalized suffix described by the summary, without a leading dot.
    #[pyo3(get)]
    pub tld: String,
    /// General registration availability: yes, no or restricted.
    #[pyo3(get)]
    pub registerable: String,
    /// Optional category explaining why registration is closed or restricted.
    #[pyo3(get)]
    pub reason: Option<String>,
    /// Optional human-readable policy note.
    #[pyo3(get)]
    pub note: Option<String>,
    /// Human-readable eligibility restrictions for this suffix.
    #[pyo3(get)]
    pub restrictions: Vec<String>,
    /// Minimum permitted applicant label length in the selected basis.
    #[pyo3(get)]
    pub min_length: u8,
    /// Maximum permitted applicant label length in the selected basis.
    #[pyo3(get)]
    pub max_length: u8,
    /// Length measurement basis, encoded as ascii or unicode.
    #[pyo3(get)]
    pub length_basis: String,
    /// Exact applicant labels prohibited by the policy.
    #[pyo3(get)]
    pub banned: Vec<String>,
    /// Permitted character repertoire, encoded as ascii or idn.
    #[pyo3(get)]
    pub charset: String,
    /// Additional non-ASCII characters permitted by an IDN policy.
    #[pyo3(get)]
    pub idn_chars: String,
    /// Source URLs indexed by the policy field they support.
    pub sources: BTreeMap<String, String>,
}

#[pymethods]
impl PyTldInfo {
    /// Copy field-to-source URLs into a new Python dictionary.
    ///
    /// # Panics
    /// Panics if Python rejects an insertion into the new dictionary.
    #[getter]
    fn sources<'py>(&self, py: Python<'py>) -> Bound<'py, PyDict> {
        let dict = PyDict::new(py);
        for (field, source) in &self.sources {
            dict.set_item(field, source)
                .expect("failed to set source item");
        }
        dict
    }

    /// Return the suffix and general availability for inspection.
    fn __repr__(&self) -> String {
        format!(
            "TldInfo(tld='{}', registerable='{}')",
            self.tld, self.registerable
        )
    }
}

impl From<TldRuleSummary> for PyTldInfo {
    /// Move a Rust legacy summary into the Python-facing record.
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

/// Python handle to one immutable, locally compiled policy and inventory release.
#[pyclass(name = "Registry")]
pub struct PyRegistry {
    /// Rust registry used for all lookups and policy evaluations.
    inner: RustRegistry,
}

#[pymethods]
impl PyRegistry {
    /// Construct a registry without runtime parsing or network access.
    #[new]
    fn new() -> Self {
        Self {
            inner: RustRegistry::new(),
        }
    }

    /// Check one candidate and return compatibility status and explanations.
    fn check(&self, domain: &str) -> PyCheckResult {
        self.inner.check(domain).into()
    }

    /// Return a legacy summary only when complete policy fits the original API.
    fn tld_info(&self, tld: &str) -> Option<PyTldInfo> {
        self.inner
            .tld_info(tld)
            .map(TldRuleSummary::from)
            .map(Into::into)
    }

    /// Return the number of legacy summaries representable by the original API.
    fn rule_count(&self) -> usize {
        self.inner.rule_count()
    }

    /// Return legacy summary counts, which are not complete policy coverage counts.
    ///
    /// # Panics
    /// Panics if Python rejects an insertion into the statistics dictionary.
    fn stats<'py>(&self, py: Python<'py>) -> Bound<'py, PyDict> {
        registry_stats_to_dict(py, self.inner.stats())
    }
}

/// Copy legacy summary counts into the original Python statistics dictionary.
///
/// # Panics
/// Panics if Python rejects an insertion into the new dictionary.
fn registry_stats_to_dict<'py>(py: Python<'py>, stats: RegistryStats) -> Bound<'py, PyDict> {
    let dict = PyDict::new(py);
    dict.set_item("compiled_rules", stats.compiled_rules)
        .expect("set compiled_rules");
    dict.set_item("total_known_suffixes", stats.total_known_suffixes)
        .expect("set total_known_suffixes");
    dict.set_item("registerable", stats.registerable)
        .expect("set registerable");
    dict.set_item("not_registerable", stats.not_registerable)
        .expect("set not_registerable");
    dict.set_item("restricted", stats.restricted)
        .expect("set restricted");
    dict.set_item("coverage_percent", stats.coverage_percent)
        .expect("set coverage_percent");
    dict
}

/// Register the native classes exported by the Python extension module.
///
/// # Errors
/// Returns a Python error if a class cannot be added to the module.
#[pymodule]
pub fn _native(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyRegistry>()?;
    module.add_class::<PyCheckResult>()?;
    module.add_class::<PyTldInfo>()?;
    Ok(())
}
