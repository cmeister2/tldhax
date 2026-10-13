//! PyO3 bindings exposing the Rust registry API to Python.

use std::collections::BTreeMap;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use crate::python_assessment::{self, NativePreparedProfile, PyAssessment};
use crate::python_namespace::{self, PyNamespaceInfo};
use crate::python_records;
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
    /// Oversized strings and lone surrogates produce structured invalid outcomes.
    ///
    /// # Errors
    /// This method currently returns no Python errors; failures are check results.
    fn check(&self, domain: &Bound<'_, PyString>) -> PyResult<PyCheckResult> {
        if python_assessment::character_count(domain) > crate::normalization::MAX_INPUT_BYTES {
            let witness = "a".repeat(crate::normalization::MAX_INPUT_BYTES + 1);
            return Ok(self.inner.check(&witness).into());
        }
        Ok(self
            .inner
            .check(domain.to_str().unwrap_or("\u{fffd}"))
            .into())
    }

    /// Validate a bounded JSON profile for reuse across policy assessments.
    ///
    /// # Errors
    /// Returns a value-free validation code for malformed, unsupported or oversized input.
    fn prepare_registrant(
        &self,
        profile_json: &Bound<'_, PyString>,
    ) -> PyResult<NativePreparedProfile> {
        python_assessment::prepare(&self.inner, profile_json)
    }

    /// Assess one candidate with optional registrant facts and expanded evidence.
    /// Private suffix routing is enabled only when `include_private` is true.
    ///
    /// # Errors
    /// This method currently returns no Python errors; invalid names are assessments.
    #[pyo3(signature = (domain, registrant=None, *, detailed=false, include_private=false))]
    fn assess(
        &self,
        py: Python<'_>,
        domain: &Bound<'_, PyString>,
        registrant: Option<&NativePreparedProfile>,
        detailed: bool,
        include_private: bool,
    ) -> PyResult<PyAssessment> {
        python_assessment::assess(
            py,
            &self.inner,
            domain,
            registrant,
            detailed,
            include_private,
        )
    }

    /// Assess a bounded list in input order using one optional prepared profile.
    ///
    /// # Errors
    /// Returns `ValueError` for an oversized batch and a type error for non-string items.
    #[pyo3(signature = (domains, registrant=None, *, detailed=false, include_private=false))]
    fn assess_many(
        &self,
        py: Python<'_>,
        domains: &Bound<'_, PyList>,
        registrant: Option<&NativePreparedProfile>,
        detailed: bool,
        include_private: bool,
    ) -> PyResult<Vec<PyAssessment>> {
        python_assessment::assess_many(
            py,
            &self.inner,
            domains,
            registrant,
            detailed,
            include_private,
        )
    }

    /// Return optional inventory, routing and policy metadata for a namespace.
    ///
    /// # Errors
    /// This method currently returns no Python errors; invalid or absent names return `None`.
    fn namespace_info(&self, namespace: &Bound<'_, PyString>) -> PyResult<Option<PyNamespaceInfo>> {
        if python_assessment::character_count(namespace) > crate::normalization::MAX_INPUT_BYTES {
            return Ok(None);
        }
        Ok(namespace
            .to_str()
            .ok()
            .and_then(|value| self.inner.namespace_info(value))
            .map(Into::into))
    }

    /// Return release identity and corpus counts as ordinary Python objects.
    ///
    /// # Errors
    /// Returns a Python allocation or conversion error while constructing output.
    fn dataset_info(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_namespace::dataset(&self.inner, py)
    }

    /// Return precomputed inventory and per-family knowledge counts.
    ///
    /// # Errors
    /// Returns a Python allocation or conversion error while constructing output.
    fn dataset_stats(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_namespace::statistics(&self.inner, py)
    }

    /// Return accepted registrant fields, types and constrained string values.
    ///
    /// # Errors
    /// Returns a Python allocation or conversion error while constructing output.
    fn profile_schema(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_namespace::profile_schema(&self.inner, py)
    }

    /// Look up one source's identity and retrieval provenance by its stable ID.
    ///
    /// # Errors
    /// Returns a Python allocation or conversion error while constructing output.
    fn source(&self, py: Python<'_>, id: &str) -> PyResult<Option<Py<PyAny>>> {
        self.inner
            .source(id)
            .map(|value| python_records::object(py, &python_records::source(value)))
            .transpose()
    }

    /// Look up one evidence assertion's scope and review state by its stable ID.
    ///
    /// # Errors
    /// Returns a Python allocation or conversion error while constructing output.
    fn assertion(&self, py: Python<'_>, id: &str) -> PyResult<Option<Py<PyAny>>> {
        self.inner
            .assertion(id)
            .map(|value| python_records::object(py, &python_records::assertion(value)))
            .transpose()
    }

    /// Return a legacy summary only when complete policy fits the original API.
    ///
    /// # Errors
    /// This method currently returns no Python errors; invalid or absent names return `None`.
    fn tld_info(&self, tld: &Bound<'_, PyString>) -> PyResult<Option<PyTldInfo>> {
        if python_assessment::character_count(tld) > crate::normalization::MAX_INPUT_BYTES {
            return Ok(None);
        }
        Ok(tld
            .to_str()
            .ok()
            .and_then(|value| self.inner.tld_info(value))
            .map(TldRuleSummary::from)
            .map(Into::into))
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
    module.add_class::<PyAssessment>()?;
    module.add_class::<NativePreparedProfile>()?;
    module.add_class::<PyNamespaceInfo>()?;
    Ok(())
}
