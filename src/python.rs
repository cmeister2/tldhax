//! PyO3 bindings exposing the Rust registry API to Python.

use std::collections::BTreeMap;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::registry::Registry as RustRegistry;
use crate::types::{CheckResult, RegistryStats, TldRuleSummary};

#[pyclass(name = "CheckResult", skip_from_py_object)]
#[derive(Clone)]
pub struct PyCheckResult {
    #[pyo3(get)]
    pub status: String,
    #[pyo3(get)]
    pub reasons: Vec<String>,
}

#[pymethods]
impl PyCheckResult {
    fn __repr__(&self) -> String {
        format!(
            "CheckResult(status='{}', reasons={:?})",
            self.status, self.reasons
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

impl From<CheckResult> for PyCheckResult {
    fn from(value: CheckResult) -> Self {
        Self {
            status: value.status.as_str().to_string(),
            reasons: value.reasons,
        }
    }
}

#[pyclass(name = "TldInfo", skip_from_py_object)]
#[derive(Clone)]
pub struct PyTldInfo {
    #[pyo3(get)]
    pub tld: String,
    #[pyo3(get)]
    pub registerable: String,
    #[pyo3(get)]
    pub reason: Option<String>,
    #[pyo3(get)]
    pub note: Option<String>,
    #[pyo3(get)]
    pub restrictions: Vec<String>,
    #[pyo3(get)]
    pub min_length: u8,
    #[pyo3(get)]
    pub max_length: u8,
    #[pyo3(get)]
    pub length_basis: String,
    #[pyo3(get)]
    pub banned: Vec<String>,
    #[pyo3(get)]
    pub charset: String,
    #[pyo3(get)]
    pub idn_chars: String,
    pub sources: BTreeMap<String, String>,
}

#[pymethods]
impl PyTldInfo {
    #[getter]
    fn sources<'py>(&self, py: Python<'py>) -> Bound<'py, PyDict> {
        let dict = PyDict::new(py);
        for (field, source) in &self.sources {
            dict.set_item(field, source)
                .expect("failed to set source item");
        }
        dict
    }

    fn __repr__(&self) -> String {
        format!(
            "TldInfo(tld='{}', registerable='{}')",
            self.tld, self.registerable
        )
    }
}

impl From<TldRuleSummary> for PyTldInfo {
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

#[pyclass(name = "Registry")]
pub struct PyRegistry {
    inner: RustRegistry,
}

#[pymethods]
impl PyRegistry {
    #[new]
    fn new() -> Self {
        Self {
            inner: RustRegistry::new(),
        }
    }

    fn check(&self, domain: &str) -> PyCheckResult {
        self.inner.check(domain).into()
    }

    fn tld_info(&self, tld: &str) -> Option<PyTldInfo> {
        self.inner
            .tld_info(tld)
            .map(TldRuleSummary::from)
            .map(Into::into)
    }

    fn rule_count(&self) -> usize {
        self.inner.rule_count()
    }

    fn stats<'py>(&self, py: Python<'py>) -> Bound<'py, PyDict> {
        registry_stats_to_dict(py, self.inner.stats())
    }
}

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

#[pymodule]
pub fn _native(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyRegistry>()?;
    module.add_class::<PyCheckResult>()?;
    module.add_class::<PyTldInfo>()?;
    Ok(())
}
