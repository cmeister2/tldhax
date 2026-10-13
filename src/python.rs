//! PyO3 bindings exposing the Rust registry API to Python.

use std::collections::BTreeMap;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use crate::python_assessment::{self, NativePreparedProfile, PyAssessment};
use crate::python_namespace::{self, PyNamespaceInfo};
use crate::python_records;
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

    fn prepare_registrant(
        &self,
        profile_json: &Bound<'_, PyString>,
    ) -> PyResult<NativePreparedProfile> {
        python_assessment::prepare(&self.inner, profile_json)
    }

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

    fn dataset_info(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_namespace::dataset(&self.inner, py)
    }

    fn dataset_stats(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_namespace::statistics(&self.inner, py)
    }

    fn profile_schema(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_namespace::profile_schema(&self.inner, py)
    }

    fn source(&self, py: Python<'_>, id: &str) -> PyResult<Option<Py<PyAny>>> {
        self.inner
            .source(id)
            .map(|value| python_records::object(py, &python_records::source(value)))
            .transpose()
    }

    fn assertion(&self, py: Python<'_>, id: &str) -> PyResult<Option<Py<PyAny>>> {
        self.inner
            .assertion(id)
            .map(|value| python_records::object(py, &python_records::assertion(value)))
            .transpose()
    }

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
    module.add_class::<PyAssessment>()?;
    module.add_class::<NativePreparedProfile>()?;
    module.add_class::<PyNamespaceInfo>()?;
    Ok(())
}
