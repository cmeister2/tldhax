//! Optional inventory and evidence presentation without invented policy defaults.
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use pyo3::prelude::*;
use serde_json::{json, Value};

use crate::namespace_info::NamespaceInfo;
use crate::policy_types::RuleEffect;
use crate::python_records::{self as records, family, input_class, knowledge};
use crate::registry::Registry;

#[pyclass(name = "NamespaceInfo", frozen, skip_from_py_object)]
pub struct PyNamespaceInfo {
    inner: NamespaceInfo,
}

impl From<NamespaceInfo> for PyNamespaceInfo {
    fn from(inner: NamespaceInfo) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyNamespaceInfo {
    #[getter]
    fn namespace(&self) -> &str {
        &self.inner.namespace
    }
    #[getter]
    fn policy_selector(&self) -> Option<&'static str> {
        self.inner.policy.map(|policy| policy.selector)
    }
    #[getter]
    fn dataset_version(&self) -> &'static str {
        self.inner.dataset_version
    }
    #[getter]
    fn evaluation_date(&self) -> &'static str {
        self.inner.evaluation_date
    }
    #[getter]
    fn inventory_date(&self) -> &'static str {
        self.inner.inventory_date
    }
    #[getter]
    fn normalization_profile(&self) -> &'static str {
        self.inner.normalization_profile
    }
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        records::object(py, &self.payload())
    }
    fn __repr__(&self) -> String {
        format!(
            "NamespaceInfo(namespace={:?}, policy_selector={:?})",
            self.namespace(),
            self.policy_selector()
        )
    }
}

impl PyNamespaceInfo {
    fn payload(&self) -> Value {
        let value = &self.inner;
        let policy = value.policy.map(|policy| {
            json!({"selector":policy.selector,
            "forms":policy.forms.iter().map(|form|form.roles).collect::<Vec<_>>(),
            "coverage":policy.coverage.iter().map(|coverage|json!({"family":family(coverage.family),
                "ascii":knowledge(coverage.ascii),"idn":knowledge(coverage.idn),
                "evidence_ids":coverage.evidence_ids,"gap":coverage.gap})).collect::<Vec<_>>(),
            "evidence_ids":policy.evidence_ids,"context":policy.context})
        });
        let rules=value.rules.iter().map(|rule|json!({"id":rule.id,"scope":rule.scope,
            "family":family(rule.family),"input_class":input_class(rule.input_class),
            "forms":rule.forms,"code":rule.code,"evidence_ids":rule.evidence_ids,
            "effect":match rule.effect { RuleEffect::Require=>"require",RuleEffect::Deny=>"deny",RuleEffect::Context=>"context" }})).collect::<Vec<_>>();
        json!({"namespace":value.namespace,"root_inventory":value.root_inventory.map(records::root),
            "icann_route":value.icann_route.map(|route|json!({"id":route.id,"selector":route.selector,
                "source_id":route.source_id,"kind":format!("{:?}",route.kind).to_lowercase()})),
            "policy":policy,"rules":rules,"assertions":value.assertions.iter().map(|item|records::assertion(item)).collect::<Vec<_>>(),
            "sources":value.sources.iter().map(|item|records::source(item)).collect::<Vec<_>>(),
            "dataset_version":value.dataset_version,"evaluation_date":value.evaluation_date,
            "inventory_date":value.inventory_date,"normalization_profile":value.normalization_profile})
    }
}

/// Format immutable dataset identity and corpus counts.
///
/// # Errors
/// Returns a Python allocation or conversion error while constructing output.
pub fn dataset(registry: &Registry, py: Python<'_>) -> PyResult<Py<PyAny>> {
    let value = registry.dataset();
    records::object(
        py,
        &json!({"dataset_version":value.version,"evaluation_date":value.evaluation_date,
        "inventory_date":value.inventory_date,"normalization_profile":value.normalization_profile,
        "root_count":value.roots.len(),"namespace_count":value.namespaces.len(),
        "rule_count":value.rules.len(),"source_count":value.sources.len(),
        "assertion_count":value.assertions.len(),"idn_profile_count":value.idn_profiles.len()}),
    )
}

/// Describe accepted profile fields from immutable fact schemas.
///
/// # Errors
/// Returns a Python allocation or conversion error while constructing output.
pub fn profile_schema(registry: &Registry, py: Python<'_>) -> PyResult<Py<PyAny>> {
    use crate::policy_types::{FactKind, FactStringFormat};
    let fields = registry
        .dataset()
        .facts
        .iter()
        .map(|fact| {
            let kind = match fact.kind {
                FactKind::Boolean => "boolean",
                FactKind::String => "string",
                FactKind::StringSet => "string_set",
            };
            let string_format = fact.string_format.map(|format| match format {
                FactStringFormat::UppercaseAlpha2 => "uppercase_alpha2",
            });
            (
                fact.field.to_owned(),
                json!({"type":kind,"allowed_values":fact.allowed_values,
                    "string_format":string_format}),
            )
        })
        .collect();
    records::object(py, &Value::Object(fields))
}

/// Format precomputed coverage counts without scanning namespace policies.
///
/// # Errors
/// Returns a Python allocation or conversion error while constructing output.
pub fn statistics(registry: &Registry, py: Python<'_>) -> PyResult<Py<PyAny>> {
    use crate::registry_stats::KnowledgeCounts;
    fn counts(value: KnowledgeCounts) -> Value {
        json!({"reviewed":value.reviewed,"partial":value.partial,"unknown":value.unknown,
            "conflicting":value.conflicting,"not_applicable":value.not_applicable})
    }
    let value = registry.dataset_stats();
    records::object(
        py,
        &json!({"active_roots":value.active_roots,"known_namespaces":value.known_namespaces,
        "published_namespaces":value.published_namespaces,"compiled_rules":value.compiled_rules,
        "compiled_assertions":value.compiled_assertions,"sources":value.sources,"idn_profiles":value.idn_profiles,
        "reviewed_idn_profiles":value.reviewed_idn_profiles,"partial_idn_profiles":value.partial_idn_profiles,
        "unresolved_legacy_entries":value.unresolved_legacy_entries,"ascii_namespaces":counts(value.ascii_namespaces),
        "idn_namespaces":counts(value.idn_namespaces),"families":value.families.iter().map(|item|json!({"family":family(item.family),"ascii":counts(item.ascii),"idn":counts(item.idn)})).collect::<Vec<_>>(),
        "dataset_version":value.dataset_version,"evaluation_date":value.evaluation_date,
        "inventory_date":value.inventory_date,"normalization_profile":value.normalization_profile}),
    )
}
