//! JSON-ready static provenance records for the optional Python boundary.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::{json, Value};

use crate::inventory_types::{RootInventory, SpecialUse};
use crate::policy_types::{EvidenceAssertion, EvidenceSource, InputClass, Knowledge, RuleFamily};

/// Return the stable Python spelling of a policy rule family.
pub fn family(value: RuleFamily) -> &'static str {
    match value {
        RuleFamily::Namespace => "namespace",
        RuleFamily::Length => "length",
        RuleFamily::Characters => "characters",
        RuleFamily::Idn => "idn",
        RuleFamily::Reserved => "reserved",
        RuleFamily::Allocation => "allocation",
        RuleFamily::Access => "access",
        RuleFamily::Eligibility => "eligibility",
    }
}

/// Return the stable Python spelling of an evidence knowledge state.
pub fn knowledge(value: Knowledge) -> &'static str {
    match value {
        Knowledge::Reviewed => "reviewed",
        Knowledge::Partial => "partial",
        Knowledge::Unknown => "unknown",
        Knowledge::Conflicting => "conflicting",
        Knowledge::NotApplicable => "not_applicable",
    }
}

/// Return the stable Python spelling of ASCII, IDN or shared applicability.
pub fn input_class(value: InputClass) -> &'static str {
    match value {
        InputClass::Ascii => "ascii",
        InputClass::Idn => "idn",
        InputClass::Any => "any",
    }
}

/// Copy source identity, retrieval metadata and translation provenance into JSON.
pub fn source(value: &EvidenceSource) -> Value {
    json!({"id":value.id,"publisher":value.publisher,"title":value.title,
        "url":value.url,"fetched_url":value.fetched_url,"sha256":value.sha256,
        "hash_representation":value.hash_representation,"version":value.version,
        "language":value.language,"retrieved_on":value.retrieved_on,
        "translation_of":value.translation_of})
}

/// Copy an evidence assertion, its scope, dates and review state into JSON.
pub fn assertion(value: &EvidenceAssertion) -> Value {
    json!({"id":value.id,"source_id":value.source_id,"locator":value.locator,
        "interpretation":value.interpretation,"operation":value.operation,
        "namespaces":value.namespaces,"forms":value.forms,
        "input_class":input_class(value.input_class),"family":family(value.family),
        "knowledge":knowledge(value.knowledge),"attests_completeness":value.attests_completeness,
        "effective_from":value.effective_from,"applicable_on":value.applicable_on,
        "effective_until":value.effective_until,"reviewer":value.reviewer,
        "reviewed_on":value.reviewed_on,"review_due":value.review_due,
        "active":value.active,"inactive_reason":value.inactive_reason})
}

/// Copy a root's delegation and operator facts with their source references.
pub fn root(value: &RootInventory) -> Value {
    json!({"tld":value.tld,"kind":value.kind,"operator":value.operator,
        "delegation_url":value.delegation_url,"icann_operator":value.icann_operator,
        "specification13":value.specification13,"contract_terminated":value.contract_terminated,
        "delegation_date":value.delegation_date,"removal_date":value.removal_date,
        "third_or_lower_level_registration":value.third_or_lower_level_registration,
        "source_ids":value.source_ids})
}

/// Copy a special-use designation and the references defining its scope.
pub fn special(value: &SpecialUse) -> Value {
    json!({"name":value.name,"descendants":value.descendants,"deprecated":value.deprecated,
        "purpose":value.purpose,"references":value.references,"source_id":value.source_id})
}

/// Convert only owned JSON-safe results, never prepared profile contents.
///
/// # Errors
/// Returns a Python allocation or conversion error while constructing output.
pub fn object(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    Ok(match value {
        Value::Null => py.None(),
        Value::Bool(value) => value.into_pyobject(py)?.to_owned().into_any().unbind(),
        Value::String(value) => value.into_pyobject(py)?.into_any().unbind(),
        Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                integer.into_pyobject(py)?.into_any().unbind()
            } else if let Some(integer) = value.as_u64() {
                integer.into_pyobject(py)?.into_any().unbind()
            } else {
                value
                    .as_f64()
                    .unwrap_or_default()
                    .into_pyobject(py)?
                    .into_any()
                    .unbind()
            }
        }
        Value::Array(values) => {
            let values = values
                .iter()
                .map(|value| object(py, value))
                .collect::<PyResult<Vec<_>>>()?;
            PyList::new(py, values)?.into_any().unbind()
        }
        Value::Object(values) => {
            let result = PyDict::new(py);
            for (key, value) in values {
                result.set_item(key, object(py, value)?)?;
            }
            result.into_any().unbind()
        }
    })
}
