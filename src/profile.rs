//! Bounded, typed declared registrant facts, prepared once for batch evaluation.

use std::collections::BTreeMap;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::policy_types::{FactKind, FactSchema};

/// Maximum UTF-8 bytes in a serialized registrant profile.
pub const MAX_PROFILE_BYTES: usize = 65_536;
/// Maximum declared fields in one profile.
pub const MAX_PROFILE_FIELDS: usize = 128;
/// Maximum distinct values in one set-valued fact.
pub const MAX_FACT_VALUES: usize = 256;
/// Maximum UTF-8 bytes in one string fact.
pub const MAX_FACT_BYTES: usize = 1_024;

/// A declared fact; an empty set or false is distinct from an omitted field.
#[derive(Clone, PartialEq, Eq)]
pub enum ProfileFact {
    /// A scalar declaration.
    String(String),
    /// An explicit positive or negative declaration.
    Boolean(bool),
    /// Sorted unique declarations supporting membership and alternatives.
    StringSet(Vec<String>),
}

impl std::fmt::Debug for ProfileFact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::String(_) => "String([REDACTED])",
            Self::Boolean(_) => "Boolean([REDACTED])",
            Self::StringSet(_) => "StringSet([REDACTED])",
        })
    }
}

/// Safe profile validation failures, excluding supplied values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    /// A documented byte, field or set budget was exceeded.
    InputLimit,
    /// The JSON is malformed, duplicated, or not an object.
    InvalidJson,
    /// A field has no declared schema in this dataset.
    UnknownField,
    /// A value has the wrong declared type.
    WrongType,
    /// A string is outside the field's documented enumeration.
    InvalidValue,
}

impl ProfileError {
    /// Stable machine-readable code; diagnostic text never prints profile values.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InputLimit => "profile_input_limit",
            Self::InvalidJson => "invalid_profile_json",
            Self::UnknownField => "unknown_profile_field",
            Self::WrongType => "invalid_profile_type",
            Self::InvalidValue => "invalid_profile_value",
        }
    }
}

/// A schema-checked profile; fact contents stay in memory during assessment.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RegistrantProfile {
    /// Only declared schema keys enter this map.
    facts: BTreeMap<String, ProfileFact>,
}

impl std::fmt::Debug for RegistrantProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistrantProfile")
            .field("fields", &self.facts.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl RegistrantProfile {
    /// Parse a flat JSON object using this release's typed field schemas.
    ///
    /// # Errors
    /// Returns a stable error for excess budgets, duplicate/unknown fields,
    /// nested objects, incorrect types or disallowed enumeration values.
    pub fn from_json(input: &str, schemas: &[FactSchema]) -> Result<Self, ProfileError> {
        if input.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::InputLimit);
        }
        let object: ProfileObject =
            serde_json::from_str(input).map_err(|_| ProfileError::InvalidJson)?;
        if object.0.len() > MAX_PROFILE_FIELDS {
            return Err(ProfileError::InputLimit);
        }
        let mut facts = BTreeMap::new();
        for (field, value) in object.0 {
            let schema = schemas
                .iter()
                .find(|schema| schema.field == field)
                .ok_or(ProfileError::UnknownField)?;
            let fact = match (schema.kind, value) {
                (FactKind::Boolean, Value::Bool(value)) => ProfileFact::Boolean(value),
                (FactKind::String, Value::String(value)) => {
                    validate_string(&value, schema)?;
                    ProfileFact::String(value)
                }
                (FactKind::StringSet, Value::Array(values)) => {
                    if values.len() > MAX_FACT_VALUES {
                        return Err(ProfileError::InputLimit);
                    }
                    let mut strings = Vec::with_capacity(values.len());
                    for value in values {
                        let Value::String(value) = value else {
                            return Err(ProfileError::WrongType);
                        };
                        validate_string(&value, schema)?;
                        strings.push(value);
                    }
                    strings.sort();
                    strings.dedup();
                    ProfileFact::StringSet(strings)
                }
                _ => return Err(ProfileError::WrongType),
            };
            facts.insert(field, fact);
        }
        Ok(Self { facts })
    }

    /// Read a fact without conflating missing information with false/empty.
    pub fn get(&self, field: &str) -> Option<&ProfileFact> {
        self.facts.get(field)
    }

    /// Iterate declared field names without exposing values in explanations.
    pub fn fields(&self) -> impl Iterator<Item = &str> {
        self.facts.keys().map(String::as_str)
    }
}

/// Check budgets and explicitly declared enumeration values.
fn validate_string(value: &str, schema: &FactSchema) -> Result<(), ProfileError> {
    if value.len() > MAX_FACT_BYTES {
        return Err(ProfileError::InputLimit);
    }
    if !schema.allowed_values.is_empty() && !schema.allowed_values.contains(&value) {
        return Err(ProfileError::InvalidValue);
    }
    Ok(())
}

/// JSON object parser retaining duplicate-field detection before map insertion.
struct ProfileObject(BTreeMap<String, Value>);

impl<'de> Deserialize<'de> for ProfileObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// An object-only visitor; nested values are rejected by the typed schema.
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = ProfileObject;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a flat object of typed registrant facts")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut fields = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if fields.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate profile field"));
                    }
                }
                Ok(ProfileObject(fields))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
