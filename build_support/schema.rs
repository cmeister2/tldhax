//! Versioned evidence and namespace authoring, separate from legacy claims.

use serde::Deserialize;

use super::idn_schema::IdnProfile;
use super::predicates::{Fact, Predicate};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Knowledge {
    Reviewed,
    Partial,
    Unknown,
    Conflicting,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Namespace,
    Length,
    Characters,
    Idn,
    Reserved,
    Allocation,
    Access,
    Eligibility,
}

pub const FAMILIES: [Family; 8] = [
    Family::Namespace,
    Family::Length,
    Family::Characters,
    Family::Idn,
    Family::Reserved,
    Family::Allocation,
    Family::Access,
    Family::Eligibility,
];

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Ascii,
    Idn,
    Any,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Require,
    Deny,
    Context,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub publisher: String,
    pub title: String,
    pub url: String,
    pub fetched_url: String,
    pub sha256: String,
    #[serde(default = "original_bytes")]
    pub hash_representation: String,
    pub version: String,
    pub language: String,
    pub retrieved_on: String,
    pub snapshot_path: Option<String>,
    pub translation_of: Option<String>,
}

fn original_bytes() -> String {
    "original_bytes".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub id: String,
    pub source_id: String,
    pub locator: String,
    pub operation: String,
    pub namespaces: Vec<String>,
    pub forms: Vec<u8>,
    pub input_class: Class,
    pub family: Family,
    pub effect: Effect,
    pub knowledge: Knowledge,
    #[serde(default)]
    pub attests_completeness: bool,
    pub interpretation: String,
    pub reviewer: String,
    pub reviewed_on: String,
    pub review_due: String,
    pub effective_from: Option<String>,
    pub applicable_on: Option<String>,
    pub effective_until: Option<String>,
    pub predicate: Option<Predicate>,
    pub code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub family: Family,
    pub ascii: Knowledge,
    pub idn: Knowledge,
    #[serde(default)]
    pub assertion_ids: Vec<String>,
    pub gap: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    pub replaces: String,
    pub with: String,
    pub reason: String,
    pub assertion_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub selector: String,
    #[serde(default)]
    pub forms: Vec<Vec<String>>,
    #[serde(default)]
    pub form_assertion_ids: Vec<String>,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub overrides: Vec<Override>,
    #[serde(default)]
    pub coverage: Vec<Coverage>,
    #[serde(default)]
    pub context: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub applicability: Vec<String>,
    pub applicability_assertions: Vec<String>,
    #[serde(default)]
    pub extends: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub coverage: Vec<Coverage>,
    #[serde(default)]
    pub context: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelSet {
    pub id: String,
    pub labels: Vec<String>,
    pub assertion_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Document {
    pub sources: Vec<Source>,
    pub assertions: Vec<Assertion>,
    pub namespaces: Vec<Namespace>,
    pub profiles: Vec<Profile>,
    pub label_sets: Vec<LabelSet>,
    pub idn_profiles: Vec<IdnProfile>,
    pub facts: Vec<Fact>,
    pub legacy: Vec<LegacyResearch>,
}

#[derive(Debug, Clone)]
pub struct LegacyResearch {
    pub selector: String,
    pub source_links: Vec<String>,
    pub provenance: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    pub schema_version: u16,
    pub sources: Vec<Source>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionFile {
    pub schema_version: u16,
    pub assertions: Vec<Assertion>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringFile {
    pub schema_version: u16,
    #[serde(default)]
    pub namespaces: Vec<Namespace>,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub label_sets: Vec<LabelSet>,
    #[serde(default)]
    pub idn_profiles: Vec<IdnProfile>,
    #[serde(default)]
    pub facts: Vec<Fact>,
}
