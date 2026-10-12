//! Finite adopted IDN profiles; unsupported table features remain explicit gaps.

use super::schema::Knowledge;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdnProfile {
    pub id: String,
    pub version: String,
    pub knowledge: Knowledge,
    #[serde(default)]
    pub repertoire_complete: bool,
    pub namespaces: Vec<String>,
    pub assertion_ids: Vec<String>,
    pub adoption_assertion_ids: Vec<String>,
    pub effective_from: Option<String>,
    pub applicable_on: Option<String>,
    pub effective_until: Option<String>,
    pub ranges: Vec<[u32; 2]>,
    #[serde(default)]
    pub contexts: Vec<Context>,
    #[serde(default)]
    pub variants: Vec<Variant>,
    #[serde(default)]
    pub unsupported_features: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub codepoint: u32,
    pub condition: Condition,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    NotStart,
    NotEnd,
    PrecededBy { values: Vec<u32> },
    FollowedBy { values: Vec<u32> },
    Between { left: Vec<u32>, right: Vec<u32> },
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Blocked,
    Conditional,
    Unresolved,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    pub sequence: String,
    pub replacement: String,
    pub disposition: Disposition,
}
