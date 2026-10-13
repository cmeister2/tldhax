//! Finite adopted IDN profiles; unsupported table features remain explicit gaps.

use super::schema::Knowledge;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Finite IDN table with explicit namespace adoption, applicability and review state.
///
/// Unsupported features remain gaps even when the known repertoire is complete.
pub struct IdnProfile {
    /// Stable table identity referenced by IDN predicates.
    pub id: String,
    /// Version identifying the adopted publisher table.
    pub version: String,
    /// Review state, downgraded to partial when unsupported features remain.
    pub knowledge: Knowledge,
    #[serde(default)]
    /// Explicit attestation that the finite ranges cover the adopted repertoire.
    pub repertoire_complete: bool,
    /// Namespace selectors in which this table is explicitly adopted.
    pub namespaces: Vec<String>,
    /// Assertions supporting the table contents and repertoire.
    pub assertion_ids: Vec<String>,
    /// Assertions proving namespace and registration-form adoption.
    pub adoption_assertion_ids: Vec<String>,
    /// Optional inclusive commencement date of the table applicability.
    pub effective_from: Option<String>,
    /// Optional date attesting that this table was applicable.
    pub applicable_on: Option<String>,
    /// Optional exclusive end date of table applicability.
    pub effective_until: Option<String>,
    /// Inclusive Unicode scalar intervals, sorted and checked for overlap.
    pub ranges: Vec<[u32; 2]>,
    #[serde(default)]
    /// Additional conditions on included code points.
    pub contexts: Vec<Context>,
    #[serde(default)]
    /// Published finite variant relationships retained as allocation gaps.
    pub variants: Vec<Variant>,
    #[serde(default)]
    /// Unsupported table semantics that prevent fully reviewed enforcement.
    pub unsupported_features: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Additional positioning or adjacency condition for one repertoire code point.
pub struct Context {
    /// Repertoire scalar to which the context condition applies.
    pub codepoint: u32,
    /// Position or immediate-neighbor condition required for this scalar.
    pub condition: Condition,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Finite positioning and neighboring-code-point conditions.
pub enum Condition {
    /// The code point cannot begin the label.
    NotStart,
    /// The code point cannot end the label.
    NotEnd,
    /// The previous scalar must belong to the finite values set.
    PrecededBy {
        /// Allowed immediate predecessor Unicode scalars.
        values: Vec<u32>,
    },
    /// The next scalar must belong to the finite values set.
    FollowedBy {
        /// Allowed immediate successor Unicode scalars.
        values: Vec<u32>,
    },
    /// Both immediate neighbors must belong to their respective sets.
    Between {
        /// Allowed immediate predecessor Unicode scalars.
        left: Vec<u32>,
        /// Allowed immediate successor Unicode scalars.
        right: Vec<u32>,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Published treatment of a variant relationship; allocation remains unresolved.
pub enum Disposition {
    /// The published variant is blocked.
    Blocked,
    /// Variant treatment depends on additional allocation conditions.
    Conditional,
    /// The available source does not resolve variant treatment.
    Unresolved,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Finite sequence replacement retained without inferring registration availability.
pub struct Variant {
    /// Source scalar sequence whose variant relationship is described.
    pub sequence: String,
    /// Published replacement scalar sequence.
    pub replacement: String,
    /// Published treatment of the replacement relationship.
    pub disposition: Disposition,
}
