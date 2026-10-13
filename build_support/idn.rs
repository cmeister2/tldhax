//! Adopted finite IDN tables and ordinary structural validation.

use serde::Deserialize;

/// Adopted character repertoire with finite supported contexts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdnProfile {
    /// Identity referenced directly by a namespace requirement.
    pub id: String,
    /// Whether the listed adopted repertoire is exhaustive.
    #[serde(default = "complete_repertoire")]
    pub repertoire_complete: bool,
    /// Inclusive Unicode scalar intervals.
    pub ranges: Vec<[u32; 2]>,
    /// Finite positional or adjacent-scalar constraints.
    #[serde(default)]
    pub contexts: Vec<Context>,
}

/// Context condition for an included Unicode scalar.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    /// Scalar constrained by this condition.
    pub codepoint: u32,
    /// Required position or immediate neighbors.
    pub condition: Condition,
}

/// Finite contextual checks implemented by the evaluator.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    /// Cannot appear first.
    NotStart,
    /// Cannot appear last.
    NotEnd,
    /// Must follow one of a finite scalar set.
    PrecededBy {
        /// Allowed preceding Unicode scalars.
        values: Vec<u32>,
    },
    /// Must precede one of a finite scalar set.
    FollowedBy {
        /// Allowed following Unicode scalars.
        values: Vec<u32>,
    },
    /// Requires both immediate neighbors.
    Between {
        /// Allowed preceding scalars.
        left: Vec<u32>,
        /// Allowed following scalars.
        right: Vec<u32>,
    },
}

/// Validate scalar ranges and bounded supported context operations.
///
/// # Errors
/// Rejects invalid or overlapping ranges and contexts referencing impossible scalars.
pub fn validate(profile: &mut IdnProfile) -> Result<(), String> {
    if profile.id.trim().is_empty() || profile.ranges.is_empty() {
        return Err("IDN table requires an identity and nonempty repertoire".into());
    }
    profile.ranges.sort_unstable();
    for (index, &[start, end]) in profile.ranges.iter().enumerate() {
        if start > end
            || char::from_u32(start).is_none()
            || char::from_u32(end).is_none()
            || start <= 0xdfff && end >= 0xd800
            || index > 0 && start <= profile.ranges[index - 1][1]
        {
            return Err("invalid or overlapping IDN intervals".into());
        }
    }
    let included = |cp: u32| {
        profile
            .ranges
            .iter()
            .any(|range| range[0] <= cp && cp <= range[1])
    };
    for context in &profile.contexts {
        if !included(context.codepoint) {
            return Err("IDN context outside repertoire".into());
        }
        let sets: Vec<&[u32]> = match &context.condition {
            Condition::NotStart | Condition::NotEnd => Vec::new(),
            Condition::PrecededBy { values } | Condition::FollowedBy { values } => vec![values],
            Condition::Between { left, right } => vec![left, right],
        };
        if sets.iter().any(|set| {
            set.is_empty() || set.len() > 256 || set.iter().any(|cp| char::from_u32(*cp).is_none())
        }) {
            return Err("invalid or unbounded IDN context set".into());
        }
    }
    Ok(())
}

/// Adopted direct table inputs describe complete repertoires unless explicitly marked partial.
fn complete_repertoire() -> bool {
    true
}
