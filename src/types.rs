//! Small compatibility result for the original profile-free check entry point.

/// Outcome of a profile-free registration check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// The applicable supported policy passes.
    Yes,
    /// An established name or profile requirement fails.
    No,
    /// Missing policy or profile information prevents a decision.
    Unknown,
}

impl CheckStatus {
    /// Lowercase status used by the compatibility API.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Unknown => "unknown",
        }
    }
}

/// Profile-free compatibility assessment with direct explanation text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// Combined decision for this candidate.
    pub status: CheckStatus,
    /// Human-readable unmet or unresolved conditions.
    pub reasons: Vec<String>,
}
