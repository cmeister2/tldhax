//! Registration decisions and useful direct explanations.

/// Prospective registration against supported static rules and declared facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The applicable supported policy passes for the name and declarations.
    Yes,
    /// An established applicable requirement fails.
    No,
    /// Unsupported policy, an unimplemented condition or a missing fact prevents a decision.
    Unknown,
}

impl Decision {
    /// Stable lowercase representation shared by all interfaces.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Unknown => "unknown",
        }
    }
}

/// One actionable failure or unresolved requirement, without profile values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// Stable machine-readable reason identifier.
    pub code: String,
    /// Description of the unmet or unresolved requirement.
    pub message: String,
}

/// Owned registration assessment which can outlive the supplied domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// Single combined registration decision.
    pub decision: Decision,
    /// Canonical ASCII identity, absent when name processing fails.
    pub canonical_domain: Option<String>,
    /// Candidate's registration namespace, when identifiable.
    pub namespace: Option<String>,
    /// Direct failures or missing-information explanations.
    pub reasons: Vec<Reason>,
    /// Sorted fields needed by unresolved applicable expressions.
    pub missing_profile_fields: Vec<String>,
}

/// An implementation budget failure, separate from policy rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    /// Domain input exceeds the normalizer's preprocessing byte budget.
    InputLimit,
}

impl InputError {
    /// Stable input-error code.
    pub const fn code(self) -> &'static str {
        "input_limit"
    }
}

impl std::fmt::Display for InputError {
    /// Explain the implementation limit without repeating the supplied input.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Domain exceeds 4096 UTF-8 bytes")
    }
}

impl std::error::Error for InputError {}
