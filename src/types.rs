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

/// Aggregate authored-policy counts; inventory membership never approves registration.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryStats {
    /// Number of unique authored direct-policy selectors.
    pub compiled_rules: usize,
    /// Number of authored and discovered namespace identifiers.
    pub total_known_suffixes: usize,
    /// Faithful summaries with a supported unrestricted ASCII scope.
    pub registerable: usize,
    /// Faithful summaries containing an unconditional ASCII prohibition.
    pub not_registerable: usize,
    /// Faithful summaries with supported ASCII scope requiring applicant declarations.
    pub restricted: usize,
    /// Percentage of inventory identifiers with authored direct-policy selectors.
    pub coverage_percent: f64,
}

/// Compatibility namespace metadata derived from direct authored policy.
///
/// Unknown or richer properties remain absent; candidate decisions use `assess`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TldRuleSummary {
    /// Canonical namespace identity.
    pub tld: String,
    /// Broad summary: yes, no, restricted or unknown; not a candidate decision.
    pub registerable: String,
    /// Optional category when the direct policy has a faithful scalar explanation.
    pub reason: Option<String>,
    /// Limits of this compatibility summary.
    pub note: Option<String>,
    /// Applicable declared-applicant requirements described without supplied values.
    pub restrictions: Vec<String>,
    /// Explicit additional registry minimum when representable.
    pub min_length: Option<u16>,
    /// Explicit additional registry maximum when representable.
    pub max_length: Option<u16>,
    /// ASCII or Unicode measurement when all represented bounds agree.
    pub length_basis: Option<String>,
    /// Exact unconditional label reservations, without conditional exceptions.
    pub banned: Vec<String>,
    /// Explicit ASCII-only or supported adopted IDN repertoire when representable.
    pub charset: Option<String>,
    /// Finite non-ASCII characters from an adopted complete repertoire when representable.
    pub idn_chars: Option<String>,
    /// Optional source links retained for interface compatibility; direct checks need no catalogue.
    pub sources: Vec<(String, String)>,
}
