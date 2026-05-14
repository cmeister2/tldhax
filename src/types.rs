//! Shared value types used by the registry and Python bindings.

/// Whether registrations are generally available under a TLD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registerable {
    /// The TLD is open for general registration.
    Yes,
    /// The TLD is not open for registration.
    No,
    /// The TLD is registerable only for eligible registrants.
    Restricted,
}

impl Registerable {
    /// Returns the serialized string form used by the CLI and Python API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Restricted => "restricted",
        }
    }
}

/// Why a TLD is closed or restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The TLD is an ICANN Spec 13 brand TLD.
    BrandTld,
    /// The TLD is reserved for infrastructure use.
    Infrastructure,
    /// The TLD is reserved for government use.
    Government,
    /// The TLD has been retired.
    Retired,
}

impl Reason {
    /// Returns the serialized string form used by generated rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BrandTld => "brand_tld",
            Self::Infrastructure => "infrastructure",
            Self::Government => "government",
            Self::Retired => "retired",
        }
    }
}

/// How label length should be measured for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthBasis {
    /// Measure the ASCII/Punycode form of the label.
    Ascii,
    /// Measure the Unicode form of the label.
    Unicode,
}

impl LengthBasis {
    /// Returns the serialized string form used by generated rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Unicode => "unicode",
        }
    }
}

/// Character repertoire allowed by a TLD rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// Only plain ASCII labels are allowed.
    Ascii,
    /// Internationalized labels are allowed.
    Idn,
}

impl Charset {
    /// Returns the serialized string form used by generated rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Idn => "idn",
        }
    }
}

/// A compiled rule describing how labels may be registered under a TLD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TldRule {
    /// The suffix this rule applies to, without a leading dot.
    pub tld: &'static str,
    /// Whether the TLD is open, closed, or eligibility-gated.
    pub registerable: Registerable,
    /// Optional category explaining why a TLD is closed or restricted.
    pub reason: Option<Reason>,
    /// Optional human-readable note shown to callers.
    pub note: Option<&'static str>,
    /// Free-form eligibility restrictions for restricted TLDs.
    pub restrictions: &'static [&'static str],
    /// Minimum allowed label length.
    pub min_length: u8,
    /// Maximum allowed label length.
    pub max_length: u8,
    /// How label length is measured.
    pub length_basis: LengthBasis,
    /// Exact labels that may not be registered.
    pub banned: &'static [&'static str],
    /// Whether ASCII-only or IDN labels are allowed.
    pub charset: Charset,
    /// Additional non-ASCII characters allowed when `charset` is IDN.
    pub idn_chars: &'static str,
    /// Source URLs for each populated field.
    pub sources: &'static [(&'static str, &'static str)],
}

/// The outcome of a registerability check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    /// The domain passes the compiled TLD rule checks.
    Yes,
    /// The domain fails the compiled TLD rule checks.
    No,
    /// The domain may be registerable, but eligibility rules apply.
    Restricted,
    /// The TLD is known or syntactically valid, but no curated policy exists.
    Unknown,
}

impl CheckStatus {
    /// Returns the lowercase status string used by the CLI and Python API.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Restricted => "restricted",
            Self::Unknown => "unknown",
        }
    }

    /// Returns the CLI exit code associated with this status.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Yes => 0,
            Self::No => 1,
            Self::Unknown => 2,
            Self::Restricted => 3,
        }
    }
}

/// A detailed registerability result for a single domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// The overall status derived from syntax and TLD rule checks.
    pub status: CheckStatus,
    /// Human-readable reasons explaining the result.
    pub reasons: Vec<String>,
}

/// Aggregate counts describing the compiled registry contents.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryStats {
    /// Number of curated rules compiled into the binary.
    pub compiled_rules: usize,
    /// Number of known suffixes loaded from the rule corpus.
    pub total_known_suffixes: usize,
    /// Count of rules with `registerable = yes`.
    pub registerable: usize,
    /// Count of rules with `registerable = no`.
    pub not_registerable: usize,
    /// Count of rules with `registerable = restricted`.
    pub restricted: usize,
    /// Percentage of known suffixes with curated rule entries.
    pub coverage_percent: f64,
}

/// Owned summary data for exposing a `TldRule` through Python and the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TldRuleSummary {
    /// The suffix this summary describes, without a leading dot.
    pub tld: String,
    /// String form of the registerability status.
    pub registerable: String,
    /// Optional string form of the rule reason.
    pub reason: Option<String>,
    /// Optional human-readable note.
    pub note: Option<String>,
    /// Human-readable eligibility restrictions.
    pub restrictions: Vec<String>,
    /// Minimum allowed label length.
    pub min_length: u8,
    /// Maximum allowed label length.
    pub max_length: u8,
    /// String form of the length basis.
    pub length_basis: String,
    /// Exact banned labels under the suffix.
    pub banned: Vec<String>,
    /// String form of the allowed charset.
    pub charset: String,
    /// Additional non-ASCII characters allowed for IDN labels.
    pub idn_chars: String,
    /// Source URLs for populated fields.
    pub sources: Vec<(String, String)>,
}

impl From<&TldRule> for TldRuleSummary {
    /// Copies a compiled rule into an owned summary representation.
    fn from(value: &TldRule) -> Self {
        Self {
            tld: value.tld.to_string(),
            registerable: value.registerable.as_str().to_string(),
            reason: value.reason.map(|reason| reason.as_str().to_string()),
            note: value.note.map(ToString::to_string),
            restrictions: value.restrictions.iter().map(|item| (*item).to_string()).collect(),
            min_length: value.min_length,
            max_length: value.max_length,
            length_basis: value.length_basis.as_str().to_string(),
            banned: value.banned.iter().map(|item| (*item).to_string()).collect(),
            charset: value.charset.as_str().to_string(),
            idn_chars: value.idn_chars.to_string(),
            sources: value
                .sources
                .iter()
                .map(|(field, source)| ((*field).to_string(), (*source).to_string()))
                .collect(),
        }
    }
}