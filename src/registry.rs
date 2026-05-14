//! Registry lookup and registerability checks.

use crate::checker::validate_ascii_domain;
use crate::types::{
    Charset, CheckResult, CheckStatus, Reason, Registerable, RegistryStats, TldRule,
};
use crate::{TOTAL_KNOWN_SUFFIXES, TLD_RULES};

/// Checks domains against the compiled TLD rule set.
pub struct Registry;

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// Creates a registry backed by the compiled rule tables.
    pub fn new() -> Self {
        Self
    }

    /// Checks whether a domain is registerable under its effective TLD.
    ///
    /// Returns a structured result describing the status and the first failing
    /// rule, or an unknown result when the suffix is known but has no curated
    /// policy entry.
    pub fn check(&self, domain: &str) -> CheckResult {
        // Normalize user input before any structural or policy checks.
        let lowered = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if lowered.is_empty() {
            // Reject empty input before attempting IDNA or PSL parsing.
            return CheckResult {
                status: CheckStatus::No,
                reasons: vec!["DNS syntax: empty domain".to_string()],
            };
        }

        let ascii_domain = match idna::domain_to_ascii(&lowered) {
            Ok(value) => value.to_ascii_lowercase(),
            Err(_) => {
                // Stop immediately when IDNA normalization itself is invalid.
                return CheckResult {
                    status: CheckStatus::No,
                    reasons: vec!["DNS syntax: invalid IDNA input".to_string()],
                };
            }
        };

        if let Err(error) = validate_ascii_domain(&ascii_domain) {
            // Surface the first ASCII DNS syntax violation from the normalized form.
            return CheckResult {
                status: CheckStatus::No,
                reasons: vec![error],
            };
        }

        // Use the PSL to distinguish bare TLDs, registrable domains, and deeper subdomains.
        let Some(suffix) = psl::suffix_str(&ascii_domain) else {
            let candidate = ascii_domain.rsplit('.').next().unwrap_or(&ascii_domain);
            // Unknown suffixes are syntactically valid but outside the compiled corpus.
            return CheckResult {
                status: CheckStatus::Unknown,
                reasons: vec![format!("No data available for TLD '{candidate}'")],
            };
        };

        let Some(registrable_domain) = psl::domain_str(&ascii_domain) else {
            // Bare suffixes do not have a registrable label to validate.
            return CheckResult {
                status: CheckStatus::No,
                reasons: vec![format!(
                    "no registrable label found — '{suffix}' is a TLD, not a domain"
                )],
            };
        };

        if registrable_domain != ascii_domain {
            // Reject deeper names so callers check the registrable domain directly.
            return CheckResult {
                status: CheckStatus::No,
                reasons: vec![format!(
                    "'{ascii_domain}' is a subdomain of '{registrable_domain}' — retry with '{registrable_domain}'"
                )],
            };
        }

        let Some(rule) = TLD_RULES.get(suffix) else {
            // Known suffixes without curated policy remain unknown rather than implicitly allowed.
            return CheckResult {
                status: CheckStatus::Unknown,
                reasons: vec![format!("No data available for TLD '{suffix}'")],
            };
        };

        // From this point onward, enforce the curated rule for the effective TLD.
        let label_ascii = registrable_label(&ascii_domain, suffix);
        let label_unicode = lowered.split('.').next().unwrap_or(&lowered);
        let label_len_ascii = label_ascii.len();
        let label_len_unicode = label_unicode.chars().count();

        let mut reasons = vec!["DNS syntax: ok".to_string()];

        if rule.charset == Charset::Ascii && (label_ascii.starts_with("xn--") || !label_unicode.is_ascii()) {
            // ASCII-only TLDs fail fast on punycode or non-ASCII user input.
            return CheckResult {
                status: CheckStatus::No,
                reasons: vec![format!(
                    "TLD rule: .{} does not support IDN (charset is ASCII only)",
                    rule.tld
                )],
            };
        }

        if rule.charset == Charset::Idn && !rule.idn_chars.is_empty() && !idn_characters_allowed(label_unicode, rule)
        {
            if let Some(offending) = label_unicode
                .chars()
                .find(|character| !character.is_ascii() && !rule.idn_chars.contains(*character))
            {
                // Explain the first disallowed non-ASCII character under the TLD rule.
                return CheckResult {
                    status: CheckStatus::No,
                    reasons: vec![format!(
                        "TLD rule: character '{}' (U+{:04X}) is not allowed under .{} (allowed IDN characters: {})",
                        offending,
                        offending as u32,
                        rule.tld,
                        rule.idn_chars,
                    )],
                };
            }
        }

        if rule.charset == Charset::Idn {
            reasons.push("TLD rule: IDN characters ok".to_string());
        }

        let measured_length = match rule.length_basis {
            crate::types::LengthBasis::Ascii => label_len_ascii,
            crate::types::LengthBasis::Unicode => label_len_unicode,
        };
        if measured_length < rule.min_length as usize {
            // Reject labels that underflow the rule's chosen length metric.
            return CheckResult {
                status: CheckStatus::No,
                reasons: vec![format!(
                    "TLD rule: label too short (min {}, got {}) under .{}",
                    rule.min_length,
                    measured_length,
                    rule.tld,
                )],
            };
        }
        if measured_length > rule.max_length as usize {
            // Reject labels that overflow the rule's chosen length metric.
            return CheckResult {
                status: CheckStatus::No,
                reasons: vec![format!(
                    "TLD rule: label too long (max {}, got {}) under .{}",
                    rule.max_length,
                    measured_length,
                    rule.tld,
                )],
            };
        }
        reasons.push(format!(
            "TLD rule: label length ok ({}-{})",
            rule.min_length, rule.max_length
        ));

        if rule
            .banned
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(label_ascii))
        {
            // Exact banned labels trump the otherwise-valid checks above.
            return CheckResult {
                status: CheckStatus::No,
                reasons: vec![format!(
                    "TLD rule: label '{}' is banned under .{}",
                    label_ascii,
                    rule.tld,
                )],
            };
        }
        reasons.push("TLD rule: label not in banned list".to_string());

        // Map the rule's registerability mode to the public result surface.
        match rule.registerable {
            Registerable::Yes => CheckResult {
                status: CheckStatus::Yes,
                reasons,
            },
            Registerable::Restricted => CheckResult {
                status: CheckStatus::Restricted,
                reasons: vec![restricted_reason(rule)],
            },
            Registerable::No => CheckResult {
                status: CheckStatus::No,
                reasons: vec![closed_reason(rule)],
            },
        }
    }

    /// Looks up the compiled rule for a TLD, if one exists.
    pub fn tld_info(&self, tld: &str) -> Option<&'static TldRule> {
        let normalized = tld.trim().trim_start_matches('.').to_ascii_lowercase();
        TLD_RULES.get(normalized.as_str())
    }

    /// Returns the number of curated rule entries compiled into the registry.
    pub fn rule_count(&self) -> usize {
        TLD_RULES.len()
    }

    /// Returns aggregate counts for the compiled rule set.
    pub fn stats(&self) -> RegistryStats {
        let registerable = TLD_RULES
            .values()
            .filter(|rule| rule.registerable == Registerable::Yes)
            .count();
        let not_registerable = TLD_RULES
            .values()
            .filter(|rule| rule.registerable == Registerable::No)
            .count();
        let restricted = TLD_RULES
            .values()
            .filter(|rule| rule.registerable == Registerable::Restricted)
            .count();
        let coverage_percent = if TOTAL_KNOWN_SUFFIXES == 0 {
            0.0
        } else {
            (self.rule_count() as f64 / TOTAL_KNOWN_SUFFIXES as f64) * 100.0
        };

        RegistryStats {
            compiled_rules: self.rule_count(),
            total_known_suffixes: TOTAL_KNOWN_SUFFIXES,
            registerable,
            not_registerable,
            restricted,
            coverage_percent,
        }
    }
}

/// Extracts the registrable label by removing the matched suffix from a domain.
fn registrable_label<'a>(domain: &'a str, suffix: &str) -> &'a str {
    domain
        .strip_suffix(suffix)
        .and_then(|value| value.strip_suffix('.'))
        .unwrap_or(domain)
}

/// Checks whether all non-ASCII characters in a label are allowed by the TLD rule.
fn idn_characters_allowed(label_unicode: &str, rule: &TldRule) -> bool {
    label_unicode.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || character == '-'
            || rule.idn_chars.contains(character)
    })
}

/// Formats the user-facing reason for a restricted but potentially eligible TLD.
fn restricted_reason(rule: &TldRule) -> String {
    if let Some(note) = rule.note {
        return format!("TLD rule: {note}");
    }

    if rule.restrictions.is_empty() {
        return format!("TLD rule: .{} requires eligibility", rule.tld);
    }

    format!(
        "TLD rule: .{} requires eligibility ({})",
        rule.tld,
        rule.restrictions.join(", "),
    )
}

/// Formats the user-facing reason for a closed or otherwise non-registerable TLD.
fn closed_reason(rule: &TldRule) -> String {
    if let Some(note) = rule.note {
        return format!("TLD rule: {note}");
    }

    match rule.reason {
        Some(Reason::BrandTld) => format!(
            "TLD rule: .{} is a brand TLD (ICANN Spec 13), not open for registration",
            rule.tld
        ),
        Some(Reason::Infrastructure) => {
            format!("TLD rule: .{} is an infrastructure TLD, not open for registration", rule.tld)
        }
        Some(Reason::Government) => {
            format!("TLD rule: .{} is a government TLD, not open for public registration", rule.tld)
        }
        Some(Reason::Retired) => {
            format!("TLD rule: .{} is a retired TLD, not open for registration", rule.tld)
        }
        None => format!("TLD rule: .{} is not open for registration", rule.tld),
    }
}

#[cfg(test)]
mod tests {
    use super::Registry;
    use crate::types::CheckStatus;

    #[test]
    fn known_domains_match_expected_statuses() {
        let registry = Registry::new();
        assert_eq!(registry.check("foo.co.uk").status, CheckStatus::Yes);
        assert_eq!(registry.check("ab.co.uk").status, CheckStatus::No);
        assert_eq!(registry.check("za.sk").status, CheckStatus::No);
        assert_eq!(registry.check("example.google").status, CheckStatus::No);
        assert_eq!(registry.check("example.com").status, CheckStatus::Yes);
        assert_eq!(registry.check("example.test").status, CheckStatus::No);
        assert_eq!(registry.check("something.mo.us").status, CheckStatus::No);
        assert_eq!(registry.check("max.de").status, CheckStatus::Restricted);
    }
}