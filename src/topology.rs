//! Public Suffix List resolution against the pinned, generated snapshot.

use crate::generated::{PSL_EXACT, PSL_EXCEPTION, PSL_WILDCARD};
use crate::types::{CandidateStatus, SuffixMatch, SuffixRule, SuffixRuleKind};

/// A candidate's registration boundary and structural relationship to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedDomain {
    /// Prevailing public-suffix boundary.
    pub(crate) suffix: SuffixMatch,
    /// One-label-above registrable domain, when the candidate has one.
    pub(crate) registrable_domain: Option<String>,
    /// Whether the input is the registrable domain, a suffix, or a subdomain.
    pub(crate) candidate_status: CandidateStatus,
}

/// Resolves a canonical ASCII domain using the exact vendored PSL snapshot.
pub(crate) fn resolve_domain(ascii_domain: &str) -> ResolvedDomain {
    let labels = ascii_domain.split('.').collect::<Vec<_>>();
    let suffix = resolve_suffix_labels(&labels);
    let suffix_labels = suffix.suffix.split('.').count();

    let registrable_domain = (labels.len() > suffix_labels)
        .then(|| labels[labels.len() - suffix_labels - 1..].join("."));
    let candidate_status = match labels.len().cmp(&suffix_labels) {
        std::cmp::Ordering::Less | std::cmp::Ordering::Equal => CandidateStatus::BareSuffix,
        std::cmp::Ordering::Greater if labels.len() == suffix_labels + 1 => {
            CandidateStatus::RegistrableDomain
        }
        std::cmp::Ordering::Greater => CandidateStatus::Subdomain,
    };

    ResolvedDomain {
        suffix,
        registrable_domain,
        candidate_status,
    }
}

/// Resolves a canonical suffix or domain without applying product policy.
pub(crate) fn resolve_suffix(ascii_name: &str) -> SuffixMatch {
    let labels = ascii_name.split('.').collect::<Vec<_>>();
    resolve_suffix_labels(&labels)
}

/// Finds the prevailing exact, wildcard, exception, or implicit PSL rule.
fn resolve_suffix_labels(labels: &[&str]) -> SuffixMatch {
    debug_assert!(!labels.is_empty());

    // PSL exceptions take precedence over every ordinary match. The public
    // suffix is the exception with its leftmost label removed.
    for index in 0..labels.len() {
        let candidate = labels[index..].join(".");
        if let Some(rule) = PSL_EXCEPTION.get(candidate.as_str()) {
            let suffix = labels[index + 1..].join(".");
            return suffix_match(suffix, format!("!{}", rule.labels), rule);
        }
    }

    let mut best: Option<(usize, bool, String, &'static SuffixRule)> = None;
    for index in 0..labels.len() {
        let candidate = labels[index..].join(".");
        let label_count = labels.len() - index;

        if let Some(rule) = PSL_EXACT.get(candidate.as_str()) {
            replace_if_better(&mut best, label_count, true, candidate.clone(), rule);
        }

        if index + 1 < labels.len() {
            let anchor = labels[index + 1..].join(".");
            if let Some(rule) = PSL_WILDCARD.get(anchor.as_str()) {
                replace_if_better(&mut best, label_count, false, candidate, rule);
            }
        }
    }

    if let Some((_length, exact, suffix, rule)) = best {
        let matched_rule = if exact {
            rule.labels.to_string()
        } else {
            format!("*.{}", rule.labels)
        };
        return suffix_match(suffix, matched_rule, rule);
    }

    SuffixMatch {
        suffix: labels.last().expect("non-empty labels").to_string(),
        matched_rule: None,
        rule_kind: SuffixRuleKind::Default,
        section: None,
        role: None,
        evidence: None,
    }
}

/// Keeps the longest rule and prefers exact syntax for an equal-length match.
fn replace_if_better(
    best: &mut Option<(usize, bool, String, &'static SuffixRule)>,
    label_count: usize,
    exact: bool,
    suffix: String,
    rule: &'static SuffixRule,
) {
    let should_replace = best.as_ref().is_none_or(|(best_count, best_exact, _, _)| {
        label_count > *best_count || (label_count == *best_count && exact && !*best_exact)
    });
    if should_replace {
        *best = Some((label_count, exact, suffix, rule));
    }
}

/// Copies source-rule metadata into an owned match.
fn suffix_match(suffix: String, matched_rule: String, rule: &SuffixRule) -> SuffixMatch {
    SuffixMatch {
        suffix,
        matched_rule: Some(matched_rule),
        rule_kind: rule.kind,
        section: Some(rule.section),
        role: Some(rule.role),
        evidence: Some(rule.evidence),
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_domain;
    use crate::types::{CandidateStatus, PslSection, SuffixRuleKind};

    #[test]
    fn exact_rule_resolves_registration_boundary() {
        let resolved = resolve_domain("example.co.uk");
        assert_eq!(resolved.suffix.suffix, "co.uk");
        assert_eq!(resolved.suffix.rule_kind, SuffixRuleKind::Exact);
        assert_eq!(resolved.suffix.section, Some(PslSection::Icann));
        assert_eq!(resolved.suffix.evidence, Some("psl"));
        assert_eq!(
            resolved.registrable_domain.as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            resolved.candidate_status,
            CandidateStatus::RegistrableDomain
        );
    }

    #[test]
    fn wildcard_rule_uses_the_matching_concrete_label() {
        let resolved = resolve_domain("bar.foo.ck");
        assert_eq!(resolved.suffix.suffix, "foo.ck");
        assert_eq!(resolved.suffix.matched_rule.as_deref(), Some("*.ck"));
        assert_eq!(resolved.suffix.rule_kind, SuffixRuleKind::Wildcard);
        assert_eq!(resolved.registrable_domain.as_deref(), Some("bar.foo.ck"));
    }

    #[test]
    fn exception_removes_its_leftmost_label() {
        let resolved = resolve_domain("foo.www.ck");
        assert_eq!(resolved.suffix.suffix, "ck");
        assert_eq!(resolved.suffix.matched_rule.as_deref(), Some("!www.ck"));
        assert_eq!(resolved.suffix.rule_kind, SuffixRuleKind::Exception);
        assert_eq!(resolved.registrable_domain.as_deref(), Some("www.ck"));
        assert_eq!(resolved.candidate_status, CandidateStatus::Subdomain);
    }

    #[test]
    fn private_rules_retain_their_section() {
        let resolved = resolve_domain("alice.github.io");
        assert_eq!(resolved.suffix.suffix, "github.io");
        assert_eq!(resolved.suffix.section, Some(PslSection::Private));
    }
}
