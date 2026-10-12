//! Namespace selection and input applicability without runtime policy parsing.

use crate::inventory_types::SpecialUse;
use crate::policy_types::{InputClass, NamespacePolicy, Predicate, SelectorKind};
use crate::resolver::{Resolution, RouteMatch, RouteSection};

/// An authored policy and the candidate spans to which it applies.
pub(crate) struct Selected<'a> {
    /// Immutable authoring record.
    pub policy: &'static NamespacePolicy,
    /// Canonical applicant components preceding that boundary.
    pub applicant: &'a str,
    /// Number of applicant-supplied components.
    pub count: usize,
}

/// Search sorted exact policy selectors.
fn lookup(
    policies: &'static [NamespacePolicy],
    selector: &str,
) -> Option<&'static NamespacePolicy> {
    policies
        .binary_search_by_key(&selector, |policy| policy.selector)
        .ok()
        .map(|index| &policies[index])
}

/// Search a wildcard key without allocating the `*.` prefix.
fn wildcard(policies: &'static [NamespacePolicy], base: &str) -> Option<&'static NamespacePolicy> {
    policies
        .binary_search_by(|policy| {
            policy
                .selector
                .bytes()
                .cmp(b"*.".iter().copied().chain(base.bytes()))
        })
        .ok()
        .map(|index| &policies[index])
}

/// Preserve the accepted reviewed route; otherwise let unknown child policy shadow ancestors.
pub(crate) fn select<'a>(
    name: &'a str,
    resolution: &Resolution<'a>,
    policies: &'static [NamespacePolicy],
) -> Option<Selected<'a>> {
    if let Some(route) = resolution
        .registration
        .filter(|route| route.rule.section == RouteSection::Reviewed)
    {
        return lookup(policies, route.rule.selector).map(|policy| selected(policy, route));
    }
    let mut suffix = name;
    let mut count = 0;
    loop {
        let exact = lookup(policies, suffix).filter(|policy| policy.kind == SelectorKind::Exact);
        let wild = suffix
            .split_once('.')
            .and_then(|(_, base)| wildcard(policies, base))
            .filter(|policy| policy.kind == SelectorKind::Wildcard);
        if let Some(policy) = exact.or(wild) {
            return Some(Selected {
                policy,
                applicant: &name[..name.len().saturating_sub(suffix.len() + 1)],
                count,
            });
        }
        let (_, next) = suffix.split_once('.')?;
        suffix = next;
        count += 1;
    }
}

/// Retain all applicant components when an approved multi-label form overrides discovery.
fn selected<'a>(policy: &'static NamespacePolicy, route: RouteMatch<'a>) -> Selected<'a> {
    Selected {
        policy,
        applicant: route.applicant,
        count: route.applicant_labels,
    }
}

/// Classify only applicant labels; a Unicode suffix never implies an IDN applicant.
pub(crate) fn input_class(applicant: &str) -> InputClass {
    if applicant.split('.').any(|label| label.starts_with("xn--")) {
        InputClass::Idn
    } else {
        InputClass::Ascii
    }
}

/// Determine whether declared facts can affect this finite predicate.
pub(crate) fn has_profile(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::FieldEquals { .. }
        | Predicate::FieldIn { .. }
        | Predicate::NameEqualsField { .. } => true,
        Predicate::All(children) | Predicate::Any(children) => children.iter().any(has_profile),
        Predicate::Not(child) => has_profile(child),
        _ => false,
    }
}

/// Select the longest label-boundary special-use designation.
pub(crate) fn special(name: &str, records: &'static [SpecialUse]) -> Option<&'static SpecialUse> {
    let mut suffix = name;
    loop {
        if let Ok(index) = records.binary_search_by_key(&suffix, |record| record.name) {
            let record = &records[index];
            if suffix == name || record.descendants {
                return Some(record);
            }
        }
        suffix = suffix.split_once('.')?.1;
    }
}
