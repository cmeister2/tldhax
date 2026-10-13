//! Registration namespace routing over direct policies and ordinary suffix selectors.

use crate::policy_types::{NamespacePolicy, SelectorKind};

/// Public suffix selector semantics used to discover an unknown policy boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// The selector names an exact namespace.
    Exact,
    /// One additional label forms the namespace.
    Wildcard,
    /// The leftmost selector label is excluded from the namespace.
    Exception,
}

/// One routing selector; routing alone never establishes registration permission.
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// Canonical selector including an optional wildcard or exception prefix.
    pub selector: &'static str,
    /// How this selector affects the namespace boundary.
    pub kind: RouteKind,
}

/// The selected registration form, borrowing candidate label spans.
#[derive(Debug, Clone, Copy)]
pub struct Resolution<'a> {
    /// Whether the final label belongs to the compiled delegated-root list.
    pub root_known: bool,
    /// Selected concrete namespace, including a wildcard's matched label.
    pub namespace: Option<&'a str>,
    /// Candidate components before the selected namespace.
    pub applicant: &'a str,
    /// Number of applicant-supplied components.
    pub applicant_labels: usize,
    /// Direct policy for the matching registration form, when implemented.
    pub policy: Option<&'static NamespacePolicy>,
}

/// Immutable registration resolver with no runtime parsing or initialization.
pub struct Resolver {
    /// Direct policies that explicitly establish registration forms.
    policies: &'static [NamespacePolicy],
    /// Canonical roots sorted lexicographically.
    roots: &'static [&'static str],
    /// Public suffix selectors sorted lexicographically by selector.
    routes: &'static [Route],
}

impl Resolver {
    /// Construct a resolver from compiler-validated static inputs.
    pub const fn new(
        policies: &'static [NamespacePolicy],
        roots: &'static [&'static str],
        routes: &'static [Route],
    ) -> Self {
        Self {
            policies,
            roots,
            routes,
        }
    }

    /// Resolve a canonical name to an explicit policy or a discovery boundary.
    ///
    /// Only a matching documented registration form selects a policy. Unknown
    /// forms retain their boundary without inheriting a different form's policy.
    pub fn resolve<'a>(&self, name: &'a str) -> Resolution<'a> {
        let root = name.rsplit('.').next().unwrap_or(name);
        let root_known = self.roots.binary_search(&root).is_ok();
        let total_labels = name.bytes().filter(|byte| *byte == b'.').count() + 1;
        let mut result = Resolution {
            root_known,
            namespace: root_known.then_some(root),
            applicant: name,
            applicant_labels: total_labels,
            policy: None,
        };
        if !root_known {
            return result;
        }
        let mut suffix = name;
        let mut exception = None;
        loop {
            if self.has_route("", suffix, RouteKind::Exact) {
                select_deeper(&mut result.namespace, suffix);
            }
            if self.has_route("*.", suffix, RouteKind::Wildcard) {
                if let Some(concrete) = preceding_label(name, suffix) {
                    select_deeper(&mut result.namespace, concrete);
                }
            }
            if self.has_route("!", suffix, RouteKind::Exception) {
                if let Some((_, parent)) = suffix.split_once('.') {
                    if exception.is_none_or(|previous: &str| suffix.len() > previous.len()) {
                        exception = Some(suffix);
                        result.namespace = Some(parent);
                    }
                }
            }
            let Some((_, parent)) = suffix.split_once('.') else {
                break;
            };
            suffix = parent;
        }
        // A prevailing exception overrides exact and wildcard discovery rules.
        if let Some(exception) = exception {
            result.namespace = exception.split_once('.').map(|(_, parent)| parent);
        }
        for policy in self.policies {
            let namespace = match policy.kind {
                SelectorKind::Exact => matches_suffix(name, policy.selector),
                SelectorKind::Wildcard => policy
                    .selector
                    .strip_prefix("*.")
                    .and_then(|base| matches_suffix(name, base))
                    .and_then(|base| preceding_label(name, base)),
            };
            let Some(namespace) = namespace else { continue };
            // A PSL exception is outside the corresponding wildcard namespace.
            if policy.kind == SelectorKind::Wildcard && exception == Some(namespace) {
                continue;
            }
            let applicant = before_namespace(name, namespace);
            let count = if applicant.is_empty() {
                0
            } else {
                applicant.bytes().filter(|byte| *byte == b'.').count() + 1
            };
            if count != policy.form.len() {
                continue;
            }
            let preferred = result.policy.is_none_or(|previous| {
                let previous_depth = previous.selector.split('.').count();
                let depth = policy.selector.split('.').count();
                depth > previous_depth
                    || (depth == previous_depth
                        && policy.kind == SelectorKind::Exact
                        && previous.kind == SelectorKind::Wildcard)
            });
            if preferred {
                result.namespace = Some(namespace);
                result.policy = Some(policy);
            }
        }
        if let Some(namespace) = result.namespace {
            result.applicant = before_namespace(name, namespace);
            result.applicant_labels = if result.applicant.is_empty() {
                0
            } else {
                result
                    .applicant
                    .bytes()
                    .filter(|byte| *byte == b'.')
                    .count()
                    + 1
            };
        }
        result
    }

    /// Look up a virtual prefixed selector without allocating a query string.
    fn has_route(&self, prefix: &str, suffix: &str, kind: RouteKind) -> bool {
        self.routes
            .binary_search_by(|route| {
                route
                    .selector
                    .bytes()
                    .cmp(prefix.bytes().chain(suffix.bytes()))
            })
            .is_ok_and(|index| self.routes[index].kind == kind)
    }
}

/// Return the candidate's suffix only when the selector matches whole labels.
fn matches_suffix<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let start = name.len().checked_sub(suffix.len())?;
    (name.get(start..) == Some(suffix) && (start == 0 || name.as_bytes()[start - 1] == b'.'))
        .then(|| &name[start..])
}

/// Include the candidate component immediately before a matched suffix.
fn preceding_label<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let start = name.len().checked_sub(suffix.len() + 1)?;
    let previous = name[..start].rfind('.').map_or(0, |dot| dot + 1);
    Some(&name[previous..])
}

/// Return all candidate components before the concrete namespace.
fn before_namespace<'a>(name: &'a str, namespace: &str) -> &'a str {
    let end = name.len() - namespace.len();
    &name[..end.saturating_sub(1)]
}

/// Prefer the most specific discovered namespace.
fn select_deeper<'a>(selected: &mut Option<&'a str>, candidate: &'a str) {
    if selected.is_none_or(|previous| candidate.len() > previous.len()) {
        *selected = Some(candidate);
    }
}

#[cfg(test)]
#[path = "resolver_tests.rs"]
mod tests;
