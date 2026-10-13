//! Immutable registration routing, separate from policy and private hosting boundaries.

/// The provenance of a routing rule; PSL discovery does not approve registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSection {
    /// Delegated-root fallback when no ICANN PSL rule applies.
    Inventory,
    /// A routing rule from the pinned ICANN section of the PSL.
    Icann,
    /// Optional hosting-boundary metadata from the pinned PRIVATE section.
    Private,
    /// A namespace with active, evidenced registration forms.
    Reviewed,
}

/// PSL rule semantics, preserved through compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// An exact suffix.
    Exact,
    /// One additional suffix label is matched by `*`.
    Wildcard,
    /// Remove the leftmost matched label from the prevailing suffix.
    Exception,
}

/// One compiled routing selector and its source identity.
#[derive(Debug, Clone, Copy)]
pub struct RouteRule {
    /// Stable selector identity, including its source section.
    pub id: &'static str,
    /// Canonical selector, preserving `*.` or `!` where applicable.
    pub selector: &'static str,
    /// Snapshot source ID, or the `reviewed-policy` provenance marker.
    pub source_id: &'static str,
    /// Routing semantics.
    pub kind: RouteKind,
    /// Discovery, hosting metadata, or reviewed forms.
    pub section: RouteSection,
    /// Accepted applicant-label counts for reviewed forms only.
    pub applicant_label_counts: &'static [u8],
    /// Evidence approving reviewed forms; PSL entries do not imply policy evidence.
    pub evidence_ids: &'static [&'static str],
}

/// One node of the generated reverse-label trie, with contiguous sorted children.
#[derive(Debug, Clone, Copy)]
pub struct RouteNode {
    /// This node's canonical ASCII label; the synthetic root uses an empty string.
    pub label: &'static str,
    /// First child in the static node array.
    pub child_start: u32,
    /// Number of children, sorted by `label`.
    pub child_count: u16,
    /// First terminal rule in the static rule array.
    pub rule_start: u32,
    /// Number of terminal rules.
    pub rule_count: u8,
    /// True only for delegated TLD nodes in the pinned active-root inventory.
    pub active_root: bool,
}

/// A selected routing rule with spans borrowed from the canonical candidate.
#[derive(Debug, Clone, Copy)]
pub struct RouteMatch<'a> {
    /// Actual suffix, including the concrete label matched by a wildcard.
    pub suffix: &'a str,
    /// All applicant-supplied labels before the namespace, in input order.
    pub applicant: &'a str,
    /// Number of applicant-supplied labels; a bare suffix has zero.
    pub applicant_labels: usize,
    /// The selected static rule, preserving wildcard and exception identity.
    pub rule: &'static RouteRule,
}

/// Registration routing and separately retained discovery/hosting boundaries.
#[derive(Debug, Clone, Copy)]
pub struct Resolution<'a> {
    /// Candidate root label, even when absent from the pinned inventory.
    pub root: &'a str,
    /// Root membership reflects the pinned snapshot, never live delegation.
    pub root_known: bool,
    /// Deepest accepted reviewed namespace, otherwise the discovered boundary.
    pub registration: Option<RouteMatch<'a>>,
    /// Prevailing ICANN PSL match, retained even when reviewed forms override it.
    pub icann: Option<RouteMatch<'a>>,
    /// PRIVATE match only when requested; it never changes registration routing.
    pub private: Option<RouteMatch<'a>>,
}

/// A resolver backed solely by generated immutable tables, with no dynamic init.
pub struct Resolver {
    /// Flattened reverse-label nodes, with compiler-validated child ranges.
    nodes: &'static [RouteNode],
    /// Terminal selector records, referenced by contiguous node ranges.
    rules: &'static [RouteRule],
}

impl Resolver {
    /// Construct a resolver from compiler-validated static trie tables.
    pub const fn new(nodes: &'static [RouteNode], rules: &'static [RouteRule]) -> Self {
        Self { nodes, rules }
    }

    /// Resolve a canonical, validated ASCII name without allocating.
    ///
    /// Policy determines whether a discovered namespace accepts the input form.
    /// Only evidenced form counts select a reviewed route ahead of PSL discovery.
    /// Unknown roots retain discovery metadata but have no registration route.
    pub fn resolve<'a>(&self, name: &'a str, include_private: bool) -> Resolution<'a> {
        let root = name.rsplit('.').next().unwrap_or(name);
        let total_labels = name.bytes().filter(|byte| *byte == b'.').count() + 1;
        let mut result = Resolution {
            root,
            root_known: false,
            registration: None,
            icann: None,
            private: None,
        };
        let (mut icann, mut private, mut reviewed, mut fallback) = (None, None, None, None);
        let (mut icann_exception, mut private_exception) = (None, None);
        let (mut node_index, mut start) = (0, name.len());
        for (index, label) in name.rsplit('.').enumerate() {
            start -= label.len();
            let Some(node) = self.nodes.get(node_index) else {
                break;
            };
            let Some(children) = self.nodes.get(
                node.child_start as usize
                    ..node.child_start as usize + usize::from(node.child_count),
            ) else {
                break;
            };
            let Ok(child) = children.binary_search_by(|node| node.label.cmp(label)) else {
                break;
            };
            node_index = node.child_start as usize + child;
            let node = &self.nodes[node_index];
            if index == 0 {
                result.root_known = node.active_root;
            }
            let Some(rules) = self.rules.get(
                node.rule_start as usize..node.rule_start as usize + usize::from(node.rule_count),
            ) else {
                break;
            };
            for rule in rules {
                if rule.section == RouteSection::Private && !include_private {
                    continue;
                }
                let (suffix_start, suffix_labels) = match rule.kind {
                    RouteKind::Exact => (start, index + 1),
                    RouteKind::Wildcard if start > 0 => (
                        name[..start - 1].rfind('.').map_or(0, |dot| dot + 1),
                        index + 2,
                    ),
                    RouteKind::Exception if index > 0 => (start + label.len() + 1, index),
                    _ => continue,
                };
                let matched = RouteMatch {
                    suffix: &name[suffix_start..],
                    applicant: &name[..suffix_start.saturating_sub(1)],
                    applicant_labels: total_labels - suffix_labels,
                    rule,
                };
                match (rule.section, rule.kind) {
                    (RouteSection::Inventory, _) => fallback = Some(matched),
                    (RouteSection::Icann, RouteKind::Exception) => {
                        prefer(&mut icann_exception, matched)
                    }
                    (RouteSection::Private, RouteKind::Exception) => {
                        prefer(&mut private_exception, matched)
                    }
                    (RouteSection::Icann, _) => prefer(&mut icann, matched),
                    (RouteSection::Private, _) => prefer(&mut private, matched),
                    (RouteSection::Reviewed, _)
                        if rule
                            .applicant_label_counts
                            .iter()
                            .any(|count| usize::from(*count) == matched.applicant_labels) =>
                    {
                        prefer(&mut reviewed, matched)
                    }
                    _ => (),
                }
            }
            if start == 0 {
                break;
            }
            start -= 1;
        }
        result.icann = icann_exception.or(icann);
        result.private = private_exception.or(private);
        if result.root_known {
            result.registration = reviewed.or(result.icann).or(fallback);
        }
        result
    }
}

/// Prefer the deepest effective suffix, using exact selectors for equal-length ties.
fn prefer<'a>(selected: &mut Option<RouteMatch<'a>>, candidate: RouteMatch<'a>) {
    let replace = selected.is_none_or(|old| {
        candidate.applicant_labels < old.applicant_labels
            || candidate.applicant_labels == old.applicant_labels
                && candidate.rule.kind == RouteKind::Exact
                && old.rule.kind != RouteKind::Exact
    });
    if replace {
        *selected = Some(candidate);
    }
}

#[cfg(test)]
#[path = "resolver_tests.rs"]
mod tests;
