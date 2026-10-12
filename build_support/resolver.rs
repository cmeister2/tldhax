//! Generate immutable routing tables from pinned, validated inventory artifacts.
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

/// Active reviewed registration forms; the policy compiler approves these records.
pub struct Supplement<'a> {
    /// Exact or single-wildcard namespace selector.
    pub selector: &'a str,
    /// Assertions approving these registration shapes.
    pub evidence_ids: &'a [&'a str],
    /// Applicant-label counts in the accepted forms, before the actual namespace.
    pub applicant_label_counts: &'a [u8],
}

#[derive(Deserialize)]
struct Roots {
    schema_version: u8,
    roots: Vec<Root>,
}
#[derive(Deserialize)]
struct Root {
    tld: String,
    active: bool,
    inventory_state: String,
}
#[derive(Deserialize)]
struct Psl {
    schema_version: u8,
    rules: Vec<PslRule>,
}
#[derive(Deserialize)]
struct PslRule {
    rule: String,
    suffix: String,
    kind: String,
    section: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Rule {
    section: &'static str,
    kind: &'static str,
    suffix: String,
    selector: String,
    source_id: &'static str,
    evidence: Vec<String>,
    counts: Vec<u8>,
}

#[derive(Default)]
struct Node {
    label: String,
    children: BTreeMap<String, usize>,
    rules: Vec<usize>,
    active_root: bool,
}

/// Use the same Rust normalisation contract as runtime, with stricter key framing.
fn canonical(name: &str) -> Result<String, String> {
    if name.is_empty()
        || name.trim() != name
        || name.ends_with(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}'])
    {
        return Err("routing keys require nonempty names without padding or a root dot".into());
    }
    crate::normalization::normalize(name)
        .map(|name| name.ascii().to_owned())
        .map_err(|error| format!("invalid routing key {name:?}: {}", error.code()))
}

/// Canonicalise a selector while checking its declared PSL rule kind.
fn selector(raw: &str, kind: &str) -> Result<(String, String), String> {
    let (prefix, body) = match kind {
        "Exact" if !raw.starts_with(['*', '!']) => ("", raw),
        "Wildcard" if raw.starts_with("*.") => ("*.", &raw[2..]),
        "Exception" if raw.starts_with('!') => ("!", &raw[1..]),
        _ => return Err("routing selector disagrees with its rule kind".into()),
    };
    let body = canonical(body)?;
    if kind == "Exception" && !body.contains('.') {
        return Err("PSL exceptions must include the removed label and a parent suffix".into());
    }
    Ok((format!("{prefix}{body}"), body))
}

/// Read only the routing fields; other inventory policy metadata remains independent.
fn inputs(
    root: &Path,
    supplements: &[Supplement<'_>],
) -> Result<(Vec<Rule>, BTreeSet<String>), String> {
    let roots: Roots = serde_json::from_slice(
        &fs::read(root.join("data/root/inventory.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let psl: Psl = serde_json::from_slice(
        &fs::read(root.join("data/psl/rules.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if roots.schema_version != 2 || psl.schema_version != 2 || psl.rules.is_empty() {
        return Err("unsupported or empty routing inventory schema".into());
    }
    let mut active = BTreeSet::new();
    let mut root_keys = BTreeSet::new();
    let mut rules = Vec::new();
    for row in roots.roots {
        let name = canonical(&row.tld)?;
        if name.contains('.') || !root_keys.insert(name.clone()) {
            return Err("duplicate canonical or multi-label root inventory key".into());
        }
        if row.active {
            if row.inventory_state != "delegated" {
                return Err("active root is not delegated".into());
            }
            active.insert(name.clone());
            rules.push(Rule {
                section: "Inventory",
                kind: "Exact",
                selector: name.clone(),
                suffix: name,
                source_id: "iana.active-roots",
                evidence: vec![],
                counts: vec![],
            });
        }
    }
    if active.is_empty() {
        return Err("empty active-root routing inventory".into());
    }
    let mut identities = BTreeSet::new();
    for row in psl.rules {
        let section = match row.section.as_str() {
            "ICANN" => "Icann",
            "PRIVATE" => "Private",
            _ => return Err("unrecognised PSL section".into()),
        };
        let kind = match row.kind.as_str() {
            "exact" => "Exact",
            "wildcard" => "Wildcard",
            "exception" => "Exception",
            _ => return Err("unrecognised PSL rule kind".into()),
        };
        let (selector, suffix) = selector(&row.rule, kind)?;
        if canonical(&row.suffix)? != suffix || !identities.insert((section, kind, suffix.clone()))
        {
            return Err("PSL suffix mismatch or duplicate canonical selector".into());
        }
        rules.push(Rule {
            section,
            kind,
            suffix,
            selector,
            source_id: "psl.list",
            evidence: vec![],
            counts: vec![],
        });
    }
    for row in supplements {
        let kind = if row.selector.starts_with("*.") {
            "Wildcard"
        } else {
            "Exact"
        };
        let (selector, suffix) = selector(row.selector, kind)?;
        if !active.contains(suffix.rsplit('.').next().unwrap_or(&suffix)) {
            return Err("reviewed namespace is outside the active-root inventory".into());
        }
        if row.evidence_ids.is_empty()
            || row
                .evidence_ids
                .iter()
                .any(|id| id.is_empty() || id.trim() != *id)
            || row.applicant_label_counts.is_empty()
            || row
                .applicant_label_counts
                .iter()
                .any(|count| !(1..=126).contains(count))
        {
            return Err(
                "reviewed routing requires evidence and bounded nonempty registration forms".into(),
            );
        }
        if !identities.insert(("Reviewed", kind, suffix.clone())) {
            return Err("duplicate canonical reviewed namespace".into());
        }
        let mut evidence = row
            .evidence_ids
            .iter()
            .map(|id| (*id).to_owned())
            .collect::<Vec<_>>();
        evidence.sort();
        evidence.dedup();
        let mut counts = row.applicant_label_counts.to_vec();
        counts.sort_unstable();
        counts.dedup();
        rules.push(Rule {
            section: "Reviewed",
            kind,
            suffix,
            selector,
            source_id: "reviewed-policy",
            evidence,
            counts,
        });
    }
    rules.sort();
    Ok((rules, active))
}

/// Flatten a reverse-label tree breadth-first so every child range is sorted/contiguous.
fn render(rules: &[Rule], active: &BTreeSet<String>) -> Result<String, String> {
    let mut nodes = vec![Node::default()];
    for (rule_index, rule) in rules.iter().enumerate() {
        let mut index = 0;
        for label in rule.suffix.rsplit('.') {
            let next = match nodes[index].children.get(label) {
                Some(child) => *child,
                None => {
                    let child = nodes.len();
                    nodes.push(Node {
                        label: label.to_owned(),
                        ..Node::default()
                    });
                    nodes[index].children.insert(label.to_owned(), child);
                    child
                }
            };
            index = next;
        }
        nodes[index].rules.push(rule_index);
        nodes[index].active_root = active.contains(&rule.suffix);
    }
    let mut order = vec![0];
    let (mut rendered_nodes, mut rendered_rules) = (Vec::new(), Vec::new());
    let mut index = 0;
    while index < order.len() {
        let node = &nodes[order[index]];
        let child_start = order.len();
        order.extend(node.children.values().copied());
        if order.len() > u32::MAX as usize
            || node.children.len() > u16::MAX as usize
            || node.rules.len() > u8::MAX as usize
            || rendered_rules.len() > u32::MAX as usize
        {
            return Err("routing trie exceeds bounded index sizes".into());
        }
        rendered_nodes.push(format!("RouteNode {{ label: {:?}, child_start: {child_start}, child_count: {}, rule_start: {}, rule_count: {}, active_root: {} }}", node.label, node.children.len(), rendered_rules.len(), node.rules.len(), node.active_root));
        for rule_index in &node.rules {
            let rule = &rules[*rule_index];
            let prefix = if rule.section == "Reviewed" {
                "reviewed"
            } else if rule.section == "Inventory" {
                "iana.active-roots"
            } else {
                "psl"
            };
            let id = format!("{prefix}:{}:{}", rule.section, rule.selector);
            rendered_rules.push(format!("RouteRule {{ id: {id:?}, selector: {:?}, source_id: {:?}, kind: RouteKind::{}, section: RouteSection::{}, applicant_label_counts: &{:?}, evidence_ids: &{:?} }}", rule.selector, rule.source_id, rule.kind, rule.section, rule.counts, rule.evidence));
        }
        index += 1;
    }
    Ok(format!("use crate::resolver::{{Resolver, RouteNode, RouteRule, RouteKind, RouteSection}};\npub static REGISTRATION_RESOLVER: Resolver = Resolver::new(&[\n{}\n], &[\n{}\n]);\n", rendered_nodes.join(",\n"), rendered_rules.join(",\n")))
}

/// Generate static registration and optional private routing without network access.
///
/// # Errors
///
/// Rejects malformed inventories, canonical collisions, or unevidenced supplements.
pub fn generate(root: &Path, out_dir: &Path, supplements: &[Supplement<'_>]) -> Result<(), String> {
    let (rules, active) = inputs(root, supplements)?;
    let output = render(&rules, &active)?;
    fs::write(out_dir.join("generated_resolver.rs"), output).map_err(|e| e.to_string())
}

#[cfg(test)]
#[path = "resolver_tests.rs"]
mod tests;
