//! Optional namespace metadata queries over the same pinned static release.

use super::Registry;
use crate::namespace_info::NamespaceInfo;
use crate::normalization::normalize;

impl Registry {
    /// Inspect known or unknown canonical namespaces and any reviewed policy.
    /// Returns `None` for invalid syntax; a valid unresearched name retains metadata.
    pub fn namespace_info(&self, input: &str) -> Option<NamespaceInfo> {
        let input = input.trim().strip_prefix('.').unwrap_or(input.trim());
        let wildcard = input.starts_with("*.");
        let canonical = normalize(input.strip_prefix("*.").unwrap_or(input)).ok()?;
        let name = canonical.ascii();
        let selector = if wildcard {
            format!("*.{name}")
        } else {
            name.to_owned()
        };
        let dataset = self.dataset();
        let policy = dataset
            .namespaces
            .binary_search_by_key(&selector.as_str(), |p| p.selector)
            .ok()
            .map(|i| &dataset.namespaces[i])
            .or_else(|| {
                if wildcard {
                    return None;
                }
                let (_, suffix) = name.split_once('.')?;
                let pattern = format!("*.{suffix}");
                dataset
                    .namespaces
                    .binary_search_by_key(&pattern.as_str(), |p| p.selector)
                    .ok()
                    .map(|i| &dataset.namespaces[i])
            });
        let root = name.rsplit('.').next()?;
        let root_inventory = dataset
            .roots
            .binary_search_by_key(&root, |r| r.tld)
            .ok()
            .map(|i| &dataset.roots[i]);
        let icann_route = dataset.resolver.resolve(name, false).icann.map(|r| r.rule);
        let scope = policy.map_or(selector.as_str(), |p| p.selector);
        let assertions = dataset
            .assertions
            .iter()
            .filter(|a| a.namespaces.contains(&scope))
            .collect::<Vec<_>>();
        let mut source_ids = assertions.iter().map(|a| a.source_id).collect::<Vec<_>>();
        if let Some(root) = root_inventory {
            source_ids.extend(root.source_ids);
        }
        if let Some(route) = icann_route {
            source_ids.push(route.source_id);
        }
        source_ids.sort_unstable();
        source_ids.dedup();
        let sources = source_ids
            .into_iter()
            .filter_map(|id| self.source(id))
            .collect();
        let rules = policy.map_or_else(Vec::new, |p| {
            p.rule_indices
                .iter()
                .filter_map(|i| dataset.rules.get(*i as usize))
                .collect()
        });
        Some(NamespaceInfo {
            namespace: selector,
            root_inventory,
            icann_route,
            policy,
            rules,
            assertions,
            sources,
            dataset_version: dataset.version,
            evaluation_date: dataset.evaluation_date,
            inventory_date: dataset.inventory_date,
            normalization_profile: dataset.normalization_profile,
        })
    }
}

#[cfg(test)]
#[path = "registry_namespace_tests.rs"]
mod tests;
