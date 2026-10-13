//! Namespace metadata is available independently of policy completeness.

use crate::registry::Registry;

/// Namespace lookup normalizes its input and returns pinned root metadata without accepting malformed names.
#[test]
fn canonical_namespace_queries_preserve_factual_root_metadata() {
    let registry = Registry::new();
    let info = registry.namespace_info(" .DE. ").unwrap();
    assert_eq!(info.namespace, "de");
    let root = info.root_inventory.unwrap();
    assert_eq!(root.tld, "de");
    assert!(root.source_ids.contains(&"iana.active-roots"));
    assert_eq!(info.dataset_version, registry.dataset().version);
    assert_eq!(info.normalization_profile, registry.dataset().normalization_profile);
    assert!(registry.namespace_info("under_score").is_none());
    assert!(registry.source("missing-source").is_none());
    assert!(registry.assertion("missing-assertion").is_none());
}

/// Namespace discovery retains wildcard and exception selectors and represents unknown roots without policy.
#[test]
fn discovery_preserves_bare_wildcard_and_exception_scopes() {
    let registry = Registry::new();
    assert!(registry.namespace_info("ck").unwrap().icann_route.is_none());
    assert_eq!(
        registry.namespace_info("foo.ck").unwrap().icann_route.unwrap().selector,
        "*.ck"
    );
    assert_eq!(
        registry.namespace_info("www.ck").unwrap().icann_route.unwrap().selector,
        "!www.ck"
    );
    let unknown = registry.namespace_info("unresearched-tldhax").unwrap();
    assert!(unknown.root_inventory.is_none());
    assert!(unknown.policy.is_none());
    assert!(unknown.rules.is_empty());
}
