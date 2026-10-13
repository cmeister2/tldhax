//! Immutable outputs of offline evidence, inventory and routing compilation.
#![allow(
    dead_code,
    unused_imports,
    missing_docs,
    clippy::missing_docs_in_private_items
)]

mod policy {
    include!(concat!(env!("OUT_DIR"), "/generated_policy.rs"));
}
mod inventory {
    include!(concat!(env!("OUT_DIR"), "/generated_inventory.rs"));
}
mod routing {
    include!(concat!(env!("OUT_DIR"), "/generated_resolver.rs"));
}

mod compatibility {
    include!(concat!(env!("OUT_DIR"), "/generated_compatibility.rs"));
}

pub use compatibility::*;
pub(crate) use inventory::*;
pub(crate) use policy::*;
pub(crate) use routing::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knowledge_statistics_include_every_discovered_namespace() {
        use crate::registry_stats::KnowledgeCounts;
        let total = |c: KnowledgeCounts| {
            c.reviewed + c.partial + c.unknown + c.conflicting + c.not_applicable
        };
        assert_eq!(DATASET_STATS.active_roots, ROOT_INVENTORY.len());
        assert_eq!(DATASET_STATS.known_namespaces, TOTAL_KNOWN_SUFFIXES);
        assert_eq!(total(DATASET_STATS.ascii_namespaces), TOTAL_KNOWN_SUFFIXES);
        assert_eq!(total(DATASET_STATS.idn_namespaces), TOTAL_KNOWN_SUFFIXES);
        for family in DATASET_STATS.families {
            assert_eq!(total(family.ascii), TOTAL_KNOWN_SUFFIXES);
            assert_eq!(total(family.idn), TOTAL_KNOWN_SUFFIXES);
        }
        assert_eq!(DATASET_STATS.dataset_version, RELEASE_FINGERPRINT);
        assert!(TLD_RULES.is_empty());
        assert_eq!(LEGACY_COVERAGE_PERCENT, 0.0);
    }

    #[test]
    fn complete_pinned_tables_compile_and_preserve_discovery_scope() {
        assert_eq!(ROOT_INVENTORY.len(), 1_437);
        assert_eq!(INVENTORY_COUNTS.active_roots, ROOT_INVENTORY.len());
        assert_eq!(INVENTORY_COUNTS.discovered_namespaces, 6_949);
        assert_eq!(SPECIAL_USE.len(), 42);
        let ck = REGISTRATION_RESOLVER.resolve("vanity.foo.ck", true);
        assert!(ck.root_known);
        assert_eq!(ck.icann.unwrap().suffix, "foo.ck");
        assert!(RELEASE_FINGERPRINT.starts_with(EVALUATION_DATE));
        assert_eq!(RELEASE_FINGERPRINT, env!("TLDHAX_DATASET_VERSION"));
    }
}
