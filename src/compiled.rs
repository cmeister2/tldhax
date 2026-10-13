//! Immutable outputs of offline evidence, inventory and routing compilation.
// These tables are connected to the assessment API in the following slices.
#![allow(dead_code, unused_imports)]

/// Evidence records, predicate rules and coverage for the pinned release.
mod policy {
    include!(concat!(env!("OUT_DIR"), "/generated_policy.rs"));
}
/// Compiled root and special-use inventories with their discovery counts.
mod inventory {
    include!(concat!(env!("OUT_DIR"), "/generated_inventory.rs"));
}
/// Compiled public-suffix trie and registration route metadata.
mod routing {
    include!(concat!(env!("OUT_DIR"), "/generated_resolver.rs"));
}

pub(crate) use inventory::*;
pub(crate) use policy::*;
pub(crate) use routing::*;

/// Checks that generated tables agree with the pinned discovery snapshots.
#[cfg(test)]
mod tests {
    use super::*;

    /// Verify inventory sizes, wildcard routes and the published dataset identity.
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
