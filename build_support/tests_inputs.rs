//! End-to-end packaged byte integrity and unapproved legacy research fixtures.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Own an isolated temporary test tree and remove it when the fixture is dropped.
struct Tree(
    /// Owned temporary root removed when the fixture guard is dropped.
    PathBuf);
impl Drop for Tree {
    /// Remove the temporary fixture directory when its owner goes out of scope.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Copy the manifest and its packaged artifacts into an isolated fixture tree.
///
/// # Panics
/// Panics if locating, parsing, copying or writing the repository fixture inputs fails.
fn make_tree() -> Tree {
    /// Process-local sequence used to give concurrently running fixtures distinct paths.
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "tldhax-compiler-fixture-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    let this_file = PathBuf::from(file!());
    let source = if this_file.is_absolute() {
        this_file
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(this_file)
    };
    let source = source.parent().unwrap().parent().unwrap().to_owned();
    let manifest = std::fs::read(source.join("data/manifest.json")).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    std::fs::create_dir_all(path.join("data")).unwrap();
    std::fs::write(path.join("data/manifest.json"), manifest).unwrap();
    for section in ["inputs", "outputs"] {
        for item in record[section].as_array().unwrap() {
            let name = item["path"].as_str().unwrap();
            let destination = path.join(name);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::copy(source.join(name), destination).unwrap();
        }
    }
    Tree(path)
}

/// Verify that legacy registerability is retained as research only.
#[test]
fn legacy_registerability_is_retained_as_research_only() {
    let tree = make_tree();
    std::fs::create_dir(tree.0.join("rules")).unwrap();
    let author = tree.0.join("rules/fixture.toml");
    std::fs::write(
        &author,
        "[[domains]]\ntld='fixture'\nregisterable='yes'\nmin_length=3\n",
    )
    .unwrap();
    let first = load::load(&tree.0).unwrap();
    assert_eq!(first.document.legacy[0].selector, "fixture");
    assert!(first.document.assertions.is_empty());
    assert!(first.document.namespaces.is_empty());
    let before = load::fingerprint(&first.evaluation_date, &first.inputs);
    std::fs::write(
        &author,
        "[[domains]]\ntld='fixture'\nregisterable='no'\nmin_length=3\n",
    )
    .unwrap();
    let second = load::load(&tree.0).unwrap();
    assert_ne!(
        before,
        load::fingerprint(&second.evaluation_date, &second.inputs)
    );
}

/// Verify that ordinary build rejects changed or omitted packaged inputs.
#[test]
fn ordinary_build_rejects_changed_or_omitted_packaged_inputs() {
    let tree = make_tree();
    std::fs::write(tree.0.join("data/psl/rules.json"), "{}").unwrap();
    assert!(load::load(&tree.0).err().unwrap().contains("hash mismatch"));
    let tree = make_tree();
    let path = tree.0.join("data/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest["outputs"]
        .as_array_mut()
        .unwrap()
        .retain(|item| item["path"] != "data/psl/rules.json");
    std::fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(load::load(&tree.0)
        .err()
        .unwrap()
        .contains("omits compiled authoritative input"));
}

/// Verify that release identity changes with policy and normalization inputs.
#[test]
fn release_identity_changes_with_policy_and_normalization_inputs() {
    let mut inputs = std::collections::BTreeMap::new();
    inputs.insert("rules/fixture.toml".into(), b"first policy".to_vec());
    let before = load::fingerprint("2026-10-12", &inputs);
    inputs.insert("rules/fixture.toml".into(), b"changed policy".to_vec());
    assert_ne!(before, load::fingerprint("2026-10-12", &inputs));
    assert_ne!(before, load::fingerprint("2026-10-13", &inputs));
    assert_eq!(
        load::fingerprint("2026-10-12", &inputs),
        load::fingerprint("2026-10-12", &inputs)
    );
}
