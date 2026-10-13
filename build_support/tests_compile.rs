//! Static emission, policy-only release identity and unsupported enforcement.

use super::{compile, compile_document, fixtures, schema};
use std::path::PathBuf;

/// Validate a synthetic policy with a deliberately identifiable release name.
fn run(document: schema::Document) -> Result<super::Compilation, String> {
    compile_document(document, "2026-10-12", None, "synthetic-compiler-release")
}

#[test]
fn emitted_policy_is_valid_rust_against_documented_runtime_contract() {
    let compilation = run(fixtures::fixture()).unwrap();
    assert_eq!(compilation.supplements[0].selector, "fixture");
    assert_eq!(
        compilation.supplements[0].evidence_ids,
        vec!["fixture.form"]
    );
    assert_eq!(compilation.supplements[0].applicant_label_counts, vec![1]);
    assert!(compilation.rust.contains("synthetic-compiler-release"));
    let directory =
        std::env::temp_dir().join(format!("tldhax-emission-test-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    super::write(&compilation, &directory).unwrap();
    assert_eq!(
        std::fs::read_to_string(directory.join("generated_policy.rs")).unwrap(),
        compilation.rust
    );
    let types = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/policy_types.rs");
    let input = directory.join("emitted.rs");
    std::fs::write(&input, format!(
        "//! Generated-contract verification.\n#![allow(dead_code)]\n#[path={types:?}] mod policy_types;\n{}", compilation.rust
    )).unwrap();
    let result = std::process::Command::new("rustc")
        .args(["--edition=2021", "--crate-type=lib", "-Dwarnings"])
        .arg(&input)
        .arg("--out-dir")
        .arg(&directory)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn not_applicable_metadata_cannot_enforce_a_name_restriction() {
    let mut document = fixtures::fixture();
    document.assertions[1].knowledge = schema::Knowledge::NotApplicable;
    assert!(run(document).unwrap_err().contains("not-applicable"));
}

#[test]
fn unsupported_interpretation_cannot_be_presented_as_reviewed() {
    let mut document = fixtures::fixture();
    document.assertions[1].predicate = Some(super::predicates::Predicate::Unsupported {
        feature: "unbounded expression".into(),
    });
    assert!(run(document).unwrap_err().contains("unsupported predicate"));
    let mut document = fixtures::fixture();
    document.assertions[1].knowledge = schema::Knowledge::Conflicting;
    let compilation = run(document).unwrap();
    assert!(!compilation
        .rust
        .contains("CompiledRule{id:\"fixture.length\""));
    assert!(compilation.rust.contains("Knowledge::Conflicting"));
}

#[test]
fn repository_compilation_retains_legacy_claims_as_unapproved_research() {
    let compilation = compile(&PathBuf::from(env!("CARGO_MANIFEST_DIR"))).unwrap();
    assert!(compilation.rust.contains("pub static LEGACY_RESEARCH"));
    assert!(!compilation.rust.contains("CompiledRule{id:\"de."));
    assert!(compilation.fingerprint.starts_with("2026-10-12+"));
    assert!(compilation
        .input_paths
        .iter()
        .any(|path| path.ends_with("rules")));
}
