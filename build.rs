//! Compile packaged evidence, factual inventory and routing without a network.

use std::env;
use std::path::{Path, PathBuf};

// The compiler uses the runtime's exact pinned registration normalization.
#[allow(dead_code)]
#[path = "src/normalization.rs"]
mod normalization;
#[path = "build_support/mod.rs"]
mod policy_compiler;
#[allow(dead_code)]
#[path = "src/registration_context.rs"]
mod registration_context;

/// Compile every packaged artifact into Cargo’s output directory.
///
/// # Panics
/// Panics when Cargo omits `OUT_DIR`, packaged evidence fails validation, or an
/// output artifact cannot be written.
fn main() {
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory missing"));
    compile_reviewed_tables(&output);
}

/// Compile verified evidence, inventory and routing without runtime loading.
///
/// # Panics
/// Panics when authoring, inventory or routing validation fails, or an output
/// artifact cannot be written.
fn compile_reviewed_tables(out_dir: &Path) {
    let root = Path::new(".");
    let policy = policy_compiler::compile(root).expect("invalid packaged policy inputs");
    println!(
        "cargo:rustc-env=TLDHAX_DATASET_VERSION={}",
        policy.fingerprint
    );
    for path in &policy.input_paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    policy_compiler::write(&policy, out_dir).expect("failed to write compiled policy");
    policy_compiler::compatibility::generate(root, out_dir, &policy.fingerprint)
        .expect("invalid compatibility and coverage inputs");
    policy_compiler::inventory::generate(root, out_dir).expect("invalid factual inventory");
    let evidence = policy
        .supplements
        .iter()
        .map(|s| {
            s.evidence_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let supplements = policy
        .supplements
        .iter()
        .zip(&evidence)
        .map(|(s, ids)| policy_compiler::resolver::Supplement {
            selector: &s.selector,
            evidence_ids: ids,
            applicant_label_counts: &s.applicant_label_counts,
        })
        .collect::<Vec<_>>();
    policy_compiler::resolver::generate(root, out_dir, &supplements)
        .expect("invalid registration routing inputs");
}
