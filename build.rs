//! Compile direct registration policies and identity data without a network.

use std::env;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "src/normalization.rs"]
mod normalization;
#[path = "build_support/mod.rs"]
mod policy_compiler;
#[allow(dead_code)]
#[path = "src/registration_context.rs"]
mod registration_context;

/// Validate packaged inputs and emit immutable Rust tables.
///
/// # Panics
/// Panics when Cargo's output directory is absent or packaged data is invalid.
fn main() {
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory missing"));
    let document =
        policy_compiler::compile(Path::new(".")).expect("invalid packaged policy inputs");
    println!("cargo:rerun-if-changed=rules");
    println!("cargo:rerun-if-changed=data");
    for path in &document.input_paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!(
        "cargo:rustc-env=TLDHAX_DATASET_VERSION={}",
        document.version
    );
    policy_compiler::write(&document, &output).expect("failed to write compiled policy");
}
