//! Build-only evidence validation and static policy compilation.
// Serde authoring records and helper functions are private build implementation;
// they are not exposed through the library API. Runtime types are documented.

mod check_predicates;
pub mod compatibility;
mod conflicts;
mod emit;
pub mod idn;
pub mod idn_schema;
mod inheritance;
pub mod inventory;
pub mod keys;
pub mod load;
pub mod predicates;
mod render_predicates;
mod resolve;
pub mod resolver;
pub mod schema;
pub mod validate;

use schema::{Document, Effect, Knowledge};
use std::path::{Path, PathBuf};

/// Owned reviewed routing supplement produced from approved registration forms.
#[derive(Debug)]
pub struct Supplement {
    /// Exact or wildcard namespace key whose registration forms were approved.
    pub selector: String,
    /// Assertions approving registration forms for this namespace.
    pub evidence_ids: Vec<String>,
    /// Applicant-controlled label counts in the approved registration forms.
    pub applicant_label_counts: Vec<u8>,
}

/// Validated static policy source and inputs needed for reproducible Cargo builds.
#[derive(Debug)]
pub struct Compilation {
    /// Generated Rust policy tables ready to write into the Cargo output directory.
    pub rust: String,
    /// Reviewed registration-form routes contributed to the resolver generator.
    pub supplements: Vec<Supplement>,
    /// Packaged files and directories watched by Cargo for rebuilds.
    pub input_paths: Vec<PathBuf>,
    /// Dataset identity binding normalization, evaluation date and packaged input bytes.
    pub fingerprint: String,
}

/// Validate owned authoring and produce immutable tables without network access.
///
/// # Errors
/// Rejects invalid references, scopes, temporal metadata, predicates or conflicts.
pub fn compile_document(
    mut document: Document,
    evaluation_date: &str,
    root: Option<&Path>,
    fingerprint: &str,
) -> Result<Compilation, String> {
    let statuses = validate::document(&mut document, evaluation_date, root)?;
    for assertion in &document.assertions {
        check_predicates::validate(assertion, &document)?;
        if assertion.knowledge == Knowledge::NotApplicable
            && assertion.effect != Effect::Context
            && assertion.predicate.is_some()
        {
            return Err("not-applicable assertion cannot carry an enforceable predicate".into());
        }
        if assertion.effect != Effect::Context
            && assertion.knowledge == Knowledge::Reviewed
            && assertion
                .predicate
                .as_ref()
                .is_some_and(predicates::Predicate::unsupported)
        {
            return Err("unsupported predicate presented as reviewed enforcement".into());
        }
    }
    document.sources.sort_by(|a, b| a.id.cmp(&b.id));
    document.assertions.sort_by(|a, b| a.id.cmp(&b.id));
    document.facts.sort_by(|a, b| a.field.cmp(&b.field));
    document.label_sets.sort_by(|a, b| a.id.cmp(&b.id));
    document.idn_profiles.sort_by(|a, b| a.id.cmp(&b.id));
    let namespaces = resolve::resolve(&document, &statuses)?;
    let rust = emit::emit(
        &document,
        &statuses,
        &namespaces,
        evaluation_date,
        fingerprint,
    )?;
    let supplements = namespaces
        .iter()
        .filter(|n| !n.forms.is_empty())
        .map(|n| Supplement {
            selector: n.selector.clone(),
            evidence_ids: n.evidence_ids.clone(),
            applicant_label_counts: n.forms.iter().map(|f| f.len() as u8).collect(),
        })
        .collect();
    Ok(Compilation {
        rust,
        supplements,
        input_paths: Vec::new(),
        fingerprint: fingerprint.to_owned(),
    })
}

/// Compile a repository's packaged inventories, evidence and reviewed policies.
///
/// # Errors
/// Rejects missing or changed packaged inputs and invalid authoring records.
pub fn compile(root: &Path) -> Result<Compilation, String> {
    let loaded = load::load(root)?;
    let fingerprint = load::fingerprint(&loaded.evaluation_date, &loaded.inputs);
    let mut input_paths = loaded
        .inputs
        .keys()
        .map(|p| root.join(p))
        .collect::<Vec<_>>();
    input_paths.extend([
        root.join("rules"),
        root.join("evidence"),
        root.join("data/idn"),
    ]);
    input_paths.sort();
    input_paths.dedup();
    let mut compilation = compile_document(
        loaded.document,
        &loaded.evaluation_date,
        Some(root),
        &fingerprint,
    )?;
    compilation.input_paths = input_paths;
    Ok(compilation)
}

/// Write the generated Rust policy artifact into Cargo's existing output directory.
///
/// # Errors
/// Returns a filesystem error when the output cannot be written.
pub fn write(compilation: &Compilation, out_dir: &Path) -> Result<(), String> {
    std::fs::write(out_dir.join("generated_policy.rs"), &compilation.rust)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests_inheritance;
#[cfg(test)]
mod tests_inputs;
#[cfg(test)]
mod tests_integrity;
#[cfg(test)]
mod tests_keys;
#[cfg(test)]
mod tests_predicates;
#[cfg(test)]
mod tests_resolution;
#[cfg(test)]
mod tests_schema;

#[cfg(test)]
mod tests_compile;
#[cfg(test)]
mod tests_assets;
