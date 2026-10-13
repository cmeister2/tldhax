//! Offline structural validation and static emission of direct policies.

mod emit;
pub mod idn;
pub mod predicates;
mod render_predicates;
pub mod schema;
mod validate;

use schema::{Document, LabelSet, Policy, SpecialUse, SpecialUses};
use std::fs;
use std::path::{Path, PathBuf};

/// Fully validated direct inputs, ready for immutable Rust emission.
pub struct CompiledInputs {
    /// Simple packaged policy release version.
    pub version: String,
    /// Direct namespace and form records sorted by selector and label count.
    pub policies: Vec<Policy>,
    /// Typed profile fields sorted by name.
    pub facts: Vec<predicates::Fact>,
    /// Adopted IDN tables sorted by identity.
    pub idn_profiles: Vec<idn::IdnProfile>,
    /// Exact shared label sets sorted by identity.
    pub label_sets: Vec<LabelSet>,
    /// Active root labels sorted canonically.
    pub roots: Vec<String>,
    /// ICANN discovery selectors sorted canonically, without permission inference.
    pub routes: Vec<String>,
    /// Non-public designated names.
    pub special_use: Vec<SpecialUse>,
    /// Authored and discovered namespace identifiers, without policy approval.
    pub known_suffixes: Vec<String>,
    /// Packaged input paths for Cargo's ordinary change tracking.
    pub input_paths: Vec<PathBuf>,
}

/// Read and validate packaged policies, facts, adopted tables and minimal identity data.
///
/// # Errors
/// Rejects malformed schemas, noncanonical keys, duplicate records, invalid expressions,
/// missing shared references and unreadable packaged files.
pub fn compile(root: &Path) -> Result<CompiledInputs, String> {
    let mut paths = vec![
        root.join("rules/VERSION"),
        root.join("data/roots.txt"),
        root.join("data/psl/icann.dat"),
        root.join("data/special-use.json"),
        root.join("data/reserved/sets.json"),
    ];
    for directory in ["rules", "rules/profiles"] {
        let directory = root.join(directory);
        let files = fs::read_dir(&directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        for file in files {
            let path = file.map_err(|error| error.to_string())?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "toml")
            {
                paths.push(path);
            }
        }
    }
    paths.sort();
    let mut input = CompiledInputs {
        version: read(&root.join("rules/VERSION"))?.trim().to_owned(),
        policies: Vec::new(),
        facts: Vec::new(),
        idn_profiles: Vec::new(),
        label_sets: Vec::new(),
        roots: lines(&read(&root.join("data/roots.txt"))?),
        routes: lines(&read(&root.join("data/psl/icann.dat"))?),
        special_use: serde_json::from_str::<SpecialUses>(&read(
            &root.join("data/special-use.json"),
        )?)
        .map_err(|error| error.to_string())?
        .names,
        known_suffixes: Vec::new(),
        input_paths: paths.clone(),
    };
    for path in &paths {
        let document: Option<Document> = if path
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            let text = read(path)?;
            let value: toml::Value =
                toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
            if value.get("schema_version").is_some() {
                Some(
                    value
                        .try_into()
                        .map_err(|error| format!("{}: {error}", path.display()))?,
                )
            } else {
                let legacy: LegacyDocument = value
                    .try_into()
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                input
                    .known_suffixes
                    .extend(legacy.domains.into_iter().map(|domain| domain.tld));
                None
            }
        } else if path.ends_with("reserved/sets.json") {
            Some(
                serde_json::from_str(&read(path)?)
                    .map_err(|error| format!("{}: {error}", path.display()))?,
            )
        } else {
            None
        };
        if let Some(document) = document {
            if document.schema_version != 1 {
                return Err(format!(
                    "{}: unsupported direct policy schema",
                    path.display()
                ));
            }
            input.policies.extend(document.policies);
            input.facts.extend(document.facts);
            input.idn_profiles.extend(document.idn_profiles);
            input.label_sets.extend(document.label_sets);
        }
    }
    validate::validate(&mut input)?;
    Ok(input)
}

/// Emit one static Rust artifact for the validated packaged release.
///
/// # Errors
/// Returns an error if rendering or writing the generated artifact fails.
pub fn write(input: &CompiledInputs, output: &Path) -> Result<(), String> {
    let source = emit::render(input)?;
    fs::write(output.join("generated_policy.rs"), source).map_err(|error| error.to_string())
}

/// Read one packaged UTF-8 input with a useful file-specific error.
fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Extract identity selectors from a plain list with optional comments.
fn lines(input: &str) -> Vec<String> {
    input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests;

/// Existing authoring is retained as namespace inventory; its constraints do not establish a decision.
#[derive(serde::Deserialize)]
struct LegacyDocument {
    /// Original namespace identities, without interpreting legacy registration defaults.
    domains: Vec<LegacyDomain>,
}

/// The only legacy field consumed by the direct compiler.
#[derive(serde::Deserialize)]
struct LegacyDomain {
    /// Namespace or wildcard selector retained for factual inventory counts.
    tld: String,
}
