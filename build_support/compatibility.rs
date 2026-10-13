//! Generate conservative compatibility tables and precomputed release statistics.
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use super::{keys, load, resolve, validate};
use std::collections::BTreeSet;
use std::path::Path;

#[path = "stats.rs"]
mod stats;

fn known(
    queue: &serde_json::Value,
    namespaces: &[resolve::ResolvedNamespace],
) -> Result<BTreeSet<String>, String> {
    let mut selectors = BTreeSet::new();
    for group in queue["groups"]
        .as_array()
        .ok_or("research groups missing")?
    {
        for row in group["namespaces"]
            .as_array()
            .ok_or("research namespaces missing")?
        {
            let selector = row["selector"]
                .as_str()
                .ok_or("research selector missing")?;
            if keys::selector(selector)? != selector || !selectors.insert(selector.to_owned()) {
                return Err("noncanonical or duplicate research selector".into());
            }
        }
    }
    selectors.extend(
        namespaces
            .iter()
            .filter(|n| !n.forms.is_empty())
            .map(|n| n.selector.clone()),
    );
    Ok(selectors)
}

/// Generate discovery compatibility and statistics only from verified build inputs.
///
/// # Errors
/// Rejects invalid inventory/authoring, missing metadata and output write failures.
pub fn generate(root: &Path, out_dir: &Path, fingerprint: &str) -> Result<(), String> {
    let mut loaded = load::load(root)?;
    let expected = load::fingerprint(&loaded.evaluation_date, &loaded.inputs);
    if expected != fingerprint {
        return Err("compatibility release fingerprint mismatch".into());
    }
    let statuses = validate::document(&mut loaded.document, &loaded.evaluation_date, Some(root))?;
    let namespaces = resolve::resolve(&loaded.document, &statuses)?;
    let queue: serde_json::Value =
        serde_json::from_slice(&loaded.inputs["data/research-queue.json"])
            .map_err(|e| e.to_string())?;
    let roots: serde_json::Value =
        serde_json::from_slice(&loaded.inputs["data/root/inventory.json"])
            .map_err(|e| e.to_string())?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&loaded.inputs["data/manifest.json"]).map_err(|e| e.to_string())?;
    let date = manifest["inputs"]
        .as_array()
        .ok_or("manifest inputs missing")?
        .iter()
        .find(|i| i["source_id"] == "iana.active-roots")
        .and_then(|i| i["retrieved_on"].as_str())
        .ok_or("inventory date missing")?;
    let selectors = known(&queue, &namespaces)?;
    let mut set = phf_codegen::Set::new();
    for selector in &selectors {
        set.entry(selector);
    }
    // Initial reviewed policies have gaps, conditional allocation or richer IDN
    // semantics. None establishes every field required by the old TldRule shape.
    // Declining to emit a summary preserves Unknown rather than inventing defaults.
    let empty = phf_codegen::Map::<&str>::new();
    let mut rust = format!("pub static KNOWN_SUFFIXES:phf::Set<&'static str>={};\npub const TOTAL_KNOWN_SUFFIXES:usize={};\npub static TLD_RULES:phf::Map<&'static str,crate::types::TldRule>={};\npub const LEGACY_COUNTS:(usize,usize,usize)=(0,0,0);\npub const LEGACY_COVERAGE_PERCENT:f64=0.0;\n",set.build(),selectors.len(),empty.build());
    rust.push_str(&stats::render(
        &loaded.document,
        &namespaces,
        &selectors,
        roots["roots"]
            .as_array()
            .ok_or("active roots missing")?
            .len(),
        fingerprint,
        &loaded.evaluation_date,
        date,
    ));
    std::fs::write(out_dir.join("generated_compatibility.rs"), rust).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_discovery_keeps_wildcards_and_reviewed_routes_without_legacy_claims() {
        let queue = serde_json::json!({"groups":[{"namespaces":[{"selector":"fixture"},{"selector":"*.fixture"}]}]});
        let namespace = resolve::ResolvedNamespace {
            selector: "name.fixture".into(),
            forms: vec![vec!["name".into()]],
            rule_ids: vec![],
            coverage: vec![],
            evidence_ids: vec![],
            context: vec![],
        };
        assert_eq!(
            known(&queue, &[namespace]).unwrap(),
            BTreeSet::from(["*.fixture".into(), "fixture".into(), "name.fixture".into()])
        );
        let invalid =
            serde_json::json!({"groups":[{"namespaces":[{"selector":"bücher.fixture"}]}]});
        assert!(known(&invalid, &[]).is_err());
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::*;

    #[test]
    fn artifact_requires_matching_release_and_writes_precomputed_statistics() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let compilation = super::super::compile(root).unwrap();
        let output = std::env::temp_dir()
            .join(format!("tldhax-compatibility-test-{}", std::process::id()));
        std::fs::create_dir_all(&output).unwrap();
        assert!(generate(root, &output, "different-release")
            .unwrap_err()
            .contains("fingerprint mismatch"));
        assert!(!output.join("generated_compatibility.rs").exists());
        generate(root, &output, &compilation.fingerprint).unwrap();
        let generated =
            std::fs::read_to_string(output.join("generated_compatibility.rs")).unwrap();
        std::fs::remove_dir_all(output).unwrap();
        assert!(generated.contains(&compilation.fingerprint));
        assert!(generated.contains("pub static DATASET_STATS"));
    }
}
