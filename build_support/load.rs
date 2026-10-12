//! Offline packaged input loading and full release identity.

use super::schema::{AssertionFile, AuthoringFile, Document, LegacyResearch, SourceFile};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

pub struct Loaded {
    pub document: Document,
    pub evaluation_date: String,
    pub inputs: BTreeMap<String, Vec<u8>>,
}

fn safe_path(root: &Path, path: &str) -> Result<PathBuf, String> {
    if Path::new(path)
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("unsafe packaged input path".into());
    }
    let target = root
        .join(path)
        .canonicalize()
        .map_err(|e| format!("missing packaged input {path}: {e}"))?;
    if !target.starts_with(root.canonicalize().map_err(|e| e.to_string())?) {
        return Err("packaged input escapes repository".into());
    }
    Ok(target)
}

fn read(root: &Path, path: &str, inputs: &mut BTreeMap<String, Vec<u8>>) -> Result<String, String> {
    let bytes = std::fs::read(safe_path(root, path)?).map_err(|e| e.to_string())?;
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| format!("non-UTF8 authoring input: {path}"))?;
    inputs.insert(path.to_owned(), bytes);
    Ok(text)
}

fn files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            result.extend(files(&path)?);
        } else {
            result.push(path);
        }
    }
    result.sort();
    Ok(result)
}

/// Serialize discovered paths with the same separators on every build platform.
fn relative_key(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path.strip_prefix(root).map_err(|e| e.to_string())?;
    let parts = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => name.to_str().ok_or("non-UTF8 source path"),
            _ => Err("unsafe relative source path"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parts.is_empty() {
        return Err("empty relative source path".into());
    }
    Ok(parts.join("/"))
}

/// Read packaged bytes and retain legacy claims only as research leads.
///
/// # Errors
/// Rejects invalid manifests, hashes, escaping paths and authoring schemas.
pub fn load(root: &Path) -> Result<Loaded, String> {
    let mut inputs = BTreeMap::new();
    let manifest_text = read(root, "data/manifest.json", &mut inputs)?;
    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_text).map_err(|e| e.to_string())?;
    if manifest["schema_version"] != 2 {
        return Err("unsupported inventory manifest version".into());
    }
    let evaluation_date = manifest["evaluation_date"]
        .as_str()
        .ok_or("manifest lacks evaluation date")?
        .to_owned();
    let mut paths = BTreeSet::new();
    for group in ["inputs", "outputs"] {
        for item in manifest[group]
            .as_array()
            .ok_or("manifest lacks input/output hashes")?
        {
            let path = item["path"].as_str().ok_or("manifest input path missing")?;
            let expected = item["sha256"]
                .as_str()
                .ok_or("manifest input hash missing")?;
            if !paths.insert(path.to_owned()) {
                return Err("duplicate manifest artifact path".into());
            }
            let bytes = std::fs::read(safe_path(root, path)?).map_err(|e| e.to_string())?;
            if format!("{:x}", Sha256::digest(&bytes)) != expected {
                return Err(format!("packaged input hash mismatch: {path}"));
            }
            inputs.insert(path.to_owned(), bytes);
        }
    }
    for required in [
        "data/root/tlds-alpha-by-domain.txt",
        "data/root/inventory.json",
        "data/psl/public_suffix_list.dat",
        "data/psl/rules.json",
        "data/special-use/names.json",
        "data/special-use/special-use-domain-names.xml",
        "data/special-use/special-use-domain-names.csv",
        "data/root/root-db.html",
        "data/root/gtlds.json",
        "data/reserved/ReservedNames.xml",
        "data/reserved/sets.json",
        "data/research-queue.json",
    ] {
        if !paths.contains(required) {
            return Err(format!(
                "manifest omits compiled authoritative input: {required}"
            ));
        }
    }
    let mut document = Document::default();
    if root.join("evidence/sources.toml").exists() {
        let parsed: SourceFile = toml::from_str(&read(root, "evidence/sources.toml", &mut inputs)?)
            .map_err(|e| e.to_string())?;
        if parsed.schema_version != 2 {
            return Err("unsupported source schema".into());
        }
        document.sources = parsed.sources;
    }
    if root.join("evidence/assertions.toml").exists() {
        let parsed: AssertionFile =
            toml::from_str(&read(root, "evidence/assertions.toml", &mut inputs)?)
                .map_err(|e| e.to_string())?;
        if parsed.schema_version != 2 {
            return Err("unsupported assertion schema".into());
        }
        document.assertions = parsed.assertions;
    }
    for path in files(&root.join("rules"))? {
        if path.extension().and_then(|p| p.to_str()) != Some("toml") {
            continue;
        }
        let relative = relative_key(root, &path)?;
        let text = read(root, &relative, &mut inputs)?;
        let value: toml::Value =
            toml::from_str(&text).map_err(|e| format!("invalid {relative}: {e}"))?;
        if let Some(version) = value.get("schema_version") {
            if version.as_integer() != Some(2) {
                return Err("unsupported policy authoring schema".into());
            }
            let parsed: AuthoringFile =
                toml::from_str(&text).map_err(|e| format!("invalid {relative}: {e}"))?;
            document.namespaces.extend(parsed.namespaces);
            document.profiles.extend(parsed.profiles);
            document.label_sets.extend(parsed.label_sets);
            document.idn_profiles.extend(parsed.idn_profiles);
            document.facts.extend(parsed.facts);
        } else {
            let entries = value
                .get("domains")
                .and_then(toml::Value::as_array)
                .ok_or("unversioned file is not legacy domain research")?;
            for entry in entries {
                let key = entry
                    .get("tld")
                    .and_then(toml::Value::as_str)
                    .ok_or("legacy research lacks suffix identity")?;
                let selector = super::keys::selector(key).unwrap_or_else(|_| key.to_owned());
                let source_links = entry
                    .get("sources")
                    .and_then(toml::Value::as_table)
                    .map(|table| {
                        table
                            .values()
                            .filter_map(toml::Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                document.legacy.push(LegacyResearch {
                    selector,
                    source_links,
                    provenance: relative.to_owned(),
                });
            }
        }
    }
    for source in &document.sources {
        if let Some(path) = &source.snapshot_path {
            let bytes = std::fs::read(safe_path(root, path)?).map_err(|e| e.to_string())?;
            inputs.insert(path.clone(), bytes);
        }
    }
    for path in files(&root.join("data/idn"))? {
        let relative = relative_key(root, &path)?;
        let bytes = std::fs::read(safe_path(root, &relative)?).map_err(|e| e.to_string())?;
        inputs.insert(relative, bytes);
    }
    document
        .legacy
        .sort_by(|a, b| (&a.selector, &a.provenance).cmp(&(&b.selector, &b.provenance)));
    Ok(Loaded {
        document,
        evaluation_date,
        inputs,
    })
}

pub fn fingerprint(evaluation_date: &str, inputs: &BTreeMap<String, Vec<u8>>) -> String {
    let mut hash = Sha256::new();
    hash.update(b"tldhax-evidence-release-v2\0");
    hash.update(crate::normalization::NORMALIZATION_PROFILE.as_bytes());
    hash.update(evaluation_date.as_bytes());
    for (path, bytes) in inputs {
        hash.update((path.len() as u64).to_be_bytes());
        hash.update(path.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    format!("{evaluation_date}+{:x}", hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovered_input_keys_use_portable_separators_and_reject_escapes() {
        let root = std::env::temp_dir().join("portable-release-key");
        for components in [
            vec!["rules", "namespaces", "de.toml"],
            vec!["data", "idn", "table.txt"],
        ] {
            let path = components
                .iter()
                .fold(root.clone(), |path, part| path.join(part));
            assert_eq!(relative_key(&root, &path).unwrap(), components.join("/"));
        }
        assert!(relative_key(&root, &root).is_err());
        assert!(relative_key(&root, &root.join("../outside.toml")).is_err());
        assert!(relative_key(&root, &root.with_file_name("other").join("rule.toml")).is_err());
    }
}
