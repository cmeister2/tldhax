//! Compile verified factual root/special-use metadata without approving policy.
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

#[path = "inventory_checks.rs"]
mod checks;

#[derive(Debug, Deserialize)]
struct Root {
    tld: String,
    active: bool,
    #[serde(rename = "type")]
    kind: String,
    operator: String,
    delegation_url: String,
    icann_operator: Option<String>,
    specification13: Option<bool>,
    contract_terminated: Option<bool>,
    delegation_date: Option<String>,
    removal_date: Option<String>,
    third_or_lower_level_registration: Option<bool>,
    source_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Designation {
    name: String,
    descendants: bool,
    deprecated: bool,
    references: Vec<String>,
    source_id: String,
}

fn strings(values: &[String]) -> String {
    format!(
        "&[{}]",
        values
            .iter()
            .map(|v| format!("{v:?}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn option(value: Option<&str>) -> String {
    value.map_or_else(|| "None".into(), |s| format!("Some({s:?})"))
}

fn verified(root: &Path, manifest: &serde_json::Value, path: &str) -> Result<Vec<u8>, String> {
    let item = manifest["inputs"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(manifest["outputs"].as_array().into_iter().flatten())
        .find(|i| i["path"] == path)
        .ok_or("inventory artifact missing from manifest")?;
    let expected = item["sha256"].as_str().ok_or("inventory hash missing")?;
    let target = root.join(path).canonicalize().map_err(|e| e.to_string())?;
    if !target.starts_with(root.canonicalize().map_err(|e| e.to_string())?) {
        return Err("inventory artifact escapes repository".into());
    }
    let bytes = std::fs::read(target).map_err(|e| e.to_string())?;
    if format!("{:x}", Sha256::digest(&bytes)) != expected {
        return Err("inventory artifact hash mismatch".into());
    }
    Ok(bytes)
}

/// Generate static factual metadata from locally verified derived inventories.
///
/// # Errors
/// Rejects malformed inventory, hash mismatches and missing/rehashed active roots.
pub fn generate(root: &Path, out_dir: &Path) -> Result<(), String> {
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("data/manifest.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if manifest["schema_version"] != 2 {
        return Err("unsupported inventory schema".into());
    }
    let roots: serde_json::Value =
        serde_json::from_slice(&verified(root, &manifest, "data/root/inventory.json")?)
            .map_err(|e| e.to_string())?;
    let special: serde_json::Value =
        serde_json::from_slice(&verified(root, &manifest, "data/special-use/names.json")?)
            .map_err(|e| e.to_string())?;
    let psl: serde_json::Value =
        serde_json::from_slice(&verified(root, &manifest, "data/psl/rules.json")?)
            .map_err(|e| e.to_string())?;
    let queue: serde_json::Value =
        serde_json::from_slice(&verified(root, &manifest, "data/research-queue.json")?)
            .map_err(|e| e.to_string())?;
    if [
        roots["schema_version"].as_u64(),
        special["schema_version"].as_u64(),
        psl["schema_version"].as_u64(),
        queue["schema_version"].as_u64(),
    ]
    .iter()
    .any(|v| *v != Some(2))
    {
        return Err("unsupported derived inventory schema".into());
    }
    let mut roots: Vec<Root> =
        serde_json::from_value(roots["roots"].clone()).map_err(|e| e.to_string())?;
    let mut special: Vec<Designation> =
        serde_json::from_value(special["names"].clone()).map_err(|e| e.to_string())?;
    let raw = String::from_utf8(verified(
        root,
        &manifest,
        "data/root/tlds-alpha-by-domain.txt",
    )?)
    .map_err(|e| e.to_string())?;
    let mut active = BTreeSet::new();
    let mut lines = raw.lines();
    let header = lines.next().ok_or("missing active-root version")?;
    if !header.starts_with("# Version ") {
        return Err("invalid active-root version header".into());
    }
    for name in lines {
        let canonical = crate::normalization::normalize(name)
            .map_err(|e| e.code().to_owned())?
            .ascii()
            .to_owned();
        if canonical.contains('.') || !active.insert(canonical) {
            return Err("duplicate/non-root active label".into());
        }
    }
    let actual = roots.iter().map(|r| r.tld.clone()).collect::<BTreeSet<_>>();
    if actual != active || actual.len() != roots.len() {
        return Err("derived active-root set disagrees with pinned IANA list".into());
    }
    for root in &roots {
        if !root.active
            || crate::normalization::normalize(&root.tld)
                .map_err(|e| e.code().to_owned())?
                .ascii()
                != root.tld
            || root.operator.is_empty()
            || root.kind.is_empty()
            || root.source_ids.is_empty()
            || !root
                .delegation_url
                .starts_with("https://www.iana.org/domains/root/db/")
        {
            return Err("invalid active-root metadata".into());
        }
    }
    let mut designated = BTreeSet::new();
    for item in &special {
        if crate::normalization::normalize(&item.name)
            .map_err(|e| e.code().to_owned())?
            .ascii()
            != item.name
            || !designated.insert(item.name.clone())
            || item.references.is_empty()
            || item.references.iter().any(|r| {
                r.len() <= 3 || !r.starts_with("rfc") || !r[3..].bytes().all(|b| b.is_ascii_digit())
            })
            || item.source_id.is_empty()
        {
            return Err("invalid special-use designation/reference".into());
        }
    }
    roots.sort_by(|a, b| a.tld.cmp(&b.tld));
    special.sort_by(|a, b| a.name.cmp(&b.name));
    let inventory_date = manifest["inputs"]
        .as_array()
        .ok_or("manifest inputs missing")?
        .iter()
        .find(|i| i["source_id"] == "iana.active-roots")
        .and_then(|i| i["retrieved_on"].as_str())
        .ok_or("inventory date missing")?;
    checks::date(inventory_date)?;
    let (namespaces, icann, private) = checks::counts(&active, &psl, &queue)?;
    let mut output=format!("use crate::inventory_types::*;\npub const INVENTORY_DATE:&str={inventory_date:?};\npub static ROOT_INVENTORY:&[RootInventory]=&[\n");
    for item in &roots {
        output.push_str(&format!("RootInventory{{tld:{:?},kind:{:?},operator:{:?},delegation_url:{:?},icann_operator:{},specification13:{:?},contract_terminated:{:?},delegation_date:{},removal_date:{},third_or_lower_level_registration:{:?},source_ids:{}}},\n",item.tld,item.kind,item.operator,item.delegation_url,option(item.icann_operator.as_deref()),item.specification13,item.contract_terminated,option(item.delegation_date.as_deref()),option(item.removal_date.as_deref()),item.third_or_lower_level_registration,strings(&item.source_ids)));
    }
    output.push_str("];\npub static SPECIAL_USE:&[SpecialUse]=&[\n");
    for item in &special {
        output.push_str(&format!("SpecialUse{{name:{:?},descendants:{},deprecated:{},purpose:\"special_use\",references:{},source_id:{:?}}},\n",item.name,item.descendants,item.deprecated,strings(&item.references),item.source_id));
    }
    output.push_str(&format!("];\npub static INVENTORY_COUNTS:InventoryCounts=InventoryCounts{{active_roots:{},discovered_namespaces:{namespaces},icann_routes:{icann},private_routes:{private},specification13_roots:{},special_use_names:{}}};\n",roots.len(),roots.iter().filter(|r|r.specification13==Some(true)).count(),special.len()));
    std::fs::write(out_dir.join("generated_inventory.rs"), output).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Tree(PathBuf);
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tree(omit_root: bool) -> Tree {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "tldhax-inventory-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let entries = if omit_root {
            serde_json::json!([])
        } else {
            serde_json::json!([{"tld":"fixture","active":true,"type":"generic","operator":"Māori registry","delegation_url":"https://www.iana.org/domains/root/db/fixture.html","specification13":true,"source_ids":["iana.active-roots"]}])
        };
        let mut sources=BTreeMap::from([
            ("data/root/inventory.json",serde_json::to_vec(&serde_json::json!({"schema_version":2,"roots":entries})).unwrap()),
            ("data/special-use/names.json",serde_json::to_vec(&serde_json::json!({"schema_version":2,"names":[{"name":"example.com","descendants":true,"deprecated":false,"references":["rfc6761"],"source_id":"iana.special-use.xml"}]})).unwrap()),
            ("data/psl/rules.json",serde_json::to_vec(&serde_json::json!({"schema_version":2,"rules":[{"section":"ICANN","kind":"exact","suffix":"fixture","rule":"fixture"},{"section":"PRIVATE","kind":"exact","suffix":"hosting.fixture","rule":"hosting.fixture"}]})).unwrap()),
            ("data/research-queue.json",serde_json::to_vec(&serde_json::json!({"schema_version":2,"groups":[{"namespaces":[{"selector":"fixture"}]}]})).unwrap()),
        ]);
        sources.insert(
            "data/root/tlds-alpha-by-domain.txt",
            b"# Version 2026101200, Last Updated fixture UTC\nFIXTURE\n".to_vec(),
        );
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for (path, bytes) in sources {
            let target = root.join(path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, &bytes).unwrap();
            let mut item =
                serde_json::json!({"path":path,"sha256":format!("{:x}",Sha256::digest(&bytes))});
            if path.ends_with(".txt") {
                item["source_id"] = serde_json::json!("iana.active-roots");
                item["retrieved_on"] = serde_json::json!("2026-10-12");
                inputs.push(item);
            } else {
                outputs.push(item);
            }
        }
        std::fs::write(
            root.join("data/manifest.json"),
            serde_json::to_vec(
                &serde_json::json!({"schema_version":2,"inputs":inputs,"outputs":outputs}),
            )
            .unwrap(),
        )
        .unwrap();
        Tree(root)
    }
    #[test]
    fn metadata_types_do_not_infer_registration_access() {
        let source = r#"{"tld":"fixture","active":true,"type":"generic","operator":"fixture operator","delegation_url":"https://www.iana.org/domains/root/db/fixture.html","specification13":true,"source_ids":["iana.active-roots"]}"#;
        let parsed: Root = serde_json::from_str(source).unwrap();
        assert_eq!(parsed.specification13, Some(true));
        assert!(parsed.contract_terminated.is_none());
        assert!(!source.contains("registerable"));
    }

    #[test]
    fn generated_inventory_retains_purpose_provenance_and_precomputed_counts() {
        let tree = tree(false);
        generate(&tree.0, &tree.0).unwrap();
        let text = std::fs::read_to_string(tree.0.join("generated_inventory.rs")).unwrap();
        assert!(text.contains("operator:\"Māori registry\""));
        assert!(text.contains("purpose:\"special_use\""));
        assert!(text.contains("references:&[\"rfc6761\"]"));
        assert!(text.contains("active_roots:1"));
        assert!(text.contains("specification13_roots:1"));
        assert!(!text.contains("registerable"));
    }

    #[test]
    fn edited_rehashed_omission_cannot_shrink_active_root_inventory() {
        let tree = tree(true);
        assert!(generate(&tree.0, &tree.0)
            .unwrap_err()
            .contains("disagrees with pinned IANA"));
    }

    #[test]
    fn discovery_denominators_preserve_wildcards_exceptions_and_private_scope() {
        let active = BTreeSet::from(["fixture".into()]);
        let psl = serde_json::json!({"rules":[
            {"section":"ICANN","kind":"wildcard","suffix":"fixture","rule":"*.fixture"},
            {"section":"ICANN","kind":"exception","suffix":"www.fixture","rule":"!www.fixture"},
            {"section":"PRIVATE","kind":"exact","suffix":"hosting.fixture","rule":"hosting.fixture"}
        ]});
        let queue = serde_json::json!({"groups":[{"namespaces":[{"selector":"fixture"},{"selector":"*.fixture"}]}]});
        assert_eq!(checks::counts(&active, &psl, &queue).unwrap(), (2, 2, 1));
        let omitted = serde_json::json!({"groups":[{"namespaces":[{"selector":"fixture"}]}]});
        assert!(checks::counts(&active, &psl, &omitted)
            .unwrap_err()
            .contains("disagrees"));
        let duplicate = serde_json::json!({"groups":[{"namespaces":[{"selector":"fixture"},{"selector":"fixture"}]}]});
        assert!(checks::counts(&active, &psl, &duplicate)
            .unwrap_err()
            .contains("duplicate"));
    }

    #[test]
    fn original_unicode_psl_rules_match_canonical_ascii_discovery() {
        let active = BTreeSet::from(["fixture".into()]);
        let psl = serde_json::json!({"rules":[{"section":"ICANN","kind":"exact","suffix":"xn--bcher-kva.fixture","rule":"bücher.fixture"}]});
        let queue = serde_json::json!({"groups":[{"namespaces":[{"selector":"fixture"},{"selector":"xn--bcher-kva.fixture"}]}]});
        assert_eq!(checks::counts(&active, &psl, &queue).unwrap(), (2, 1, 0));
        let mut invalid = psl;
        invalid["rules"][0]["rule"] = serde_json::json!("!bücher.fixture");
        assert!(checks::counts(&active, &invalid, &queue).is_err());
    }

    #[test]
    fn inventory_dates_require_real_calendar_dates() {
        assert!(checks::date("2024-02-29").is_ok());
        for value in [
            "2025-02-29",
            "2026-13-01",
            "2026-10-32",
            "2026-1-01",
            "0000-01-01",
        ] {
            assert!(checks::date(value).is_err());
        }
    }
}
