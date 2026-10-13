//! Small independent compiler fixtures for deterministic static routing.
#![allow(clippy::missing_docs_in_private_items)]

use super::{inputs, render, Rule, Supplement};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tldhax-resolver-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join("data/root")).unwrap();
        fs::create_dir_all(path.join("data/psl")).unwrap();
        fs::write(path.join("data/root/inventory.json"), r#"{"schema_version":2,"roots":[{"tld":"ck","active":true,"inventory_state":"delegated"},{"tld":"name","active":true,"inventory_state":"delegated"}]}"#).unwrap();
        fs::write(path.join("data/psl/rules.json"), r#"{"schema_version":2,"rules":[{"rule":"*.ck","suffix":"ck","kind":"wildcard","section":"ICANN"},{"rule":"!www.ck","suffix":"www.ck","kind":"exception","section":"ICANN"},{"rule":"*.name","suffix":"name","kind":"wildcard","section":"ICANN"}]}"#).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn supplements_require_active_roots_evidence_and_real_form_counts() {
    let fixture = Fixture::new();
    let approved = Supplement {
        selector: "NAME",
        evidence_ids: &["name.two-labels"],
        applicant_label_counts: &[2, 1, 2],
    };
    let (rules, active) = inputs(&fixture.0, &[approved]).unwrap();
    let reviewed = rules
        .iter()
        .find(|rule| rule.section == "Reviewed")
        .unwrap();
    assert_eq!(reviewed.selector, "name");
    assert_eq!(reviewed.counts, [1, 2]);
    let output = render(&rules, &active).unwrap();
    assert_eq!(output, render(&rules, &active).unwrap());
    assert!(output.contains("RouteKind::Exception"));
    for invalid in [
        Supplement {
            selector: "unknown",
            evidence_ids: &["rule"],
            applicant_label_counts: &[1],
        },
        Supplement {
            selector: "name",
            evidence_ids: &[],
            applicant_label_counts: &[1],
        },
        Supplement {
            selector: "name",
            evidence_ids: &["rule"],
            applicant_label_counts: &[],
        },
        Supplement {
            selector: "name",
            evidence_ids: &["rule"],
            applicant_label_counts: &[0],
        },
    ] {
        assert!(inputs(&fixture.0, &[invalid]).is_err());
    }
}

#[test]
fn canonical_collisions_selector_mismatches_and_root_exceptions_fail() {
    let fixture = Fixture::new();
    let path = fixture.0.join("data/psl/rules.json");
    for body in [
        r#"[{"rule":"ck","suffix":"name","kind":"exact","section":"ICANN"}]"#,
        r#"[{"rule":"!ck","suffix":"ck","kind":"exception","section":"ICANN"}]"#,
        r#"[{"rule":"食狮.ck","suffix":"xn--85x722f.ck","kind":"exact","section":"ICANN"},{"rule":"xn--85x722f.ck","suffix":"xn--85x722f.ck","kind":"exact","section":"ICANN"}]"#,
        r#"[{"rule":"*.ck","suffix":"ck","kind":"exact","section":"ICANN"}]"#,
    ] {
        fs::write(&path, format!("{{\"schema_version\":2,\"rules\":{body}}}")).unwrap();
        assert!(inputs(&fixture.0, &[]).is_err());
    }
}

#[test]
fn generation_is_independent_of_semantic_input_order() {
    let fixture = Fixture::new();
    let path = fixture.0.join("data/psl/rules.json");
    let (original, active) = inputs(&fixture.0, &[]).unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    document["rules"].as_array_mut().unwrap().reverse();
    fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    let (reordered, _) = inputs(&fixture.0, &[]).unwrap();
    assert_eq!(original, reordered);
    assert_eq!(
        render(&original, &active).unwrap(),
        render(&reordered, &active).unwrap()
    );
    super::generate(&fixture.0, &fixture.0, &[]).unwrap();
    let generated = fs::read_to_string(fixture.0.join("generated_resolver.rs")).unwrap();
    assert!(generated.contains("RouteKind::Exception"));
    assert!(generated.contains("psl:Icann:!www.ck"));
}

#[test]
fn nontransitional_keys_share_runtime_normalisation() {
    assert_eq!(super::canonical("faß.name").unwrap(), "xn--fa-hia.name");
    assert!(super::canonical("_invalid.name").is_err());
    assert!(super::canonical("name.").is_err());
    assert!(super::canonical(" name").is_err());
    let active = BTreeSet::from(["name".to_owned()]);
    let rules = [Rule {
        section: "Inventory",
        kind: "Exact",
        suffix: "name".into(),
        selector: "name".into(),
        source_id: "iana.active-roots",
        evidence: vec![],
        counts: vec![],
    }];
    assert!(render(&rules, &active)
        .unwrap()
        .contains("active_root: true"));
}
