//! Evidence identity, scope and canonical collision rejection.

use super::{fixtures, schema, validate};

/// Verify that complete source and assertion metadata validate.
#[test]
fn complete_source_and_assertion_metadata_validate() {
    let mut document = fixtures::fixture();
    let statuses = validate::document(&mut document, "2026-10-12", None).unwrap();
    assert!(statuses.values().all(|status| status.active));
    assert_eq!(document.namespaces[0].selector, "fixture");
}

/// Verify that missing evidence locators hashes dates and operation are rejected.
#[test]
fn missing_evidence_locators_hashes_dates_and_operation_are_rejected() {
    for mutation in 0..8 {
        let mut document = fixtures::fixture();
        match mutation {
            0 => document.assertions[0].source_id = "missing".into(),
            1 => document.assertions[0].locator.clear(),
            2 => document.sources[0].sha256 = "invalid".into(),
            3 => document.assertions[0].review_due = "2026-02-30".into(),
            4 => document.assertions[0].operation = "renewal".into(),
            5 => document.assertions[0].namespaces.clear(),
            6 => document.sources[0].hash_representation = "unspecified_pdf".into(),
            _ => document.sources[0].snapshot_path = Some("../outside".into()),
        }
        assert!(
            validate::document(&mut document, "2026-10-12", None).is_err(),
            "mutation {mutation}"
        );
    }
}

/// Verify that unicode and alabel namespace collisions are rejected.
#[test]
fn unicode_and_alabel_namespace_collisions_are_rejected() {
    let mut document = fixtures::fixture();
    document.namespaces[0].selector = "é.fixture".into();
    let mut duplicate = document.namespaces[0].clone();
    duplicate.selector = "xn--9ca.fixture".into();
    document.namespaces.push(duplicate);
    assert!(validate::document(&mut document, "2026-10-12", None)
        .unwrap_err()
        .contains("canonical namespace"));
    let mut document = fixtures::fixture();
    document.label_sets.push(schema::LabelSet {
        id: "fixture.set".into(),
        labels: vec!["é".into(), "xn--9ca".into()],
        assertion_ids: vec!["fixture.length".into()],
    });
    assert!(validate::document(&mut document, "2026-10-12", None)
        .unwrap_err()
        .contains("canonical label collision"));
}

/// Verify that translation relationships require existing acyclic sources.
#[test]
fn translation_relationships_require_existing_acyclic_sources() {
    for cycle in [false, true] {
        let mut document = fixtures::fixture();
        if cycle {
            let mut translation = document.sources[0].clone();
            translation.id = "fixture.translation".into();
            translation.translation_of = Some("fixture.source".into());
            document.sources[0].translation_of = Some(translation.id.clone());
            document.sources.push(translation);
        } else {
            document.sources[0].translation_of = Some("missing.translation".into());
        }
        assert!(validate::document(&mut document, "2026-10-12", None).is_err());
    }
}
