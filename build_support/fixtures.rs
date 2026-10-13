//! Synthetic evidence helpers; these assert no real registry policy.

/// Compile a deliberately synthetic policy without a publisher snapshot.
///
/// # Errors
/// Returns the evidence-validation, resolution or emission error for the synthetic input.
pub(super) fn run(document: super::schema::Document) -> Result<super::Compilation, String> {
    super::compile_document(document, "2026-10-12", None, "fixture-release")
}

use super::predicates::{Basis, Predicate};
use super::schema::{
    Assertion, Class, Coverage, Document, Effect, Family, Knowledge, Namespace, Source,
};

/// Create a current reviewed assertion scoped to the synthetic fixture namespace.
pub(super) fn assertion(id: &str, family: Family, predicate: Option<Predicate>) -> Assertion {
    Assertion {
        id: id.into(),
        source_id: "fixture.source".into(),
        locator: "Synthetic fixture clause 1".into(),
        operation: "new_registration".into(),
        namespaces: vec!["fixture".into()],
        forms: vec![1],
        input_class: Class::Any,
        family,
        effect: Effect::Require,
        knowledge: Knowledge::Reviewed,
        attests_completeness: false,
        interpretation: "Mechanical compiler test; no real registry policy is asserted.".into(),
        reviewer: "test fixture".into(),
        reviewed_on: "2026-10-12".into(),
        review_due: "2027-10-12".into(),
        effective_from: Some("2020-01-01".into()),
        applicable_on: None,
        effective_until: None,
        predicate,
        code: None,
    }
}

/// Build a synthetic one-label policy with evidence-backed length and form approval.
pub(super) fn fixture() -> Document {
    let source = Source {
        id: "fixture.source".into(),
        publisher: "Synthetic compiler test".into(),
        title: "Non-policy fixture".into(),
        url: "https://example.invalid/fixture".into(),
        fetched_url: "https://example.invalid/fixture".into(),
        sha256: "0".repeat(64),
        hash_representation: "original_bytes".into(),
        version: "fixture-1".into(),
        language: "en".into(),
        retrieved_on: "2026-10-12".into(),
        snapshot_path: None,
        translation_of: None,
    };
    let form = assertion("fixture.form", Family::Namespace, None);
    let length = assertion(
        "fixture.length",
        Family::Length,
        Some(Predicate::LabelLength {
            component: 0,
            min: 1,
            max: 63,
            basis: Basis::Ascii,
        }),
    );
    let mut complete = assertion("fixture.length.complete", Family::Length, None);
    complete.attests_completeness = true;
    Document {
        sources: vec![source],
        assertions: vec![form, length, complete],
        namespaces: vec![Namespace {
            selector: "fixture".into(),
            forms: vec![vec!["label".into()]],
            form_assertion_ids: vec!["fixture.form".into()],
            profiles: vec![],
            rules: vec!["fixture.length".into()],
            overrides: vec![],
            coverage: vec![Coverage {
                family: Family::Length,
                ascii: Knowledge::Reviewed,
                idn: Knowledge::Unknown,
                assertion_ids: vec!["fixture.length.complete".into()],
                gap: Some("IDN policy not reviewed".into()),
            }],
            context: vec![],
        }],
        ..Document::default()
    }
}
