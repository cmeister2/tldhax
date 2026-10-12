//! Assessment facade tests independent of the presence of curated policy facts.

use crate::assessment_types::{NameValidity, Summary};
use crate::profile::{ProfileError, MAX_PROFILE_BYTES};
use crate::registry::Registry;

#[test]
fn handles_and_statistics_reference_one_static_release() {
    let registry = Registry::new();
    assert!(std::ptr::eq(registry.dataset(), Registry::new().dataset()));
    assert_eq!(
        registry.dataset().version,
        registry.dataset_stats().dataset_version
    );
    assert_eq!(
        registry.dataset().evaluation_date,
        registry.dataset_stats().evaluation_date
    );
}

#[test]
fn compact_and_detailed_assessment_preserve_protocol_outcomes() {
    let registry = Registry::new();
    for input in ["", "under_score.com", "a..com"] {
        assert_eq!(
            registry.assess(input, None).name_validity,
            NameValidity::Invalid
        );
        assert_eq!(
            registry.assess_detailed(input, None).compact.summary,
            Summary::No
        );
    }
    let unicode = registry.assess("bücher.de", None);
    let ascii = registry.assess("xn--bcher-kva.de", None);
    assert_eq!(unicode.ascii(), ascii.ascii());
    assert_eq!(unicode.name_validity, ascii.name_validity);
    assert_eq!(unicode.dataset_version, ascii.dataset_version);
    assert_eq!(
        registry
            .assess("vanity.unlisted-root-fixture", None)
            .summary,
        Summary::Unknown
    );
}

#[test]
fn the_public_profile_factory_rejects_unknown_fields_and_input_budgets_privately() {
    let registry = Registry::new();
    assert!(registry.prepare_registrant("{}").is_ok());
    let error = registry
        .prepare_registrant(r#"{"undeclared_private_field":"sensitive-profile-token"}"#)
        .unwrap_err();
    assert_eq!(error, ProfileError::UnknownField);
    assert!(!format!("{error:?}").contains("sensitive-profile-token"));
    assert_eq!(
        registry
            .prepare_registrant(&"x".repeat(MAX_PROFILE_BYTES + 1))
            .unwrap_err(),
        ProfileError::InputLimit
    );
    assert_eq!(
        registry
            .prepare_registrant(r#"{"duplicate":true,"duplicate":false}"#)
            .unwrap_err(),
        ProfileError::InvalidJson
    );
}
