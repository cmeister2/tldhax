//! Public profile-contract fixtures independent of the predicate implementation.

use super::*;

/// Small explicit schema with enumeration, set membership and negative declarations.
const SCHEMAS: &[FactSchema] = &[
    FactSchema {
        field: "applicant_kind",
        kind: FactKind::String,
        allowed_values: &["individual", "organisation"],
    },
    FactSchema {
        field: "citizenships",
        kind: FactKind::StringSet,
        allowed_values: &["US", "DE"],
    },
    FactSchema {
        field: "us.presence",
        kind: FactKind::Boolean,
        allowed_values: &[],
    },
];

/// Parsing preserves absent facts, explicit negatives, and empty sets while deduplicating and sorting set values.
#[test]
fn preserves_missing_empty_false_and_set_identity() {
    let profile = RegistrantProfile::from_json(
        r#"{"citizenships":["US","DE","US"],"us.presence":false}"#,
        SCHEMAS,
    )
    .unwrap();
    assert_eq!(profile.get("applicant_kind"), None);
    assert_eq!(
        profile.get("us.presence"),
        Some(&ProfileFact::Boolean(false))
    );
    assert_eq!(
        profile.get("citizenships"),
        Some(&ProfileFact::StringSet(vec!["DE".into(), "US".into()]))
    );
    let empty = RegistrantProfile::from_json(r#"{"citizenships":[]}"#, SCHEMAS).unwrap();
    assert_eq!(
        empty.get("citizenships"),
        Some(&ProfileFact::StringSet(vec![]))
    );
}

/// Duplicate JSON fields, malformed input, undeclared fields, and wrong fact types fail distinctly.
#[test]
fn rejects_ambiguous_or_untyped_declarations() {
    for input in [
        r#"{"us.presence":true,"us.presence":false}"#,
        "[]",
        "null",
        "{",
    ] {
        assert_eq!(
            RegistrantProfile::from_json(input, SCHEMAS),
            Err(ProfileError::InvalidJson)
        );
    }
    for input in [
        r#"{"us.presence":"true"}"#,
        r#"{"us.presence":null}"#,
        r#"{"citizenships":[1]}"#,
        r#"{"applicant_kind":{"value":"individual"}}"#,
    ] {
        assert_eq!(
            RegistrantProfile::from_json(input, SCHEMAS),
            Err(ProfileError::WrongType)
        );
    }
    assert_eq!(
        RegistrantProfile::from_json(r#"{"secret":"private"}"#, SCHEMAS),
        Err(ProfileError::UnknownField)
    );
    assert_eq!(
        RegistrantProfile::from_json(r#"{"citizenships":["us"]}"#, SCHEMAS),
        Err(ProfileError::InvalidValue)
    );
}

/// Profile and fact limits reject oversized declarations, and debug output hides private values.
#[test]
fn enforces_input_budgets_and_omits_values_from_debug() {
    assert_eq!(
        RegistrantProfile::from_json(&" ".repeat(MAX_PROFILE_BYTES + 1), SCHEMAS),
        Err(ProfileError::InputLimit)
    );
    let schema = [FactSchema {
        field: "rights",
        kind: FactKind::String,
        allowed_values: &[],
    }];
    let value = "x".repeat(MAX_FACT_BYTES + 1);
    assert_eq!(
        RegistrantProfile::from_json(&format!(r#"{{"rights":"{value}"}}"#), &schema),
        Err(ProfileError::InputLimit)
    );
    let profile = RegistrantProfile::from_json(r#"{"rights":"sensitive-mark"}"#, &schema).unwrap();
    assert!(!format!("{profile:?}").contains("sensitive-mark"));
    assert!(format!("{profile:?}").contains("rights"));
    assert!(!format!("{:?}", profile.get("rights")).contains("sensitive-mark"));
    let set_schema = [FactSchema {
        field: "rights",
        kind: FactKind::StringSet,
        allowed_values: &[],
    }];
    let profile =
        RegistrantProfile::from_json(r#"{"rights":["private-trademark-claim"]}"#, &set_schema)
            .unwrap();
    assert!(!format!("{:?}", profile.get("rights")).contains("private-trademark-claim"));
}
