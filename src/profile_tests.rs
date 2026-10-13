//! Public profile-contract fixtures independent of the predicate implementation.

use super::*;

/// Small explicit schema with enumeration, set membership and negative declarations.
const SCHEMAS: &[FactSchema] = &[
    FactSchema {
        field: "applicant_kind",
        kind: FactKind::String,
        allowed_values: &["individual", "organisation"],
        string_format: None,
    },
    FactSchema {
        field: "citizenships",
        kind: FactKind::StringSet,
        allowed_values: &["US", "DE"],
        string_format: None,
    },
    FactSchema {
        field: "us.presence",
        kind: FactKind::Boolean,
        allowed_values: &[],
        string_format: None,
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
        string_format: None,
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
        string_format: None,
    }];
    let profile =
        RegistrantProfile::from_json(r#"{"rights":["private-trademark-claim"]}"#, &set_schema)
            .unwrap();
    assert!(!format!("{:?}", profile.get("rights")).contains("private-trademark-claim"));
}

/// Scalar and set country fields accept structural codes without an exhaustive list.
const COUNTRY_SCHEMAS: &[FactSchema] = &[
    FactSchema {
        field: "residence",
        kind: FactKind::String,
        allowed_values: &[],
        string_format: Some(FactStringFormat::UppercaseAlpha2),
    },
    FactSchema {
        field: "citizenships",
        kind: FactKind::StringSet,
        allowed_values: &[],
        string_format: Some(FactStringFormat::UppercaseAlpha2),
    },
];

/// Structural country-code validation accepts uppercase scalar and set facts and preserves set identity.
#[test]
fn country_formats_accept_uppercase_scalars_and_set_entries() {
    let profile = RegistrantProfile::from_json(
        r#"{"residence":"PR","citizenships":["GB","PR","GB"]}"#,
        COUNTRY_SCHEMAS,
    )
    .unwrap();
    assert_eq!(
        profile.get("residence"),
        Some(&ProfileFact::String("PR".into()))
    );
    assert_eq!(
        profile.get("citizenships"),
        Some(&ProfileFact::StringSet(vec!["GB".into(), "PR".into()]))
    );
}

/// Every country-code value must contain exactly two uppercase ASCII letters, including each set member.
#[test]
fn country_formats_reject_malformed_scalars_and_each_set_entry() {
    for invalid in [
        "pr",
        "gB",
        "United Kingdom",
        " PR",
        "PR ",
        "P",
        "PRI",
        "P1",
        "",
        "PR\n",
        "GB\0",
        "Å",
        "ＰＲ",
        "ΡR",
        "PＲ",
    ] {
        for input in [
            serde_json::json!({"residence": invalid}),
            serde_json::json!({"citizenships": ["GB", invalid, "PR"]}),
        ] {
            let error =
                RegistrantProfile::from_json(&input.to_string(), COUNTRY_SCHEMAS).unwrap_err();
            assert_eq!(error, ProfileError::InvalidValue);
            assert_eq!(error.code(), "invalid_profile_value");
            assert_eq!(format!("{error:?}"), "InvalidValue");
        }
    }
}

/// Country-code formatting leaves missing declarations and explicitly empty sets distinguishable.
#[test]
fn country_formats_preserve_missing_facts_and_explicit_empty_sets() {
    let absent = RegistrantProfile::from_json("{}", COUNTRY_SCHEMAS).unwrap();
    assert_eq!(absent.get("residence"), None);
    assert_eq!(absent.get("citizenships"), None);
    let empty = RegistrantProfile::from_json(r#"{"citizenships":[]}"#, COUNTRY_SCHEMAS).unwrap();
    assert_eq!(empty.get("residence"), None);
    assert_eq!(
        empty.get("citizenships"),
        Some(&ProfileFact::StringSet(vec![]))
    );
}

/// Unformatted strings remain unrestricted, while formatted enumerations enforce both constraints.
#[test]
fn string_format_is_optional_and_composes_with_explicit_enumerations() {
    let plain = [FactSchema {
        field: "description",
        kind: FactKind::String,
        allowed_values: &[],
        string_format: None,
    }];
    let unrestricted =
        RegistrantProfile::from_json(r#"{"description":"United Kingdom "}"#, &plain).unwrap();
    assert_eq!(
        unrestricted.get("description"),
        Some(&ProfileFact::String("United Kingdom ".into()))
    );
    let enumerated = [FactSchema {
        field: "residence",
        kind: FactKind::String,
        allowed_values: &["GB"],
        string_format: Some(FactStringFormat::UppercaseAlpha2),
    }];
    assert!(RegistrantProfile::from_json(r#"{"residence":"GB"}"#, &enumerated).is_ok());
    assert_eq!(
        RegistrantProfile::from_json(r#"{"residence":"PR"}"#, &enumerated),
        Err(ProfileError::InvalidValue)
    );
}
