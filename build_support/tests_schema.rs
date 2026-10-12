//! Owned authoring parsing and finite predicate schema tests.

use super::*;

#[test]
fn synthetic_multiform_authoring_round_trips_through_typed_schema() {
    let parsed: schema::AuthoringFile =
        toml::from_str(include_str!("../tests/compiler/authoring.toml")).unwrap();
    assert_eq!(parsed.schema_version, 2);
    assert_eq!(
        parsed.namespaces[0]
            .forms
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(parsed.facts[0].kind, predicates::FactKind::StringSet);
}

#[test]
fn unknown_predicate_or_namespace_fields_are_rejected() {
    let unknown =
        "schema_version=2\n[[namespaces]]\nselector='fixture'\ninferred_registerable=true\n";
    assert!(toml::from_str::<schema::AuthoringFile>(unknown).is_err());
    assert!(
        serde_json::from_str::<predicates::Predicate>(r#"{"kind":"regex","pattern":".*"}"#)
            .is_err()
    );
    assert!(serde_json::from_str::<predicates::Predicate>(
        r#"{"kind":"constant","value":true,"invented":true}"#
    )
    .is_err());
}
