//! Independent compiler integrity and finite-expression fixtures.

use super::predicates::{Basis, Fact, FactKind, Predicate, Value};
use super::schema::{Class, Effect, Requirement, Support};
use super::*;

/// Minimal direct dataset which requires no source graph or reviewer metadata.
fn fixture() -> CompiledInputs {
    CompiledInputs {
        known_suffixes: Vec::new(),
        version: "fixture".into(),
        input_paths: Vec::new(),
        roots: vec!["test".into()],
        routes: vec!["test".into()],
        special_use: Vec::new(),
        facts: vec![Fact {
            field: "eligible".into(),
            kind: FactKind::Boolean,
            allowed_values: Vec::new(),
            string_format: None,
        }],
        idn_profiles: Vec::new(),
        label_sets: Vec::new(),
        policies: vec![Policy {
            id: "fixture".into(),
            selector: "test".into(),
            form: vec!["label".into()],
            ascii: Support::Supported,
            idn: Support::Unsupported,
            source_notes: vec!["Ordinary source note omitted from runtime".into()],
            gaps: Vec::new(),
            requirements: vec![Requirement {
                code: "eligible".into(),
                message: "The applicant must declare eligibility".into(),
                effect: Effect::Require,
                input_class: Class::Any,
                predicate: Predicate::FieldEquals {
                    field: "eligible".into(),
                    value: Value::Boolean(true),
                },
                source_notes: Vec::new(),
            }],
        }],
    }
}

/// Direct positive-scope records need only executable conditions and ordinary schema integrity.
#[test]
fn direct_records_compile_without_citation_or_attestation_graph() {
    let mut input = fixture();
    validate::validate(&mut input).unwrap();
    let output = emit::render(&input).unwrap();
    assert!(output.contains("NamespacePolicy"));
    assert!(output.contains("The applicant must declare eligibility"));
    assert!(!output.contains("Ordinary source note"));
    assert!(!output.contains("EvidenceAssertion"));
}

/// Unknown schema fields cannot silently alter the public meaning of a direct policy.
#[test]
fn malformed_schema_is_rejected() {
    let valid = r#"schema_version=1
[[policies]]
id="fixture"
selector="test"
form=["label"]
ascii="supported"
idn="unsupported"
"#;
    assert!(toml::from_str::<Document>(valid).is_ok());
    assert!(toml::from_str::<Document>(&format!("{valid}\nregisterable=true\n")).is_err());
    assert!(toml::from_str::<Document>(&valid.replace("supported", "invented")).is_err());
}

/// A candidate component reference must fit the single authored registration form.
#[test]
fn component_ranges_and_ambiguous_forms_are_rejected() {
    let mut input = fixture();
    input.policies[0].requirements[0].predicate = Predicate::LabelMinimum {
        component: 1,
        min: 2,
        basis: Basis::Ascii,
    };
    assert!(validate::validate(&mut input)
        .unwrap_err()
        .contains("component"));
    let mut input = fixture();
    let mut duplicate = input.policies[0].clone();
    duplicate.id = "different".into();
    input.policies.push(duplicate);
    assert!(validate::validate(&mut input)
        .unwrap_err()
        .contains("ambiguous"));
    let mut input = fixture();
    input.policies[0].form.clear();
    assert!(validate::validate(&mut input)
        .unwrap_err()
        .contains("nonempty"));
}

/// Shared tables and typed profile comparisons must resolve before runtime evaluation.
#[test]
fn missing_assets_and_wrong_profile_literal_types_are_rejected() {
    for expression in [
        Predicate::LabelInSet {
            component: 0,
            set_id: "missing".into(),
        },
        Predicate::Idn {
            component: 0,
            profile_id: "missing".into(),
        },
        Predicate::FieldEquals {
            field: "missing".into(),
            value: Value::Boolean(true),
        },
        Predicate::FieldEquals {
            field: "eligible".into(),
            value: Value::String("true".into()),
        },
    ] {
        let mut input = fixture();
        input.policies[0].requirements[0].predicate = expression;
        assert!(validate::validate(&mut input).is_err());
    }
}

/// Unbounded nesting and impossible length bounds fail during ordinary compilation.
#[test]
fn excessive_work_and_invalid_bounds_are_rejected() {
    let mut input = fixture();
    let mut expression = Predicate::Constant { value: true };
    for _ in 0..17 {
        expression = Predicate::Not {
            predicate: Box::new(expression),
        };
    }
    input.policies[0].requirements[0].predicate = expression;
    assert!(validate::validate(&mut input)
        .unwrap_err()
        .contains("budget"));
    let mut input = fixture();
    input.policies[0].requirements[0].predicate = Predicate::LabelLength {
        component: 0,
        min: 10,
        max: 5,
        basis: Basis::Ascii,
    };
    assert!(validate::validate(&mut input)
        .unwrap_err()
        .contains("length"));
}

/// Discovery data is canonicalized independently while curated namespace keys remain explicit.
#[test]
fn discovery_unicode_and_marker_semantics_are_preserved() {
    let mut input = fixture();
    input.routes = vec!["*.é.test".into(), "!www.é.test".into(), "é.test".into()];
    validate::validate(&mut input).unwrap();
    assert_eq!(
        input.routes,
        ["!www.xn--9ca.test", "*.xn--9ca.test", "xn--9ca.test"]
    );
    let mut input = fixture();
    input.policies[0].selector = "TEST".into();
    assert!(validate::validate(&mut input)
        .unwrap_err()
        .contains("noncanonical"));
}

/// The packaged offline dataset passes the same loader and writer used by Cargo.
#[test]
fn packaged_inputs_validate_and_emit_offline() {
    let input = compile(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    assert!(!input.roots.is_empty());
    assert!(input.input_paths.len() >= 5);
    let output =
        std::env::temp_dir().join(format!("tldhax-direct-compiler-{}", std::process::id()));
    fs::create_dir_all(&output).unwrap();
    write(&input, &output).unwrap();
    let generated = fs::read_to_string(output.join("generated_policy.rs")).unwrap();
    assert!(generated.contains(&format!("DATASET_VERSION: &str = {:?}", input.version)));
    assert!(generated.contains("NAMESPACE_POLICIES"));
    fs::remove_dir_all(output).unwrap();
}

/// Legacy authoring contributes namespace identity only; unsupported defaults never become executable requirements.
#[test]
fn legacy_registration_defaults_are_inventory_only() {
    let text = r#"[[domains]]
tld = "unreviewed.test"
registerable = "yes"
min_length = 0
"#;
    let legacy: LegacyDocument = toml::from_str(text).unwrap();
    assert_eq!(legacy.domains[0].tld, "unreviewed.test");
    let mut input = fixture();
    input
        .known_suffixes
        .extend(legacy.domains.into_iter().map(|domain| domain.tld));
    validate::validate(&mut input).unwrap();
    assert!(input.known_suffixes.contains(&"unreviewed.test".to_owned()));
    assert_eq!(input.policies.len(), 1);
    assert_eq!(input.policies[0].selector, "test");
}
