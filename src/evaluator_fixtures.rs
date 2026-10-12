//! Independent synthetic authoring fixtures, never expectations derived from the evaluator.
#![allow(clippy::missing_docs_in_private_items)]

use super::*;
use crate::inventory_types::{RootInventory, SpecialUse};
use crate::resolver::Resolver;
use crate::resolver::{RouteKind, RouteNode, RouteRule, RouteSection};

pub const COMPLETE: &[FamilyCoverage] = &[
    coverage(RuleFamily::Namespace),
    coverage(RuleFamily::Length),
    coverage(RuleFamily::Characters),
    coverage(RuleFamily::Idn),
    coverage(RuleFamily::Reserved),
    coverage(RuleFamily::Allocation),
    coverage(RuleFamily::Eligibility),
    coverage(RuleFamily::Access),
];

const fn coverage(family: RuleFamily) -> FamilyCoverage {
    FamilyCoverage {
        family,
        ascii: Knowledge::Reviewed,
        idn: Knowledge::Reviewed,
        evidence_ids: &["fixture.assertion"],
        gap: None,
    }
}

pub const POLICY: NamespacePolicy = NamespacePolicy {
    selector: "fixture",
    kind: SelectorKind::Exact,
    forms: &[RegistrationForm { roles: &["label"] }],
    coverage: COMPLETE,
    rule_indices: &[0, 1],
    evidence_ids: &["fixture.assertion"],
    context: &[],
};

pub const RULES: &[CompiledRule] = &[
    rule(
        "reserved",
        RuleFamily::Reserved,
        RuleEffect::Deny,
        Predicate::LabelInSet {
            component: 0,
            set_id: "reserved",
        },
    ),
    rule(
        "length",
        RuleFamily::Length,
        RuleEffect::Require,
        Predicate::LabelLength {
            component: 0,
            min: 3,
            max: 12,
            basis: LengthMeasure::Ascii,
        },
    ),
    rule(
        "citizen-or-resident",
        RuleFamily::Eligibility,
        RuleEffect::Require,
        Predicate::Any(&[
            Predicate::FieldIn {
                field: "citizenships",
                values: &[FactValue::String("US")],
            },
            Predicate::FieldEquals {
                field: "resident",
                value: FactValue::Boolean(true),
            },
        ]),
    ),
    rule(
        "conditional-reservation",
        RuleFamily::Reserved,
        RuleEffect::Deny,
        Predicate::All(&[
            Predicate::LabelInSet {
                component: 0,
                set_id: "reserved",
            },
            Predicate::Not(&Predicate::NameEqualsField {
                component: 0,
                field: "authorized_labels",
            }),
        ]),
    ),
    CompiledRule {
        forms: &[2],
        ..rule(
            "second-component",
            RuleFamily::Length,
            RuleEffect::Require,
            Predicate::LabelMinimum {
                component: 1,
                min: 3,
                basis: LengthMeasure::Ascii,
            },
        )
    },
    CompiledRule {
        input_class: InputClass::Idn,
        ..rule(
            "idn-character",
            RuleFamily::Characters,
            RuleEffect::Deny,
            Predicate::LabelPattern {
                component: 0,
                pattern: PatternKind::Contains,
                value: "é",
                basis: LengthMeasure::Unicode,
            },
        )
    },
    rule(
        "external-proof-context",
        RuleFamily::Eligibility,
        RuleEffect::Context,
        Predicate::Constant(false),
    ),
];

const fn rule(
    id: &'static str,
    family: RuleFamily,
    effect: RuleEffect,
    predicate: Predicate,
) -> CompiledRule {
    CompiledRule {
        id,
        family,
        effect,
        predicate,
        input_class: InputClass::Any,
        forms: &[1],
        evidence_ids: &["fixture.assertion"],
        scope: "fixture",
        code: id,
    }
}

pub const FACTS: &[FactSchema] = &[
    FactSchema {
        field: "authorized_labels",
        kind: FactKind::StringSet,
        allowed_values: &[],
    },
    FactSchema {
        field: "citizenships",
        kind: FactKind::StringSet,
        allowed_values: &[],
    },
    FactSchema {
        field: "resident",
        kind: FactKind::Boolean,
        allowed_values: &[],
    },
];

const SOURCES: &[EvidenceSource] = &[EvidenceSource {
    id: "fixture.source",
    publisher: "Synthetic registry",
    title: "Independent fixture policy",
    url: "https://registry.invalid/policy",
    fetched_url: "https://registry.invalid/policy",
    sha256: "fixture-fingerprint",
    hash_representation: "fixture",
    version: "1",
    language: "en",
    retrieved_on: "2026-10-12",
    translation_of: None,
}];
const ASSERTIONS: &[EvidenceAssertion] = &[EvidenceAssertion {
    id: "fixture.assertion",
    source_id: "fixture.source",
    locator: "Synthetic clauses 1–8",
    interpretation: "Synthetic fixture explicitly supplies each tested family.",
    operation: "new_registration",
    namespaces: &["fixture"],
    forms: &[1, 2],
    input_class: InputClass::Any,
    family: RuleFamily::Reserved,
    knowledge: Knowledge::Reviewed,
    attests_completeness: false,
    effective_from: None,
    applicable_on: Some("2026-10-12"),
    effective_until: None,
    reviewer: "fixture-author",
    reviewed_on: "2026-10-12",
    review_due: "2027-01-10",
    active: true,
    inactive_reason: None,
}];

const NODES: &[RouteNode] = &[
    node("", 1, 3, 0, 0, false),
    node("arpa", 0, 0, 0, 1, true),
    node("fixture", 4, 2, 1, 3, true),
    node("xn--bcher-kva", 0, 0, 4, 3, true),
    node("child", 0, 0, 7, 1, false),
    node("host", 0, 0, 8, 1, false),
];
const fn node(
    label: &'static str,
    child_start: u32,
    child_count: u16,
    rule_start: u32,
    rule_count: u8,
    active_root: bool,
) -> RouteNode {
    RouteNode {
        label,
        child_start,
        child_count,
        rule_start,
        rule_count,
        active_root,
    }
}
const fn route(selector: &'static str, section: RouteSection, counts: &'static [u8]) -> RouteRule {
    RouteRule {
        id: selector,
        selector,
        section,
        applicant_label_counts: counts,
        kind: RouteKind::Exact,
        source_id: "fixture.routes",
        evidence_ids: &[],
    }
}

/// Construct immutable test tables; route arities come from independent authored forms.
pub fn dataset(policies: &'static [NamespacePolicy]) -> &'static PolicyDataset {
    let counts = |selector| -> &'static [u8] {
        Box::leak(
            policies
                .iter()
                .find(|policy| policy.selector == selector)
                .into_iter()
                .flat_map(|policy| policy.forms)
                .map(|form| u8::try_from(form.roles.len()).unwrap())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    };
    let routes = Box::leak(
        vec![
            route("arpa", RouteSection::Inventory, &[]),
            route("fixture", RouteSection::Inventory, &[]),
            route("fixture", RouteSection::Icann, &[]),
            route("fixture", RouteSection::Reviewed, counts("fixture")),
            route("xn--bcher-kva", RouteSection::Inventory, &[]),
            route("xn--bcher-kva", RouteSection::Icann, &[]),
            route(
                "xn--bcher-kva",
                RouteSection::Reviewed,
                counts("xn--bcher-kva"),
            ),
            route("child.fixture", RouteSection::Icann, &[]),
            route("host.fixture", RouteSection::Private, &[]),
        ]
        .into_boxed_slice(),
    );
    Box::leak(Box::new(PolicyDataset {
        version: "fixture-v1",
        evaluation_date: "2026-10-12",
        inventory_date: "2026-10-10",
        normalization_profile: crate::normalization::NORMALIZATION_PROFILE,
        resolver: Box::leak(Box::new(Resolver::new(NODES, routes))),
        namespaces: policies,
        rules: RULES,
        label_sets: &[LabelSet {
            id: "reserved",
            labels: &["blocked", "conditional"],
            evidence_ids: &["fixture.assertion"],
        }],
        idn_profiles: &[],
        facts: FACTS,
        assertions: ASSERTIONS,
        sources: SOURCES,
        roots: &[RootInventory {
            tld: "arpa",
            kind: "infrastructure",
            operator: "IANA",
            delegation_url: "https://www.iana.org/domains/root/db/arpa.html",
            icann_operator: None,
            specification13: None,
            contract_terminated: None,
            delegation_date: None,
            removal_date: None,
            third_or_lower_level_registration: None,
            source_ids: &["fixture.roots"],
        }],
        special_use: SPECIAL_USE,
    }))
}

const fn designation(name: &'static str, descendants: bool, deprecated: bool) -> SpecialUse {
    SpecialUse {
        name,
        descendants,
        deprecated,
        purpose: "synthetic_special_use",
        references: &["rfc6761"],
        source_id: "fixture.special",
    }
}

const SPECIAL_USE: &[SpecialUse] = &[
    designation("deprecated.fixture", true, true),
    designation("exact.fixture", false, false),
    designation("local.fixture", true, false),
    designation("nested.local.fixture", false, false),
];

pub fn profile(json: &str) -> RegistrantProfile {
    RegistrantProfile::from_json(json, FACTS).unwrap()
}

pub fn policies(policies: Vec<NamespacePolicy>) -> &'static [NamespacePolicy] {
    let mut policies = policies;
    policies.sort_by_key(|policy| policy.selector);
    Box::leak(policies.into_boxed_slice())
}
