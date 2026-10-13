//! Synthetic routing cases independent of current registry policy.

use super::{Resolver, RouteKind, RouteMatch, RouteNode, RouteRule, RouteSection};

/// Construct a trie node with explicit child and rule slices for the synthetic routes.
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

/// Construct a route with independently authored kind, section, and supported form arities.
const fn rule(
    selector: &'static str,
    kind: RouteKind,
    section: RouteSection,
    counts: &'static [u8],
) -> RouteRule {
    RouteRule {
        id: selector,
        selector,
        source_id: "fixture",
        kind,
        section,
        applicant_label_counts: counts,
        evidence_ids: &["fixture.forms"],
    }
}

/// Trie containing root, wildcard-exception, reviewed-child, and private-hosting scenarios.
static NODES: &[RouteNode] = &[
    node("", 1, 5, 0, 0, false),
    node("ck", 6, 1, 0, 2, true),
    node("com", 7, 1, 2, 1, true),
    node("io", 8, 1, 3, 1, true),
    node("name", 9, 1, 4, 3, true),
    node("uk", 10, 1, 7, 1, true),
    node("www", 0, 0, 8, 1, false),
    node("blogspot", 0, 0, 9, 1, false),
    node("github", 0, 0, 10, 1, false),
    node("foo", 0, 0, 11, 1, false),
    node("special", 0, 0, 12, 1, false),
];

/// Independent discovery and reviewed routes used to test selection precedence.
static RULES: &[RouteRule] = &[
    rule("ck", RouteKind::Exact, RouteSection::Inventory, &[]),
    rule("*.ck", RouteKind::Wildcard, RouteSection::Icann, &[]),
    rule("com", RouteKind::Exact, RouteSection::Icann, &[]),
    rule("io", RouteKind::Exact, RouteSection::Icann, &[]),
    rule("name", RouteKind::Exact, RouteSection::Inventory, &[]),
    rule("*.name", RouteKind::Wildcard, RouteSection::Icann, &[]),
    rule("name", RouteKind::Exact, RouteSection::Reviewed, &[1, 2]),
    rule("uk", RouteKind::Exact, RouteSection::Icann, &[]),
    rule("!www.ck", RouteKind::Exception, RouteSection::Icann, &[]),
    rule("blogspot.com", RouteKind::Exact, RouteSection::Private, &[]),
    rule("github.io", RouteKind::Exact, RouteSection::Private, &[]),
    rule("foo.name", RouteKind::Exact, RouteSection::Reviewed, &[1]),
    rule("special.uk", RouteKind::Exact, RouteSection::Reviewed, &[1]),
];

/// Resolve a fixture name and require that its registration route exists.
fn registration(name: &str) -> RouteMatch<'_> {
    Resolver::new(NODES, RULES)
        .resolve(name, true)
        .registration
        .unwrap()
}

/// Wildcard and exception routes retain their selector identity and distinct applicant spans.
#[test]
fn wildcard_and_exception_preserve_selected_rule_identity() {
    let wildcard = registration("a.b.ck");
    assert_eq!(wildcard.suffix, "b.ck");
    assert_eq!(wildcard.applicant, "a");
    assert_eq!(wildcard.rule.id, "*.ck");
    assert_eq!(wildcard.rule.kind, RouteKind::Wildcard);
    let exception = registration("a.www.ck");
    assert_eq!(exception.suffix, "ck");
    assert_eq!(exception.applicant, "a.www");
    assert_eq!(exception.rule.id, "!www.ck");
    assert_eq!(exception.rule.kind, RouteKind::Exception);
    assert_eq!(registration("www.ck").applicant, "www");
}

/// Routing records zero or multiple applicant labels without treating the route as policy approval.
#[test]
fn bare_and_deeper_inputs_are_routed_without_inventing_validity() {
    let bare = registration("b.ck");
    assert_eq!(bare.suffix, "b.ck");
    assert_eq!(bare.applicant_labels, 0);
    let deeper = registration("one.two.com");
    assert_eq!(deeper.suffix, "com");
    assert_eq!(deeper.applicant, "one.two");
    assert_eq!(deeper.applicant_labels, 2);
    assert_eq!(registration("ck").rule.section, RouteSection::Inventory);
}

/// Private suffix classification remains optional and separate from registration scope.
#[test]
fn private_hosting_boundaries_never_replace_registration_routes() {
    let resolver = Resolver::new(NODES, RULES);
    let resolved = resolver.resolve("alice.github.io", true);
    assert_eq!(resolved.registration.unwrap().suffix, "io");
    assert_eq!(resolved.private.unwrap().suffix, "github.io");
    assert_eq!(resolved.private.unwrap().applicant, "alice");
    assert!(resolver.resolve("alice.github.io", false).private.is_none());
    assert_eq!(
        resolver
            .resolve("blogspot.com", true)
            .registration
            .unwrap()
            .applicant,
        "blogspot"
    );
}

/// Reviewed form arities override PSL discovery, with deeper reviewed namespaces taking precedence.
#[test]
fn reviewed_forms_override_discovery_and_the_deepest_approved_form_wins() {
    let resolver = Resolver::new(NODES, RULES);
    let direct = resolver.resolve("a.b.name", false);
    assert_eq!(direct.icann.unwrap().suffix, "b.name");
    assert_eq!(direct.registration.unwrap().suffix, "name");
    assert_eq!(direct.registration.unwrap().applicant_labels, 2);
    assert_eq!(
        direct.registration.unwrap().rule.section,
        RouteSection::Reviewed
    );
    assert_eq!(registration("a.foo.name").suffix, "foo.name");
    assert_eq!(registration("a.special.uk").suffix, "special.uk");
    let unmatched_form = resolver.resolve("one.two.three.name", false);
    assert_eq!(
        unmatched_form.registration.unwrap().rule.section,
        RouteSection::Icann
    );
    assert_eq!(unmatched_form.registration.unwrap().suffix, "three.name");
}

/// An unknown root produces no registration route, and known roots need not have private routes.
#[test]
fn unknown_roots_and_unmatched_private_names_remain_separate() {
    let resolver = Resolver::new(NODES, RULES);
    let unknown = resolver.resolve("example.unknown", true);
    assert_eq!(unknown.root, "unknown");
    assert!(!unknown.root_known);
    assert!(unknown.registration.is_none());
    assert!(unknown.private.is_none());
    assert!(resolver.resolve("example.com", true).private.is_none());
}

/// Selected suffix and applicant slices point into the original candidate string.
#[test]
fn returned_suffix_and_applicant_are_borrowed_candidate_spans() {
    let input = String::from("one.two.com");
    let matched = registration(&input);
    assert_eq!(matched.suffix.as_ptr(), input[8..].as_ptr());
    assert_eq!(matched.applicant.as_ptr(), input.as_ptr());
}
