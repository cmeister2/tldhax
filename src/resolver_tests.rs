//! Resolver regressions for supported forms, wildcard discovery and exceptions.

use super::*;
use crate::policy_types::Support;

/// Synthetic direct forms for testing routing independently of registry policy.
static POLICIES: &[NamespacePolicy] = &[
    NamespacePolicy {
        id: "fixture.one", selector: "fixture", kind: SelectorKind::Exact,
        form: &["label"], ascii: Support::Supported, idn: Support::Unsupported,
        requirements: &[], gaps: &[],
    },
    NamespacePolicy {
        id: "fixture.two", selector: "fixture", kind: SelectorKind::Exact,
        form: &["given", "family"], ascii: Support::Supported, idn: Support::Unsupported,
        requirements: &[], gaps: &[],
    },
    NamespacePolicy {
        id: "co.uk.one", selector: "co.uk", kind: SelectorKind::Exact,
        form: &["label"], ascii: Support::Supported, idn: Support::Unsupported,
        requirements: &[], gaps: &[],
    },
    NamespacePolicy {
        id: "ck.wildcard", selector: "*.ck", kind: SelectorKind::Wildcard,
        form: &["label"], ascii: Support::Supported, idn: Support::Unsupported,
        requirements: &[], gaps: &[],
    },
];
/// Sorted synthetic root identities.
static ROOTS: &[&str] = &["ck", "fixture", "uk"];
/// Sorted suffix routes, including the standard wildcard/exception example.
static ROUTES: &[Route] = &[
    Route {selector: "!www.ck", kind: RouteKind::Exception},
    Route {selector: "*.ck", kind: RouteKind::Wildcard},
    Route {selector: "ck", kind: RouteKind::Exact},
    Route {selector: "co.uk", kind: RouteKind::Exact},
    Route {selector: "family.fixture", kind: RouteKind::Exact},
    Route {selector: "fixture", kind: RouteKind::Exact},
    Route {selector: "uk", kind: RouteKind::Exact},
];

#[test]
/// Unknown roots cannot acquire policy through a suffix spelling coincidence.
fn unknown_root_stays_unknown() {
    let result = Resolver::new(POLICIES, ROOTS, ROUTES).resolve("label.unknown");
    assert!(!result.root_known);
    assert!(result.policy.is_none());
    assert!(result.namespace.is_none());
}

#[test]
/// A known root selects only an explicitly implemented component count.
fn documented_forms_are_independent() {
    let resolver = Resolver::new(POLICIES, ROOTS, ROUTES);
    let one = resolver.resolve("alice.fixture");
    assert_eq!(one.policy.unwrap().id, "fixture.one");
    let two = resolver.resolve("alice.family.fixture");
    assert_eq!(two.policy.unwrap().id, "fixture.two");
    assert_eq!(two.namespace, Some("fixture"));
    assert_eq!(two.applicant, "alice.family");
    let deeper = resolver.resolve("extra.alice.family.fixture");
    assert!(deeper.policy.is_none());
    assert_eq!(deeper.namespace, Some("family.fixture"));
}

#[test]
/// A multi-label namespace does not treat an extra subdomain as a supported form.
fn namespace_boundaries_match_whole_labels() {
    let resolver = Resolver::new(POLICIES, ROOTS, ROUTES);
    let supported = resolver.resolve("label.co.uk");
    assert_eq!(supported.namespace, Some("co.uk"));
    assert_eq!(supported.applicant, "label");
    assert_eq!(supported.policy.unwrap().id, "co.uk.one");
    assert!(resolver.resolve("deeper.label.co.uk").policy.is_none());
    assert!(resolver.resolve("label.notco.uk").policy.is_none());
    assert_eq!(resolver.resolve("co.uk").applicant_labels, 0);
}

#[test]
/// A wildcard applies to a concrete namespace while exceptions retain the parent.
fn wildcard_and_exception_semantics_survive() {
    let resolver = Resolver::new(POLICIES, ROOTS, ROUTES);
    let wildcard = resolver.resolve("label.foo.ck");
    assert_eq!(wildcard.namespace, Some("foo.ck"));
    assert_eq!(wildcard.applicant, "label");
    assert_eq!(wildcard.policy.unwrap().id, "ck.wildcard");
    let exception = resolver.resolve("label.www.ck");
    assert_eq!(exception.namespace, Some("ck"));
    assert_eq!(exception.applicant, "label.www");
    assert!(exception.policy.is_none());
    assert_eq!(resolver.resolve("www.ck").namespace, Some("ck"));
}

#[test]
/// Whole-label matching prevents a namespace suffix from matching a partial label.
fn selector_requires_a_label_boundary() {
    assert_eq!(matches_suffix("a.fixture", "fixture"), Some("fixture"));
    assert!(matches_suffix("a.notfixture", "fixture").is_none());
}
