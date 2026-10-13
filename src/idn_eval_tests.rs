//! Independent table membership, contextual and partial-policy cases.

use super::*;
use crate::policy_types::{CodepointRange, IdnContext, IdnVariant, VariantDisposition};

/// Complete finite synthetic table with a contextual middle dot.
const IDN: IdnProfile = IdnProfile {
    id: "fixture",
    version: "1",
    knowledge: Knowledge::Reviewed,
    repertoire_complete: true,
    ranges: &[
        CodepointRange {
            start: 0x61,
            end: 0x7a,
        },
        CodepointRange {
            start: 0xb7,
            end: 0xb7,
        },
        CodepointRange {
            start: 0xe9,
            end: 0xe9,
        },
    ],
    contexts: &[IdnContext {
        codepoint: 0xb7,
        kind: ContextKind::Between {
            left: &[0x6c],
            right: &[0x6c],
        },
    }],
    variants: &[],
    evidence_ids: &["synthetic-table"],
    unsupported_features: &[],
};

/// A complete repertoire distinguishes adjacent included and excluded characters and contextual failures.
#[test]
fn complete_repertoire_has_nearby_membership_and_context_cases() {
    assert_eq!(evaluate("é", "fixture", &[IDN]).truth, Truth::True);
    assert_eq!(
        evaluate("ø", "fixture", &[IDN]),
        PredicateResult::issue(Truth::False, PredicateIssue::IdnCharacter(0xf8))
    );
    assert_eq!(evaluate("l·l", "fixture", &[IDN]).truth, Truth::True);
    assert_eq!(
        evaluate("a·b", "fixture", &[IDN]),
        PredicateResult::issue(
            Truth::False,
            PredicateIssue::IdnContext {
                codepoint: 0xb7,
                position: 1
            }
        )
    );
}

/// Partial knowledge or a blocked variant prevents permission, but a supported context failure still rejects.
#[test]
fn partial_context_or_variant_membership_cannot_establish_permission() {
    /// Table whose repertoire is complete but broader policy knowledge is partial.
    const PARTIAL: IdnProfile = IdnProfile {
        knowledge: Knowledge::Partial,
        ..IDN
    };
    /// Table carrying an unresolved blocked variant for the tested character.
    const VARIANT: IdnProfile = IdnProfile {
        variants: &[IdnVariant {
            sequence: "é",
            replacement: "e",
            disposition: VariantDisposition::Blocked,
        }],
        ..IDN
    };
    for profiles in [&[PARTIAL][..], &[VARIANT][..]] {
        assert_eq!(evaluate("é", "fixture", profiles).truth, Truth::Unknown);
    }
    assert_eq!(evaluate("a·b", "fixture", &[PARTIAL]).truth, Truth::False);
}

/// Only an active complete repertoire can reject an absent character when other policy knowledge is partial.
#[test]
fn complete_repertoire_can_disprove_membership_despite_context_gaps() {
    /// Active complete repertoire with incomplete contextual policy knowledge.
    const PARTIAL: &[IdnProfile] = &[IdnProfile {
        knowledge: Knowledge::Partial,
        ..IDN
    }];
    /// Partial table that cannot establish the exhaustiveness of its character list.
    const INCOMPLETE: &[IdnProfile] = &[IdnProfile {
        knowledge: Knowledge::Partial,
        repertoire_complete: false,
        ..IDN
    }];
    /// Unreviewed table whose apparent repertoire cannot support a prohibition.
    const INACTIVE: &[IdnProfile] = &[IdnProfile {
        knowledge: Knowledge::Unknown,
        ..IDN
    }];
    for (profiles, expected) in [
        (PARTIAL, Truth::False),
        (INCOMPLETE, Truth::Unknown),
        (INACTIVE, Truth::Unknown),
    ] {
        assert_eq!(evaluate("ø", "fixture", profiles).truth, expected);
    }
}

/// An absent IDN profile yields unknown with an explicit missing-table diagnostic.
#[test]
fn missing_table_does_not_mean_characters_are_prohibited() {
    assert_eq!(
        evaluate("é", "missing", &[IDN]),
        PredicateResult::issue(Truth::Unknown, PredicateIssue::MissingTable("missing"))
    );
}
