//! Independent adopted repertoire, contextual and partial-table cases.

use super::*;
use crate::policy_types::{CodepointRange, IdnContext};

/// Complete finite synthetic table with a contextual middle dot.
const IDN: IdnProfile = IdnProfile {
    id: "fixture",
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
};

/// An adopted complete repertoire distinguishes included and excluded scalars and contextual failures.
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

/// An incomplete repertoire cannot infer a prohibition from an absent character or establish permission.
#[test]
fn partial_repertoire_preserves_unknown_but_known_context_failures_reject() {
    /// Partial adopted repertoire which cannot prove character-list exhaustiveness.
    const PARTIAL: &[IdnProfile] = &[IdnProfile {
        repertoire_complete: false,
        ..IDN
    }];
    for label in ["é", "ø"] {
        assert_eq!(evaluate(label, "fixture", PARTIAL).truth, Truth::Unknown);
    }
    assert_eq!(evaluate("a·b", "fixture", PARTIAL).truth, Truth::False);
}

/// An absent adopted table is missing policy data, rather than a character prohibition.
#[test]
fn missing_table_does_not_mean_characters_are_prohibited() {
    assert_eq!(
        evaluate("é", "missing", &[IDN]),
        PredicateResult::issue(Truth::Unknown, PredicateIssue::MissingTable("missing"))
    );
}
