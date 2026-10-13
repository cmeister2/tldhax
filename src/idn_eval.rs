//! Adopted finite IDN repertoires with independent completeness and context.

use crate::policy_types::{ContextKind, IdnProfile};
use crate::predicate_types::{PredicateIssue, PredicateResult, Truth};

/// Enforce a complete adopted table, with finite Unicode context checks.
pub fn evaluate(
    label: &str,
    profile_id: &'static str,
    profiles: &'static [IdnProfile],
) -> PredicateResult {
    let Ok(index) = profiles.binary_search_by_key(&profile_id, |profile| profile.id) else {
        return PredicateResult::issue(Truth::Unknown, PredicateIssue::MissingTable(profile_id));
    };
    let profile = &profiles[index];
    let mut incomplete = !profile.repertoire_complete;
    for (position, character) in label.chars().enumerate() {
        let cp = u32::from(character);
        let index = profile.ranges.partition_point(|range| range.end < cp);
        if !profile
            .ranges
            .get(index)
            .is_some_and(|range| range.start <= cp)
        {
            if profile.repertoire_complete {
                return PredicateResult::issue(Truth::False, PredicateIssue::IdnCharacter(cp));
            }
            incomplete = true;
        }
        for context in profile
            .contexts
            .iter()
            .filter(|context| context.codepoint == cp)
        {
            let previous = position
                .checked_sub(1)
                .and_then(|previous| label.chars().nth(previous))
                .map(u32::from);
            let next = label.chars().nth(position + 1).map(u32::from);
            let valid = match context.kind {
                ContextKind::NotStart => position > 0,
                ContextKind::NotEnd => next.is_some(),
                ContextKind::PrecededBy(values) => previous.is_some_and(|cp| values.contains(&cp)),
                ContextKind::FollowedBy(values) => next.is_some_and(|cp| values.contains(&cp)),
                ContextKind::Between { left, right } => {
                    previous.is_some_and(|cp| left.contains(&cp))
                        && next.is_some_and(|cp| right.contains(&cp))
                }
            };
            if !valid {
                return PredicateResult::issue(
                    Truth::False,
                    PredicateIssue::IdnContext {
                        codepoint: cp,
                        position,
                    },
                );
            }
        }
    }
    if incomplete {
        PredicateResult::issue(Truth::Unknown, PredicateIssue::IdnIncomplete(profile_id))
    } else {
        PredicateResult::plain(Truth::True)
    }
}

#[cfg(test)]
#[path = "idn_eval_tests.rs"]
mod tests;
