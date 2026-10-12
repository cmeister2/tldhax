//! Shared applicability, inheritance and completeness resolution helpers.

use super::predicates::{Basis, Predicate};
use super::schema::{Assertion, Class, Coverage, Effect, Knowledge, Namespace, Profile};
use super::validate::Status;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn scoped(assertion: &Assertion, selector: &str, counts: &[u8], class: Class) -> bool {
    assertion.namespaces.iter().any(|scope| scope == selector)
        && counts.iter().all(|count| assertion.forms.contains(count))
        && (assertion.input_class == Class::Any
            || assertion.input_class == class
            || class == Class::Any)
}

pub(super) fn reference<'a>(
    id: &str,
    assertions: &'a BTreeMap<&str, &Assertion>,
) -> Result<&'a Assertion, String> {
    assertions
        .get(id)
        .copied()
        .ok_or_else(|| format!("missing assertion: {id}"))
}

pub(super) fn expand<'a>(
    id: &str,
    profiles: &BTreeMap<&str, &'a Profile>,
    stack: &mut BTreeSet<String>,
    output: &mut Vec<&'a Profile>,
) -> Result<(), String> {
    if stack.len() >= 16 || !stack.insert(id.to_owned()) {
        return Err("profile inheritance cycle/depth limit".into());
    }
    let profile = profiles
        .get(id)
        .ok_or_else(|| format!("missing shared profile: {id}"))?;
    for parent in &profile.extends {
        expand(parent, profiles, stack, output)?;
    }
    if !output.iter().any(|p| p.id == profile.id) {
        output.push(profile);
    }
    stack.remove(id);
    Ok(())
}

pub(super) fn conflict(left: &Assertion, right: &Assertion) -> bool {
    if left.family != right.family
        || left.effect == Effect::Context
        || right.effect == Effect::Context
        || left.input_class != Class::Any
            && right.input_class != Class::Any
            && left.input_class != right.input_class
        || !left.forms.iter().any(|c| right.forms.contains(c))
    {
        return false;
    }
    if left.predicate == right.predicate && left.effect != right.effect {
        return true;
    }
    if left.effect == Effect::Require && right.effect == Effect::Require {
        if let (Some((a, amin, amax, ab)), Some((b, bmin, bmax, bb))) = (
            bounds(left.predicate.as_ref()),
            bounds(right.predicate.as_ref()),
        ) {
            return a == b && ab == bb && (amax < bmin || bmax < amin);
        }
    }
    false
}

fn bounds(predicate: Option<&Predicate>) -> Option<(u8, u16, u16, Basis)> {
    match predicate? {
        Predicate::LabelLength {
            component,
            min,
            max,
            basis,
        } => Some((*component, *min, *max, *basis)),
        Predicate::LabelMinimum {
            component,
            min,
            basis,
        } => Some((*component, *min, u16::MAX, *basis)),
        Predicate::LabelMaximum {
            component,
            max,
            basis,
        } => Some((*component, 0, *max, *basis)),
        _ => None,
    }
}

pub(super) fn coverage(
    entry: &mut Coverage,
    namespace: &Namespace,
    assertions: &BTreeMap<&str, &Assertion>,
    statuses: &BTreeMap<String, Status>,
) -> Result<(), String> {
    let counts = namespace
        .forms
        .iter()
        .map(|f| f.len() as u8)
        .collect::<Vec<_>>();
    for (class, state) in [
        (Class::Ascii, &mut entry.ascii),
        (Class::Idn, &mut entry.idn),
    ] {
        if !matches!(state, Knowledge::Reviewed | Knowledge::NotApplicable) {
            continue;
        }
        if entry.assertion_ids.is_empty() {
            return Err("complete/not-applicable family has no evidence".into());
        }
        let mut approved = false;
        let mut attested = false;
        for id in &entry.assertion_ids {
            let assertion = reference(id, assertions)?;
            if assertion.family != entry.family {
                return Err("coverage assertion belongs to another family".into());
            }
            if !scoped(assertion, &namespace.selector, &counts, class) {
                continue;
            }
            attested |= assertion.attests_completeness;
            let status = &statuses[id];
            if status.active && assertion.attests_completeness {
                approved = true;
            } else {
                entry.gap.get_or_insert_with(|| {
                    status
                        .reason
                        .clone()
                        .unwrap_or_else(|| "research_unresolved".into())
                });
            }
        }
        if !attested {
            return Err("family completeness lacks scoped completeness attestation".into());
        }
        if !approved {
            *state = Knowledge::Unknown;
            entry
                .gap
                .get_or_insert_with(|| "no_active_applicable_coverage_evidence".into());
        }
    }
    for id in &entry.assertion_ids {
        reference(id, assertions)?;
    }
    Ok(())
}
