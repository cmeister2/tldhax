//! Shared applicability, inheritance and completeness resolution helpers.

use super::predicates::{Basis, Predicate};
use super::schema::{Assertion, Class, Coverage, Effect, Family, Knowledge, Namespace, Profile};
use super::validate::Status;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn scoped(assertion: &Assertion, selector: &str, counts: &[u8], class: Class) -> bool {
    assertion.namespaces.iter().any(|scope| scope == selector)
        && counts.iter().all(|count| assertion.forms.contains(count))
        && (assertion.input_class == Class::Any || assertion.input_class == class)
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

pub(super) fn profile_applicability(
    profile: &Profile,
    namespace: &Namespace,
    approved_counts: &[u8],
    assertions: &BTreeMap<&str, &Assertion>,
    statuses: &BTreeMap<String, Status>,
) -> Result<(), String> {
    let declared = namespace
        .forms
        .iter()
        .map(|form| form.len() as u8)
        .collect::<BTreeSet<_>>();
    let mut required = approved_counts.iter().copied().collect::<BTreeSet<_>>();
    for id in profile.rules.iter().chain(
        profile
            .coverage
            .iter()
            .flat_map(|coverage| &coverage.assertion_ids),
    ) {
        let assertion = reference(id, assertions)?;
        if statuses[id].active && assertion.namespaces.contains(&namespace.selector) {
            required.extend(
                assertion
                    .forms
                    .iter()
                    .filter(|count| declared.contains(count))
                    .copied(),
            );
        }
    }
    let mut approved = BTreeSet::new();
    for id in &profile.applicability_assertions {
        let assertion = reference(id, assertions)?;
        if assertion.input_class != Class::Any
            || !assertion
                .namespaces
                .iter()
                .any(|selector| profile.applicability.contains(selector))
        {
            return Err("profile applicability assertion scope mismatch".into());
        }
        if statuses[id].active
            && assertion.knowledge == Knowledge::Reviewed
            && assertion.namespaces.contains(&namespace.selector)
        {
            approved.extend(
                assertion
                    .forms
                    .iter()
                    .filter(|count| declared.contains(count))
                    .copied(),
            );
        }
    }
    if required.is_empty() || !required.is_subset(&approved) {
        return Err("profile applicability evidence missing/inactive".into());
    }
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
    approved_counts: &[u8],
    assertions: &BTreeMap<&str, &Assertion>,
    statuses: &BTreeMap<String, Status>,
) -> Result<(), String> {
    let counts = if approved_counts.is_empty() {
        namespace
            .forms
            .iter()
            .map(|f| f.len() as u8)
            .collect::<Vec<_>>()
    } else {
        approved_counts.to_vec()
    };
    for id in &entry.assertion_ids {
        if reference(id, assertions)?.family != entry.family {
            return Err("coverage assertion belongs to another family".into());
        }
    }
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
        if counts.is_empty() || entry.family == Family::Namespace && approved_counts.is_empty() {
            *state = Knowledge::Unknown;
            entry
                .gap
                .get_or_insert_with(|| "registration_form_approval_missing".into());
            continue;
        }
        let mut approved = BTreeSet::<u8>::new();
        let mut attested = BTreeSet::<u8>::new();
        for id in &entry.assertion_ids {
            let assertion = reference(id, assertions)?;
            let matched = counts
                .iter()
                .copied()
                .filter(|count| scoped(assertion, &namespace.selector, &[*count], class))
                .collect::<Vec<_>>();
            if matched.is_empty() {
                continue;
            }
            if assertion.attests_completeness {
                attested.extend(&matched);
            }
            let status = &statuses[id];
            if status.active && assertion.attests_completeness {
                approved.extend(&matched);
            } else {
                entry.gap.get_or_insert_with(|| {
                    status
                        .reason
                        .clone()
                        .unwrap_or_else(|| "research_unresolved".into())
                });
            }
        }
        if attested.len() != counts.len() {
            return Err("family completeness lacks scoped completeness attestation".into());
        }
        if approved.len() != counts.len() {
            *state = Knowledge::Unknown;
            entry
                .gap
                .get_or_insert_with(|| "no_active_applicable_coverage_evidence".into());
        }
    }
    Ok(())
}
