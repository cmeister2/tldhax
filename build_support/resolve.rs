//! Resolve shared policies and scope rules before emitting immutable tables.

use super::inheritance::{conflict, coverage, expand, profile_applicability, reference, scoped};
use super::predicates::Predicate;
use super::schema::{Class, Coverage, Document, Effect, Family, Knowledge, FAMILIES};
use super::validate::Status;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct ResolvedNamespace {
    pub selector: String,
    pub forms: Vec<Vec<String>>,
    pub rule_ids: Vec<String>,
    pub coverage: Vec<Coverage>,
    pub evidence_ids: Vec<String>,
    pub context: Vec<String>,
}

pub fn resolve(
    document: &Document,
    statuses: &BTreeMap<String, Status>,
) -> Result<Vec<ResolvedNamespace>, String> {
    let assertions = document
        .assertions
        .iter()
        .map(|a| (a.id.as_str(), a))
        .collect::<BTreeMap<_, _>>();
    let profiles = document
        .profiles
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect::<BTreeMap<_, _>>();
    for profile in &document.profiles {
        expand(
            &profile.id,
            &profiles,
            &mut BTreeSet::new(),
            &mut Vec::new(),
        )?;
    }
    for set in &document.label_sets {
        if set.labels.is_empty()
            && !set.assertion_ids.iter().any(|id| {
                assertions
                    .get(id.as_str())
                    .is_some_and(|a| a.attests_completeness)
            })
        {
            return Err("empty label set lacks reviewed completeness attestation".into());
        }
        for id in &set.assertion_ids {
            if reference(id, &assertions)?.family != Family::Reserved {
                return Err("label set evidence belongs to another family".into());
            }
        }
    }
    for profile in &document.idn_profiles {
        for id in profile
            .assertion_ids
            .iter()
            .chain(&profile.adoption_assertion_ids)
        {
            let assertion = reference(id, &assertions)?;
            if assertion.family != Family::Idn
                || !profile
                    .namespaces
                    .iter()
                    .all(|s| assertion.namespaces.contains(s))
            {
                return Err("IDN adoption/table evidence scope mismatch".into());
            }
        }
    }
    let mut output = Vec::new();
    for namespace in &document.namespaces {
        if namespace.forms.iter().any(|roles| {
            roles.is_empty() || roles.len() > 126 || roles.iter().any(|r| r.trim().is_empty())
        }) {
            return Err("invalid registration form roles/count".into());
        }
        let counts = namespace
            .forms
            .iter()
            .map(|f| f.len() as u8)
            .collect::<Vec<_>>();
        if counts.iter().collect::<BTreeSet<_>>().len() != counts.len() {
            return Err("ambiguous registration forms with equal count".into());
        }
        let mut forms = Vec::new();
        let mut form_evidence = BTreeSet::new();
        for id in &namespace.form_assertion_ids {
            let assertion = reference(id, &assertions)?;
            if assertion.family != Family::Namespace
                || assertion.input_class != Class::Any
                || !assertion.namespaces.contains(&namespace.selector)
                || !counts.iter().any(|count| assertion.forms.contains(count))
            {
                return Err("registration form assertion scope mismatch".into());
            }
        }
        for (form, count) in namespace.forms.iter().zip(&counts) {
            let mut supported = false;
            for id in &namespace.form_assertion_ids {
                let assertion = reference(id, &assertions)?;
                if statuses[id].active
                    && assertion.knowledge == Knowledge::Reviewed
                    && assertion.forms.contains(count)
                {
                    supported = true;
                    form_evidence.insert(id.clone());
                }
            }
            if supported {
                forms.push(form.clone());
            }
        }
        let approved_counts = forms
            .iter()
            .map(|form| form.len() as u8)
            .collect::<Vec<_>>();
        let mut inherited = Vec::new();
        for id in &namespace.profiles {
            expand(id, &profiles, &mut BTreeSet::new(), &mut inherited)?;
        }
        let mut rules = BTreeSet::new();
        let mut states = BTreeMap::new();
        let mut context = namespace.context.clone();
        for profile in inherited {
            if !profile.applicability.contains(&namespace.selector) {
                return Err("profile applied outside explicit applicability list".into());
            }
            profile_applicability(profile, namespace, &approved_counts, &assertions, statuses)?;
            rules.extend(profile.rules.iter().cloned());
            for state in &profile.coverage {
                if let Some(prior) = states.insert(state.family, state.clone()) {
                    if prior.ascii != state.ascii || prior.idn != state.idn {
                        return Err("incompatible inherited family coverage".into());
                    }
                }
            }
            context.extend(profile.context.iter().cloned());
        }
        rules.extend(namespace.rules.iter().cloned());
        let mut local_families = BTreeSet::new();
        for state in &namespace.coverage {
            if !local_families.insert(state.family) {
                return Err("duplicate namespace family coverage".into());
            }
            states.insert(state.family, state.clone());
        }
        for override_rule in &namespace.overrides {
            if override_rule.reason.trim().is_empty()
                || override_rule.assertion_ids.is_empty()
                || !rules.remove(&override_rule.replaces)
            {
                return Err("override lacks replaced rule, rationale or evidence".into());
            }
            let before = reference(&override_rule.replaces, &assertions)?;
            let after = reference(&override_rule.with, &assertions)?;
            if before.family != after.family
                || after.knowledge != Knowledge::Reviewed
                || before.effect != Effect::Context && after.effect == Effect::Context
                || after.input_class != Class::Any && before.input_class != after.input_class
                || counts
                    .iter()
                    .filter(|c| before.forms.contains(c))
                    .any(|c| !after.forms.contains(c))
                || !statuses[&override_rule.with].active
                || !scoped(after, &namespace.selector, &counts, Class::Any)
            {
                return Err("incompatible override".into());
            }
            for id in &override_rule.assertion_ids {
                if !statuses.get(id).is_some_and(|s| s.active)
                    || !scoped(
                        reference(id, &assertions)?,
                        &namespace.selector,
                        &counts,
                        Class::Any,
                    )
                {
                    return Err("override rationale evidence scope mismatch".into());
                }
            }
            rules.insert(override_rule.with.clone());
            context.push(format!(
                "override {} -> {}: {}",
                override_rule.replaces, override_rule.with, override_rule.reason
            ));
        }
        let mut active: Vec<String> = Vec::new();
        for id in rules {
            let assertion = reference(&id, &assertions)?;
            if !assertion.namespaces.contains(&namespace.selector)
                || !counts.iter().any(|c| assertion.forms.contains(c))
            {
                return Err("rule assertion does not include namespace/form scope".into());
            }
            if assertion.effect == Effect::Context && assertion.predicate.is_none() {
                context.push(format!("{}: {}", assertion.id, assertion.interpretation));
                continue;
            }
            let state = states.entry(assertion.family).or_insert_with(|| Coverage {
                family: assertion.family,
                ascii: Knowledge::Unknown,
                idn: Knowledge::Unknown,
                assertion_ids: Vec::new(),
                gap: None,
            });
            if !statuses[&id].active
                || assertion
                    .predicate
                    .as_ref()
                    .is_some_and(Predicate::unsupported)
            {
                if matches!(
                    statuses[&id].reason.as_deref(),
                    Some("future_effective" | "no_longer_effective")
                ) {
                    continue;
                }
                state.gap.get_or_insert_with(|| {
                    statuses[&id]
                        .reason
                        .clone()
                        .unwrap_or_else(|| "unsupported_predicate".into())
                });
                if assertion.input_class != Class::Idn {
                    state.ascii = statuses[&id].knowledge;
                }
                if assertion.input_class != Class::Ascii {
                    state.idn = statuses[&id].knowledge;
                }
                continue;
            }
            if assertion.predicate.is_none() {
                return Err("enforceable rule lacks typed predicate".into());
            }
            let mut nodes = vec![assertion.predicate.as_ref().unwrap()];
            let selected_counts = counts
                .iter()
                .copied()
                .filter(|c| assertion.forms.contains(c))
                .collect::<Vec<_>>();
            let mut assets_active = true;
            while let Some(node) = nodes.pop() {
                if let Predicate::LabelInSet { set_id, .. } = node {
                    let set = document
                        .label_sets
                        .iter()
                        .find(|set| &set.id == set_id)
                        .ok_or("missing named set")?;
                    for id in &set.assertion_ids {
                        if !scoped(
                            reference(id, &assertions)?,
                            &namespace.selector,
                            &selected_counts,
                            assertion.input_class,
                        ) {
                            return Err("reserved set applied outside assertion scope".into());
                        }
                        assets_active &= statuses[id].active;
                    }
                }
                if let Predicate::Idn { profile_id, .. } = node {
                    let profile = document
                        .idn_profiles
                        .iter()
                        .find(|p| &p.id == profile_id)
                        .ok_or("missing IDN profile")?;
                    if !profile.namespaces.contains(&namespace.selector) {
                        return Err("IDN table applied outside adopted namespace".into());
                    }
                    for id in profile
                        .assertion_ids
                        .iter()
                        .chain(&profile.adoption_assertion_ids)
                    {
                        if !scoped(
                            reference(id, &assertions)?,
                            &namespace.selector,
                            &selected_counts,
                            Class::Idn,
                        ) {
                            return Err("IDN adoption evidence form/class mismatch".into());
                        }
                        assets_active &= statuses[id].active;
                    }
                    if profile.knowledge != Knowledge::Reviewed {
                        state.idn = profile.knowledge;
                        state.gap = Some("idn_table_features_or_adoption_unresolved".into());
                        assets_active &= profile.knowledge != Knowledge::Unknown;
                    }
                }
                nodes.extend(node.children());
            }
            if !assets_active {
                if assertion.input_class != Class::Idn {
                    state.ascii = Knowledge::Unknown;
                }
                if assertion.input_class != Class::Ascii {
                    state.idn = Knowledge::Unknown;
                }
                state.gap = Some("referenced_set_or_adoption_evidence_inactive".into());
                continue;
            }
            for prior in &active {
                if conflict(reference(prior, &assertions)?, assertion) {
                    return Err("simultaneously enforceable conflicting assertions".into());
                }
            }
            active.push(id);
        }
        let mut all_states = Vec::new();
        for family in FAMILIES {
            for class in [Class::Ascii, Class::Idn] {
                for count in &counts {
                    let applicable = active
                        .iter()
                        .map(|id| reference(id, &assertions))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .filter(|a| {
                            a.family == family
                                && a.effect != Effect::Context
                                && (a.input_class == Class::Any || a.input_class == class)
                                && a.forms.contains(count)
                        })
                        .collect::<Vec<_>>();
                    super::conflicts::check(&applicable)?;
                }
            }
        }
        for family in FAMILIES {
            let mut state = states.remove(&family).unwrap_or(Coverage {
                family,
                ascii: Knowledge::Unknown,
                idn: Knowledge::Unknown,
                assertion_ids: Vec::new(),
                gap: Some("unresearched_family".into()),
            });
            coverage(
                &mut state,
                namespace,
                &approved_counts,
                &assertions,
                statuses,
            )?;
            all_states.push(state);
        }
        context.sort();
        context.dedup();
        output.push(ResolvedNamespace {
            selector: namespace.selector.clone(),
            forms,
            rule_ids: active,
            coverage: all_states,
            evidence_ids: form_evidence.into_iter().collect(),
            context,
        });
    }
    output.sort_by(|a, b| a.selector.cmp(&b.selector));
    Ok(output)
}
