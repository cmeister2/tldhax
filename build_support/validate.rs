//! Source identity, packaged hashes and canonical document validation.

pub use super::keys::{assertion_status, date, selector, temporal, unique, Status};
use super::schema::{Document, Knowledge};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

/// Validate evidence identity and normalize authoring keys before compilation.
///
/// # Errors
/// Rejects invalid metadata, missing references, canonical collisions or hashes.
pub fn document(
    document: &mut Document,
    evaluation_date: &str,
    root: Option<&Path>,
) -> Result<BTreeMap<String, Status>, String> {
    date(evaluation_date)?;
    unique(&document.sources, |s| &s.id, "source")?;
    unique(&document.assertions, |s| &s.id, "assertion")?;
    unique(&document.profiles, |s| &s.id, "profile")?;
    unique(&document.label_sets, |s| &s.id, "label set")?;
    unique(&document.idn_profiles, |s| &s.id, "IDN profile")?;
    unique(&document.facts, |s| &s.field, "fact")?;
    let source_ids = document
        .sources
        .iter()
        .map(|s| s.id.clone())
        .collect::<BTreeSet<_>>();
    let translations = document
        .sources
        .iter()
        .map(|s| (s.id.as_str(), s.translation_of.as_deref()))
        .collect::<BTreeMap<_, _>>();
    for source in &document.sources {
        let mut visited = BTreeSet::new();
        let mut current = Some(source.id.as_str());
        while let Some(id) = current {
            if !visited.insert(id) {
                return Err("translation evidence cycle".into());
            }
            current = translations.get(id).copied().flatten();
        }
    }
    for source in &document.sources {
        if [
            &source.publisher,
            &source.title,
            &source.version,
            &source.language,
        ]
        .iter()
        .any(|v| v.trim().is_empty())
            || !source.url.starts_with("https://")
            || !source.fetched_url.starts_with("https://")
            || source.sha256.len() != 64
            || !source.sha256.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(format!("incomplete source identity/hash: {}", source.id));
        }
        if !matches!(
            source.hash_representation.as_str(),
            "original_bytes" | "extracted_text/v1"
        ) {
            return Err("unsupported source hash representation".into());
        }
        date(&source.retrieved_on)?;
        if source
            .translation_of
            .as_ref()
            .is_some_and(|id| !source_ids.contains(id) || id == &source.id)
        {
            return Err("missing/recursive translation source".into());
        }
        if let Some(path) = &source.snapshot_path {
            if Path::new(path)
                .components()
                .any(|p| !matches!(p, Component::Normal(_)))
            {
                return Err("unsafe evidence snapshot path".into());
            }
            if let Some(root) = root {
                let content = std::fs::read(root.join(path))
                    .map_err(|e| format!("missing packaged evidence: {path}: {e}"))?;
                if format!("{:x}", Sha256::digest(content)) != source.sha256.to_ascii_lowercase() {
                    return Err("evidence snapshot hash mismatch".into());
                }
            }
        }
    }
    let mut statuses = BTreeMap::new();
    for assertion in &mut document.assertions {
        if !source_ids.contains(&assertion.source_id)
            || [
                &assertion.locator,
                &assertion.interpretation,
                &assertion.reviewer,
            ]
            .iter()
            .any(|v| v.trim().is_empty())
            || assertion.operation != "new_registration"
            || assertion.namespaces.is_empty()
            || assertion.forms.is_empty()
            || assertion.forms.iter().any(|x| *x == 0 || *x > 126)
        {
            return Err(format!(
                "missing assertion evidence or applicability: {}",
                assertion.id
            ));
        }
        date(&assertion.reviewed_on)?;
        date(&assertion.review_due)?;
        if assertion.review_due < assertion.reviewed_on {
            return Err("review deadline precedes review".into());
        }
        let mut scopes = BTreeSet::new();
        for scope in &mut assertion.namespaces {
            *scope = selector(scope)?;
            if !scopes.insert(scope.clone()) {
                return Err("duplicate canonical assertion scope".into());
            }
        }
        assertion.forms.sort();
        assertion.forms.dedup();
        statuses.insert(
            assertion.id.clone(),
            assertion_status(assertion, evaluation_date)?,
        );
    }
    let mut namespaces = BTreeSet::new();
    for namespace in &mut document.namespaces {
        namespace.selector = selector(&namespace.selector)?;
        if !namespaces.insert(namespace.selector.clone()) {
            return Err("duplicate canonical namespace key".into());
        }
    }
    for set in &mut document.label_sets {
        let mut labels = BTreeSet::new();
        for label in &mut set.labels {
            *label = selector(label)?;
            if label.contains('.') || !labels.insert(label.clone()) {
                return Err("non-label or canonical label collision".into());
            }
        }
        set.labels.sort();
        if set.assertion_ids.is_empty() {
            return Err("label set lacks completeness/source evidence".into());
        }
    }
    for profile in &mut document.profiles {
        for selector_key in &mut profile.applicability {
            *selector_key = selector(selector_key)?;
        }
        if profile.applicability.is_empty() || profile.applicability_assertions.is_empty() {
            return Err("shared profile lacks explicit applicability evidence".into());
        }
    }
    for profile in &mut document.idn_profiles {
        for scope in &mut profile.namespaces {
            *scope = selector(scope)?;
        }
        super::idn::validate(profile)?;
        if profile.repertoire_complete {
            let complete = profile.assertion_ids.iter().any(|id| {
                document.assertions.iter().any(|a| {
                    a.id == *id && a.knowledge == Knowledge::Reviewed && a.attests_completeness
                })
            });
            if !complete {
                return Err("complete IDN repertoire lacks reviewed table attestation".into());
            }
            let active = profile
                .assertion_ids
                .iter()
                .chain(&profile.adoption_assertion_ids)
                .all(|id| {
                    statuses
                        .get(id)
                        .is_some_and(|s| s.active && s.knowledge == Knowledge::Reviewed)
                });
            if !active {
                profile.knowledge = Knowledge::Unknown;
                profile.repertoire_complete = false;
            }
        }
        if temporal(
            profile.effective_from.as_deref(),
            profile.applicable_on.as_deref(),
            profile.effective_until.as_deref(),
            evaluation_date,
        )?
        .is_some()
        {
            profile.knowledge = Knowledge::Unknown;
            profile.repertoire_complete = false;
        }
    }
    for fact in &document.facts {
        if fact.allowed_values.len() > 4096
            || fact
                .allowed_values
                .iter()
                .any(|v| v.is_empty() || v.len() > 512)
            || fact.allowed_values.iter().collect::<BTreeSet<_>>().len()
                != fact.allowed_values.len()
            || fact.kind == super::predicates::FactKind::Boolean && !fact.allowed_values.is_empty()
            || fact.string_format.is_some() && fact.kind == super::predicates::FactKind::Boolean
            || fact.string_format.is_some_and(|format| {
                fact.allowed_values
                    .iter()
                    .any(|value| !format.matches(value))
            })
        {
            return Err("invalid typed profile fact allowed values".into());
        }
    }
    Ok(statuses)
}
