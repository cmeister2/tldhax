//! Validate finite adopted IDN features without assuming allocation semantics.

pub use super::idn_schema::*;
use super::schema::Knowledge;

/// Validate finite table features and preserve unsupported allocation as gaps.
///
/// # Errors
/// Rejects missing adoption metadata, invalid scalar ranges and unbounded context.
pub fn validate(profile: &mut IdnProfile) -> Result<(), String> {
    if profile.id.trim().is_empty()
        || profile.version.trim().is_empty()
        || profile.namespaces.is_empty()
        || profile.assertion_ids.is_empty()
        || profile.adoption_assertion_ids.is_empty()
    {
        return Err("IDN table lacks identity, scope, source or adoption evidence".into());
    }
    if profile.knowledge == Knowledge::Reviewed && !profile.repertoire_complete {
        return Err("reviewed IDN table lacks explicit complete repertoire attestation".into());
    }
    if profile.repertoire_complete
        && profile.unsupported_features.iter().any(|feature| {
            !matches!(
                feature.as_str(),
                "variant_allocation_relationship" | "ordering_rule"
            ) && !feature.starts_with("context:")
                && !feature.starts_with("allocation:")
                && !feature.starts_with("metadata:")
                && !feature.starts_with("context_")
                && !feature.starts_with("negative_context_")
                && !feature.starts_with("combined_any_context:")
                && !feature.starts_with("empty_context_rule:")
                && !feature.starts_with("rules_element:")
                && !feature.starts_with("variant_")
                && !feature.starts_with("contextual_variant_")
                && feature != "range_variant_relationship"
                && feature != "nonscalar_context_binding"
        })
    {
        return Err("complete IDN repertoire retains unsupported definitions".into());
    }
    profile.ranges.sort_unstable();
    for (index, &[start, end]) in profile.ranges.iter().enumerate() {
        if start > end
            || char::from_u32(start).is_none()
            || char::from_u32(end).is_none()
            || start <= 0xdfff && end >= 0xd800
            || index > 0 && start <= profile.ranges[index - 1][1]
        {
            return Err("invalid or overlapping IDN code point intervals".into());
        }
    }
    let included = |cp: u32| profile.ranges.iter().any(|r| r[0] <= cp && cp <= r[1]);
    for context in &profile.contexts {
        if !included(context.codepoint) {
            return Err("IDN context outside repertoire".into());
        }
        let sets: Vec<&[u32]> = match &context.condition {
            Condition::NotStart | Condition::NotEnd => Vec::new(),
            Condition::PrecededBy { values } | Condition::FollowedBy { values } => vec![values],
            Condition::Between { left, right } => vec![left, right],
        };
        if sets.iter().any(|s| {
            s.is_empty() || s.len() > 256 || s.iter().any(|cp| char::from_u32(*cp).is_none())
        }) {
            return Err("invalid or unbounded IDN context set".into());
        }
    }
    for variant in &profile.variants {
        if variant.sequence.is_empty()
            || variant.replacement.is_empty()
            || variant.sequence.chars().count() > 32
            || variant.replacement.chars().count() > 32
            || variant.sequence.chars().any(|cp| !included(cp as u32))
        {
            return Err("invalid IDN variant sequence".into());
        }
        profile
            .unsupported_features
            .push("variant_allocation_relationship".into());
    }
    profile.unsupported_features.sort();
    profile.unsupported_features.dedup();
    if !profile.unsupported_features.is_empty() {
        profile.knowledge = Knowledge::Partial;
    }
    Ok(())
}
