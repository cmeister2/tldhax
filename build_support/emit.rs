//! Render validated direct policies as immutable Rust literals.

use super::idn::Condition;
use super::render_predicates::{render as predicate, strings};
use super::CompiledInputs;

/// Emit all packaged static tables using escaped Rust string literals.
///
/// # Errors
/// Returns an error if an expression cannot be rendered.
pub fn render(input: &CompiledInputs) -> Result<String, String> {
    let mut output = String::new();
    // Fully qualified generated expressions let unused imports disappear without suppressing checks.
    let version = format!(
        "/// Packaged direct-policy release version.\npub const DATASET_VERSION: &str = {:?};\n",
        input.version
    );
    output.push_str(&version);
    output.push_str("/// Authored and discovered namespace identities; membership is not registration permission.\npub const KNOWN_SUFFIXES: &[&str] = ");
    output.push_str(&strings(&input.known_suffixes));
    output.push_str(";\n");
    output.push_str("/// Sorted active root identities.\npub const ACTIVE_ROOTS: &[&str] = ");
    output.push_str(&strings(&input.roots));
    output.push_str(";\n/// Sorted ICANN discovery selectors, independent of registration permission.\npub const ROUTES: &[crate::resolver::Route] = &[\n");
    for selector in &input.routes {
        let kind = if selector.starts_with('!') {
            "Exception"
        } else if selector.starts_with("*.") {
            "Wildcard"
        } else {
            "Exact"
        };
        output.push_str(&format!("crate::resolver::Route{{selector:{selector:?},kind:crate::resolver::RouteKind::{kind}}},\n"));
    }
    output.push_str("];\n/// Non-public special-use exclusions.\npub const SPECIAL_USE: &[crate::inventory_types::SpecialUse] = &[\n");
    for special in &input.special_use {
        output.push_str(&format!(
            "crate::inventory_types::SpecialUse{{name:{:?},descendants:{}}},\n",
            special.name, special.descendants
        ));
    }
    output.push_str("];\n/// Typed declared applicant facts accepted by this release.\npub const FACT_SCHEMAS: &[crate::policy_types::FactSchema] = &[\n");
    for fact in &input.facts {
        let format = fact.string_format.map_or_else(
            || "None".to_owned(),
            |format| format!("Some(crate::policy_types::FactStringFormat::{format:?})"),
        );
        output.push_str(&format!("crate::policy_types::FactSchema{{field:{:?},kind:crate::policy_types::FactKind::{:?},allowed_values:{},string_format:{format}}},\n", fact.field, fact.kind, strings(&fact.allowed_values)));
    }
    output.push_str("];\n/// Explicit shared exact-label sets.\npub const LABEL_SETS: &[crate::policy_types::LabelSet] = &[\n");
    for set in &input.label_sets {
        output.push_str(&format!(
            "crate::policy_types::LabelSet{{id:{:?},labels:{}}},\n",
            set.id,
            strings(&set.labels)
        ));
    }
    output.push_str("];\n/// Adopted finite IDN repertoires and supported context operations.\npub const IDN_PROFILES: &[crate::policy_types::IdnProfile] = &[\n");
    for profile in &input.idn_profiles {
        let ranges = profile
            .ranges
            .iter()
            .map(|range| {
                format!(
                    "crate::policy_types::CodepointRange{{start:{},end:{}}}",
                    range[0], range[1]
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let contexts = profile.contexts.iter().map(|context| {
            let kind = match &context.condition {
                Condition::NotStart => "crate::policy_types::ContextKind::NotStart".to_owned(),
                Condition::NotEnd => "crate::policy_types::ContextKind::NotEnd".to_owned(),
                Condition::PrecededBy { values } => format!("crate::policy_types::ContextKind::PrecededBy(&{values:?})"),
                Condition::FollowedBy { values } => format!("crate::policy_types::ContextKind::FollowedBy(&{values:?})"),
                Condition::Between { left, right } => format!("crate::policy_types::ContextKind::Between{{left:&{left:?},right:&{right:?}}}"),
            };
            format!("crate::policy_types::IdnContext{{codepoint:{},kind:{kind}}}", context.codepoint)
        }).collect::<Vec<_>>().join(",");
        output.push_str(&format!("crate::policy_types::IdnProfile{{id:{:?},repertoire_complete:{},ranges:&[{ranges}],contexts:&[{contexts}]}},\n", profile.id, profile.repertoire_complete));
    }
    output.push_str("];\n/// Direct policies sorted by namespace selector and component count.\npub const NAMESPACE_POLICIES: &[crate::policy_types::NamespacePolicy] = &[\n");
    for policy in &input.policies {
        let mut requirements = Vec::new();
        for requirement in &policy.requirements {
            requirements.push(format!("crate::policy_types::Requirement{{code:{:?},message:{:?},effect:crate::policy_types::RuleEffect::{:?},input_class:crate::policy_types::InputClass::{:?},predicate:{}}}", requirement.code, requirement.message, requirement.effect, requirement.input_class, predicate(&requirement.predicate)?));
        }
        let mut gaps = Vec::new();
        for gap in &policy.gaps {
            let condition = gap
                .predicate
                .as_ref()
                .map(predicate)
                .transpose()?
                .map_or_else(
                    || "None".to_owned(),
                    |expression| format!("Some({expression})"),
                );
            gaps.push(format!("crate::policy_types::PolicyGap{{code:{:?},message:{:?},input_class:crate::policy_types::InputClass::{:?},predicate:{condition}}}", gap.code, gap.message, gap.input_class));
        }
        let kind = if policy.selector.starts_with("*.") {
            "Wildcard"
        } else {
            "Exact"
        };
        output.push_str(&format!("crate::policy_types::NamespacePolicy{{id:{:?},selector:{:?},kind:crate::policy_types::SelectorKind::{kind},form:{},ascii:crate::policy_types::Support::{:?},idn:crate::policy_types::Support::{:?},requirements:&[{}],gaps:&[{}]}},\n", policy.id, policy.selector, strings(&policy.form), policy.ascii, policy.idn, requirements.join(","), gaps.join(",")));
    }
    output.push_str("];\n");
    Ok(output)
}
