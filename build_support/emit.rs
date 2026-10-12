//! Deterministic Rust table emission; evidence prose stays off the hot path.

use super::idn::Condition;
use super::render_predicates::{option, render, strings};
use super::resolve::ResolvedNamespace;
use super::schema::{Document, Family};
use super::validate::Status;
use std::collections::{BTreeMap, BTreeSet};

fn table(output: &mut String, name: &str, kind: &str, rows: Vec<String>) {
    output.push_str(&format!(
        "pub static {name}: &[{kind}] = &[\n{}\n];\n",
        rows.join(",\n")
    ));
}

pub fn emit(
    document: &Document,
    statuses: &BTreeMap<String, Status>,
    namespaces: &[ResolvedNamespace],
    evaluation_date: &str,
    fingerprint: &str,
) -> Result<String, String> {
    let mut output = format!("use crate::policy_types::*;\npub const EVALUATION_DATE: &str = {evaluation_date:?};\npub const RELEASE_FINGERPRINT: &str = {fingerprint:?};\n");
    table(&mut output,"SOURCES","EvidenceSource",document.sources.iter().map(|s| format!("EvidenceSource{{id:{:?},publisher:{:?},title:{:?},url:{:?},fetched_url:{:?},sha256:{:?},hash_representation:{:?},version:{:?},language:{:?},retrieved_on:{:?},translation_of:{}}}",s.id,s.publisher,s.title,s.url,s.fetched_url,s.sha256,s.hash_representation,s.version,s.language,s.retrieved_on,option(s.translation_of.as_deref()))).collect());
    table(&mut output,"ASSERTIONS","EvidenceAssertion",document.assertions.iter().map(|a| {
        let s=&statuses[&a.id];
        format!("EvidenceAssertion{{id:{:?},source_id:{:?},locator:{:?},interpretation:{:?},operation:{:?},namespaces:{},forms:&{:?},input_class:InputClass::{:?},family:RuleFamily::{:?},knowledge:Knowledge::{:?},attests_completeness:{},effective_from:{},applicable_on:{},effective_until:{},reviewer:{:?},reviewed_on:{:?},review_due:{:?},active:{},inactive_reason:{}}}",a.id,a.source_id,a.locator,a.interpretation,a.operation,strings(&a.namespaces),a.forms,a.input_class,a.family,s.knowledge,a.attests_completeness,option(a.effective_from.as_deref()),option(a.applicable_on.as_deref()),option(a.effective_until.as_deref()),a.reviewer,a.reviewed_on,a.review_due,s.active,option(s.reason.as_deref()))
    }).collect());
    let used = namespaces
        .iter()
        .flat_map(|n| n.rule_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let rules = document
        .assertions
        .iter()
        .filter(|a| used.contains(&a.id))
        .collect::<Vec<_>>();
    let indices = rules
        .iter()
        .enumerate()
        .map(|(i, a)| (a.id.as_str(), i as u32))
        .collect::<BTreeMap<_, _>>();
    table(&mut output,"RULES","CompiledRule",rules.iter().map(|a| {
        let predicate=render(a.predicate.as_ref().ok_or("rule predicate missing")?)?;
        let code = a.code.as_deref().unwrap_or(match a.family {Family::Reserved=>"reserved_label",Family::Eligibility=>"eligibility_predicate",Family::Length=>"label_length",Family::Idn=>"idn_constraint",Family::Allocation=>"name_allocation",Family::Access=>"namespace_access",_=>"policy_constraint"});
        Ok(format!("CompiledRule{{id:{:?},family:RuleFamily::{:?},input_class:InputClass::{:?},forms:&{:?},effect:RuleEffect::{:?},predicate:{predicate},evidence_ids:&[{:?}],scope:{:?},code:{code:?}}}",a.id,a.family,a.input_class,a.forms,a.effect,a.id,a.namespaces.join(",")))
    }).collect::<Result<Vec<_>,String>>()?);
    table(&mut output,"NAMESPACE_POLICIES","NamespacePolicy",namespaces.iter().map(|n| {
        let kind=if n.selector.starts_with("*.") {"Wildcard"} else {"Exact"};
        let forms=n.forms.iter().map(|f| format!("RegistrationForm{{roles:{}}}",strings(f))).collect::<Vec<_>>().join(",");
        let coverage=n.coverage.iter().map(|c|format!("FamilyCoverage{{family:RuleFamily::{:?},ascii:Knowledge::{:?},idn:Knowledge::{:?},evidence_ids:{},gap:{}}}",c.family,c.ascii,c.idn,strings(&c.assertion_ids),option(c.gap.as_deref()))).collect::<Vec<_>>().join(",");
        let rule_indices=n.rule_ids.iter().map(|id| indices[id.as_str()]).collect::<Vec<_>>();
        format!("NamespacePolicy{{selector:{:?},kind:SelectorKind::{kind},forms:&[{forms}],coverage:&[{coverage}],rule_indices:&{rule_indices:?},evidence_ids:{},context:{}}}",n.selector,strings(&n.evidence_ids),strings(&n.context))
    }).collect());
    table(
        &mut output,
        "LABEL_SETS",
        "LabelSet",
        document
            .label_sets
            .iter()
            .map(|s| {
                format!(
                    "LabelSet{{id:{:?},labels:{},evidence_ids:{}}}",
                    s.id,
                    strings(&s.labels),
                    strings(&s.assertion_ids)
                )
            })
            .collect(),
    );
    table(
        &mut output,
        "FACT_SCHEMAS",
        "FactSchema",
        document
            .facts
            .iter()
            .map(|f| {
                format!(
                    "FactSchema{{field:{:?},kind:FactKind::{:?},allowed_values:{},string_format:{}}}",
                    f.field,
                    f.kind,
                    strings(&f.allowed_values),
                    f.string_format.map_or("None".into(), |format| format!("Some(FactStringFormat::{format:?})"))
                )
            })
            .collect(),
    );
    table(&mut output,"IDN_PROFILES","IdnProfile",document.idn_profiles.iter().map(|p| {
        let ranges=p.ranges.iter().map(|[a,b]| format!("CodepointRange{{start:{a},end:{b}}}")).collect::<Vec<_>>().join(",");
        let contexts=p.contexts.iter().map(|c| {
            let condition=match &c.condition {
                Condition::NotStart => "ContextKind::NotStart".into(),Condition::NotEnd=>"ContextKind::NotEnd".into(),
                Condition::PrecededBy{values}=>format!("ContextKind::PrecededBy(&{values:?})"),Condition::FollowedBy{values}=>format!("ContextKind::FollowedBy(&{values:?})"),
                Condition::Between{left,right}=>format!("ContextKind::Between{{left:&{left:?},right:&{right:?}}}"),
            };
            format!("IdnContext{{codepoint:{},kind:{condition}}}",c.codepoint)
        }).collect::<Vec<_>>().join(",");
        let variants=p.variants.iter().map(|v| format!("IdnVariant{{sequence:{:?},replacement:{:?},disposition:VariantDisposition::{:?}}}",v.sequence,v.replacement,v.disposition)).collect::<Vec<_>>().join(",");
        let evidence=p.assertion_ids.iter().chain(&p.adoption_assertion_ids).cloned().collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
        format!("IdnProfile{{id:{:?},version:{:?},knowledge:Knowledge::{:?},repertoire_complete:{},ranges:&[{ranges}],contexts:&[{contexts}],variants:&[{variants}],evidence_ids:{},unsupported_features:{}}}",p.id,p.version,p.knowledge,p.repertoire_complete,strings(&evidence),strings(&p.unsupported_features))
    }).collect());
    table(
        &mut output,
        "LEGACY_RESEARCH",
        "LegacyResearch",
        document
            .legacy
            .iter()
            .map(|l| {
                format!(
                    "LegacyResearch{{selector:{:?},source_links:{},provenance:{:?}}}",
                    l.selector,
                    strings(&l.source_links),
                    l.provenance
                )
            })
            .collect(),
    );
    Ok(output)
}
