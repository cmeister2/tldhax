//! Precompute explicit corpus denominators from resolved, validated knowledge.
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use super::super::resolve::ResolvedNamespace;
use super::super::schema::{Class, Document, Family, Knowledge, FAMILIES};
use std::collections::BTreeSet;

#[derive(Default)]
struct Counts([usize; 5]);
impl Counts {
    fn add(&mut self, value: Knowledge) {
        self.0[match value {
            Knowledge::Reviewed => 0,
            Knowledge::Partial => 1,
            Knowledge::Unknown => 2,
            Knowledge::Conflicting => 3,
            Knowledge::NotApplicable => 4,
        }] += 1;
    }
    fn rust(&self) -> String {
        format!(
            "KnowledgeCounts{{reviewed:{},partial:{},unknown:{},conflicting:{},not_applicable:{}}}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4]
        )
    }
}

fn knowledge(namespace: Option<&ResolvedNamespace>, family: Family, class: Class) -> Knowledge {
    namespace
        .and_then(|n| n.coverage.iter().find(|c| c.family == family))
        .map_or(Knowledge::Unknown, |c| {
            if class == Class::Ascii {
                c.ascii
            } else {
                c.idn
            }
        })
}

fn name_coverage(namespace: Option<&ResolvedNamespace>, class: Class) -> Knowledge {
    let values = FAMILIES
        .into_iter()
        .filter(|f| {
            !matches!(f, Family::Access | Family::Eligibility)
                && !(class == Class::Ascii && *f == Family::Idn)
        })
        .map(|f| knowledge(namespace, f, class))
        .collect::<Vec<_>>();
    if values.contains(&Knowledge::Conflicting) {
        Knowledge::Conflicting
    } else if values
        .iter()
        .all(|k| matches!(k, Knowledge::Reviewed | Knowledge::NotApplicable))
    {
        Knowledge::Reviewed
    } else if values.iter().all(|k| *k == Knowledge::Unknown) {
        Knowledge::Unknown
    } else {
        Knowledge::Partial
    }
}

pub(super) fn render(
    document: &Document,
    namespaces: &[ResolvedNamespace],
    selectors: &BTreeSet<String>,
    active_roots: usize,
    fingerprint: &str,
    evaluation_date: &str,
    inventory_date: &str,
) -> String {
    let (mut ascii, mut idn) = (Counts::default(), Counts::default());
    for selector in selectors {
        let namespace = namespaces.iter().find(|n| &n.selector == selector);
        ascii.add(name_coverage(namespace, Class::Ascii));
        idn.add(name_coverage(namespace, Class::Idn));
    }
    let mut families = Vec::new();
    for family in FAMILIES {
        let (mut ascii, mut idn) = (Counts::default(), Counts::default());
        for selector in selectors {
            let namespace = namespaces.iter().find(|n| &n.selector == selector);
            ascii.add(knowledge(namespace, family, Class::Ascii));
            idn.add(knowledge(namespace, family, Class::Idn));
        }
        families.push(format!(
            "FamilyStats{{family:crate::policy_types::RuleFamily::{family:?},ascii:{},idn:{}}}",
            ascii.rust(),
            idn.rust()
        ));
    }
    let rules = namespaces
        .iter()
        .flat_map(|n| n.rule_ids.iter())
        .collect::<BTreeSet<_>>()
        .len();
    let reviewed_idn = document
        .idn_profiles
        .iter()
        .filter(|p| p.knowledge == Knowledge::Reviewed)
        .count();
    let partial_idn = document
        .idn_profiles
        .iter()
        .filter(|p| p.knowledge == Knowledge::Partial)
        .count();
    format!("use crate::registry_stats::*;\npub static DATASET_STATS:DatasetStats=DatasetStats{{active_roots:{active_roots},known_namespaces:{},published_namespaces:{},compiled_rules:{rules},compiled_assertions:{},sources:{},idn_profiles:{},reviewed_idn_profiles:{reviewed_idn},partial_idn_profiles:{partial_idn},unresolved_legacy_entries:{},ascii_namespaces:{},idn_namespaces:{},families:&[{}],dataset_version:{fingerprint:?},evaluation_date:{evaluation_date:?},inventory_date:{inventory_date:?},normalization_profile:crate::normalization::NORMALIZATION_PROFILE}};\n",selectors.len(),namespaces.len(),document.assertions.len(),document.sources.len(),document.idn_profiles.len(),document.legacy.len(),ascii.rust(),idn.rust(),families.join(","))
}

#[cfg(test)]
mod tests {
    use super::super::super::schema::Coverage;
    use super::*;

    #[test]
    fn unresearched_namespaces_contribute_unknown_to_every_denominator() {
        assert_eq!(name_coverage(None, Class::Ascii), Knowledge::Unknown);
        assert_eq!(name_coverage(None, Class::Idn), Knowledge::Unknown);
        for family in FAMILIES {
            assert_eq!(knowledge(None, family, Class::Idn), Knowledge::Unknown);
        }
    }

    #[test]
    fn complete_ascii_does_not_invent_idn_or_applicant_completeness() {
        let mut namespace = ResolvedNamespace {
            selector: "fixture".into(),
            forms: vec![],
            rule_ids: vec![],
            coverage: FAMILIES
                .into_iter()
                .filter(|f| !matches!(f, Family::Idn | Family::Access | Family::Eligibility))
                .map(|family| Coverage {
                    family,
                    ascii: Knowledge::Reviewed,
                    idn: Knowledge::Unknown,
                    assertion_ids: vec![],
                    gap: None,
                })
                .collect(),
            evidence_ids: vec![],
            context: vec![],
        };
        assert_eq!(
            name_coverage(Some(&namespace), Class::Ascii),
            Knowledge::Reviewed
        );
        assert_eq!(
            name_coverage(Some(&namespace), Class::Idn),
            Knowledge::Unknown
        );
        assert_eq!(
            knowledge(Some(&namespace), Family::Eligibility, Class::Ascii),
            Knowledge::Unknown
        );
        namespace.coverage[0].ascii = Knowledge::Conflicting;
        assert_eq!(
            name_coverage(Some(&namespace), Class::Ascii),
            Knowledge::Conflicting
        );
        namespace.coverage[0].ascii = Knowledge::Unknown;
        assert_eq!(
            name_coverage(Some(&namespace), Class::Ascii),
            Knowledge::Partial
        );
    }
}
