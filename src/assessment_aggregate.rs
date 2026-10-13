//! Independent name and declared-applicant aggregation with explicit research gaps.

use crate::assessment_types::{
    CompactAssessment, Coverage, CoverageGap, Eligibility, NameValidity, Summary,
};
use crate::policy_types::{InputClass, Knowledge, NamespacePolicy, RuleFamily};

/// Accumulated decisive and missing information; no sensitive facts are retained.
#[derive(Default)]
pub(crate) struct State {
    /// A universal name failure was established.
    pub name_failed: bool,
    /// An applicable name predicate could not be established.
    pub name_unresolved: bool,
    /// A declared applicant or conditional permission failed.
    pub applicant_failed: bool,
    /// A known condition requires additional declared fields.
    pub applicant_missing: bool,
    /// Applicant-policy research is incomplete or conflicting.
    pub applicant_policy_unknown: bool,
    /// Independent public-access research prevents an overall positive.
    pub access_policy_unknown: bool,
    /// At least one applicable declared condition was evaluated.
    pub applicant_conditions: bool,
}

/// Find the explicitly attested status for one family and applicant class.
pub(crate) fn knowledge(
    policy: Option<&NamespacePolicy>,
    family: RuleFamily,
    class: InputClass,
) -> Knowledge {
    policy
        .and_then(|policy| {
            policy
                .coverage
                .iter()
                .find(|coverage| coverage.family == family)
        })
        .map_or(Knowledge::Unknown, |coverage| match class {
            InputClass::Idn => coverage.idn,
            _ => coverage.ascii,
        })
}

/// Record every applicable research gap rather than inventing omitted defaults.
pub(crate) fn coverage(
    policy: Option<&'static NamespacePolicy>,
    class: InputClass,
    access_rules: bool,
    result: &mut CompactAssessment<'_>,
    state: &mut State,
) {
    let mut known = 0;
    let mut total = 0;
    let mut conflicting = false;
    for family in [
        RuleFamily::Namespace,
        RuleFamily::Length,
        RuleFamily::Characters,
        RuleFamily::Idn,
        RuleFamily::Reserved,
        RuleFamily::Allocation,
        RuleFamily::Eligibility,
        RuleFamily::Access,
    ] {
        if family == RuleFamily::Idn && class == InputClass::Ascii {
            continue;
        }
        // An explicit access family is independent; omission adds no invented gate.
        if family == RuleFamily::Access
            && !access_rules
            && !policy.is_some_and(|policy| {
                policy
                    .coverage
                    .iter()
                    .any(|coverage| coverage.family == family)
            })
        {
            continue;
        }
        let status = knowledge(policy, family, class);
        let applicant = matches!(family, RuleFamily::Eligibility | RuleFamily::Access);
        let complete = matches!(status, Knowledge::Reviewed | Knowledge::NotApplicable);
        if applicant {
            if family == RuleFamily::Access {
                state.access_policy_unknown |= !complete;
            } else {
                state.applicant_policy_unknown |= !complete;
            }
        } else {
            total += 1;
            known += usize::from(complete);
            conflicting |= status == Knowledge::Conflicting;
        }
        if !complete {
            let coverage = policy.and_then(|policy| {
                policy
                    .coverage
                    .iter()
                    .find(|coverage| coverage.family == family)
            });
            result.gaps.push(CoverageGap {
                family,
                input_class: class,
                knowledge: status,
                evidence_ids: coverage.map_or(&[], |coverage| coverage.evidence_ids),
                scope: policy.map_or("root-snapshot", |policy| policy.selector),
                reason: coverage.and_then(|coverage| coverage.gap),
            });
        }
    }
    result.policy_coverage = if conflicting {
        Coverage::Conflicting
    } else if known == total {
        Coverage::Complete
    } else if known == 0 {
        Coverage::Unknown
    } else {
        Coverage::Partial
    };
}

/// Proven failures outrank gaps; applicant failure never invalidates the name.
pub(crate) fn finish(state: State, result: &mut CompactAssessment<'_>) {
    result.name_validity = if state.name_failed {
        NameValidity::Invalid
    } else if state.name_unresolved || result.policy_coverage != Coverage::Complete {
        NameValidity::Unknown
    } else {
        NameValidity::Valid
    };
    result.eligibility = if state.applicant_failed {
        Eligibility::DoesNotMatch
    } else if state.applicant_policy_unknown {
        Eligibility::UnknownPolicy
    } else if state.applicant_missing {
        Eligibility::NeedsProfile
    } else if state.applicant_conditions {
        Eligibility::DeclaredMatch
    } else {
        Eligibility::NotRequired
    };
    result.summary = if state.name_failed || state.applicant_failed {
        Summary::No
    } else if result.name_validity == NameValidity::Unknown
        || result.eligibility == Eligibility::UnknownPolicy
        || state.access_policy_unknown
    {
        Summary::Unknown
    } else if result.eligibility == Eligibility::NeedsProfile {
        Summary::Restricted
    } else {
        Summary::Yes
    };
}
