//! Pure safety-first verdict derivation.
//!
//! Lookup and policy evaluation produce the axes in [`EvaluationInput`]. This
//! module combines them without performing I/O or inferring missing policy.

use crate::types::{
    CandidateStatus, Claim, ClaimStatus, EligibilityStatus, LabelPolicyStatus, NamespaceState,
    OfferingState, PublicAccess, RootState, SyntaxStatus, Verdict,
};

/// Decision-critical inputs after normalization, topology, and policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluationInput {
    /// Result of protocol-level IDNA and DNS syntax validation.
    pub syntax: SyntaxStatus,
    /// Relationship between the input and its registration boundary.
    pub candidate_status: CandidateStatus,
    /// Current state of the root namespace.
    pub root_state: Claim<RootState>,
    /// Whether the candidate is within a standards-defined special-use namespace.
    pub namespace_state: Claim<NamespaceState>,
    /// Current state of the registration offering.
    pub offering_state: Claim<OfferingState>,
    /// Who may use the registration product.
    pub public_access: Claim<PublicAccess>,
    /// Result of applying typed registrant eligibility.
    pub eligibility: EligibilityStatus,
    /// Result of applying registry-specific label policy.
    pub label_policy: LabelPolicyStatus,
}

/// Derives a verdict using hard-failure, unresolved-fact, then success precedence.
///
/// A verified hard failure always wins, even when another axis is unresolved.
/// Stale and conflicting last-known values never authorize either a positive or
/// negative policy result. Eligibility is decision-critical only for products
/// whose verified access class is conditional or controlled-group.
pub fn derive_verdict(input: &EvaluationInput) -> Verdict {
    if input.syntax == SyntaxStatus::Invalid {
        return Verdict::Impossible;
    }

    if matches!(
        input.candidate_status,
        CandidateStatus::BareSuffix | CandidateStatus::Subdomain
    ) {
        return Verdict::Impossible;
    }

    let root_state = verified_value(input.root_state);
    let namespace_state = verified_value(input.namespace_state);
    let offering_state = verified_value(input.offering_state);
    let public_access = verified_value(input.public_access);

    if matches!(root_state, Some(RootState::Absent | RootState::SpecialUse)) {
        return Verdict::Impossible;
    }

    if namespace_state == Some(NamespaceState::SpecialUse) {
        return Verdict::Impossible;
    }

    if matches!(
        offering_state,
        Some(
            OfferingState::Paused
                | OfferingState::RenewalOnly
                | OfferingState::NotLaunched
                | OfferingState::Closed
        )
    ) {
        return Verdict::Impossible;
    }

    if public_access == Some(PublicAccess::Unavailable) {
        return Verdict::Impossible;
    }

    if input.label_policy == LabelPolicyStatus::Fail {
        return Verdict::Impossible;
    }

    if matches!(
        public_access,
        Some(PublicAccess::Conditional | PublicAccess::ControlledGroup)
    ) && input.eligibility == EligibilityStatus::Unsatisfied
    {
        return Verdict::Impossible;
    }

    if input.candidate_status != CandidateStatus::RegistrableDomain
        || root_state != Some(RootState::Delegated)
        || namespace_state != Some(NamespaceState::Ordinary)
        || offering_state != Some(OfferingState::Accepting)
        || public_access.is_none()
        || input.label_policy != LabelPolicyStatus::Pass
    {
        return Verdict::Indeterminate;
    }

    let Some(public_access) = public_access else {
        return Verdict::Indeterminate;
    };

    match public_access {
        PublicAccess::Open => Verdict::Plausible,
        PublicAccess::Conditional | PublicAccess::ControlledGroup => match input.eligibility {
            EligibilityStatus::Required | EligibilityStatus::Satisfied => Verdict::Conditional,
            EligibilityStatus::Unsatisfied => Verdict::Impossible,
            EligibilityStatus::Unknown | EligibilityStatus::NotApplicable => Verdict::Indeterminate,
        },
        PublicAccess::Unavailable => Verdict::Impossible,
    }
}

/// Returns a copied claim value only when its evidence state is verified.
fn verified_value<T: Copy>(claim: Claim<T>) -> Option<T> {
    if claim.status == ClaimStatus::Verified {
        claim.value
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_verdict, EvaluationInput};
    use crate::types::{
        CandidateStatus, Claim, ClaimStatus, EligibilityStatus, LabelPolicyStatus, NamespaceState,
        OfferingState, PublicAccess, RootState, SyntaxStatus, Verdict,
    };

    const EVIDENCE: &[&str] = &["fixture"];

    fn verified<T>(value: T) -> Claim<T> {
        Claim::verified(value, EVIDENCE)
    }

    fn open_input() -> EvaluationInput {
        EvaluationInput {
            syntax: SyntaxStatus::Valid,
            candidate_status: CandidateStatus::RegistrableDomain,
            root_state: verified(RootState::Delegated),
            namespace_state: verified(NamespaceState::Ordinary),
            offering_state: verified(OfferingState::Accepting),
            public_access: verified(PublicAccess::Open),
            eligibility: EligibilityStatus::NotApplicable,
            label_policy: LabelPolicyStatus::Pass,
        }
    }

    #[test]
    fn fully_verified_open_product_is_plausible() {
        assert_eq!(derive_verdict(&open_input()), Verdict::Plausible);
    }

    #[test]
    fn gated_products_are_conditional() {
        for access in [PublicAccess::Conditional, PublicAccess::ControlledGroup] {
            for eligibility in [EligibilityStatus::Required, EligibilityStatus::Satisfied] {
                let input = EvaluationInput {
                    public_access: verified(access),
                    eligibility,
                    ..open_input()
                };
                assert_eq!(derive_verdict(&input), Verdict::Conditional);
            }
        }
    }

    #[test]
    fn protocol_and_candidate_shape_failures_are_impossible() {
        let invalid = EvaluationInput {
            syntax: SyntaxStatus::Invalid,
            ..open_input()
        };
        assert_eq!(derive_verdict(&invalid), Verdict::Impossible);

        for candidate_status in [CandidateStatus::BareSuffix, CandidateStatus::Subdomain] {
            let input = EvaluationInput {
                candidate_status,
                ..open_input()
            };
            assert_eq!(derive_verdict(&input), Verdict::Impossible);
        }
    }

    #[test]
    fn every_verified_offering_failure_is_impossible() {
        for state in [
            OfferingState::Paused,
            OfferingState::RenewalOnly,
            OfferingState::NotLaunched,
            OfferingState::Closed,
        ] {
            let input = EvaluationInput {
                offering_state: verified(state),
                root_state: Claim::unknown(),
                ..open_input()
            };
            assert_eq!(derive_verdict(&input), Verdict::Impossible);
        }
    }

    #[test]
    fn hard_policy_failure_dominates_unknown_axes() {
        let unavailable = EvaluationInput {
            root_state: Claim::unknown(),
            offering_state: Claim::unknown(),
            public_access: verified(PublicAccess::Unavailable),
            label_policy: LabelPolicyStatus::Unknown,
            ..open_input()
        };
        assert_eq!(derive_verdict(&unavailable), Verdict::Impossible);

        let label_failure = EvaluationInput {
            root_state: Claim::unknown(),
            offering_state: Claim::unknown(),
            public_access: Claim::unknown(),
            label_policy: LabelPolicyStatus::Fail,
            ..open_input()
        };
        assert_eq!(derive_verdict(&label_failure), Verdict::Impossible);
    }

    #[test]
    fn absent_and_special_use_roots_are_impossible() {
        for state in [RootState::Absent, RootState::SpecialUse] {
            let input = EvaluationInput {
                root_state: verified(state),
                ..open_input()
            };
            assert_eq!(derive_verdict(&input), Verdict::Impossible);
        }
    }

    #[test]
    fn special_use_namespace_is_impossible_without_product_policy() {
        let input = EvaluationInput {
            namespace_state: verified(NamespaceState::SpecialUse),
            offering_state: Claim::unknown(),
            public_access: Claim::unknown(),
            ..open_input()
        };
        assert_eq!(derive_verdict(&input), Verdict::Impossible);
    }

    #[test]
    fn failed_conditional_eligibility_is_impossible() {
        let input = EvaluationInput {
            public_access: verified(PublicAccess::Conditional),
            eligibility: EligibilityStatus::Unsatisfied,
            ..open_input()
        };
        assert_eq!(derive_verdict(&input), Verdict::Impossible);
    }

    #[test]
    fn unresolved_critical_axes_are_indeterminate() {
        let cases = [
            EvaluationInput {
                candidate_status: CandidateStatus::Unresolved,
                ..open_input()
            },
            EvaluationInput {
                root_state: Claim::unknown(),
                ..open_input()
            },
            EvaluationInput {
                namespace_state: Claim::stale(NamespaceState::Ordinary, EVIDENCE),
                ..open_input()
            },
            EvaluationInput {
                offering_state: Claim::stale(OfferingState::Accepting, EVIDENCE),
                ..open_input()
            },
            EvaluationInput {
                public_access: Claim::conflicting(EVIDENCE),
                ..open_input()
            },
            EvaluationInput {
                label_policy: LabelPolicyStatus::Partial,
                ..open_input()
            },
            EvaluationInput {
                label_policy: LabelPolicyStatus::Unknown,
                ..open_input()
            },
        ];

        for input in cases {
            assert_eq!(derive_verdict(&input), Verdict::Indeterminate);
        }
    }

    #[test]
    fn stale_negative_claim_does_not_authorize_impossible() {
        let input = EvaluationInput {
            public_access: Claim::stale(PublicAccess::Unavailable, EVIDENCE),
            ..open_input()
        };
        assert_eq!(derive_verdict(&input), Verdict::Indeterminate);
    }

    #[test]
    fn eligibility_is_critical_only_for_gated_access() {
        let open = EvaluationInput {
            eligibility: EligibilityStatus::Unknown,
            ..open_input()
        };
        assert_eq!(derive_verdict(&open), Verdict::Plausible);

        let conditional = EvaluationInput {
            public_access: verified(PublicAccess::Conditional),
            eligibility: EligibilityStatus::Unknown,
            ..open_input()
        };
        assert_eq!(derive_verdict(&conditional), Verdict::Indeterminate);
    }

    #[test]
    fn verified_claim_without_value_is_indeterminate() {
        let input = EvaluationInput {
            public_access: Claim {
                status: ClaimStatus::Verified,
                value: None,
                evidence: EVIDENCE,
            },
            ..open_input()
        };
        assert_eq!(derive_verdict(&input), Verdict::Indeterminate);
    }
}
