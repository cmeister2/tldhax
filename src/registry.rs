//! Evidence-aware registry assessment over pinned namespace data.

use std::collections::BTreeSet;

use crate::checker::validate_ascii_domain;
use crate::evaluator::{derive_verdict, EvaluationInput};
use crate::generated::{
    CURRENT_ROOT_EVIDENCE, EVIDENCE, POLICY_PROFILES, PRODUCT_BY_SUFFIX, PRODUCT_ONE_LABEL_BELOW,
    PSL_EXACT, PSL_EXCEPTION, PSL_WILDCARD, REGISTRATION_PRODUCTS, ROOT_TLDS, SPECIAL_USE_EVIDENCE,
    SPECIAL_USE_NAMES,
};
use crate::topology::{resolve_domain, resolve_suffix};
use crate::types::{
    ApplicationChannel, Assessment, CandidateStatus, Claim, ClaimCounts, ClaimStatus, Designation,
    EligibilityExpression, EligibilityRequirement, EligibilityRequirementAssessment,
    EligibilityRequirementOutcome, EligibilityStatus, Evidence, Finding, FindingCode, IdnSupport,
    LabelPolicy, LabelPolicyStatus, LengthUnit, NamespaceState, OfferingState, PolicyCoverage,
    PolicyProfile, PslSection, PublicAccess, RegistrantContext, RegistrationProduct, RegistryStats,
    ReservedDisposition, RootCounts, RootState, RootTld, SelectorCounts, SuffixInfo, SyntaxStatus,
    TopologyCounts,
};

/// Evidence-aware access to the compiled namespace and registration-product catalog.
#[derive(Debug, Clone, Copy, Default)]
pub struct Registry;

impl Registry {
    /// Creates a registry backed entirely by checked-in, build-validated data.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Assesses a proposed new registration without registrant-specific facts.
    #[must_use]
    pub fn assess(&self, domain: &str) -> Assessment {
        self.assess_internal(domain, None)
    }

    /// Assesses a proposed registration using explicit registrant facts.
    #[must_use]
    pub fn assess_for(&self, domain: &str, context: &RegistrantContext) -> Assessment {
        self.assess_internal(domain, Some(context))
    }

    /// Returns namespace and product metadata for a suffix-like input.
    #[must_use]
    pub fn suffix_info(&self, suffix: &str) -> Option<SuffixInfo> {
        let normalized = suffix.trim().trim_start_matches('.');
        if normalized.is_empty() {
            return None;
        }

        let ascii_name = idna::domain_to_ascii(normalized).ok()?.to_ascii_lowercase();
        let ascii_name = ascii_name
            .strip_suffix('.')
            .unwrap_or(&ascii_name)
            .to_string();
        validate_ascii_domain(&ascii_name).ok()?;
        let topology = resolve_suffix(&ascii_name);
        let product_match = product_for_domain(&ascii_name);
        let canonical_suffix = product_match
            .as_ref()
            .map_or_else(|| topology.suffix.clone(), |value| value.suffix.clone());
        let root = ascii_name.rsplit('.').next()?.to_string();
        let root_record = ROOT_TLDS.get(root.as_str());
        let root_state = root_state_for(&root, root_record);
        let namespace_state = namespace_state_for(&ascii_name);
        let product = product_match.as_ref().map(|value| value.product);
        let product_suffix = product_match.map(|value| value.suffix);
        let (unicode_suffix, unicode_status) = idna::domain_to_unicode(&canonical_suffix);
        let display_suffix = unicode_status
            .is_ok()
            .then_some(unicode_suffix)
            .filter(|value| value != &canonical_suffix);
        let mut designations = Vec::new();
        if let Some(root_record) = root_record {
            extend_unique_designations(&mut designations, root_record.designations);
        }
        if let Some(product) = product {
            extend_unique_designations(&mut designations, product.designations);
        }

        Some(SuffixInfo {
            canonical_suffix,
            display_suffix,
            root,
            topology,
            root_state,
            namespace_state,
            product_id: product.map(|value| value.id),
            product_suffix,
            offering_state: product.map_or_else(Claim::unknown, |value| value.offering_state),
            public_access: product.map_or_else(Claim::unknown, |value| value.public_access),
            designations,
        })
    }

    /// Looks up one compiled root record by A-label or U-label.
    #[must_use]
    pub fn root_tld(&self, label: &str) -> Option<&'static RootTld> {
        let normalized = label.trim().trim_start_matches('.');
        let ascii_label = idna::domain_to_ascii(normalized).ok()?.to_ascii_lowercase();
        let ascii_label = ascii_label.strip_suffix('.').unwrap_or(&ascii_label);
        if ascii_label.is_empty() || ascii_label.contains('.') {
            return None;
        }
        ROOT_TLDS.get(ascii_label)
    }

    /// Looks up one compiled registration product by its stable identifier.
    #[must_use]
    pub fn registration_product(&self, id: &str) -> Option<&'static RegistrationProduct> {
        REGISTRATION_PRODUCTS.get(id.trim())
    }

    /// Looks up one compiled policy profile by its stable identifier.
    #[must_use]
    pub fn policy_profile(&self, id: &str) -> Option<&'static PolicyProfile> {
        POLICY_PROFILES.get(id.trim())
    }

    /// Looks up one stable evidence record.
    #[must_use]
    pub fn evidence(&self, id: &str) -> Option<&'static Evidence> {
        EVIDENCE.get(id.trim())
    }

    /// Reports dimensional data coverage without treating PSL import as policy research.
    #[must_use]
    pub fn stats(&self) -> RegistryStats {
        let mut roots = RootCounts::default();
        for root in ROOT_TLDS.values() {
            match root.state.verified_value() {
                Some(RootState::Delegated) => roots.current += 1,
                Some(RootState::SpecialUse) => roots.special_use += 1,
                Some(RootState::Absent) => roots.absent += 1,
                None => roots.unresolved += 1,
            }
        }

        let mut topology = TopologyCounts::default();
        for rule in PSL_EXACT
            .values()
            .chain(PSL_WILDCARD.values())
            .chain(PSL_EXCEPTION.values())
        {
            match rule.section {
                PslSection::Icann => topology.icann += 1,
                PslSection::Private => topology.private += 1,
            }
        }

        let selectors = SelectorCounts {
            exact: PRODUCT_BY_SUFFIX.len(),
            one_label_below: PRODUCT_ONE_LABEL_BELOW.len(),
        };
        let mut coverage = CoverageAccumulators::default();
        for product in REGISTRATION_PRODUCTS.values() {
            increment_product_coverage(&mut coverage, product, CoverageUnit::Product);
        }
        for product_id in PRODUCT_BY_SUFFIX
            .values()
            .chain(PRODUCT_ONE_LABEL_BELOW.values())
        {
            if let Some(product) = REGISTRATION_PRODUCTS.get(*product_id) {
                increment_product_coverage(&mut coverage, product, CoverageUnit::Selector);
            }
        }

        RegistryStats {
            roots,
            topology,
            products: REGISTRATION_PRODUCTS.len(),
            policy_profiles: POLICY_PROFILES.len(),
            selectors,
            offering_state: coverage.offering_state,
            public_access: coverage.public_access,
            eligibility: coverage.eligibility,
            label_policy: coverage.label_policy,
            idn_policy: coverage.idn_policy,
            reserved_labels: coverage.reserved_labels,
        }
    }

    /// Implements assessment with optional registrant facts.
    fn assess_internal(&self, domain: &str, context: Option<&RegistrantContext>) -> Assessment {
        let input = domain.to_string();
        if domain.is_empty() {
            return invalid_assessment(input, FindingCode::InvalidDnsSyntax, "empty domain");
        }

        let ascii_domain = match idna::domain_to_ascii(domain) {
            Ok(value) => value.to_ascii_lowercase(),
            Err(_) => {
                return invalid_assessment(
                    input,
                    FindingCode::InvalidIdna,
                    "input cannot be converted to a valid IDNA A-label",
                );
            }
        };
        let ascii_domain = ascii_domain
            .strip_suffix('.')
            .unwrap_or(&ascii_domain)
            .to_string();
        if ascii_domain.is_empty() {
            return invalid_assessment(input, FindingCode::InvalidDnsSyntax, "empty domain");
        }
        if let Err(message) = validate_ascii_domain(&ascii_domain) {
            return invalid_assessment(input, FindingCode::InvalidDnsSyntax, &message);
        }

        let resolved = resolve_domain(&ascii_domain);
        let product_match = product_for_domain(&ascii_domain);
        let product = product_match.as_ref().map(|value| value.product);
        let candidate_status = product_match
            .as_ref()
            .map_or(resolved.candidate_status, |value| value.candidate_status);
        let product_suffix = product_match.as_ref().map(|value| value.suffix.clone());
        let registrable_domain = match product_match.as_ref() {
            Some(value) => registration_domain_for(&ascii_domain, &value.suffix),
            None => resolved.registrable_domain.clone(),
        };
        let root = ascii_domain
            .rsplit('.')
            .next()
            .expect("validated domain has one label");
        let root_record = ROOT_TLDS.get(root);
        let root_state = root_state_for(root, root_record);
        let namespace_state = namespace_state_for(&ascii_domain);

        let offering_state = product.map_or_else(Claim::unknown, |value| value.offering_state);
        let public_access = product.map_or_else(Claim::unknown, |value| value.public_access);
        let application_channel =
            product.map_or_else(Claim::unknown, |value| value.application_channel);

        let eligibility = evaluate_eligibility(product, public_access, context);
        let eligibility_requirements = assess_eligibility_requirements(product, context);
        let label_policy = product.map_or(LabelPolicyStatus::Unknown, |value| {
            evaluate_label_policy(
                value.label_policy,
                registrable_domain.as_deref(),
                product_suffix.as_deref(),
                &ascii_domain,
            )
        });
        let verdict = derive_verdict(&EvaluationInput {
            syntax: SyntaxStatus::Valid,
            candidate_status,
            root_state,
            namespace_state,
            offering_state,
            public_access,
            eligibility,
            label_policy,
        });

        let mut findings = Vec::new();
        append_candidate_finding(
            candidate_status,
            product_suffix.as_deref().unwrap_or(&resolved.suffix.suffix),
            registrable_domain.as_deref(),
            &mut findings,
        );
        append_root_finding(root, root_state, &mut findings);
        append_namespace_finding(namespace_state, &mut findings);
        if product.is_none()
            && namespace_state.verified_value() != Some(&NamespaceState::SpecialUse)
        {
            findings.push(Finding {
                code: FindingCode::NoRegistrationProduct,
                message: format!(
                    "no researched registration product is assigned to '{}'",
                    resolved.suffix.suffix
                ),
            });
        }
        append_claim_findings("root state", root_state.status, &mut findings);
        append_claim_findings("offering state", offering_state.status, &mut findings);
        append_claim_findings("public access", public_access.status, &mut findings);
        append_unknown_eligibility_requirement_findings(product, context, &mut findings);
        append_policy_findings(
            product,
            offering_state,
            public_access,
            eligibility,
            label_policy,
            &mut findings,
        );

        let mut evidence = BTreeSet::new();
        collect_claim_evidence(root_state, &mut evidence);
        collect_claim_evidence(namespace_state, &mut evidence);
        collect_claim_evidence(offering_state, &mut evidence);
        collect_claim_evidence(public_access, &mut evidence);
        collect_claim_evidence(application_channel, &mut evidence);
        if let Some(topology_evidence) = resolved.suffix.evidence {
            evidence.insert(topology_evidence);
        }
        if let Some(product) = product {
            collect_product_evidence(product, &mut evidence);
        }

        Assessment {
            input,
            ascii_domain: Some(ascii_domain),
            registrable_domain,
            syntax: SyntaxStatus::Valid,
            candidate_status,
            suffix: Some(resolved.suffix),
            root_state,
            namespace_state,
            product_id: product.map(|value| value.id),
            product_suffix,
            offering_state,
            public_access,
            application_channel,
            eligibility,
            eligibility_requirements,
            label_policy,
            verdict,
            findings,
            evidence: evidence.into_iter().collect(),
        }
    }
}

/// Produces an invalid-syntax result without consulting namespace data.
fn invalid_assessment(input: String, code: FindingCode, message: &str) -> Assessment {
    let unknown_root = Claim::unknown();
    let unknown_namespace = Claim::unknown();
    let unknown_offering = Claim::unknown();
    let unknown_access = Claim::unknown();
    let evaluation = EvaluationInput {
        syntax: SyntaxStatus::Invalid,
        candidate_status: CandidateStatus::Unresolved,
        root_state: unknown_root,
        namespace_state: unknown_namespace,
        offering_state: unknown_offering,
        public_access: unknown_access,
        eligibility: EligibilityStatus::Unknown,
        label_policy: LabelPolicyStatus::Unknown,
    };
    Assessment {
        input,
        ascii_domain: None,
        registrable_domain: None,
        syntax: SyntaxStatus::Invalid,
        candidate_status: CandidateStatus::Unresolved,
        suffix: None,
        root_state: unknown_root,
        namespace_state: unknown_namespace,
        product_id: None,
        product_suffix: None,
        offering_state: unknown_offering,
        public_access: unknown_access,
        application_channel: Claim::<ApplicationChannel>::unknown(),
        eligibility: EligibilityStatus::Unknown,
        eligibility_requirements: Vec::new(),
        label_policy: LabelPolicyStatus::Unknown,
        verdict: derive_verdict(&evaluation),
        findings: vec![Finding {
            code,
            message: message.to_string(),
        }],
        evidence: Vec::new(),
    }
}

/// Resolves a root fact, using the exhaustive current list for verified absence.
fn root_state_for(
    root: &str,
    root_record: Option<&'static crate::types::RootTld>,
) -> Claim<RootState> {
    root_record.map_or_else(
        || {
            if SPECIAL_USE_NAMES.contains(root) {
                Claim::verified(RootState::SpecialUse, &[SPECIAL_USE_EVIDENCE])
            } else {
                Claim::verified(RootState::Absent, &[CURRENT_ROOT_EVIDENCE])
            }
        },
        |value| value.state,
    )
}

/// Classifies whether the candidate is at or below an IANA special-use name.
fn namespace_state_for(ascii_domain: &str) -> Claim<NamespaceState> {
    let mut candidate = ascii_domain;
    loop {
        if SPECIAL_USE_NAMES.contains(candidate) {
            return Claim::verified(NamespaceState::SpecialUse, &[SPECIAL_USE_EVIDENCE]);
        }
        let Some((_, parent)) = candidate.split_once('.') else {
            return Claim::verified(NamespaceState::Ordinary, &[SPECIAL_USE_EVIDENCE]);
        };
        candidate = parent;
    }
}

/// A product selector resolved against one concrete candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProductAssignment {
    /// Stable generated product identifier.
    product_id: &'static str,
    /// Concrete suffix at which the product allocates names.
    suffix: String,
    /// Candidate shape relative to the product suffix.
    candidate_status: CandidateStatus,
}

/// A resolved product and its concrete allocation boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MatchedProduct {
    /// Compiled product policy.
    product: &'static RegistrationProduct,
    /// Concrete suffix at which the product allocates names.
    suffix: String,
    /// Candidate shape relative to the product suffix.
    candidate_status: CandidateStatus,
}

/// Matches explicit products independently of the prevailing PSL boundary.
fn product_for_domain(ascii_domain: &str) -> Option<MatchedProduct> {
    let assignment = select_product_assignment(
        ascii_domain,
        |suffix| PRODUCT_BY_SUFFIX.get(suffix).copied(),
        |parent| PRODUCT_ONE_LABEL_BELOW.get(parent).copied(),
        |suffix| PSL_EXCEPTION.contains_key(suffix),
    )?;
    let product = REGISTRATION_PRODUCTS.get(assignment.product_id)?;
    Some(MatchedProduct {
        product,
        suffix: assignment.suffix,
        candidate_status: assignment.candidate_status,
    })
}

/// Applies most-specific selector precedence, preferring exact at equal depth.
fn select_product_assignment<Exact, OneBelow, Exception>(
    ascii_domain: &str,
    exact: Exact,
    one_label_below: OneBelow,
    is_psl_exception: Exception,
) -> Option<ProductAssignment>
where
    Exact: Fn(&str) -> Option<&'static str>,
    OneBelow: Fn(&str) -> Option<&'static str>,
    Exception: Fn(&str) -> bool,
{
    let labels = ascii_domain.split('.').collect::<Vec<_>>();
    for index in 0..labels.len() {
        let suffix = labels[index..].join(".");
        let candidate_status = match index {
            0 => CandidateStatus::BareSuffix,
            1 => CandidateStatus::RegistrableDomain,
            _ => CandidateStatus::Subdomain,
        };

        if let Some(product_id) = exact(&suffix) {
            return Some(ProductAssignment {
                product_id,
                suffix,
                candidate_status,
            });
        }

        if index + 1 < labels.len() && !is_psl_exception(&suffix) {
            let parent = labels[index + 1..].join(".");
            if let Some(product_id) = one_label_below(&parent) {
                return Some(ProductAssignment {
                    product_id,
                    suffix,
                    candidate_status,
                });
            }
        }
    }
    None
}

/// Finds the registrable domain immediately above a selected product suffix.
fn registration_domain_for(ascii_domain: &str, product_suffix: &str) -> Option<String> {
    let prefix = ascii_domain
        .strip_suffix(product_suffix)?
        .strip_suffix('.')?;
    let label = prefix.rsplit('.').next()?;
    (!label.is_empty()).then(|| format!("{label}.{product_suffix}"))
}

/// Extends a designation list without losing independent root or product tags.
fn extend_unique_designations(target: &mut Vec<Designation>, source: &[Designation]) {
    for designation in source {
        if !target.contains(designation) {
            target.push(*designation);
        }
    }
}

/// Produces discoverable per-requirement results for a selected product.
fn assess_eligibility_requirements(
    product: Option<&RegistrationProduct>,
    context: Option<&RegistrantContext>,
) -> Vec<EligibilityRequirementAssessment> {
    let mut assessments = Vec::new();
    if let Some(expression) = product.and_then(|value| value.eligibility) {
        collect_requirement_assessments(expression, context, &mut assessments);
    }
    assessments
}

/// Returns every atomic requirement identifier referenced by an expression.
fn eligibility_requirement_ids(expression: &EligibilityExpression) -> BTreeSet<&'static str> {
    let mut ids = BTreeSet::new();
    collect_eligibility_requirement_ids(expression, &mut ids);
    ids
}

/// Traverses an eligibility expression and de-duplicates its atomic identifiers.
fn collect_eligibility_requirement_ids(
    expression: &EligibilityExpression,
    ids: &mut BTreeSet<&'static str>,
) {
    match expression {
        EligibilityExpression::Requirement(requirement) => {
            ids.insert(requirement.id);
        }
        EligibilityExpression::All(expressions) | EligibilityExpression::Any(expressions) => {
            for expression in *expressions {
                collect_eligibility_requirement_ids(expression, ids);
            }
        }
    }
}

/// Keeps only caller facts that occur in the selected eligibility expression.
fn applicable_registrant_context(
    expression: &EligibilityExpression,
    context: &RegistrantContext,
) -> Option<RegistrantContext> {
    let ids = eligibility_requirement_ids(expression);
    let filtered = RegistrantContext {
        satisfied_requirements: context
            .satisfied_requirements
            .iter()
            .filter(|id| ids.contains(id.as_str()))
            .cloned()
            .collect(),
        unsatisfied_requirements: context
            .unsatisfied_requirements
            .iter()
            .filter(|id| ids.contains(id.as_str()))
            .cloned()
            .collect(),
    };
    (!filtered.satisfied_requirements.is_empty() || !filtered.unsatisfied_requirements.is_empty())
        .then_some(filtered)
}

/// Traverses one eligibility expression in stable authoring order.
fn collect_requirement_assessments(
    expression: &EligibilityExpression,
    context: Option<&RegistrantContext>,
    assessments: &mut Vec<EligibilityRequirementAssessment>,
) {
    match expression {
        EligibilityExpression::Requirement(requirement) => {
            if !assessments.iter().any(|value| value.id == requirement.id) {
                assessments.push(requirement_assessment(requirement, context));
            }
        }
        EligibilityExpression::All(expressions) | EligibilityExpression::Any(expressions) => {
            for expression in *expressions {
                collect_requirement_assessments(expression, context, assessments);
            }
        }
    }
}

/// Renders one atomic requirement and the matching caller fact.
fn requirement_assessment(
    requirement: &EligibilityRequirement,
    context: Option<&RegistrantContext>,
) -> EligibilityRequirementAssessment {
    let satisfied =
        context.is_some_and(|value| value.satisfied_requirements.contains(requirement.id));
    let unsatisfied =
        context.is_some_and(|value| value.unsatisfied_requirements.contains(requirement.id));
    let outcome = match (satisfied, unsatisfied) {
        (true, false) => EligibilityRequirementOutcome::Satisfied,
        (false, true) => EligibilityRequirementOutcome::Unsatisfied,
        (false, false) | (true, true) => EligibilityRequirementOutcome::Unknown,
    };
    EligibilityRequirementAssessment {
        id: requirement.id,
        kind: requirement.kind,
        value: requirement.value,
        explanation: requirement.explanation,
        evidence: requirement.evidence,
        outcome,
    }
}

/// Evaluates a typed eligibility expression with three-valued caller facts.
fn evaluate_eligibility(
    product: Option<&RegistrationProduct>,
    access: Claim<PublicAccess>,
    context: Option<&RegistrantContext>,
) -> EligibilityStatus {
    let gated = matches!(
        access.verified_value(),
        Some(PublicAccess::Conditional | PublicAccess::ControlledGroup)
    );
    if !gated {
        return if access.status == ClaimStatus::Verified {
            EligibilityStatus::NotApplicable
        } else {
            EligibilityStatus::Unknown
        };
    }

    let Some(expression) = product.and_then(|value| value.eligibility) else {
        return EligibilityStatus::Unknown;
    };
    let Some(context) = context.and_then(|value| applicable_registrant_context(expression, value))
    else {
        return EligibilityStatus::Required;
    };

    match evaluate_expression(expression, &context) {
        RequirementResult::Satisfied => EligibilityStatus::Satisfied,
        RequirementResult::Unsatisfied => EligibilityStatus::Unsatisfied,
        RequirementResult::Unknown => EligibilityStatus::Unknown,
    }
}

/// Reports supplied caller-fact identifiers outside the selected eligibility expression.
fn append_unknown_eligibility_requirement_findings(
    product: Option<&RegistrationProduct>,
    context: Option<&RegistrantContext>,
    findings: &mut Vec<Finding>,
) {
    let Some(context) = context else { return };
    let known = product
        .and_then(|value| value.eligibility)
        .map(eligibility_requirement_ids)
        .unwrap_or_default();
    let supplied = context
        .satisfied_requirements
        .union(&context.unsatisfied_requirements);
    for id in supplied.filter(|id| !known.contains(id.as_str())) {
        findings.push(Finding {
            code: FindingCode::UnknownEligibilityRequirement,
            message: format!(
                "supplied eligibility requirement '{id}' does not apply to the selected product"
            ),
        });
    }
}

/// Three-valued intermediate result for composed eligibility expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequirementResult {
    /// The expression is proven true.
    Satisfied,
    /// The expression is proven false.
    Unsatisfied,
    /// Supplied facts do not decide the expression.
    Unknown,
}

/// Recursively evaluates an all/any eligibility expression.
fn evaluate_expression(
    expression: &EligibilityExpression,
    context: &RegistrantContext,
) -> RequirementResult {
    match expression {
        EligibilityExpression::Requirement(requirement) => {
            let satisfied = context.satisfied_requirements.contains(requirement.id);
            let unsatisfied = context.unsatisfied_requirements.contains(requirement.id);
            match (satisfied, unsatisfied) {
                (true, false) => RequirementResult::Satisfied,
                (false, true) => RequirementResult::Unsatisfied,
                _ => RequirementResult::Unknown,
            }
        }
        EligibilityExpression::All(expressions) => {
            let mut unresolved = false;
            for expression in *expressions {
                match evaluate_expression(expression, context) {
                    RequirementResult::Unsatisfied => return RequirementResult::Unsatisfied,
                    RequirementResult::Unknown => unresolved = true,
                    RequirementResult::Satisfied => {}
                }
            }
            if unresolved {
                RequirementResult::Unknown
            } else {
                RequirementResult::Satisfied
            }
        }
        EligibilityExpression::Any(expressions) => {
            let mut unresolved = false;
            for expression in *expressions {
                match evaluate_expression(expression, context) {
                    RequirementResult::Satisfied => return RequirementResult::Satisfied,
                    RequirementResult::Unknown => unresolved = true,
                    RequirementResult::Unsatisfied => {}
                }
            }
            if unresolved {
                RequirementResult::Unknown
            } else {
                RequirementResult::Unsatisfied
            }
        }
    }
}

/// Applies researched registry constraints to the registrable label.
fn evaluate_label_policy(
    policy: Option<&LabelPolicy>,
    registrable_domain: Option<&str>,
    product_suffix: Option<&str>,
    ascii_domain: &str,
) -> LabelPolicyStatus {
    let Some(policy) = policy else {
        return LabelPolicyStatus::Unknown;
    };
    let (Some(registrable_domain), Some(product_suffix)) = (registrable_domain, product_suffix)
    else {
        return LabelPolicyStatus::Unknown;
    };
    let suffix_pattern = format!(".{product_suffix}");
    let label_ascii = registrable_domain
        .strip_suffix(&suffix_pattern)
        .unwrap_or(ascii_domain);
    let (label_unicode, unicode_status) = idna::domain_to_unicode(label_ascii);
    let is_idn = label_ascii.starts_with("xn--") || !label_unicode.is_ascii();
    let mut known_facet = false;
    let mut unresolved = policy.completeness != ClaimStatus::Verified;

    if let Some(length) = policy.length {
        known_facet = true;
        let measured = match length.unit {
            LengthUnit::ALabelOctets => Some(label_ascii.len()),
            LengthUnit::UnicodeCodePoints => unicode_status
                .is_ok()
                .then(|| label_unicode.chars().count()),
            LengthUnit::GraphemeClusters => None,
        };
        let Some(measured) = measured else {
            return LabelPolicyStatus::Partial;
        };
        if measured < usize::from(length.minimum) || measured > usize::from(length.maximum) {
            return LabelPolicyStatus::Fail;
        }
    }

    if is_idn {
        known_facet = true;
        match policy.idn_support.verified_value() {
            Some(IdnSupport::Unsupported) => return LabelPolicyStatus::Fail,
            // An IDN profile currently carries provenance metadata, not an
            // executable repertoire. Its presence must not authorize a label.
            Some(IdnSupport::Supported) | None => unresolved = true,
        }
    }

    if policy.reserved_status == ClaimStatus::Verified {
        known_facet = true;
        if let Some(reserved) = policy
            .reserved_labels
            .iter()
            .find(|entry| entry.label.eq_ignore_ascii_case(label_ascii))
        {
            return match reserved.disposition {
                ReservedDisposition::Prohibited | ReservedDisposition::Held => {
                    LabelPolicyStatus::Fail
                }
                ReservedDisposition::Premium | ReservedDisposition::SpecialAllocation => {
                    LabelPolicyStatus::Partial
                }
            };
        }
    } else {
        unresolved = true;
    }

    if unresolved {
        if known_facet {
            LabelPolicyStatus::Partial
        } else {
            LabelPolicyStatus::Unknown
        }
    } else {
        LabelPolicyStatus::Pass
    }
}

/// Adds a structural finding for non-registrable candidate shapes.
fn append_candidate_finding(
    status: CandidateStatus,
    boundary_suffix: &str,
    registrable_domain: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    match status {
        CandidateStatus::BareSuffix => findings.push(Finding {
            code: FindingCode::BareSuffix,
            message: format!("'{boundary_suffix}' is a suffix, not a registrable domain"),
        }),
        CandidateStatus::Subdomain => findings.push(Finding {
            code: FindingCode::Subdomain,
            message: format!(
                "input is below registrable domain '{}'",
                registrable_domain.unwrap_or("")
            ),
        }),
        CandidateStatus::RegistrableDomain | CandidateStatus::Unresolved => {}
    }
}

/// Adds a finding for an absent root.
fn append_root_finding(root: &str, claim: Claim<RootState>, findings: &mut Vec<Finding>) {
    match claim.verified_value() {
        Some(RootState::Absent) => findings.push(Finding {
            code: FindingCode::RootAbsent,
            message: format!("root label '{root}' is absent from the pinned IANA root list"),
        }),
        Some(RootState::Delegated | RootState::SpecialUse) | None => {}
    }
}

/// Adds a finding for a standards-defined special-use namespace.
fn append_namespace_finding(claim: Claim<NamespaceState>, findings: &mut Vec<Finding>) {
    if claim.verified_value() == Some(&NamespaceState::SpecialUse) {
        findings.push(Finding {
            code: FindingCode::SpecialUseNamespace,
            message: "candidate is at or below an IANA special-use name".to_string(),
        });
    }
}

/// Adds a stable finding when one decision fact is not verified.
fn append_claim_findings(axis: &str, status: ClaimStatus, findings: &mut Vec<Finding>) {
    let (code, state) = match status {
        ClaimStatus::Verified => return,
        ClaimStatus::Unknown => (FindingCode::ClaimUnknown, "unknown"),
        ClaimStatus::Stale => (FindingCode::ClaimStale, "stale"),
        ClaimStatus::Conflicting => (FindingCode::ClaimConflicting, "conflicting"),
    };
    findings.push(Finding {
        code,
        message: format!("{axis} is {state}"),
    });
}

/// Adds findings for concrete offering, access, eligibility, and label outcomes.
fn append_policy_findings(
    product: Option<&RegistrationProduct>,
    offering: Claim<OfferingState>,
    access: Claim<PublicAccess>,
    eligibility: EligibilityStatus,
    label: LabelPolicyStatus,
    findings: &mut Vec<Finding>,
) {
    if matches!(
        offering.verified_value(),
        Some(
            OfferingState::Paused
                | OfferingState::RenewalOnly
                | OfferingState::NotLaunched
                | OfferingState::Closed
        )
    ) {
        findings.push(Finding {
            code: FindingCode::OfferingNotAccepting,
            message: "registration product is not accepting new allocations".to_string(),
        });
    }
    if access.verified_value() == Some(&PublicAccess::Unavailable) {
        findings.push(Finding {
            code: FindingCode::PublicAccessUnavailable,
            message: "registration is unavailable to the public".to_string(),
        });
    }
    match eligibility {
        EligibilityStatus::Required => findings.push(Finding {
            code: FindingCode::EligibilityRequired,
            message: "registrant eligibility and/or approval is required".to_string(),
        }),
        EligibilityStatus::Unsatisfied => findings.push(Finding {
            code: FindingCode::EligibilityFailed,
            message: "supplied registrant facts do not satisfy eligibility".to_string(),
        }),
        EligibilityStatus::Unknown if product.is_some() => findings.push(Finding {
            code: FindingCode::EligibilityUnknown,
            message: "eligibility could not be decided from current facts".to_string(),
        }),
        EligibilityStatus::Satisfied
        | EligibilityStatus::Unknown
        | EligibilityStatus::NotApplicable => {}
    }
    match label {
        LabelPolicyStatus::Fail => findings.push(Finding {
            code: FindingCode::LabelPolicyFailed,
            message: "a verified registry label rule fails".to_string(),
        }),
        LabelPolicyStatus::Partial | LabelPolicyStatus::Unknown => findings.push(Finding {
            code: FindingCode::LabelPolicyIncomplete,
            message: "registry-specific label policy is incomplete".to_string(),
        }),
        LabelPolicyStatus::Pass => {}
    }
}

/// Adds every evidence ID attached directly to a claim.
fn collect_claim_evidence<T>(claim: Claim<T>, evidence: &mut BTreeSet<&'static str>) {
    evidence.extend(claim.evidence.iter().copied());
}

/// Adds evidence embedded in a product's eligibility and label policies.
fn collect_product_evidence(product: &RegistrationProduct, evidence: &mut BTreeSet<&'static str>) {
    if let Some(expression) = product.eligibility {
        collect_expression_evidence(expression, evidence);
    }
    if let Some(policy) = product.label_policy {
        evidence.extend(policy.completeness_evidence.iter().copied());
        evidence.extend(policy.length_evidence.iter().copied());
        collect_claim_evidence(policy.idn_support, evidence);
        evidence.extend(policy.reserved_set_evidence.iter().copied());
        for reserved in policy.reserved_labels {
            evidence.extend(reserved.evidence.iter().copied());
        }
        if let Some(profile) = policy.idn_profile {
            evidence.extend(profile.evidence.iter().copied());
        }
    }
}

/// Recursively gathers eligibility evidence.
fn collect_expression_evidence(
    expression: &EligibilityExpression,
    evidence: &mut BTreeSet<&'static str>,
) {
    match expression {
        EligibilityExpression::Requirement(requirement) => {
            evidence.extend(requirement.evidence.iter().copied());
        }
        EligibilityExpression::All(expressions) | EligibilityExpression::Any(expressions) => {
            for expression in *expressions {
                collect_expression_evidence(expression, evidence);
            }
        }
    }
}

/// Mutable coverage totals for each policy dimension.
#[derive(Debug, Default)]
struct CoverageAccumulators {
    /// Offering-state totals.
    offering_state: PolicyCoverage,
    /// Public-access totals.
    public_access: PolicyCoverage,
    /// Eligibility-policy totals.
    eligibility: PolicyCoverage,
    /// Overall label-policy totals.
    label_policy: PolicyCoverage,
    /// IDN-policy totals.
    idn_policy: PolicyCoverage,
    /// Reserved-label-set totals.
    reserved_labels: PolicyCoverage,
}

/// Unit used for one coverage observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoverageUnit {
    /// Count once for the product.
    Product,
    /// Count once for an explicit selector assigned to the product.
    Selector,
}

/// Adds every policy dimension for one product at the requested unit.
fn increment_product_coverage(
    coverage: &mut CoverageAccumulators,
    product: &RegistrationProduct,
    unit: CoverageUnit,
) {
    increment_policy_coverage(
        &mut coverage.offering_state,
        product.offering_state.status,
        unit,
    );
    increment_policy_coverage(
        &mut coverage.public_access,
        product.public_access.status,
        unit,
    );
    increment_policy_coverage(
        &mut coverage.eligibility,
        eligibility_coverage_status(product),
        unit,
    );
    increment_policy_coverage(
        &mut coverage.label_policy,
        product
            .label_policy
            .map_or(ClaimStatus::Unknown, |policy| policy.completeness),
        unit,
    );
    increment_policy_coverage(&mut coverage.idn_policy, idn_coverage_status(product), unit);
    increment_policy_coverage(
        &mut coverage.reserved_labels,
        product
            .label_policy
            .map_or(ClaimStatus::Unknown, |policy| policy.reserved_status),
        unit,
    );
}

/// Returns eligibility-policy coverage without confusing non-applicability with unknown.
fn eligibility_coverage_status(product: &RegistrationProduct) -> ClaimStatus {
    match (product.public_access.status, product.public_access.value) {
        (ClaimStatus::Verified, Some(PublicAccess::Open | PublicAccess::Unavailable)) => {
            ClaimStatus::Verified
        }
        (
            ClaimStatus::Verified,
            Some(PublicAccess::Conditional | PublicAccess::ControlledGroup),
        ) => {
            if product.eligibility.is_some() {
                ClaimStatus::Verified
            } else {
                ClaimStatus::Unknown
            }
        }
        (ClaimStatus::Verified, None) => ClaimStatus::Unknown,
        (status, _) => status,
    }
}

/// Returns per-product IDN coverage, treating verified unsupported as complete.
fn idn_coverage_status(product: &RegistrationProduct) -> ClaimStatus {
    let Some(policy) = product.label_policy else {
        return ClaimStatus::Unknown;
    };
    match (policy.idn_support.status, policy.idn_support.value) {
        (ClaimStatus::Verified, Some(IdnSupport::Unsupported)) => ClaimStatus::Verified,
        (ClaimStatus::Verified, Some(IdnSupport::Supported)) => {
            if policy.idn_profile.is_some() {
                ClaimStatus::Verified
            } else {
                ClaimStatus::Unknown
            }
        }
        (ClaimStatus::Verified, None) => ClaimStatus::Unknown,
        (status, _) => status,
    }
}

/// Increments product- or selector-weighted coverage for one claim state.
fn increment_policy_coverage(
    coverage: &mut PolicyCoverage,
    status: ClaimStatus,
    unit: CoverageUnit,
) {
    let counts = match unit {
        CoverageUnit::Product => &mut coverage.by_product,
        CoverageUnit::Selector => &mut coverage.by_selector,
    };
    increment_claim_count(counts, status);
}

/// Increments the bucket corresponding to one audit state.
fn increment_claim_count(counts: &mut ClaimCounts, status: ClaimStatus) {
    match status {
        ClaimStatus::Verified => counts.verified += 1,
        ClaimStatus::Unknown => counts.unknown += 1,
        ClaimStatus::Stale => counts.stale += 1,
        ClaimStatus::Conflicting => counts.conflicting += 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate_label_policy, select_product_assignment, Registry};
    use crate::generated::{
        PRODUCT_BY_SUFFIX, PRODUCT_ONE_LABEL_BELOW, PSL_EXACT, PSL_EXCEPTION, PSL_WILDCARD,
        REGISTRATION_PRODUCTS, ROOT_TLDS,
    };
    use crate::types::{
        CandidateStatus, Claim, ClaimStatus, Designation, EligibilityRequirementOutcome,
        EligibilityStatus, FindingCode, IdnProfile, IdnSupport, LabelPolicy, LabelPolicyStatus,
        NamespaceState, PslSection, PublicAccess, RegistrantContext, RootState, SuffixRuleKind,
        Verdict,
    };

    static TEST_IDN_PROFILE: IdnProfile = IdnProfile {
        id: "test-idn-profile",
        version: "1",
        evidence: &["test-idn-evidence"],
    };

    static TEST_IDN_POLICY: LabelPolicy = LabelPolicy {
        id: "test-idn-policy",
        completeness: ClaimStatus::Verified,
        completeness_evidence: &["test-policy-evidence"],
        length: None,
        length_evidence: &[],
        idn_support: Claim::verified(IdnSupport::Supported, &["test-idn-evidence"]),
        idn_profile: Some(&TEST_IDN_PROFILE),
        reserved_status: ClaimStatus::Verified,
        reserved_set_evidence: &["test-reserved-evidence"],
        reserved_labels: &[],
    };

    #[test]
    fn bootstrap_topology_is_not_an_open_policy_claim() {
        let result = Registry::new().assess("ordinary-candidate.com");
        assert_eq!(result.verdict, Verdict::Indeterminate);
        assert_eq!(result.public_access.status, ClaimStatus::Unknown);
    }

    #[test]
    fn infrastructure_and_special_use_names_are_impossible() {
        let registry = Registry::new();
        for name in ["example.arpa", "example.test", "example.invalid"] {
            assert_eq!(registry.assess(name).verdict, Verdict::Impossible, "{name}");
        }
    }

    #[test]
    fn special_use_is_an_independent_decision_axis() {
        let result = Registry::new().assess("candidate.local");
        assert_eq!(
            result.namespace_state.verified_value(),
            Some(&NamespaceState::SpecialUse)
        );
        assert_eq!(result.offering_state.status, ClaimStatus::Unknown);
        assert_eq!(result.public_access.status, ClaimStatus::Unknown);
        assert_eq!(result.verdict, Verdict::Impossible);
        assert!(result.evidence.contains(&"iana_special_use"));
    }

    #[test]
    fn de_is_verified_open_without_a_residency_gate() {
        let result = Registry::new().assess("max.de");
        assert_eq!(result.product_suffix.as_deref(), Some("de"));
        assert_eq!(result.registrable_domain.as_deref(), Some("max.de"));
        assert_eq!(
            result.public_access.verified_value(),
            Some(&PublicAccess::Open)
        );
        assert_eq!(result.verdict, Verdict::Indeterminate);
    }

    #[test]
    fn eligibility_namespaces_are_not_reported_open() {
        let registry = Registry::new();
        for name in ["example.gov", "example.bank", "example.gov.uk"] {
            let result = registry.assess(name);
            assert_eq!(
                result.public_access.verified_value(),
                Some(&PublicAccess::Conditional),
                "{name}"
            );
            assert_ne!(result.verdict, Verdict::Plausible, "{name}");
        }

        let edu = registry.assess("example.edu");
        assert_eq!(edu.product_id, Some("edu-institutions"));
        assert_eq!(edu.public_access.status, ClaimStatus::Unknown);
        assert_eq!(edu.verdict, Verdict::Indeterminate);
    }

    #[test]
    fn eligibility_requirements_are_discoverable_with_individual_outcomes() {
        let registry = Registry::new();
        let without_context = registry.assess("candidate.gov");
        assert_eq!(without_context.eligibility_requirements.len(), 2);
        assert_eq!(
            without_context.eligibility_requirements[0].id,
            "us-government-organization"
        );
        assert!(without_context
            .eligibility_requirements
            .iter()
            .all(|value| value.outcome == EligibilityRequirementOutcome::Unknown));

        let mut context = RegistrantContext::default();
        context
            .satisfied_requirements
            .insert("us-government-organization".to_string());
        context
            .unsatisfied_requirements
            .insert("dotgov-senior-official-approval".to_string());
        let with_context = registry.assess_for("candidate.gov", &context);
        assert_eq!(with_context.eligibility, EligibilityStatus::Unsatisfied);
        assert_eq!(
            with_context.eligibility_requirements[0].outcome,
            EligibilityRequirementOutcome::Satisfied
        );
        assert_eq!(
            with_context.eligibility_requirements[1].outcome,
            EligibilityRequirementOutcome::Unsatisfied
        );
        assert!(!with_context.eligibility_requirements[0]
            .explanation
            .is_empty());
        assert!(!with_context.eligibility_requirements[0].evidence.is_empty());
    }

    #[test]
    fn unknown_eligibility_ids_do_not_activate_requirement_evaluation() {
        let registry = Registry::new();
        let mut context = RegistrantContext::default();
        context.satisfied_requirements.insert("typo".to_string());

        let result = registry.assess_for("candidate.bank", &context);
        assert_eq!(result.eligibility, EligibilityStatus::Required);
        assert!(result
            .eligibility_requirements
            .iter()
            .all(|requirement| requirement.outcome == EligibilityRequirementOutcome::Unknown));
        assert!(result.findings.iter().any(|finding| {
            finding.code == FindingCode::UnknownEligibilityRequirement
                && finding.message.contains("'typo'")
        }));
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::EligibilityRequired));
    }

    #[test]
    fn relevant_eligibility_ids_are_evaluated_while_unknown_ids_are_reported() {
        let registry = Registry::new();
        let mut context = RegistrantContext::default();
        context
            .satisfied_requirements
            .insert("bank-regulated-entity".to_string());
        context
            .unsatisfied_requirements
            .insert("another-product-requirement".to_string());

        let result = registry.assess_for("candidate.bank", &context);
        assert_eq!(result.eligibility, EligibilityStatus::Satisfied);
        assert_eq!(
            result.eligibility_requirements[0].outcome,
            EligibilityRequirementOutcome::Satisfied
        );
        assert!(result.findings.iter().any(|finding| {
            finding.code == FindingCode::UnknownEligibilityRequirement
                && finding.message.contains("'another-product-requirement'")
        }));
    }

    #[test]
    fn compiled_catalog_records_are_available_by_stable_id() {
        let registry = Registry::new();
        assert_eq!(
            registry.root_tld(".信息.").map(|value| value.ascii_label),
            Some("xn--vuq861b")
        );
        assert_eq!(
            registry
                .registration_product(" de-direct ")
                .map(|value| value.id),
            Some("de-direct")
        );
        assert_eq!(
            registry
                .policy_profile("denic-open-v1")
                .map(|value| value.id),
            Some("denic-open-v1")
        );
    }

    #[test]
    fn idn_suffix_lookup_is_canonical() {
        let registry = Registry::new();
        let unicode = registry.suffix_info("信息").expect("Unicode root");
        let ascii = registry
            .suffix_info("xn--vuq861b")
            .expect("canonical A-label root");
        assert_eq!(unicode.canonical_suffix, "xn--vuq861b");
        assert_eq!(unicode.canonical_suffix, ascii.canonical_suffix);
        assert_eq!(
            unicode.root_state.verified_value(),
            Some(&RootState::Delegated)
        );
    }

    #[test]
    fn idn_profile_metadata_cannot_authorize_a_label() {
        assert_eq!(
            evaluate_label_policy(
                Some(&TEST_IDN_POLICY),
                Some("xn--fa-hia.de"),
                Some("de"),
                "xn--fa-hia.de",
            ),
            LabelPolicyStatus::Partial
        );
        assert_eq!(
            evaluate_label_policy(
                Some(&TEST_IDN_POLICY),
                Some("ascii.de"),
                Some("de"),
                "ascii.de",
            ),
            LabelPolicyStatus::Pass
        );
    }

    #[test]
    fn suffix_info_unions_root_and_product_designations() {
        let info = Registry::new()
            .suffix_info("xn--5su34j936bgsg")
            .expect("active IDN brand root");
        assert!(info.designations.contains(&Designation::BrandSpec13));
        assert!(info.designations.contains(&Designation::IdnTld));
    }

    #[test]
    fn wildcard_and_exception_rules_are_reachable() {
        let registry = Registry::new();
        let wildcard = registry.assess("bar.foo.ck");
        let wildcard_suffix = wildcard.suffix.expect("wildcard suffix");
        assert_eq!(wildcard_suffix.suffix, "foo.ck");
        assert_eq!(wildcard_suffix.rule_kind, SuffixRuleKind::Wildcard);
        assert_eq!(wildcard_suffix.evidence, Some("psl"));
        assert!(wildcard.evidence.contains(&"psl"));

        let exception = registry.assess("foo.www.ck");
        let exception_suffix = exception.suffix.expect("exception suffix");
        assert_eq!(exception_suffix.suffix, "ck");
        assert_eq!(exception_suffix.rule_kind, SuffixRuleKind::Exception);
    }

    #[test]
    fn private_suffixes_keep_their_non_registry_role() {
        let result = Registry::new().assess("alice.github.io");
        let suffix = result.suffix.expect("private suffix");
        assert_eq!(suffix.section, Some(PslSection::Private));
        assert_eq!(result.public_access.status, ClaimStatus::Unknown);
    }

    #[test]
    fn bare_suffix_and_subdomain_are_impossible() {
        let registry = Registry::new();
        let bare = registry.assess("co.uk");
        assert_eq!(bare.candidate_status, CandidateStatus::BareSuffix);
        assert_eq!(bare.verdict, Verdict::Impossible);

        let subdomain = registry.assess("www.example.com");
        assert_eq!(subdomain.candidate_status, CandidateStatus::Subdomain);
        assert_eq!(subdomain.verdict, Verdict::Impossible);
    }

    #[test]
    fn unknown_root_is_verified_absent() {
        let result = Registry::new().assess("example.not-a-real-root");
        assert_eq!(result.root_state.verified_value(), Some(&RootState::Absent));
        assert_eq!(result.verdict, Verdict::Impossible);
    }

    #[test]
    fn mapped_terminal_dot_is_normalized_after_idna() {
        let registry = Registry::new();
        let ascii = registry.assess("ordinary-candidate.com.");
        let unicode_separator = registry.assess("ordinary-candidate.com。");
        assert_eq!(unicode_separator.syntax, ascii.syntax);
        assert_eq!(unicode_separator.ascii_domain, ascii.ascii_domain);
        assert_eq!(unicode_separator.verdict, ascii.verdict);
    }

    #[test]
    fn empty_registrant_context_behaves_like_absent_context() {
        let registry = Registry::new();
        let without_context = registry.assess("candidate.bank");
        let empty_context = registry.assess_for("candidate.bank", &RegistrantContext::default());
        assert_eq!(empty_context.eligibility, without_context.eligibility);
        assert_eq!(empty_context.verdict, without_context.verdict);
    }

    #[test]
    fn product_selectors_use_most_specific_boundary_and_exact_tiebreak() {
        let exact_root = |suffix: &str| (suffix == "test").then_some("root");
        let one_below = |parent: &str| (parent == "test").then_some("family");
        let family =
            select_product_assignment("candidate.city.test", exact_root, one_below, |_| false)
                .expect("one-label-below selector");
        assert_eq!(family.product_id, "family");
        assert_eq!(family.suffix, "city.test");
        assert_eq!(family.candidate_status, CandidateStatus::RegistrableDomain);

        let exact_specific = |suffix: &str| match suffix {
            "city.test" => Some("specific"),
            "test" => Some("root"),
            _ => None,
        };
        let exact =
            select_product_assignment("candidate.city.test", exact_specific, one_below, |_| false)
                .expect("specific exact selector");
        assert_eq!(exact.product_id, "specific");
        assert_eq!(exact.suffix, "city.test");

        let subdomain =
            select_product_assignment("deep.candidate.city.test", exact_root, one_below, |_| false)
                .expect("family selector below a deeper candidate");
        assert_eq!(subdomain.suffix, "city.test");
        assert_eq!(subdomain.candidate_status, CandidateStatus::Subdomain);

        let exception =
            select_product_assignment("candidate.city.test", exact_root, one_below, |suffix| {
                suffix == "city.test"
            });
        assert_eq!(exception.expect("root fallback").product_id, "root");
    }

    #[test]
    fn reserved_r_ldh_candidate_is_invalid() {
        let result = Registry::new().assess("ab--cd.de");
        assert_eq!(result.syntax, crate::types::SyntaxStatus::Invalid);
        assert_eq!(result.verdict, Verdict::Impossible);
    }

    #[test]
    fn statistics_use_explicit_and_consistent_denominators() {
        let stats = Registry::new().stats();
        assert_eq!(stats.roots.total(), ROOT_TLDS.len());
        assert!(stats.roots.current > 0);
        assert!(stats.roots.special_use > 0);
        assert_eq!(
            stats.topology.total(),
            PSL_EXACT.len() + PSL_WILDCARD.len() + PSL_EXCEPTION.len()
        );
        assert!(stats.topology.icann > 0);
        assert!(stats.topology.private > 0);
        assert_eq!(
            stats.selectors.total(),
            PRODUCT_BY_SUFFIX.len() + PRODUCT_ONE_LABEL_BELOW.len()
        );

        for coverage in [
            stats.offering_state,
            stats.public_access,
            stats.eligibility,
            stats.label_policy,
            stats.idn_policy,
            stats.reserved_labels,
        ] {
            assert_eq!(coverage.by_product.total(), REGISTRATION_PRODUCTS.len());
            assert_eq!(coverage.by_selector.total(), stats.selectors.total());
        }
    }
}
