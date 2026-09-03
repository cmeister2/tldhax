//! PyO3 bindings exposing the evidence-aware registry API to Python.

use std::collections::BTreeSet;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::registry::Registry as RustRegistry;
use crate::types::{
    ApplicationChannel, Assessment, CandidateStatus, Claim, ClaimCounts, ClaimStatus, Designation,
    EligibilityKind, EligibilityRequirementAssessment, EligibilityRequirementOutcome,
    EligibilityStatus, Evidence, Finding, FindingCode, LabelPolicyStatus, NamespaceState,
    OfferingState, PolicyCoverage, PslSection, PublicAccess, RegistrantContext, RegistryStats,
    RootCounts, RootState, SelectorCounts, SourceKind, SuffixInfo, SuffixRole, SuffixRuleKind,
    SyntaxStatus, TopologyCounts,
};

#[pyclass(name = "Finding", skip_from_py_object)]
#[derive(Clone)]
pub struct PyFinding {
    #[pyo3(get)]
    pub code: String,
    #[pyo3(get)]
    pub message: String,
}

#[pymethods]
impl PyFinding {
    fn __repr__(&self) -> String {
        format!("Finding(code='{}', message={:?})", self.code, self.message)
    }
}

impl From<Finding> for PyFinding {
    fn from(value: Finding) -> Self {
        Self {
            code: finding_code(value.code).to_string(),
            message: value.message,
        }
    }
}

#[pyclass(name = "EligibilityRequirement", skip_from_py_object)]
#[derive(Clone)]
pub struct PyEligibilityRequirement {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub kind: String,
    #[pyo3(get)]
    pub value: String,
    #[pyo3(get)]
    pub explanation: String,
    #[pyo3(get)]
    pub evidence: Vec<String>,
    #[pyo3(get)]
    pub outcome: String,
}

#[pymethods]
impl PyEligibilityRequirement {
    fn __repr__(&self) -> String {
        format!(
            "EligibilityRequirement(id='{}', kind='{}', outcome='{}')",
            self.id, self.kind, self.outcome
        )
    }
}

impl From<EligibilityRequirementAssessment> for PyEligibilityRequirement {
    fn from(value: EligibilityRequirementAssessment) -> Self {
        Self {
            id: value.id.to_string(),
            kind: eligibility_kind(value.kind).to_string(),
            value: value.value.to_string(),
            explanation: value.explanation.to_string(),
            evidence: value
                .evidence
                .iter()
                .map(|item| (*item).to_string())
                .collect(),
            outcome: eligibility_requirement_outcome(value.outcome).to_string(),
        }
    }
}

#[pyclass(name = "Assessment", skip_from_py_object)]
#[derive(Clone)]
pub struct PyAssessment {
    #[pyo3(get)]
    pub input: String,
    #[pyo3(get)]
    pub ascii_domain: Option<String>,
    #[pyo3(get)]
    pub registrable_domain: Option<String>,
    #[pyo3(get)]
    pub syntax: String,
    #[pyo3(get)]
    pub candidate_status: String,
    #[pyo3(get)]
    pub public_suffix: Option<String>,
    #[pyo3(get)]
    pub suffix_rule: Option<String>,
    #[pyo3(get)]
    pub suffix_rule_kind: Option<String>,
    #[pyo3(get)]
    pub suffix_section: Option<String>,
    #[pyo3(get)]
    pub suffix_role: Option<String>,
    #[pyo3(get)]
    pub suffix_evidence: Option<String>,
    #[pyo3(get)]
    pub root_state: Option<String>,
    #[pyo3(get)]
    pub root_state_status: String,
    #[pyo3(get)]
    pub root_state_evidence: Vec<String>,
    #[pyo3(get)]
    pub namespace_state: Option<String>,
    #[pyo3(get)]
    pub namespace_state_status: String,
    #[pyo3(get)]
    pub namespace_state_evidence: Vec<String>,
    #[pyo3(get)]
    pub offering_state: Option<String>,
    #[pyo3(get)]
    pub offering_state_status: String,
    #[pyo3(get)]
    pub offering_state_evidence: Vec<String>,
    #[pyo3(get)]
    pub public_access: Option<String>,
    #[pyo3(get)]
    pub public_access_status: String,
    #[pyo3(get)]
    pub public_access_evidence: Vec<String>,
    #[pyo3(get)]
    pub application_channel: Option<String>,
    #[pyo3(get)]
    pub application_channel_status: String,
    #[pyo3(get)]
    pub application_channel_evidence: Vec<String>,
    #[pyo3(get)]
    pub eligibility: String,
    #[pyo3(get)]
    pub label_policy: String,
    #[pyo3(get)]
    pub product_id: Option<String>,
    #[pyo3(get)]
    pub product_suffix: Option<String>,
    #[pyo3(get)]
    pub verdict: String,
    findings: Vec<PyFinding>,
    eligibility_requirements: Vec<PyEligibilityRequirement>,
    #[pyo3(get)]
    pub evidence: Vec<String>,
}

#[pymethods]
impl PyAssessment {
    #[getter]
    fn findings<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let findings = self
            .findings
            .iter()
            .cloned()
            .map(|item| Py::new(py, item))
            .collect::<PyResult<Vec<_>>>()?;
        PyList::new(py, findings)
    }

    #[getter]
    fn eligibility_requirements<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let requirements = self
            .eligibility_requirements
            .iter()
            .cloned()
            .map(|item| Py::new(py, item))
            .collect::<PyResult<Vec<_>>>()?;
        PyList::new(py, requirements)
    }

    fn __repr__(&self) -> String {
        format!(
            "Assessment(input={:?}, verdict='{}', candidate_status='{}')",
            self.input, self.verdict, self.candidate_status
        )
    }
}

impl From<Assessment> for PyAssessment {
    fn from(value: Assessment) -> Self {
        let (root_state_status, root_state, root_state_evidence) =
            claim_parts(value.root_state, root_state);
        let (namespace_state_status, namespace_state, namespace_state_evidence) =
            claim_parts(value.namespace_state, namespace_state);
        let (offering_state_status, offering_state, offering_state_evidence) =
            claim_parts(value.offering_state, offering_state);
        let (public_access_status, public_access, public_access_evidence) =
            claim_parts(value.public_access, public_access);
        let (application_channel_status, application_channel, application_channel_evidence) =
            claim_parts(value.application_channel, application_channel);

        let (
            public_suffix,
            suffix_rule,
            suffix_rule_kind,
            suffix_section,
            suffix_role,
            suffix_evidence,
        ) = value
            .suffix
            .map(|suffix| {
                (
                    Some(suffix.suffix),
                    suffix.matched_rule,
                    Some(suffix_rule_kind(suffix.rule_kind).to_string()),
                    suffix.section.map(|item| psl_section(item).to_string()),
                    suffix.role.map(|item| suffix_role(item).to_string()),
                    suffix.evidence.map(str::to_string),
                )
            })
            .unwrap_or((None, None, None, None, None, None));

        Self {
            input: value.input,
            ascii_domain: value.ascii_domain,
            registrable_domain: value.registrable_domain,
            syntax: syntax_status(value.syntax).to_string(),
            candidate_status: candidate_status(value.candidate_status).to_string(),
            public_suffix,
            suffix_rule,
            suffix_rule_kind,
            suffix_section,
            suffix_role,
            suffix_evidence,
            root_state,
            root_state_status,
            root_state_evidence,
            namespace_state,
            namespace_state_status,
            namespace_state_evidence,
            offering_state,
            offering_state_status,
            offering_state_evidence,
            public_access,
            public_access_status,
            public_access_evidence,
            application_channel,
            application_channel_status,
            application_channel_evidence,
            eligibility: eligibility_status(value.eligibility).to_string(),
            eligibility_requirements: value
                .eligibility_requirements
                .into_iter()
                .map(Into::into)
                .collect(),
            label_policy: label_policy_status(value.label_policy).to_string(),
            product_id: value.product_id.map(str::to_string),
            product_suffix: value.product_suffix,
            verdict: value.verdict.as_str().to_string(),
            findings: value.findings.into_iter().map(Into::into).collect(),
            evidence: value.evidence.into_iter().map(str::to_string).collect(),
        }
    }
}

#[pyclass(name = "SuffixInfo", skip_from_py_object)]
#[derive(Clone)]
pub struct PySuffixInfo {
    #[pyo3(get)]
    pub canonical_suffix: String,
    #[pyo3(get)]
    pub display_suffix: Option<String>,
    #[pyo3(get)]
    pub root: String,
    #[pyo3(get)]
    pub public_suffix: String,
    #[pyo3(get)]
    pub suffix_rule: Option<String>,
    #[pyo3(get)]
    pub suffix_rule_kind: String,
    #[pyo3(get)]
    pub suffix_section: Option<String>,
    #[pyo3(get)]
    pub suffix_role: Option<String>,
    #[pyo3(get)]
    pub suffix_evidence: Option<String>,
    #[pyo3(get)]
    pub root_state: Option<String>,
    #[pyo3(get)]
    pub root_state_status: String,
    #[pyo3(get)]
    pub root_state_evidence: Vec<String>,
    #[pyo3(get)]
    pub namespace_state: Option<String>,
    #[pyo3(get)]
    pub namespace_state_status: String,
    #[pyo3(get)]
    pub namespace_state_evidence: Vec<String>,
    #[pyo3(get)]
    pub product_id: Option<String>,
    #[pyo3(get)]
    pub product_suffix: Option<String>,
    #[pyo3(get)]
    pub offering_state: Option<String>,
    #[pyo3(get)]
    pub offering_state_status: String,
    #[pyo3(get)]
    pub offering_state_evidence: Vec<String>,
    #[pyo3(get)]
    pub public_access: Option<String>,
    #[pyo3(get)]
    pub public_access_status: String,
    #[pyo3(get)]
    pub public_access_evidence: Vec<String>,
    #[pyo3(get)]
    pub designations: Vec<String>,
}

#[pymethods]
impl PySuffixInfo {
    fn __repr__(&self) -> String {
        format!(
            "SuffixInfo(canonical_suffix='{}', product_id={:?})",
            self.canonical_suffix, self.product_id
        )
    }
}

impl From<SuffixInfo> for PySuffixInfo {
    fn from(value: SuffixInfo) -> Self {
        let (root_state_status, root_state, root_state_evidence) =
            claim_parts(value.root_state, root_state);
        let (namespace_state_status, namespace_state, namespace_state_evidence) =
            claim_parts(value.namespace_state, namespace_state);
        let (offering_state_status, offering_state, offering_state_evidence) =
            claim_parts(value.offering_state, offering_state);
        let (public_access_status, public_access, public_access_evidence) =
            claim_parts(value.public_access, public_access);

        Self {
            canonical_suffix: value.canonical_suffix,
            display_suffix: value.display_suffix,
            root: value.root,
            public_suffix: value.topology.suffix,
            suffix_rule: value.topology.matched_rule,
            suffix_rule_kind: suffix_rule_kind(value.topology.rule_kind).to_string(),
            suffix_section: value
                .topology
                .section
                .map(|item| psl_section(item).to_string()),
            suffix_role: value
                .topology
                .role
                .map(|item| suffix_role(item).to_string()),
            suffix_evidence: value.topology.evidence.map(str::to_string),
            root_state,
            root_state_status,
            root_state_evidence,
            namespace_state,
            namespace_state_status,
            namespace_state_evidence,
            product_id: value.product_id.map(str::to_string),
            product_suffix: value.product_suffix,
            offering_state,
            offering_state_status,
            offering_state_evidence,
            public_access,
            public_access_status,
            public_access_evidence,
            designations: value
                .designations
                .iter()
                .copied()
                .map(designation)
                .map(str::to_string)
                .collect(),
        }
    }
}

#[pyclass(name = "Evidence", skip_from_py_object)]
#[derive(Clone)]
pub struct PyEvidence {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub kind: String,
    #[pyo3(get)]
    pub publisher: String,
    #[pyo3(get)]
    pub url: String,
    #[pyo3(get)]
    pub locator: String,
    #[pyo3(get)]
    pub retrieved_at: String,
    #[pyo3(get)]
    pub review_after: Option<String>,
    #[pyo3(get)]
    pub sha256: String,
}

#[pymethods]
impl PyEvidence {
    fn __repr__(&self) -> String {
        format!("Evidence(id='{}', kind='{}')", self.id, self.kind)
    }
}

impl From<&Evidence> for PyEvidence {
    fn from(value: &Evidence) -> Self {
        Self {
            id: value.id.to_string(),
            kind: source_kind(value.kind).to_string(),
            publisher: value.publisher.to_string(),
            url: value.url.to_string(),
            locator: value.locator.to_string(),
            retrieved_at: value.retrieved_at.to_string(),
            review_after: value.review_after.map(str::to_string),
            sha256: value.sha256.to_string(),
        }
    }
}

#[pyclass(name = "Registry")]
pub struct PyRegistry {
    inner: RustRegistry,
}

#[pymethods]
impl PyRegistry {
    #[new]
    fn new() -> Self {
        Self {
            inner: RustRegistry::new(),
        }
    }

    fn assess(&self, domain: &str) -> PyAssessment {
        self.inner.assess(domain).into()
    }

    #[pyo3(signature = (domain, *, satisfied=None, unsatisfied=None))]
    fn assess_for(
        &self,
        domain: &str,
        satisfied: Option<Vec<String>>,
        unsatisfied: Option<Vec<String>>,
    ) -> PyResult<PyAssessment> {
        let context = RegistrantContext {
            satisfied_requirements: satisfied.unwrap_or_default().into_iter().collect(),
            unsatisfied_requirements: unsatisfied.unwrap_or_default().into_iter().collect(),
        };

        let overlap: BTreeSet<_> = context
            .satisfied_requirements
            .intersection(&context.unsatisfied_requirements)
            .cloned()
            .collect();
        if !overlap.is_empty() {
            return Err(PyValueError::new_err(format!(
                "requirement identifiers cannot be both satisfied and unsatisfied: {}",
                overlap.into_iter().collect::<Vec<_>>().join(", ")
            )));
        }

        Ok(self.inner.assess_for(domain, &context).into())
    }

    fn suffix_info(&self, suffix: &str) -> Option<PySuffixInfo> {
        self.inner.suffix_info(suffix).map(Into::into)
    }

    fn evidence(&self, evidence_id: &str) -> Option<PyEvidence> {
        self.inner.evidence(evidence_id).map(Into::into)
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        registry_stats_to_dict(py, self.inner.stats())
    }
}

fn registry_stats_to_dict<'py>(
    py: Python<'py>,
    stats: RegistryStats,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("roots", root_counts_to_dict(py, stats.roots)?)?;
    dict.set_item("topology", topology_counts_to_dict(py, stats.topology)?)?;
    dict.set_item("products", stats.products)?;
    dict.set_item("policy_profiles", stats.policy_profiles)?;
    dict.set_item("selectors", selector_counts_to_dict(py, stats.selectors)?)?;
    dict.set_item(
        "offering_state",
        policy_coverage_to_dict(py, stats.offering_state)?,
    )?;
    dict.set_item(
        "public_access",
        policy_coverage_to_dict(py, stats.public_access)?,
    )?;
    dict.set_item(
        "eligibility",
        policy_coverage_to_dict(py, stats.eligibility)?,
    )?;
    dict.set_item(
        "label_policy",
        policy_coverage_to_dict(py, stats.label_policy)?,
    )?;
    dict.set_item("idn_policy", policy_coverage_to_dict(py, stats.idn_policy)?)?;
    dict.set_item(
        "reserved_labels",
        policy_coverage_to_dict(py, stats.reserved_labels)?,
    )?;
    Ok(dict)
}

fn root_counts_to_dict<'py>(py: Python<'py>, counts: RootCounts) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("current", counts.current)?;
    dict.set_item("special_use", counts.special_use)?;
    dict.set_item("absent", counts.absent)?;
    dict.set_item("unresolved", counts.unresolved)?;
    Ok(dict)
}

fn topology_counts_to_dict<'py>(
    py: Python<'py>,
    counts: TopologyCounts,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("icann", counts.icann)?;
    dict.set_item("private", counts.private)?;
    Ok(dict)
}

fn selector_counts_to_dict<'py>(
    py: Python<'py>,
    counts: SelectorCounts,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("exact", counts.exact)?;
    dict.set_item("one_label_below", counts.one_label_below)?;
    Ok(dict)
}

fn policy_coverage_to_dict<'py>(
    py: Python<'py>,
    coverage: PolicyCoverage,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("by_product", claim_counts_to_dict(py, coverage.by_product)?)?;
    dict.set_item(
        "by_selector",
        claim_counts_to_dict(py, coverage.by_selector)?,
    )?;
    Ok(dict)
}

fn claim_counts_to_dict<'py>(py: Python<'py>, counts: ClaimCounts) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("verified", counts.verified)?;
    dict.set_item("unknown", counts.unknown)?;
    dict.set_item("stale", counts.stale)?;
    dict.set_item("conflicting", counts.conflicting)?;
    Ok(dict)
}

fn claim_parts<T: Copy>(
    claim: Claim<T>,
    render: fn(T) -> &'static str,
) -> (String, Option<String>, Vec<String>) {
    (
        claim_status(claim.status).to_string(),
        claim.value.map(render).map(str::to_string),
        claim
            .evidence
            .iter()
            .map(|item| (*item).to_string())
            .collect(),
    )
}

fn syntax_status(value: SyntaxStatus) -> &'static str {
    match value {
        SyntaxStatus::Valid => "valid",
        SyntaxStatus::Invalid => "invalid",
    }
}

fn candidate_status(value: CandidateStatus) -> &'static str {
    match value {
        CandidateStatus::RegistrableDomain => "registrable_domain",
        CandidateStatus::BareSuffix => "bare_suffix",
        CandidateStatus::Subdomain => "subdomain",
        CandidateStatus::Unresolved => "unresolved",
    }
}

fn claim_status(value: ClaimStatus) -> &'static str {
    match value {
        ClaimStatus::Verified => "verified",
        ClaimStatus::Unknown => "unknown",
        ClaimStatus::Stale => "stale",
        ClaimStatus::Conflicting => "conflicting",
    }
}

fn root_state(value: RootState) -> &'static str {
    match value {
        RootState::Delegated => "delegated",
        RootState::SpecialUse => "special_use",
        RootState::Absent => "absent",
    }
}

fn namespace_state(value: NamespaceState) -> &'static str {
    match value {
        NamespaceState::Ordinary => "ordinary",
        NamespaceState::SpecialUse => "special_use",
    }
}

fn offering_state(value: OfferingState) -> &'static str {
    match value {
        OfferingState::Accepting => "accepting",
        OfferingState::Paused => "paused",
        OfferingState::RenewalOnly => "renewal_only",
        OfferingState::NotLaunched => "not_launched",
        OfferingState::Closed => "closed",
    }
}

fn public_access(value: PublicAccess) -> &'static str {
    match value {
        PublicAccess::Open => "open",
        PublicAccess::Conditional => "conditional",
        PublicAccess::ControlledGroup => "controlled_group",
        PublicAccess::Unavailable => "unavailable",
    }
}

fn application_channel(value: ApplicationChannel) -> &'static str {
    match value {
        ApplicationChannel::Registrar => "registrar",
        ApplicationChannel::RegistryDirect => "registry_direct",
        ApplicationChannel::ApprovalWorkflow => "approval_workflow",
        ApplicationChannel::DelegatedAuthority => "delegated_authority",
        ApplicationChannel::Internal => "internal",
    }
}

fn eligibility_status(value: EligibilityStatus) -> &'static str {
    match value {
        EligibilityStatus::Satisfied => "satisfied",
        EligibilityStatus::Unsatisfied => "unsatisfied",
        EligibilityStatus::Required => "required",
        EligibilityStatus::Unknown => "unknown",
        EligibilityStatus::NotApplicable => "not_applicable",
    }
}

fn eligibility_kind(value: EligibilityKind) -> &'static str {
    match value {
        EligibilityKind::Residence => "residence",
        EligibilityKind::Citizenship => "citizenship",
        EligibilityKind::LegalPresence => "legal_presence",
        EligibilityKind::EntityType => "entity_type",
        EligibilityKind::RegulatedSectorCredential => "regulated_sector_credential",
        EligibilityKind::CommunityMembership => "community_membership",
        EligibilityKind::NamingEntitlement => "naming_entitlement",
        EligibilityKind::IntendedUse => "intended_use",
        EligibilityKind::AuthorityApproval => "authority_approval",
    }
}

fn eligibility_requirement_outcome(value: EligibilityRequirementOutcome) -> &'static str {
    match value {
        EligibilityRequirementOutcome::Satisfied => "satisfied",
        EligibilityRequirementOutcome::Unsatisfied => "unsatisfied",
        EligibilityRequirementOutcome::Unknown => "unknown",
    }
}

fn label_policy_status(value: LabelPolicyStatus) -> &'static str {
    match value {
        LabelPolicyStatus::Pass => "pass",
        LabelPolicyStatus::Fail => "fail",
        LabelPolicyStatus::Partial => "partial",
        LabelPolicyStatus::Unknown => "unknown",
    }
}

fn psl_section(value: PslSection) -> &'static str {
    match value {
        PslSection::Icann => "icann",
        PslSection::Private => "private",
    }
}

fn suffix_rule_kind(value: SuffixRuleKind) -> &'static str {
    match value {
        SuffixRuleKind::Exact => "exact",
        SuffixRuleKind::Wildcard => "wildcard",
        SuffixRuleKind::Exception => "exception",
        SuffixRuleKind::Default => "default",
    }
}

fn suffix_role(value: SuffixRole) -> &'static str {
    match value {
        SuffixRole::RegistryBoundary => "registry_boundary",
        SuffixRole::PrivateServiceBoundary => "private_service_boundary",
    }
}

fn designation(value: Designation) -> &'static str {
    match value {
        Designation::BrandSpec13 => "brand_spec13",
        Designation::CommunitySpec12 => "community_spec12",
        Designation::Geographic => "geographic",
        Designation::SponsoredLegacy => "sponsored_legacy",
        Designation::NonSponsored => "non_sponsored",
        Designation::ExclusiveUse => "exclusive_use",
        Designation::IdnTld => "idn_tld",
    }
}

fn source_kind(value: SourceKind) -> &'static str {
    match value {
        SourceKind::IanaCurrentRoot => "iana_current_root",
        SourceKind::IanaRootDatabase => "iana_root_database",
        SourceKind::PublicSuffixList => "public_suffix_list",
        SourceKind::RegistryAgreement => "registry_agreement",
        SourceKind::RegistryPolicy => "registry_policy",
        SourceKind::GovernmentPolicy => "government_policy",
        SourceKind::SpecialUseRegistry => "special_use_registry",
        SourceKind::StandardsDocument => "standards_document",
        SourceKind::RegistryIdnTable => "registry_idn_table",
        SourceKind::IanaIdnTable => "iana_idn_table",
        SourceKind::Secondary => "secondary",
    }
}

fn finding_code(value: FindingCode) -> &'static str {
    match value {
        FindingCode::InvalidIdna => "invalid_idna",
        FindingCode::InvalidDnsSyntax => "invalid_dns_syntax",
        FindingCode::RootAbsent => "root_absent",
        FindingCode::SpecialUseNamespace => "special_use_namespace",
        FindingCode::BareSuffix => "bare_suffix",
        FindingCode::Subdomain => "subdomain",
        FindingCode::NoRegistrationProduct => "no_registration_product",
        FindingCode::OfferingNotAccepting => "offering_not_accepting",
        FindingCode::PublicAccessUnavailable => "public_access_unavailable",
        FindingCode::EligibilityRequired => "eligibility_required",
        FindingCode::EligibilityFailed => "eligibility_failed",
        FindingCode::EligibilityUnknown => "eligibility_unknown",
        FindingCode::UnknownEligibilityRequirement => "unknown_eligibility_requirement",
        FindingCode::LabelPolicyFailed => "label_policy_failed",
        FindingCode::LabelPolicyIncomplete => "label_policy_incomplete",
        FindingCode::ClaimUnknown => "claim_unknown",
        FindingCode::ClaimStale => "claim_stale",
        FindingCode::ClaimConflicting => "claim_conflicting",
    }
}

#[pymodule]
pub fn _native(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyRegistry>()?;
    module.add_class::<PyAssessment>()?;
    module.add_class::<PyFinding>()?;
    module.add_class::<PyEligibilityRequirement>()?;
    module.add_class::<PySuffixInfo>()?;
    module.add_class::<PyEvidence>()?;
    Ok(())
}
