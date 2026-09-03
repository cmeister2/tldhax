"""Example-based tests for multidimensional registration assessments."""

from __future__ import annotations

import pytest


def test_legacy_boolean_api_is_removed(registry) -> None:
    """The pre-0.1 API cannot conceal uncertainty behind yes/no labels."""
    assert not hasattr(registry, "check")
    assert not hasattr(registry, "tld_info")


def test_infrastructure_names_are_impossible(registry) -> None:
    """Namespace/access evidence can decide without inventing offering state."""
    result = registry.assess("example.arpa")

    assert result.verdict == "impossible"
    assert result.product_id == "arpa-infrastructure"
    assert result.offering_state is None
    assert result.offering_state_status == "unknown"
    assert result.public_access == "unavailable"
    assert result.public_access_status == "verified"
    assert result.evidence


def test_special_use_is_a_namespace_fact_not_a_product_policy(registry) -> None:
    """Special-use evidence decides the namespace axis without fabricating policy."""
    result = registry.assess("example.com")

    assert result.verdict == "impossible"
    assert result.root_state == "delegated"
    assert result.namespace_state == "special_use"
    assert result.namespace_state_status == "verified"
    assert result.product_id is None
    assert result.product_suffix is None
    assert result.offering_state is None
    assert result.offering_state_status == "unknown"
    assert result.public_access is None
    assert result.public_access_status == "unknown"


def test_de_is_open_without_an_invented_residency_requirement(registry) -> None:
    """DENIC's researched access policy is represented independently."""
    result = registry.assess("example.de")

    assert result.product_id == "de-direct"
    assert result.offering_state == "accepting"
    assert result.offering_state_status == "verified"
    assert result.public_access == "open"
    assert result.public_access_status == "verified"
    assert result.eligibility == "not_applicable"
    assert result.verdict == "indeterminate"


def test_claim_evidence_remains_attributed_to_each_assessment_axis(registry) -> None:
    """Flattened Python claims retain the evidence links available in Rust."""
    result = registry.assess("example.de")

    assert result.root_state_evidence
    assert result.namespace_state_evidence
    assert result.offering_state_evidence == ["denic-public-applicants"]
    assert result.public_access_evidence == ["denic-public-applicants"]
    assert result.application_channel_evidence == []

    attributed = (
        result.root_state_evidence
        + result.namespace_state_evidence
        + result.offering_state_evidence
        + result.public_access_evidence
        + result.application_channel_evidence
    )
    assert set(attributed) <= set(result.evidence)
    assert all(registry.evidence(evidence_id) is not None for evidence_id in attributed)


@pytest.mark.parametrize(
    ("domain", "product_id", "requirement_id"),
    [
        ("example.bank", "bank-regulated", "bank-regulated-entity"),
        ("example.gov.uk", "govuk-public-sector", "govuk-public-sector"),
    ],
)
def test_conditional_products_expose_eligibility(
    registry, domain: str, product_id: str, requirement_id: str
) -> None:
    """Eligibility is explicit and can be evaluated with caller-supplied facts."""
    without_context = registry.assess(domain)
    assert without_context.product_id == product_id
    assert without_context.public_access == "conditional"
    assert without_context.public_access_status == "verified"
    assert without_context.eligibility == "required"
    assert without_context.product_suffix is not None
    assert without_context.eligibility_requirements
    assert {item.outcome for item in without_context.eligibility_requirements} == {
        "unknown"
    }

    with_context = registry.assess_for(domain, satisfied=[requirement_id])
    assert with_context.product_id == product_id
    assert with_context.eligibility in {"satisfied", "unknown"}
    outcomes = {item.id: item.outcome for item in with_context.eligibility_requirements}
    assert outcomes[requirement_id] == "satisfied"


def test_edu_policy_stays_unknown_without_reproducible_source_capture(registry) -> None:
    """A discoverable product does not acquire policy claims from proxy content."""
    result = registry.assess("example.edu")

    assert result.product_id == "edu-institutions"
    assert result.offering_state is None
    assert result.public_access is None
    assert result.eligibility == "unknown"
    assert result.eligibility_requirements == []
    assert result.verdict == "indeterminate"


def test_requirements_expose_metadata_and_per_requirement_outcomes(registry) -> None:
    """Callers can discover IDs before supplying facts and inspect each outcome."""
    initial = registry.assess("service.gov.uk")
    requirements = {item.id: item for item in initial.eligibility_requirements}

    assert set(requirements) == {"govuk-public-sector", "govuk-name-approval"}
    public_sector = requirements["govuk-public-sector"]
    assert public_sector.kind == "entity_type"
    assert public_sector.value
    assert public_sector.explanation
    assert public_sector.evidence == ["govuk-eligible-public-sector"]
    assert public_sector.outcome == "unknown"

    assessed = registry.assess_for(
        "service.gov.uk",
        satisfied=["govuk-public-sector"],
        unsatisfied=["govuk-name-approval"],
    )
    outcomes = {item.id: item.outcome for item in assessed.eligibility_requirements}
    assert outcomes == {
        "govuk-public-sector": "satisfied",
        "govuk-name-approval": "unsatisfied",
    }


def test_empty_context_has_the_same_missing_context_semantics(registry) -> None:
    """An explicitly empty fact set still means eligibility is required."""
    direct = registry.assess("candidate.bank")
    empty = registry.assess_for("candidate.bank", satisfied=[], unsatisfied=[])

    assert direct.eligibility == "required"
    assert empty.eligibility == direct.eligibility
    assert [item.outcome for item in empty.eligibility_requirements] == ["unknown"]


def test_assess_for_rejects_contradictory_context(registry) -> None:
    """A requirement cannot be asserted both true and false."""
    with pytest.raises(ValueError, match="both satisfied and unsatisfied"):
        registry.assess_for(
            "example.bank",
            satisfied=["bank-regulated-entity"],
            unsatisfied=["bank-regulated-entity"],
        )


def test_unknown_context_id_is_reported_without_activating_evaluation(registry) -> None:
    """A typo is visible and does not turn missing context into partial context."""
    result = registry.assess_for("candidate.bank", satisfied=["definitely-a-typo"])

    assert result.eligibility == "required"
    assert [item.outcome for item in result.eligibility_requirements] == ["unknown"]
    assert any(
        item.code == "unknown_eligibility_requirement" for item in result.findings
    )


def test_delegation_and_psl_membership_do_not_imply_access(registry) -> None:
    """Unresearched policy remains indeterminate rather than default-open."""
    result = registry.assess("ordinary-candidate.com")

    assert result.root_state == "delegated"
    assert result.root_state_status == "verified"
    assert result.product_id is None
    assert result.public_access is None
    assert result.public_access_status == "unknown"
    assert result.verdict == "indeterminate"
    assert any(item.code == "no_registration_product" for item in result.findings)


def test_invalid_idna_is_impossible(registry) -> None:
    """Protocol failures are hard failures and do not require policy data."""
    result = registry.assess("bad domain.com")

    assert result.syntax == "invalid"
    assert result.verdict == "impossible"
    assert result.ascii_domain is None
    assert result.findings[0].code in {"invalid_idna", "invalid_dns_syntax"}
