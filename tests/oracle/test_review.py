"""Provider signals flag scoped research without rewriting static policies."""

from dataclasses import replace

from tools.oracle.models import Candidate, Observation
from tools.oracle.review import review_findings


def observed(signal, provider="example"):
    """Construct an observation independently of transport and scheduling."""
    return Observation(
        "a.com",
        "a.com",
        "a.com",
        provider,
        "v1",
        "production",
        "fixture",
        "v1",
        validity_signal=signal,
        native_reason="native reason",
    )


def test_inconclusive_availability_never_creates_policy_claim():
    """Taken and premium native details do not establish invalidity."""
    candidate = Candidate("a.com", offline_validity="invalid", evidence_ids=("rule",))
    item = replace(observed("inconclusive"), response={"premium": True, "taken": True})
    assert review_findings(candidate, [item]) == []


def test_acceptance_contradiction_requires_an_evidenced_static_denial():
    """A supported denial produces a review item, never an automatic override."""
    item = observed("accepted")
    assert review_findings(Candidate("a.com", offline_validity="invalid"), [item]) == []
    candidate = Candidate("a.com", offline_validity="invalid", evidence_ids=("rule",))
    findings = review_findings(candidate, [item])
    assert findings[0]["code"] == "acceptance_contradicts_evidenced_rule"
    assert findings[0]["evidence_ids"] == ("rule",)
    assert candidate.offline_validity == "invalid"


def test_explicit_native_reason_and_provider_disagreement_retain_context():
    """Both observed signals remain reviewable with their provider provenance."""
    candidate = Candidate("a.com", offline_validity="valid")
    findings = review_findings(
        candidate, [observed("explicitly_invalid"), observed("accepted", "other")]
    )
    assert {item["code"] for item in findings} == {
        "provider_policy_reason",
        "provider_disagreement",
    }
    reason = findings[0]
    assert (reason["api_version"], reason["environment"], reason["native_reason"]) == (
        "v1",
        "production",
        "native reason",
    )
