"""Command-line interface for evidence-aware registration assessments."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from typing import Any

from . import Assessment, Evidence, Registry, SuffixInfo

VERDICT_EXIT_CODES = {
    "plausible": 0,
    "impossible": 1,
    "indeterminate": 2,
    "conditional": 3,
}


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser for the CLI."""
    parser = argparse.ArgumentParser(prog="tldhax")
    subparsers = parser.add_subparsers(dest="command", required=True)

    assess_parser = subparsers.add_parser(
        "assess", help="assess a proposed registration"
    )
    assess_parser.add_argument("domain")
    assess_parser.add_argument(
        "--satisfied",
        action="append",
        default=[],
        metavar="REQUIREMENT_ID",
        help="mark an eligibility requirement as satisfied (repeatable)",
    )
    assess_parser.add_argument(
        "--unsatisfied",
        action="append",
        default=[],
        metavar="REQUIREMENT_ID",
        help="mark an eligibility requirement as unsatisfied (repeatable)",
    )
    assess_parser.add_argument("--json", action="store_true", dest="as_json")
    assess_parser.add_argument("--quiet", action="store_true")

    suffix_parser = subparsers.add_parser(
        "suffix-info", help="show namespace topology and assigned product"
    )
    suffix_parser.add_argument("suffix")
    suffix_parser.add_argument("--json", action="store_true", dest="as_json")

    evidence_parser = subparsers.add_parser("evidence", help="show one evidence record")
    evidence_parser.add_argument("evidence_id")
    evidence_parser.add_argument("--json", action="store_true", dest="as_json")

    stats_parser = subparsers.add_parser(
        "stats", help="show coverage by independently researched dimension"
    )
    stats_parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def assessment_payload(assessment: Assessment) -> dict[str, Any]:
    """Convert an assessment to its stable JSON representation."""
    return {
        "input": assessment.input,
        "ascii_domain": assessment.ascii_domain,
        "registrable_domain": assessment.registrable_domain,
        "syntax": assessment.syntax,
        "candidate_status": assessment.candidate_status,
        "public_suffix": assessment.public_suffix,
        "suffix_rule": assessment.suffix_rule,
        "suffix_rule_kind": assessment.suffix_rule_kind,
        "suffix_section": assessment.suffix_section,
        "suffix_role": assessment.suffix_role,
        "suffix_evidence": assessment.suffix_evidence,
        "root_state": assessment.root_state,
        "root_state_status": assessment.root_state_status,
        "root_state_evidence": assessment.root_state_evidence,
        "namespace_state": assessment.namespace_state,
        "namespace_state_status": assessment.namespace_state_status,
        "namespace_state_evidence": assessment.namespace_state_evidence,
        "offering_state": assessment.offering_state,
        "offering_state_status": assessment.offering_state_status,
        "offering_state_evidence": assessment.offering_state_evidence,
        "public_access": assessment.public_access,
        "public_access_status": assessment.public_access_status,
        "public_access_evidence": assessment.public_access_evidence,
        "application_channel": assessment.application_channel,
        "application_channel_status": assessment.application_channel_status,
        "application_channel_evidence": assessment.application_channel_evidence,
        "eligibility": assessment.eligibility,
        "eligibility_requirements": [
            {
                "id": requirement.id,
                "kind": requirement.kind,
                "value": requirement.value,
                "explanation": requirement.explanation,
                "evidence": requirement.evidence,
                "outcome": requirement.outcome,
            }
            for requirement in assessment.eligibility_requirements
        ],
        "label_policy": assessment.label_policy,
        "product_id": assessment.product_id,
        "product_suffix": assessment.product_suffix,
        "verdict": assessment.verdict,
        "findings": [
            {"code": finding.code, "message": finding.message}
            for finding in assessment.findings
        ],
        "evidence": assessment.evidence,
    }


def suffix_info_payload(info: SuffixInfo) -> dict[str, Any]:
    """Convert suffix metadata to its stable JSON representation."""
    return {
        "canonical_suffix": info.canonical_suffix,
        "display_suffix": info.display_suffix,
        "root": info.root,
        "public_suffix": info.public_suffix,
        "suffix_rule": info.suffix_rule,
        "suffix_rule_kind": info.suffix_rule_kind,
        "suffix_section": info.suffix_section,
        "suffix_role": info.suffix_role,
        "suffix_evidence": info.suffix_evidence,
        "root_state": info.root_state,
        "root_state_status": info.root_state_status,
        "root_state_evidence": info.root_state_evidence,
        "namespace_state": info.namespace_state,
        "namespace_state_status": info.namespace_state_status,
        "namespace_state_evidence": info.namespace_state_evidence,
        "product_id": info.product_id,
        "product_suffix": info.product_suffix,
        "offering_state": info.offering_state,
        "offering_state_status": info.offering_state_status,
        "offering_state_evidence": info.offering_state_evidence,
        "public_access": info.public_access,
        "public_access_status": info.public_access_status,
        "public_access_evidence": info.public_access_evidence,
        "designations": info.designations,
    }


def evidence_payload(evidence: Evidence) -> dict[str, str | None]:
    """Convert an evidence record to its stable JSON representation."""
    return {
        "id": evidence.id,
        "kind": evidence.kind,
        "publisher": evidence.publisher,
        "url": evidence.url,
        "locator": evidence.locator,
        "retrieved_at": evidence.retrieved_at,
        "review_after": evidence.review_after,
        "sha256": evidence.sha256,
    }


def error_payload(code: str, message: str, **details: str) -> dict[str, Any]:
    """Return the stable JSON representation of a command failure."""
    return {"error": {"code": code, "message": message, **details}}


def _render_claim(
    label: str, value: str | None, status: str, evidence: list[str]
) -> str:
    rendered = value if value is not None else "unknown"
    sources = ", ".join(evidence) if evidence else "none"
    return f"{label}: {rendered} ({status}; evidence: {sources})"


def _print_assessment(assessment: Assessment) -> None:
    print(f"{assessment.input}: {assessment.verdict.upper()}")
    print(f"Syntax: {assessment.syntax}")
    print(f"Candidate: {assessment.candidate_status}")
    print(f"ASCII domain: {assessment.ascii_domain or '(none)'}")
    print(f"Registrable domain: {assessment.registrable_domain or '(none)'}")
    print(f"Public suffix: {assessment.public_suffix or '(unresolved)'}")
    if assessment.suffix_rule_kind is not None:
        print(
            "Suffix rule: "
            f"{assessment.suffix_rule or '(implicit)'} "
            f"({assessment.suffix_rule_kind}, "
            f"{assessment.suffix_section or 'no section'}, "
            f"{assessment.suffix_role or 'no role'})"
        )
        print(f"Suffix evidence: {assessment.suffix_evidence or '(none)'}")
    product = assessment.product_id or "(none)"
    if assessment.product_suffix is not None:
        product = f"{product} at {assessment.product_suffix}"
    print(f"Product: {product}")
    print(
        _render_claim(
            "Root state",
            assessment.root_state,
            assessment.root_state_status,
            assessment.root_state_evidence,
        )
    )
    print(
        _render_claim(
            "Namespace state",
            assessment.namespace_state,
            assessment.namespace_state_status,
            assessment.namespace_state_evidence,
        )
    )
    print(
        _render_claim(
            "Offering state",
            assessment.offering_state,
            assessment.offering_state_status,
            assessment.offering_state_evidence,
        )
    )
    print(
        _render_claim(
            "Public access",
            assessment.public_access,
            assessment.public_access_status,
            assessment.public_access_evidence,
        )
    )
    print(
        _render_claim(
            "Application channel",
            assessment.application_channel,
            assessment.application_channel_status,
            assessment.application_channel_evidence,
        )
    )
    print(f"Eligibility: {assessment.eligibility}")
    if assessment.eligibility_requirements:
        print("Eligibility requirements:")
        for requirement in assessment.eligibility_requirements:
            print(
                f"  {requirement.id}: {requirement.outcome} "
                f"({requirement.kind}={requirement.value})"
            )
            print(f"    {requirement.explanation}")
            if requirement.evidence:
                print(f"    Evidence: {', '.join(requirement.evidence)}")
    print(f"Label policy: {assessment.label_policy}")
    if assessment.findings:
        print("Findings:")
        for finding in assessment.findings:
            print(f"  {finding.code}: {finding.message}")
    print(
        "Evidence: "
        + (", ".join(assessment.evidence) if assessment.evidence else "(none)")
    )


def _print_suffix_info(info: SuffixInfo) -> None:
    print(f"Suffix: {info.canonical_suffix}")
    if info.display_suffix is not None:
        print(f"Display suffix: {info.display_suffix}")
    print(f"Root: {info.root}")
    print(f"Public suffix: {info.public_suffix}")
    print(
        f"Suffix rule: {info.suffix_rule or '(implicit)'} "
        f"({info.suffix_rule_kind}, {info.suffix_section or 'no section'}, "
        f"{info.suffix_role or 'no role'})"
    )
    print(f"Suffix evidence: {info.suffix_evidence or '(none)'}")
    product = info.product_id or "(none)"
    if info.product_suffix is not None:
        product = f"{product} at {info.product_suffix}"
    print(f"Product: {product}")
    print(
        _render_claim(
            "Root state",
            info.root_state,
            info.root_state_status,
            info.root_state_evidence,
        )
    )
    print(
        _render_claim(
            "Namespace state",
            info.namespace_state,
            info.namespace_state_status,
            info.namespace_state_evidence,
        )
    )
    print(
        _render_claim(
            "Offering state",
            info.offering_state,
            info.offering_state_status,
            info.offering_state_evidence,
        )
    )
    print(
        _render_claim(
            "Public access",
            info.public_access,
            info.public_access_status,
            info.public_access_evidence,
        )
    )
    print(
        "Designations: "
        + (", ".join(info.designations) if info.designations else "(none)")
    )


def _print_evidence(evidence: Evidence) -> None:
    print(f"Evidence: {evidence.id}")
    print(f"Kind: {evidence.kind}")
    print(f"Publisher: {evidence.publisher}")
    print(f"URL: {evidence.url}")
    print(f"Locator: {evidence.locator}")
    print(f"Retrieved: {evidence.retrieved_at}")
    print(f"Review after: {evidence.review_after or '(none)'}")
    print(f"SHA-256: {evidence.sha256}")


def _print_stats(stats: Mapping[str, Any]) -> None:
    roots = stats["roots"]
    topology = stats["topology"]
    selectors = stats["selectors"]
    print(
        "Root records: "
        f"{roots['current']} current, {roots['special_use']} special-use, "
        f"{roots['absent']} absent, {roots['unresolved']} unresolved"
    )
    print(f"Suffix topology: {topology['icann']} ICANN, {topology['private']} PRIVATE")
    print(f"Registration products: {stats['products']:,}")
    print(f"Policy profiles: {stats['policy_profiles']:,}")
    print(
        f"Product selectors: {selectors['exact']} exact, "
        f"{selectors['one_label_below']} one-label-below"
    )
    for dimension in (
        "offering_state",
        "public_access",
        "eligibility",
        "label_policy",
        "idn_policy",
        "reserved_labels",
    ):
        coverage = stats[dimension]
        product = coverage["by_product"]
        selector = coverage["by_selector"]
        label = dimension.replace("_", " ").title()
        print(
            f"{label} by product: {product['verified']} verified, "
            f"{product['unknown']} unknown, {product['stale']} stale, "
            f"{product['conflicting']} conflicting"
        )
        print(
            f"{label} by selector: {selector['verified']} verified, "
            f"{selector['unknown']} unknown, {selector['stale']} stale, "
            f"{selector['conflicting']} conflicting"
        )


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    registry = Registry()

    if args.command == "assess":
        overlap = sorted(set(args.satisfied) & set(args.unsatisfied))
        if overlap:
            parser.error(
                "requirement identifiers cannot be both satisfied and unsatisfied: "
                + ", ".join(overlap)
            )
        if args.satisfied or args.unsatisfied:
            assessment = registry.assess_for(
                args.domain,
                satisfied=args.satisfied,
                unsatisfied=args.unsatisfied,
            )
        else:
            assessment = registry.assess(args.domain)
        if args.as_json:
            print(json.dumps(assessment_payload(assessment), indent=2, sort_keys=True))
        elif args.quiet:
            print(assessment.verdict.upper())
        else:
            _print_assessment(assessment)
        return VERDICT_EXIT_CODES[assessment.verdict]

    if args.command == "suffix-info":
        info = registry.suffix_info(args.suffix)
        if info is None:
            message = f"No namespace data available for suffix '{args.suffix}'"
            if args.as_json:
                print(
                    json.dumps(
                        error_payload("suffix_not_found", message, suffix=args.suffix),
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(message, file=sys.stderr)
            return 2
        if args.as_json:
            print(json.dumps(suffix_info_payload(info), indent=2, sort_keys=True))
        else:
            _print_suffix_info(info)
        return 0

    if args.command == "evidence":
        evidence = registry.evidence(args.evidence_id)
        if evidence is None:
            message = f"No evidence record with id '{args.evidence_id}'"
            if args.as_json:
                print(
                    json.dumps(
                        error_payload(
                            "evidence_not_found",
                            message,
                            evidence_id=args.evidence_id,
                        ),
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(message, file=sys.stderr)
            return 2
        if args.as_json:
            print(json.dumps(evidence_payload(evidence), indent=2, sort_keys=True))
        else:
            _print_evidence(evidence)
        return 0

    stats = registry.stats()
    if args.as_json:
        print(json.dumps(stats, indent=2, sort_keys=True))
    else:
        _print_stats(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
