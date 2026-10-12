"""Type stubs for the native tldhax extension module."""

from typing import Any, Literal

class Assessment:
    name_validity: Literal["valid", "invalid", "unknown"]
    status: Literal["yes", "no", "restricted", "unknown"]
    policy_coverage: Literal["complete", "partial", "unknown", "conflicting"]
    eligibility: Literal[
        "not_required",
        "declared_match",
        "does_not_match",
        "needs_profile",
        "unknown_policy",
    ]
    canonical_ascii: str | None
    canonical_unicode: str | None
    namespace: str | None
    root_known: bool
    detailed: bool
    diagnostics_truncated: bool
    dataset_version: str
    evaluation_date: str
    inventory_date: str
    normalization_profile: str
    def to_dict(self) -> dict[str, Any]: ...

class PreparedRegistrant:
    """Opaque validated facts, created through Registry.prepare_registrant."""

class NamespaceInfo:
    namespace: str
    policy_selector: str | None
    dataset_version: str
    evaluation_date: str
    inventory_date: str
    normalization_profile: str
    def to_dict(self) -> dict[str, Any]: ...

class CheckResult:
    status: Literal["yes", "no", "restricted", "unknown"]
    reasons: list[str]

class TldInfo:
    tld: str
    registerable: Literal["yes", "no", "restricted"]
    reason: str | None
    note: str | None
    restrictions: list[str]
    min_length: int
    max_length: int
    length_basis: Literal["ascii", "unicode"]
    banned: list[str]
    charset: Literal["ascii", "idn"]
    idn_chars: str
    sources: dict[str, str]

class Registry:
    def __init__(self) -> None: ...
    def check(self, domain: str) -> CheckResult: ...
    def prepare_registrant(self, profile_json: str) -> PreparedRegistrant: ...
    def assess(
        self,
        domain: str,
        registrant: PreparedRegistrant | None = ...,
        *,
        detailed: bool = ...,
        include_private: bool = ...,
    ) -> Assessment: ...
    def assess_many(
        self,
        domains: list[str],
        registrant: PreparedRegistrant | None = ...,
        *,
        detailed: bool = ...,
        include_private: bool = ...,
    ) -> list[Assessment]: ...
    def namespace_info(self, namespace: str) -> NamespaceInfo | None: ...
    def dataset_info(self) -> dict[str, Any]: ...
    def dataset_stats(self) -> dict[str, Any]: ...
    def profile_schema(self) -> dict[str, dict[str, Any]]: ...
    def source(self, id: str) -> dict[str, Any] | None: ...
    def assertion(self, id: str) -> dict[str, Any] | None: ...
    def tld_info(self, tld: str) -> TldInfo | None: ...
    def rule_count(self) -> int: ...
    def stats(self) -> dict[str, int | float]: ...
