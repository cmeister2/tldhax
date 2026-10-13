"""Type stubs for the small native decision interface."""

from typing import Any, Literal

class Reason:
    code: str
    message: str

class Assessment:
    decision: Literal["yes", "no", "unknown"]
    status: Literal["yes", "no", "unknown"]
    canonical_domain: str | None
    namespace: str | None
    reasons: list[Reason]
    missing_profile_fields: list[str]
    def to_dict(self) -> dict[str, Any]: ...

class PreparedRegistrant:
    """Opaque validated facts, created through Registry.prepare_registrant."""

class CheckResult:
    status: Literal["yes", "no", "unknown"]
    reasons: list[str]

class TldInfo:
    """Faithful namespace metadata; unknown scalar requirements remain None."""

    tld: str
    registerable: Literal["yes", "no", "restricted", "unknown"]
    reason: str | None
    note: str | None
    restrictions: list[str]
    min_length: int | None
    max_length: int | None
    length_basis: Literal["ascii", "unicode"] | None
    banned: list[str]
    charset: Literal["ascii", "idn"] | None
    idn_chars: str | None
    sources: dict[str, str]

class Registry:
    def __init__(self) -> None: ...
    def check(self, domain: str) -> CheckResult: ...
    def tld_info(self, tld: str) -> TldInfo | None: ...
    def rule_count(self) -> int: ...
    def stats(self) -> dict[str, int | float]: ...
    def prepare_registrant(self, profile_json: str) -> PreparedRegistrant: ...
    def assess(
        self, domain: str, registrant: PreparedRegistrant | None = ...
    ) -> Assessment: ...
    def assess_many(
        self, domains: list[str], registrant: PreparedRegistrant | None = ...
    ) -> list[Assessment]: ...
    def dataset_version(self) -> str: ...
    def supported_namespaces(self) -> list[str]: ...
    def profile_schema(self) -> dict[str, dict[str, Any]]: ...
