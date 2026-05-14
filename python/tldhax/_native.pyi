"""Type stubs for the native tldhax extension module."""

from typing import Literal

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
    def tld_info(self, tld: str) -> TldInfo | None: ...
    def rule_count(self) -> int: ...
    def stats(self) -> dict[str, int | float]: ...
