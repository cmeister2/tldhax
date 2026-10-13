"""Oracle identity and observations, separate from the offline library."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

import idna

Signal = Literal[
    "accepted", "explicitly_invalid", "explicitly_restricted", "inconclusive"
]


def canonical_name(name: str) -> str | None:
    """Strict UTS46 nontransitional/STD3 identity; one root dot is equivalent.

    Invalid negative probes retain their exact raw identity. In particular this
    function never drops underscores, whitespace, empty labels, or punctuation.
    """
    try:
        if not name or len(name.encode("utf-8")) > 4096:
            return None
        return (
            idna.encode(name, uts46=True, std3_rules=True)
            .decode("ascii")
            .removesuffix(".")
        )
    except (idna.IDNAError, UnicodeError):
        return None


def identity(name: str) -> str:
    """Return canonical DNS identity, or exact raw identity for an invalid probe."""
    canonical = canonical_name(name)
    return f"dns:{canonical}" if canonical is not None else f"raw:{name}"


@dataclass(frozen=True)
class Candidate:
    """A named probe and optional published policy comparison context."""

    name: str
    namespace: str = ""
    stratum: str = ""
    offline_validity: str = "unknown"
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate all metadata before any candidate is assigned or transmitted."""
        if (
            not isinstance(self.name, str)
            or not self.name
            or len(self.name.encode("utf-8")) > 4096
        ):
            raise ValueError("candidate names require 1 to 4096 UTF-8 bytes")
        if not isinstance(self.namespace, str) or not isinstance(self.stratum, str):
            raise ValueError("namespace and stratum must be strings")
        if self.offline_validity not in ("valid", "invalid", "conditional", "unknown"):
            raise ValueError("unsupported offline_validity")
        if not isinstance(self.evidence_ids, (list, tuple)) or any(
            not isinstance(value, str) or not value for value in self.evidence_ids
        ):
            raise ValueError("evidence_ids must be a sequence of nonempty strings")
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))

    @property
    def canonical(self) -> str | None:
        """Return strict canonical form when the raw candidate has one."""
        return canonical_name(self.name)

    @property
    def key(self) -> str:
        """Return the candidate identity used for deduplication."""
        return identity(self.name)

    @property
    def group(self) -> str:
        """Return the configured cross-check stratum or namespace."""
        return self.stratum or self.namespace or self.name.rsplit(".", 1)[-1]


@dataclass(frozen=True)
class Observation:
    """Sanitised native response and a separately interpreted validity signal."""

    requested_name: str
    canonical_name: str | None
    returned_name: str | None
    provider: str
    api_version: str
    environment: str
    observed_at: str
    dataset_version: str
    validity_signal: Signal = "inconclusive"
    native_status: str | None = None
    native_reason: str | None = None
    response: dict[str, Any] = field(default_factory=dict)
    findings: tuple[str, ...] = ()
    transient: bool = False
    support: str = "unknown"
    source: str = "unspecified"
    query_context: str = "prospective-name/registration"

    def to_dict(self) -> dict[str, Any]:
        """Convert the observation to JSON-compatible fields."""
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Observation:
        """Restore a persisted observation without changing its native meaning."""
        value = dict(value)
        value["findings"] = tuple(value.get("findings", ()))
        return cls(**value)


def timestamp(seconds: float) -> str:
    """Format an observation time in UTC."""
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


class Redactor:
    """Remove known credential values and the encoded Basic auth value."""

    def __init__(
        self, secrets: tuple[str, ...] = (), basic: tuple[str, str] | None = None
    ):
        """Initialize explicit dependencies and configuration."""
        values = list(secrets)
        if basic:
            values.append(base64.b64encode(":".join(basic).encode()).decode())
        self.secrets = tuple(
            sorted({value for value in values if value}, key=len, reverse=True)
        )

    def clean(self, value: Any) -> Any:
        """Recursively redact native strings before persistence or output."""
        if isinstance(value, str):
            for secret in self.secrets:
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, dict):
            return {key: self.clean(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.clean(item) for item in value]
        return value
