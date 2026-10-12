"""Explicit provider budgets and separate observation/research/error output."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .limits import Window
from .models import Candidate, Observation
from .providers import Provider


@dataclass(frozen=True)
class ProviderConfig:
    """Provider coverage, explicit shared quota, health and run budgets."""

    provider: Provider
    windows: tuple[Window, ...] = (Window(1, 1), Window(30, 60))
    quota_group: str = ""
    concurrency: int = 1
    weight: float = 1
    max_candidates: int = 30
    retries: int = 2
    namespaces: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        """Reject invalid budgets before any network request."""
        if (
            any(
                type(value) is not int
                for value in (self.concurrency, self.max_candidates, self.retries)
            )
            or self.concurrency <= 0
            or not math.isfinite(self.weight)
            or self.weight <= 0
            or self.max_candidates <= 0
            or self.retries < 0
        ):
            raise ValueError(
                "invalid provider concurrency, weight, candidate budget or retries"
            )

    def supports(self, candidate: Candidate) -> bool:
        """Match configured supported suffixes without rejecting invalid probes locally."""
        name = candidate.canonical or candidate.name
        return self.namespaces is None or any(
            name.endswith("." + suffix) for suffix in self.namespaces
        )


@dataclass
class RunResult:
    """Observations and research findings, with tool failures kept separate."""

    observations: list[Observation] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    tool_errors: list[dict] = field(default_factory=list)
    cross_check: str = "unavailable"
    reused: int = 0
