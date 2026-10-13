"""Coverage-aware batching, bounded retries, fallback and stratified corroboration."""

from __future__ import annotations

import asyncio
import hashlib
import math
from collections import defaultdict
from collections.abc import Coroutine
from typing import Any

from .checks import check_batch
from .dispatch_config import ProviderConfig, RunResult
from .limits import Clock, Quota
from .models import Candidate, Observation
from .review import review_findings
from .store import Store, observation_key


class Runner:
    """Dispatch probes within quotas and retain disagreements as review findings."""

    def __init__(
        self,
        configs: list[ProviderConfig],
        store: Store,
        dataset_version: str,
        clock: Clock | None = None,
        refresh: bool = False,
        max_age: float = 86400,
        cross_check_rate: float = 0.1,
    ):
        """Initialize explicit dependencies and configuration."""
        if (
            not configs
            or not 0 <= cross_check_rate <= 1
            or not math.isfinite(max_age)
            or max_age < 0
        ):
            raise ValueError(
                "providers, nonnegative cache age and cross-check rate in [0,1] required"
            )
        if len({c.provider.name for c in configs}) != len(configs):
            raise ValueError(
                "one adapter per provider; tokens share source-IP/account quota"
            )
        self.configs, self.store, self.dataset = configs, store, dataset_version
        self.clock, self.refresh, self.max_age = clock or Clock(), refresh, max_age
        self.cross_rate = cross_check_rate
        self.sent: dict[str, set[str]] = defaultdict(set)
        self.paused: set[str] = set()
        self.result = RunResult()
        self.quotas: dict[str, Quota] = {}
        self.semaphores = {
            c.provider.name: asyncio.Semaphore(c.concurrency) for c in configs
        }
        for config in configs:
            group = config.quota_group or config.provider.name
            if group in self.quotas:
                existing = self.quotas[group]
                existing.windows = tuple(set(existing.windows + config.windows))
            else:
                self.quotas[group] = Quota(
                    config.windows, self.clock, self.store, group
                )

    def _cached(
        self, candidate: Candidate, config: ProviderConfig
    ) -> Observation | None:
        if self.refresh:
            return None
        return self.store.cached(
            observation_key(candidate, config.provider),
            candidate,
            self.dataset,
            self.clock.time(),
            self.max_age,
        )

    def _select(
        self, candidate: Candidate, excluded: set[str]
    ) -> ProviderConfig | None:
        eligible = [
            c
            for c in self.configs
            if c.provider.name not in excluded | self.paused
            and c.supports(candidate)
            and (
                candidate.key in self.sent[c.provider.name]
                or len(self.sent[c.provider.name]) < c.max_candidates
            )
        ]
        if not eligible:
            return None
        return min(
            eligible,
            key=lambda c: (
                self.quotas[c.quota_group or c.provider.name].cooldown
                > self.clock.monotonic(),
                len(self.sent[c.provider.name]) / c.weight,
                c.provider.name,
            ),
        )

    async def _batch(
        self, config: ProviderConfig, candidates: list[Candidate]
    ) -> list[Observation]:
        return await check_batch(
            config,
            candidates,
            store=self.store,
            dataset=self.dataset,
            clock=self.clock,
            quota=self.quotas[config.quota_group or config.provider.name],
            semaphore=self.semaphores[config.provider.name],
            paused=self.paused,
            tool_errors=self.result.tool_errors,
            refresh=self.refresh,
        )

    async def _dispatch(
        self, candidates: list[Candidate], tried: dict[str, set[str]]
    ) -> None:
        pending = candidates
        while pending:
            assignments: dict[str, tuple[ProviderConfig, list[Candidate]]] = {}
            for candidate in pending:
                # Prefer any eligible completed observation over another network query.
                cached = [
                    (config, self._cached(candidate, config))
                    for config in self.configs
                    if config.provider.name not in tried[candidate.key]
                    and config.supports(candidate)
                ]
                cached = [(config, item) for config, item in cached if item is not None]
                if cached:
                    cached_config, item = cached[0]
                    assert item is not None
                    self.result.observations.append(item)
                    self.result.reused += 1
                    tried[candidate.key].add(cached_config.provider.name)
                    if not item.transient and item.support != "unsupported":
                        continue
                config = self._select(candidate, tried[candidate.key])
                if config is None:
                    self.result.findings.append(
                        {
                            "code": "no_supported_provider_with_budget",
                            "requested_name": candidate.name,
                        }
                    )
                    continue
                name = config.provider.name
                tried[candidate.key].add(name)
                self.sent[name].add(candidate.key)
                assignments.setdefault(name, (config, []))[1].append(candidate)
            tasks: list[Coroutine[Any, Any, list[Observation]]] = []
            for config, names in assignments.values():
                size = config.provider.batch_size
                tasks.extend(
                    self._batch(config, names[i : i + size])
                    for i in range(0, len(names), size)
                )
            if not tasks:
                break
            batches = await asyncio.gather(*tasks)
            newest = [item for batch in batches for item in batch]
            self.result.observations.extend(newest)
            resolved = {
                item.requested_name
                for item in newest
                if not item.transient and item.support != "unsupported"
            }
            attempted = {c.name: c for _, names in assignments.values() for c in names}
            pending = [
                candidate
                for name, candidate in attempted.items()
                if name not in resolved
            ]

    def _sample(self, candidates: list[Candidate]) -> list[Candidate]:
        successful = {
            item.requested_name
            for item in self.result.observations
            if not item.transient
            and item.support != "unsupported"
            and not item.findings
        }
        groups: dict[str, list[Candidate]] = defaultdict(list)
        contradictions = []
        for candidate in candidates:
            signals = {
                item.validity_signal
                for item in self.result.observations
                if item.requested_name == candidate.name
            }
            if candidate.evidence_ids and (
                (candidate.offline_validity == "invalid" and "accepted" in signals)
                or (
                    candidate.offline_validity == "valid"
                    and signals & {"explicitly_invalid", "explicitly_restricted"}
                )
            ):
                contradictions.append(candidate)
            if candidate.name in successful:
                groups[candidate.group].append(candidate)
        for group in groups.values():
            group.sort(key=lambda c: hashlib.sha256(c.key.encode()).digest())
        sample: list[Candidate] = []
        target = math.ceil(len(successful) * self.cross_rate)
        while groups and len(sample) < target:
            for name in sorted(list(groups)):
                sample.append(groups[name].pop(0))
                if not groups[name]:
                    del groups[name]
                if len(sample) == target:
                    break
        return list({c.key: c for c in sample + contradictions}.values())

    async def run(self, candidates: list[Candidate]) -> RunResult:
        """Run the explicit suite, resuming persisted observations when permitted."""
        candidates = list(
            {candidate.key: candidate for candidate in candidates}.values()
        )
        tried: dict[str, set[str]] = defaultdict(set)
        await self._dispatch(candidates, tried)
        if len(self.configs) > 1:
            sample = self._sample(candidates)
            await self._dispatch(sample, tried)
            corroborated = sum(
                len(
                    {
                        item.provider
                        for item in self.result.observations
                        if item.requested_name == candidate.name
                        and not item.transient
                        and item.support != "unsupported"
                        and not item.findings
                    }
                )
                > 1
                for candidate in sample
            )
            self.result.cross_check = (
                "completed"
                if sample and corroborated == len(sample)
                else "partial"
                if corroborated
                else "unavailable"
            )
        for candidate in candidates:
            items = [
                item
                for item in self.result.observations
                if item.requested_name == candidate.name
            ]
            self.result.findings.extend(review_findings(candidate, items))
        return self.result
