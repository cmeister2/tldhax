"""Bounded transmission and retry handling, independent of dispatch selection."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from .limits import Clock, Quota, retry_delay
from .models import Candidate, Observation, timestamp
from .providers import ProviderError
from .store import Store, observation_key

if TYPE_CHECKING:
    from .dispatch_config import ProviderConfig


async def check_batch(
    config: ProviderConfig,
    candidates: list[Candidate],
    *,
    store: Store,
    dataset: str,
    clock: Clock,
    quota: Quota,
    semaphore: asyncio.Semaphore,
    paused: set[str],
    tool_errors: list[dict[str, Any]],
    refresh: bool,
) -> list[Observation]:
    """Persist attempts before sending and pause after auth or persistent failures."""
    provider = config.provider
    observations = []
    pending = candidates
    attempts = {
        c.key: 0
        if refresh
        else store.attempts_since_observation(observation_key(c, provider))
        for c in candidates
    }
    async with semaphore:
        while pending and provider.name not in paused:
            eligible = [c for c in pending if attempts[c.key] <= config.retries]
            for candidate in pending:
                if candidate not in eligible:
                    item = provider.observation(
                        candidate,
                        dataset,
                        findings=("attempt_budget_exhausted",),
                        transient=True,
                    )
                    store.save(observation_key(candidate, provider), item, clock.time())
                    observations.append(item)
            pending = []
            if not eligible:
                break
            await quota.acquire()
            if provider.name in paused:
                break
            started = {
                c.key: store.start(observation_key(c, provider), clock.time())
                for c in eligible
            }
            for candidate in eligible:
                attempts[candidate.key] += 1
            try:
                batch = await provider.check(eligible, dataset)
                quota.headers(provider.last_headers)
            except ProviderError as error:
                quota.headers(provider.last_headers)
                if error.retry_after:
                    quota.defer(retry_delay(error.retry_after, clock.time()))
                for attempt in started.values():
                    store.finish(attempt, clock.time(), error.code)
                if error.code == "authentication_failure":
                    paused.add(provider.name)
                    tool_errors.append({"provider": provider.name, "code": error.code})
                    break
                if error.transient and all(
                    attempts[c.key] <= config.retries for c in eligible
                ):
                    quota.defer(
                        max(
                            retry_delay(error.retry_after, clock.time()),
                            2 ** (max(attempts.values()) - 1),
                        )
                    )
                    pending = eligible
                    continue
                tool_errors.append({"provider": provider.name, "code": error.code})
                batch = [
                    provider.observation(
                        c,
                        dataset,
                        findings=(error.code,),
                        native_status=f"HTTP{error.status}" if error.status else None,
                        native_reason=error.code,
                        transient=error.transient,
                        support="unsupported"
                        if error.status in (404, 405, 422)
                        else "unknown",
                    )
                    for c in eligible
                ]
                if error.transient:
                    paused.add(provider.name)
            for candidate, item in zip(eligible, batch):
                item = replace(item, observed_at=timestamp(clock.time()))
                store.finish(started[candidate.key], clock.time())
                retry = item.transient and attempts[candidate.key] <= config.retries
                store.save(
                    observation_key(candidate, provider),
                    item,
                    clock.time(),
                    complete=not retry,
                )
                if retry:
                    pending.append(candidate)
                else:
                    observations.append(item)
                    if item.transient:
                        paused.add(provider.name)
            if pending:
                quota.defer(2 ** (max(attempts.values()) - 1))
    return observations
