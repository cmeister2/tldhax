"""Quota windows and cooldowns shared by source IP/account, not token."""

from __future__ import annotations

import asyncio
import math
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .store import Store


class Clock:
    """Injectable wall time, monotonic time and async waits."""

    def monotonic(self) -> float:
        """Return elapsed time for request-window calculations."""
        return time.monotonic()

    def time(self) -> float:
        """Return wall-clock time for UTC observations and HTTP date handling."""
        return time.time()

    async def sleep(self, delay: float) -> None:
        """Yield during the configured cooldown interval."""
        await asyncio.sleep(delay)


def retry_delay(value: str | None, now: float) -> float:
    """Parse Retry-After seconds or HTTP dates into a nonnegative delay."""
    if value is None:
        return 0
    try:
        return max(0, float(value))
    except ValueError:
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            return max(0, date.timestamp() - now)
        except (ValueError, TypeError, OverflowError):
            return 0


@dataclass(frozen=True)
class Window:
    """An explicit local request ceiling for one rolling time window."""

    requests: int
    seconds: float

    def __post_init__(self) -> None:
        """Reject invalid budgets before any network request."""
        if (
            type(self.requests) is not int
            or self.requests <= 0
            or not math.isfinite(self.seconds)
            or self.seconds <= 0
        ):
            raise ValueError("quota windows require positive requests and seconds")


class Quota:
    """Serialize acquisition across all adapters sharing an account or IP quota."""

    def __init__(
        self,
        windows: tuple[Window, ...],
        clock: Clock,
        store: Store | None = None,
        scope: str = "",
    ):
        """Initialize explicit dependencies and configuration."""
        if not windows:
            raise ValueError("at least one explicit quota window is required")
        self.windows, self.clock, self.store, self.scope = windows, clock, store, scope
        self.events: deque[float] = deque()
        self.cooldown = (
            clock.monotonic() + max(0, store.quota_cooldown(scope) - clock.time())
            if store
            else 0.0
        )
        self.lock = asyncio.Lock()

    def defer(self, delay: float) -> None:
        """Extend a shared provider cooldown without shortening an existing delay."""
        self.cooldown = max(self.cooldown, self.clock.monotonic() + delay)
        if self.store:
            self.store.defer_quota(self.scope, self.clock.time() + delay)

    def headers(self, headers: Mapping[str, str]) -> None:
        """Honor standard RateLimit exhaustion if sent; unknown headers stay native.

        Provider configurations remain conservative local ceilings. Server hints
        can delay requests, never expand those ceilings.
        """
        try:
            remaining = headers.get(
                "RateLimit-Remaining", headers.get("X-RateLimit-Remaining")
            )
            standard_reset = headers.get("RateLimit-Reset")
            reset = (
                standard_reset
                if standard_reset is not None
                else headers.get("X-RateLimit-Reset")
            )
            if remaining is not None and int(remaining) <= 0 and reset is not None:
                delay = float(reset)
                if standard_reset is None:  # Legacy X-RateLimit-Reset is an epoch.
                    delay -= self.clock.time()
                self.defer(max(0, delay))
        except (AttributeError, TypeError, ValueError):
            pass

    async def acquire(self) -> None:
        """Wait until every quota window and provider cooldown permits a request."""
        async with self.lock:
            while True:
                if self.store:
                    delay = self.store.reserve_quota(
                        self.scope,
                        tuple((w.requests, w.seconds) for w in self.windows),
                        self.clock.time(),
                    )
                    if delay <= 0:
                        return
                    await self.clock.sleep(min(delay, 60))
                    continue
                now = self.clock.monotonic()
                horizon = max(window.seconds for window in self.windows)
                while self.events and self.events[0] <= now - horizon:
                    self.events.popleft()
                delay = max(0, self.cooldown - now)
                for window in self.windows:
                    active = [
                        event for event in self.events if event > now - window.seconds
                    ]
                    if len(active) >= window.requests:
                        delay = max(
                            delay, active[-window.requests] + window.seconds - now
                        )
                if delay <= 0:
                    self.events.append(now)
                    return
                # Real waits yield regularly so cancellation/progress stay responsive.
                await self.clock.sleep(min(delay, 60))
