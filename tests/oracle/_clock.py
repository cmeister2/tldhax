"""Deterministic test clock; never waits for wall time."""

from tools.oracle.limits import Clock


class FakeClock(Clock):
    """Deterministic clock that advances during quota and backoff waits."""

    def __init__(self):
        """Initialize explicit dependencies and configuration."""
        self.now = 0.0
        self.waits = []

    def monotonic(self):
        """Return elapsed time for request-window calculations."""
        return self.now

    def time(self):
        """Return wall-clock time for UTC observations and HTTP date handling."""
        return 1_700_000_000 + self.now

    async def sleep(self, delay):
        """Yield during the configured cooldown interval."""
        self.waits.append(delay)
        self.now += delay
