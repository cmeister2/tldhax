"""Fake providers and explicit runner setup without credentials or requests."""

import httpx
from tools.oracle.config import Credentials
from tools.oracle.providers import Provider


class FakeProvider(Provider):
    """Network-free provider with controllable failures and native signals."""

    api_version, batch_size = "test/v1", 50

    def __init__(self, name, clock, handler=None):
        """Initialize explicit dependencies and configuration."""
        super().__init__(httpx.AsyncClient(), Credentials(name))
        self.name, self.clock, self.handler, self.calls = name, clock, handler, []

    async def check(self, candidates, dataset):
        """Query the non-purchasing endpoint for the supplied batch."""
        self.calls.append((self.clock.monotonic(), [c.name for c in candidates]))
        if self.handler:
            response = self.handler(len(self.calls), candidates)
            if isinstance(response, Exception):
                raise response
            if response is not None:
                return [
                    self.observation(c, dataset, c.name, **response) for c in candidates
                ]
        return [
            self.observation(c, dataset, c.name, validity_signal="accepted")
            for c in candidates
        ]
