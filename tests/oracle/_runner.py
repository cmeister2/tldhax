"""Run the explicit scheduler in a deterministic async loop."""

import asyncio

from tools.oracle.runner import Runner


def run(configs, store, candidates, clock, **kwargs):
    """Run the explicit suite, resuming persisted observations when permitted."""
    return asyncio.run(
        Runner(configs, store, "v1", clock=clock, **kwargs).run(candidates)
    )
