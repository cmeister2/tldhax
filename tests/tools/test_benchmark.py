"""Verify reported latency quantiles independently of machine performance."""

import pytest
from tools.benchmark import distribution, measure


def test_nearest_rank_percentiles_keep_tail_and_do_not_mutate() -> None:
    """Rare slow requests must remain visible in the p99 tail."""
    durations = [*range(98, 0, -1), 1000, 2000]
    original = durations.copy()
    assert distribution(durations) == {
        "samples": 100,
        "p50_ns": 50,
        "p99_ns": 1000,
        "min_ns": 1,
        "max_ns": 2000,
    }
    assert durations == original
    with pytest.raises(ValueError):
        distribution([])


def test_single_request_and_batch_use_real_method_calls() -> None:
    """One batch request invokes one method rather than simulating scalar calls."""
    seen = []
    batch = ["one.com", "two.com"]

    def method(argument: list[str]) -> list[str]:
        """Record each native-facing argument without decomposing its batch."""
        seen.append(argument)
        return argument.copy()

    result = measure(method, batch, samples=3, warmup=2)
    assert seen == [batch] * 6  # first invocation + warmup + samples
    assert result["samples"] == 3
    assert result["p99_ns"] == result["max_ns"]
