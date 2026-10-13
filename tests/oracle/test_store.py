"""SQLite identity, environments, history and crashed transmission boundaries."""

from dataclasses import replace

import httpx
from tools.oracle.config import Credentials
from tools.oracle.models import Candidate
from tools.oracle.providers import Provider
from tools.oracle.store import Store, observation_key


def test_quota_reservations_and_cooldown_survive_independent_connections(tmp_path):
    """Two runs sharing a store cannot reuse the same account quota window."""
    path = tmp_path / "history.sqlite"
    with Store(path) as first, Store(path) as second:
        assert first.reserve_quota("account", ((1, 10),), 100) == 0
        assert second.reserve_quota("account", ((1, 10),), 100) == 10
        assert second.reserve_quota("other", ((1, 10),), 100) == 0
        first.defer_quota("account", 125)
        second.defer_quota("account", 120)
    with Store(path) as restarted:
        assert restarted.reserve_quota("account", ((1, 10),), 110) == 15
        assert restarted.reserve_quota("account", ((1, 10),), 125) == 0


def adapter(environment="production"):
    """Construct transport identity without requests or real credentials."""
    provider = Provider(httpx.AsyncClient(), Credentials("example"), environment)
    provider.name, provider.api_version = "example", "v1"
    return provider


def test_environment_and_version_are_separate_cache_identities():
    """Never reuse sandbox responses, another API version or a changed raw probe."""
    production, sandbox = adapter(), adapter("sandbox")
    name = Candidate("A.COM.")
    assert observation_key(name, production) == observation_key(
        Candidate("a.com"), production
    )
    assert observation_key(name, production) != observation_key(name, sandbox)
    assert observation_key(Candidate("_a.com"), production) != observation_key(
        Candidate("a.com"), production
    )
    sandbox.api_version = "v2"
    assert observation_key(name, production) != observation_key(name, sandbox)


def test_unfinished_retry_observations_do_not_reset_attempt_limit(tmp_path):
    """Preserve native retry responses while counting crashed and pending attempts."""
    provider, candidate = adapter(), Candidate("a.com")
    key = observation_key(candidate, provider)
    path = tmp_path / "history.sqlite"
    with Store(path) as store:
        store.start(key, 10)
        transient = provider.observation(
            candidate, "v1", native_status="pending", transient=True
        )
        store.save(key, transient, 10, complete=False)
    with Store(path) as resumed:
        assert resumed.cached(key, candidate, "v2", 10, 100) is None
        assert resumed.attempts_since_observation(key) == 1
        attempt = resumed.start(key, 11)
        resumed.finish(attempt, 11, "server_failure")
        resumed.finish(attempt, 11)
        assert (
            resumed.connection.execute(
                "SELECT error FROM attempts WHERE id=?", (attempt,)
            ).fetchone()[0]
            == "server_failure"
        )
        completed = replace(transient, validity_signal="accepted", transient=False)
        resumed.save(key, completed, 11)
        assert resumed.attempts_since_observation(key) == 0
        assert resumed.cached(key, candidate, "v2", 11, 100).dataset_version == "v2"
        assert resumed.cached(key, candidate, "v2", 200, 100) is None
        assert resumed.cached(key, candidate, "v2", 0, 100) is None
        assert (
            resumed.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[
                0
            ]
            == 2
        )
