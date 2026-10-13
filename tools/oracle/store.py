"""Append-only observations and committed transmission attempts for resume."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

from .models import Candidate, Observation
from .providers import Provider


def observation_key(candidate: Candidate, provider: Provider) -> str:
    """Key by canonical/raw identity, provider, API, context and environment."""
    return json.dumps(
        [
            candidate.key,
            provider.name,
            provider.api_version,
            provider.environment,
            "prospective-name/registration",
        ],
        separators=(",", ":"),
    )


class Store:
    """Local SQLite history of responses and committed transmission attempts."""

    def __init__(self, path: Path | str):
        """Initialize explicit dependencies and configuration."""
        self.connection = sqlite3.connect(path)
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY, query_key TEXT NOT NULL,
                observed_at REAL NOT NULL, response TEXT NOT NULL,
                complete INTEGER NOT NULL DEFAULT 1, last_attempt_id INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS observation_lookup ON observations(query_key, id DESC);
            CREATE TABLE IF NOT EXISTS attempts (
                id INTEGER PRIMARY KEY, query_key TEXT NOT NULL,
                started_at REAL NOT NULL, finished_at REAL, error TEXT);
            CREATE INDEX IF NOT EXISTS attempt_lookup ON attempts(query_key, id DESC);
            CREATE TABLE IF NOT EXISTS quota_events (scope TEXT NOT NULL, requested_at REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS quota_lookup ON quota_events(scope, requested_at);
            CREATE TABLE IF NOT EXISTS quota_cooldowns (scope TEXT PRIMARY KEY, until REAL NOT NULL);
        """)
        self.connection.commit()

    def cached(
        self, key: str, candidate: Candidate, dataset: str, now: float, max_age: float
    ) -> Observation | None:
        """Reuse a completed response within the configured freshness window."""
        row = self.connection.execute(
            "SELECT observed_at, response FROM observations WHERE query_key=? AND complete=1 ORDER BY id DESC LIMIT 1",
            (key,),
        ).fetchone()
        if row is None or not 0 <= now - row[0] <= max_age:
            return None
        observation = Observation.from_dict(json.loads(row[1]))
        return replace(
            observation, requested_name=candidate.name, dataset_version=dataset
        )

    def start(self, key: str, now: float) -> int:
        """Commit an attempt before transmission so crashes remain bounded."""
        cursor = self.connection.execute(
            "INSERT INTO attempts(query_key,started_at) VALUES (?,?)", (key, now)
        )
        self.connection.commit()  # Persist before transmission, including crashed attempts.
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    def attempts_since_observation(self, key: str) -> int:
        """Count transmitted attempts since the last completed observation."""
        row = self.connection.execute(
            "SELECT last_attempt_id FROM observations WHERE query_key=? AND complete=1 ORDER BY id DESC LIMIT 1",
            (key,),
        ).fetchone()
        after = row[0] if row else -1
        return self.connection.execute(
            "SELECT COUNT(*) FROM attempts WHERE query_key=? AND id>?", (key, after)
        ).fetchone()[0]

    def finish(self, attempt: int, now: float, error: str | None = None) -> None:
        """Record safe completion or error metadata for one transmission."""
        self.connection.execute(
            "UPDATE attempts SET finished_at=?,error=COALESCE(?,error) WHERE id=?",
            (now, error, attempt),
        )
        self.connection.commit()

    def save(
        self, key: str, observation: Observation, now: float, complete: bool = True
    ) -> None:
        """Append a response, retaining retry observations without completing the query."""
        last_attempt = self.connection.execute(
            "SELECT COALESCE(MAX(id),0) FROM attempts WHERE query_key=?", (key,)
        ).fetchone()[0]
        self.connection.execute(
            "INSERT INTO observations(query_key,observed_at,response,complete,last_attempt_id) VALUES (?,?,?,?,?)",
            (
                key,
                now,
                json.dumps(observation.to_dict(), sort_keys=True),
                int(complete),
                last_attempt,
            ),
        )
        self.connection.commit()

    def quota_cooldown(self, scope: str) -> float:
        """Return the persisted wall-clock cooldown for an account/source-IP group."""
        row = self.connection.execute(
            "SELECT until FROM quota_cooldowns WHERE scope=?", (scope,)
        ).fetchone()
        return row[0] if row else 0.0

    def defer_quota(self, scope: str, until: float) -> None:
        """Persist the longest observed cooldown across runners and processes."""
        self.connection.execute(
            "INSERT INTO quota_cooldowns(scope,until) VALUES (?,?) "
            "ON CONFLICT(scope) DO UPDATE SET until=MAX(until,excluded.until)",
            (scope, until),
        )
        self.connection.commit()

    def reserve_quota(
        self, scope: str, windows: tuple[tuple[int, float], ...], now: float
    ) -> float:
        """Atomically reserve a request, or return the next permitted delay.

        Wall time permits resume after a restart. Future events caused by clock
        rollback delay requests conservatively. Quota history shares the same
        explicit observation store; separate stores cannot coordinate an IP.
        """
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            delay = max(0, self.quota_cooldown(scope) - now)
            horizon = max(seconds for _, seconds in windows)
            events = [
                row[0]
                for row in self.connection.execute(
                    "SELECT requested_at FROM quota_events WHERE scope=? AND requested_at>? ORDER BY requested_at",
                    (scope, now - horizon),
                )
            ]
            for requests, seconds in windows:
                active = [event for event in events if event > now - seconds]
                if len(active) >= requests:
                    delay = max(delay, active[-requests] + seconds - now)
            if delay <= 0:
                self.connection.execute(
                    "INSERT INTO quota_events(scope,requested_at) VALUES (?,?)",
                    (scope, now),
                )
            self.connection.commit()
            return delay
        except BaseException:
            self.connection.rollback()
            raise

    def close(self) -> None:
        """Close the local observation database."""
        self.connection.close()

    def __enter__(self) -> Store:
        """Return this store for deterministic resource cleanup."""
        return self

    def __exit__(self, *_args: object) -> None:
        """Close the database when the explicit run finishes."""
        self.close()
