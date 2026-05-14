"""Shared pytest fixtures for Python integration tests."""

from __future__ import annotations

import pytest

from tldhax import Registry


@pytest.fixture()
def registry() -> Registry:
    """Return a fresh registry for each test."""
    return Registry()