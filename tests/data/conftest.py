"""Temporary dataset trees for deterministic pipeline checks."""

from pathlib import Path

import pytest
from scripts.data.sources import SOURCES

from .samples import RAW


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """Tree."""
    for source, (path, _) in SOURCES.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(RAW[source], encoding="utf-8")
    return tmp_path
