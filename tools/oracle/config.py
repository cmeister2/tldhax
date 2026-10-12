"""Credentials come from process environment or an explicitly selected file."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values


@dataclass(frozen=True)
class Credentials:
    """Provider credentials excluded from object representations."""

    provider: str
    username: str = field(default="", repr=False)
    token: str = field(default="", repr=False)


def load_credentials(
    env_file: Path | None = None, environ: Mapping[str, str] | None = None
) -> list[Credentials]:
    """Load only the selected file, with process environment taking precedence."""
    values = (
        dict(dotenv_values(env_file, interpolate=False)) if env_file is not None else {}
    )
    values.update(os.environ if environ is None else environ)
    configured = []
    user, token = values.get("NAMECOM_USERNAME"), values.get("NAMECOM_API_TOKEN")
    if bool(user) != bool(token):
        raise ValueError("Name.com requires NAMECOM_USERNAME and NAMECOM_API_TOKEN")
    if user and token:
        configured.append(Credentials("namecom", user, token))
    if values.get("GANDI_PAT"):
        configured.append(Credentials("gandi", token=values["GANDI_PAT"] or ""))
    return configured
