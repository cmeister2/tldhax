"""Offline domain registration decisions with actionable explanations."""

from ._native import CheckResult
from .registry import Assessment, PreparedRegistrant, Reason, Registry

__all__ = ["Assessment", "CheckResult", "PreparedRegistrant", "Reason", "Registry"]
