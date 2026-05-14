"""Public Python bindings for the tldhax registry checker."""

from ._native import CheckResult, Registry, TldInfo

__all__ = ["CheckResult", "Registry", "TldInfo"]