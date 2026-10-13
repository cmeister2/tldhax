"""Public offline assessment API with reusable declared registrant profiles."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from . import _native

Assessment = _native.Assessment
Reason = _native.Reason
PreparedRegistrant = _native.PreparedRegistrant
MAX_BATCH = 10_000
MAX_PROFILE_BYTES = 65_536
MAX_PROFILE_FIELDS = 128
MAX_FACT_VALUES = 256
MAX_FACT_BYTES = 1_024


def _profile_json(profile: Mapping[str, Any]) -> str:
    """Bound flat input before serialization; all diagnostics exclude values."""
    if len(profile) > MAX_PROFILE_FIELDS:
        raise ValueError("profile_input_limit")
    values: dict[str, Any] = {}
    byte_count = 2

    def text_size(value: str) -> int:
        if str.__len__(value) > MAX_PROFILE_BYTES:
            raise ValueError("profile_input_limit")
        try:
            return len(str.encode(value, "utf-8"))
        except UnicodeError:
            raise ValueError("invalid_profile_json") from None

    for index, (key, value) in enumerate(profile.items()):
        if index >= MAX_PROFILE_FIELDS:
            raise ValueError("profile_input_limit")
        if not isinstance(key, str):
            raise ValueError("invalid_profile_type")
        byte_count += text_size(key) + 4
        if isinstance(value, bool):
            normalized: Any = value
            byte_count += 5
        elif isinstance(value, str):
            size = text_size(value)
            if size > MAX_FACT_BYTES:
                raise ValueError("profile_input_limit")
            normalized = value
            byte_count += size + 2
        elif isinstance(value, (list, tuple, set, frozenset)):
            # Read builtin storage directly: subclass callbacks cannot replace
            # length or iteration with an unbounded user-defined computation.
            if isinstance(value, list):
                size, items = list.__len__(value), list.__iter__(value)
            elif isinstance(value, tuple):
                size, items = tuple.__len__(value), tuple.__iter__(value)
            elif isinstance(value, set):
                size, items = set.__len__(value), set.__iter__(value)
            else:
                size, items = frozenset.__len__(value), frozenset.__iter__(value)
            if size > MAX_FACT_VALUES:
                raise ValueError("profile_input_limit")
            normalized = []
            for item_index, item in enumerate(items):
                if item_index >= MAX_FACT_VALUES:
                    raise ValueError("profile_input_limit")
                if not isinstance(item, str):
                    raise ValueError("invalid_profile_type")
                size = text_size(item)
                if size > MAX_FACT_BYTES:
                    raise ValueError("profile_input_limit")
                byte_count += size + 3
                if byte_count > MAX_PROFILE_BYTES:
                    raise ValueError("profile_input_limit")
                normalized.append(item)
            byte_count += 2
        else:
            raise ValueError("invalid_profile_type")
        if byte_count > MAX_PROFILE_BYTES:
            raise ValueError("profile_input_limit")
        values[key] = normalized
    result = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
    if len(result.encode("utf-8")) > MAX_PROFILE_BYTES:
        raise ValueError("profile_input_limit")
    return result


class Registry:
    """Evaluate supported static registration rules and declared applicant facts.

    Results contain one decision and actionable reasons. Matching declarations
    does not verify them, and a permitted name may already be registered.
    """

    __slots__ = ("_inner",)

    def __init__(self) -> None:
        """Construct a cheap handle to the immutable compiled policies."""
        self._inner = _native.Registry()

    def prepare_registrant(
        self, registrant: Mapping[str, Any] | PreparedRegistrant
    ) -> PreparedRegistrant:
        """Validate typed declarations once without exposing them in repr."""
        if isinstance(registrant, PreparedRegistrant):
            return registrant
        if not isinstance(registrant, Mapping):
            raise TypeError("registrant must be a mapping or PreparedRegistrant")
        return self._inner.prepare_registrant(_profile_json(registrant))

    def prepare_registrant_json(self, profile_json: str) -> PreparedRegistrant:
        """Parse bounded JSON with duplicate-key detection and value-free errors."""
        if not isinstance(profile_json, str):
            raise TypeError("profile_json must be a string")
        if str.__len__(profile_json) > MAX_PROFILE_BYTES:
            raise ValueError("profile_input_limit")
        try:
            str.encode(profile_json, "utf-8")
        except UnicodeError:
            raise ValueError("invalid_profile_json") from None
        return self._inner.prepare_registrant(profile_json)

    def assess(
        self,
        domain: str,
        registrant: Mapping[str, Any] | PreparedRegistrant | None = None,
    ) -> Assessment:
        """Return yes/no/unknown, reasons and any still-needed profile fields."""
        prepared = None if registrant is None else self.prepare_registrant(registrant)
        return self._inner.assess(domain, prepared)

    def assess_many(
        self,
        domains: Iterable[str],
        registrant: Mapping[str, Any] | PreparedRegistrant | None = None,
    ) -> list[Assessment]:
        """Evaluate at most 10,000 candidates in order, preparing facts once."""
        if isinstance(domains, (str, bytes)):
            raise TypeError("domains must be an iterable of strings")
        names: list[str] = []
        for index, domain in enumerate(domains):
            if index >= MAX_BATCH:
                raise ValueError("batch_input_limit")
            if not isinstance(domain, str):
                raise TypeError("domains must contain only strings")
            names.append(domain)
        prepared = None if registrant is None else self.prepare_registrant(registrant)
        return self._inner.assess_many(names, prepared)

    def check(self, domain: str) -> _native.CheckResult:
        """Return the inexpensive legacy status/reasons shape from the evaluator."""
        return self._inner.check(domain)

    def profile_schema(self) -> dict[str, dict[str, Any]]:
        """List accepted profile fields, types and constrained string values."""
        return self._inner.profile_schema()

    def dataset_version(self) -> str:
        """Identify the compiled direct-policy release."""
        return self._inner.dataset_version()

    def supported_namespaces(self) -> list[str]:
        """List authored policy selectors; individual unsupported scopes stay unknown."""
        return self._inner.supported_namespaces()

    def dataset_info(self) -> dict[str, Any]:
        """Return release identity and the authored-policy namespace count."""
        return {
            "dataset_version": self.dataset_version(),
            "namespace_count": len(self.supported_namespaces()),
        }
