"""Public offline assessment API with reusable declared registrant profiles."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from . import _native

Assessment = _native.Assessment
NamespaceInfo = _native.NamespaceInfo
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
    """Check compiled policy without runtime networking or policy file loading.

    Registrant facts are self-declared. Prepare once for repeated calls or a batch.
    Detailed results add formatted explanations to the same compact assessment.
    """

    __slots__ = ("_inner",)

    def __init__(self) -> None:
        """Construct a cheap handle to the compiled immutable release."""
        self._inner = _native.Registry()

    def prepare_registrant(
        self, registrant: Mapping[str, Any] | PreparedRegistrant
    ) -> PreparedRegistrant:
        """Validate typed facts once; the prepared object has a redacted repr."""
        if isinstance(registrant, PreparedRegistrant):
            return registrant
        if not isinstance(registrant, Mapping):
            raise TypeError("registrant must be a mapping or PreparedRegistrant")
        return self._inner.prepare_registrant(_profile_json(registrant))

    def prepare_registrant_json(self, profile_json: str) -> PreparedRegistrant:
        """Parse bounded JSON without losing duplicate-field detection."""
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
        *,
        detailed: bool = False,
        include_private: bool = False,
    ) -> Assessment:
        """Return name, eligibility, coverage, canonical identity and evidence IDs."""
        prepared = None if registrant is None else self.prepare_registrant(registrant)
        return self._inner.assess(
            domain, prepared, detailed=detailed, include_private=include_private
        )

    def assess_many(
        self,
        domains: Iterable[str],
        registrant: Mapping[str, Any] | PreparedRegistrant | None = None,
        *,
        detailed: bool = False,
        include_private: bool = False,
    ) -> list[Assessment]:
        """Assess up to 10,000 ordered candidates while preparing facts once."""
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
        return self._inner.assess_many(
            names, prepared, detailed=detailed, include_private=include_private
        )

    def namespace_info(self, namespace: str) -> NamespaceInfo | None:
        """Describe inventory, reviewed policy and gaps for a known namespace."""
        return self._inner.namespace_info(namespace)

    def dataset_info(self) -> dict[str, Any]:
        """Return immutable release dates, normalization profile and table counts."""
        return self._inner.dataset_info()

    def dataset_stats(self) -> dict[str, Any]:
        """Return factual denominators and reviewed coverage by class and family."""
        return self._inner.dataset_stats()

    def profile_schema(self) -> dict[str, dict[str, Any]]:
        """Discover accepted fields, typed values and optional finite enums."""
        return self._inner.profile_schema()

    def source(self, source_id: str) -> dict[str, Any] | None:
        """Look up an exact publication record by stable source ID."""
        return self._inner.source(source_id)

    def assertion(self, assertion_id: str) -> dict[str, Any] | None:
        """Look up a reviewed assertion, including inactive applicability metadata."""
        return self._inner.assertion(assertion_id)

    def check(self, domain: str) -> _native.CheckResult:
        """Preserve the legacy status/reasons result shape."""
        return self._inner.check(domain)

    def tld_info(self, tld: str) -> _native.TldInfo | None:
        """Return a legacy summary only where policy fits its fields faithfully."""
        return self._inner.tld_info(tld)

    def rule_count(self) -> int:
        """Return faithful legacy-summary counts; policy counts use dataset_stats."""
        return self._inner.rule_count()

    def stats(self) -> dict[str, int | float]:
        """Return legacy summary statistics; coverage counts use dataset_stats."""
        return self._inner.stats()
