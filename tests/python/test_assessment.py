"""Useful registration decisions, direct explanations and bounded interfaces."""

from __future__ import annotations

import json
import tracemalloc

import pytest

from tldhax import Assessment, PreparedRegistrant, Reason, Registry, _native


def test_supported_name_and_direct_negative_reasons(registry: Registry) -> None:
    """A permitted common form and distinct concrete failures are actionable."""
    permitted = registry.assess("SUNFLOWER.COM.")
    assert isinstance(permitted, Assessment)
    assert permitted.decision == permitted.status == "yes"
    assert permitted.canonical_domain == "sunflower.com"
    assert permitted.namespace == "com"
    assert permitted.reasons == []
    assert permitted.missing_profile_fields == []

    short = registry.assess("a.au")
    assert short.decision == "no"
    assert short.missing_profile_fields == []
    reason = next(reason for reason in short.reasons if reason.code == "label_minimum")
    assert isinstance(reason, Reason)
    assert "2" in reason.message and "1" in reason.message
    assert str(reason) == reason.message

    reserved = registry.assess("iana.com", {"com_icann_authorized_labels": []})
    assert reserved.decision == "no"
    reason = next(
        reason for reason in reserved.reasons if reason.code == "reserved_label"
    )
    assert "iana" in reason.message


def test_profile_matching_failing_and_missing(registry: Registry) -> None:
    """A missing declaration is distinct from an explicit applicant failure."""
    assert (
        registry.assess(
            "vanity.me.uk", {"entity_kind": "individual", "organizational_proxy": False}
        ).decision
        == "yes"
    )
    denied = registry.assess(
        "vanity.me.uk", {"entity_kind": "organization", "organizational_proxy": False}
    )
    assert denied.decision == "no"
    assert any(reason.code == "natural_person" for reason in denied.reasons)
    incomplete = registry.assess("vanity.me.uk")
    assert incomplete.decision == "unknown"
    assert set(incomplete.missing_profile_fields) == {
        "entity_kind",
        "organizational_proxy",
    }
    assert all(reason.message for reason in incomplete.reasons)


def test_decisive_eligibility_alternative_does_not_request_unused_facts(
    registry: Registry,
) -> None:
    """An established route can pass without declarations for another route."""
    profile = registry.prepare_registrant({"com_registry_operational_labels": ["nic"]})
    result = registry.assess("nic.com", profile)
    assert result.decision == "yes"
    assert result.missing_profile_fields == []
    assert result.reasons == []


def test_idn_equivalence_and_scoped_unknown(registry: Registry) -> None:
    """Supported IDN, disallowed repertoire and unimplemented IDN stay distinct."""
    profile = {"de_contract_capacity": True}
    names = ["bücher.de", "BÜCHER.DE", "bu\u0308cher.de", "xn--bcher-kva.de"]
    results = [registry.assess(name, profile).to_dict() for name in names]
    assert all(result == results[0] for result in results)
    assert results[0]["decision"] == "yes"
    assert results[0]["canonical_domain"] == "xn--bcher-kva.de"
    rejected = registry.assess("日本.de", profile)
    assert rejected.decision == "no"
    assert any(reason.code == "idn_repertoire" for reason in rejected.reasons)
    unsupported = registry.assess("bücher.com")
    assert unsupported.decision == "unknown"
    assert any(reason.code == "idn_policy" for reason in unsupported.reasons)


def test_small_serializable_contract_and_legacy_adapter(registry: Registry) -> None:
    """Explanation strings and structured reasons come from the same checks."""
    result = registry.assess("faß.com")
    payload = result.to_dict()
    assert set(payload) == {
        "decision",
        "canonical_domain",
        "namespace",
        "reasons",
        "missing_profile_fields",
    }
    assert payload["decision"] == "no"
    assert any(reason["code"] == "idn_sharp_s" for reason in payload["reasons"])
    assert json.loads(json.dumps(payload)) == payload
    check = registry.check("faß.com")
    assert check.status == result.decision
    assert check.reasons == [reason.message for reason in result.reasons]
    with pytest.raises(AttributeError):
        result.decision = "yes"  # type: ignore[misc]


def test_batch_order_duplicates_and_input_budgets(registry: Registry) -> None:
    """Batch transport preserves decisions while rejecting exceeded budgets."""
    names = ["SUNFLOWER.COM", "sunflower.com", "", "_vanity.com", "vanity.aaa"]
    batch = registry.assess_many(iter(names))
    assert [item.to_dict() for item in batch] == [
        registry.assess(name).to_dict() for name in names
    ]
    assert batch[0].decision == batch[1].decision == "yes"
    assert batch[2].decision == batch[3].decision == "no"
    assert batch[4].decision == "unknown"
    with pytest.raises(ValueError, match="^input_limit$"):
        registry.assess("a" * 4097)
    with pytest.raises(ValueError, match="^input_limit$"):
        registry.assess_many(["sunflower.com", "a" * 4097])
    with pytest.raises(ValueError, match="^batch_input_limit$"):
        registry.assess_many("sunflower.com" for _ in range(10001))
    with pytest.raises(ValueError, match="^batch_input_limit$"):
        _native.Registry().assess_many([None] * 10001)  # type: ignore[list-item]
    with pytest.raises(TypeError):
        registry.assess_many("sunflower.com")
    with pytest.raises(TypeError):
        registry.assess_many(["sunflower.com", 3])  # type: ignore[list-item]


def test_profile_values_stay_private_and_preparation_is_reusable(
    registry: Registry,
) -> None:
    """Results, representations and invalid-profile errors omit declared values."""
    secret = "private-registrant-value-729613"
    profile = registry.prepare_registrant({"au_trademark_exact_labels": [secret]})
    assert isinstance(profile, PreparedRegistrant)
    assert registry.prepare_registrant(profile) is profile
    result = registry.assess("vanity.com.au", profile)
    assert secret not in repr(profile) + repr(result) + json.dumps(result.to_dict())
    assert secret not in "".join(repr(reason) for reason in result.reasons)
    assert [
        item.to_dict() for item in registry.assess_many(["vanity.com.au"], profile)
    ] == [result.to_dict()]
    with pytest.raises(ValueError) as error:
        registry.prepare_registrant({"unsupported_field": secret})
    assert str(error.value) == "unknown_profile_field"
    assert secret not in repr(error.value)
    with pytest.raises(ValueError, match="^invalid_profile_type$"):
        registry.prepare_registrant({"au_trademark_exact_labels": {"nested": secret}})
    with pytest.raises(ValueError, match="^invalid_profile_json$"):
        registry.prepare_registrant_json(
            '{"proxy_registration":false,"proxy_registration":true}'
        )
    with pytest.raises(ValueError, match="^profile_input_limit$"):
        registry.prepare_registrant({"au_trademark_exact_labels": ["a" * 1025]})
    with pytest.raises(ValueError) as invalid_unicode:
        registry.prepare_registrant({"au_trademark_exact_labels": [secret + "\ud800"]})
    assert str(invalid_unicode.value) == "invalid_profile_json"
    assert secret not in repr(invalid_unicode.value)
    with pytest.raises(ValueError) as native_unicode:
        _native.Registry().prepare_registrant(
            '{"au_trademark_exact_labels":["' + secret + '\ud800"]}'
        )
    assert str(native_unicode.value) == "invalid_profile_json"
    assert secret not in repr(native_unicode.value)


def test_native_limits_precede_large_unicode_utf8_allocation() -> None:
    """Existing oversized input does not allocate its UTF-8 representation."""

    class MisleadingString(str):
        """Report a misleading Python length; native storage remains authoritative."""

        def __len__(self) -> int:
            return 1

    oversized = MisleadingString("😀" * 1_000_000)
    registry = _native.Registry()
    tracemalloc.start()
    try:
        for call in [
            lambda: registry.assess(oversized),
            lambda: registry.check(oversized),
            lambda: registry.assess_many([oversized]),
        ]:
            with pytest.raises(ValueError, match="^input_limit$"):
                call()
        with pytest.raises(ValueError, match="^profile_input_limit$"):
            registry.prepare_registrant(oversized)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 100_000


def test_lone_surrogate_is_malformed_name_not_profile_error(registry: Registry) -> None:
    """Python-only invalid Unicode remains an ordinary negative assessment."""
    result = registry.assess("bad\ud800.com")
    assert result.decision == "no"
    assert result.canonical_domain is None
    assert registry.assess_many(["bad\ud800.com"])[0].to_dict() == result.to_dict()


@pytest.mark.parametrize("base", [list, tuple, set, frozenset])
def test_profile_collection_limits_use_builtin_contents(base: type) -> None:
    """Subclass callbacks cannot replace bounded builtin collection storage."""

    class CallbackCollection(base):  # type: ignore[valid-type,misc]
        """Reject callback use to expose a collection-boundary regression."""

        def __len__(self) -> int:
            raise AssertionError("subclass length callback invoked")

        def __iter__(self):
            raise AssertionError("subclass iterator callback invoked")

    registry = Registry()
    assert isinstance(
        registry.prepare_registrant(
            {"au_trademark_exact_labels": CallbackCollection(["vanity"])}
        ),
        PreparedRegistrant,
    )
    with pytest.raises(ValueError, match="^profile_input_limit$"):
        registry.prepare_registrant(
            {
                "au_trademark_exact_labels": CallbackCollection(
                    str(i) for i in range(257)
                )
            }
        )


def test_small_metadata_and_schema(registry: Registry) -> None:
    """Release identity and profile definitions need no evidence catalogue."""
    info = registry.dataset_info()
    assert info["dataset_version"] == registry.dataset_version()
    assert info["namespace_count"] == len(registry.supported_namespaces())
    assert "com" in registry.supported_namespaces()
    assert "aaa" not in registry.supported_namespaces()
    schema = registry.profile_schema()
    assert schema["citizenships"]["type"] == "string_set"
    assert schema["citizenships"]["string_format"] == "uppercase_alpha2"
    assert schema["google_qualifying_trademark_licensee"]["type"] == "boolean"
