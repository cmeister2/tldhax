"""Representative native/public API contracts without repeating every TLD fixture."""

from __future__ import annotations

import json
import tracemalloc

import pytest

from tldhax import Assessment, PreparedRegistrant, Registry, _native


def test_compact_and_detailed_share_outcomes_and_evidence_ids():
    """Formatting only adds prose and resolved provenance to the same decision."""
    registry = Registry()
    profile = registry.prepare_registrant(
        {"com_icann_authorized_labels": [], "com_registry_operational_labels": []}
    )
    compact = registry.assess("nic.com", profile)
    detailed = registry.assess("nic.com", profile, detailed=True)
    assert isinstance(compact, Assessment)
    assert compact.status == "no"
    assert compact.name_validity == "unknown"
    assert compact.eligibility == "does_not_match"
    left, right = compact.to_dict(), detailed.to_dict()
    for key in left.keys() - {"findings", "detailed"}:
        assert left[key] == right[key], key
    for plain, expanded in zip(left["findings"], right["findings"], strict=True):
        assert all(expanded[key] == value for key, value in plain.items())
        assert "message" in expanded
    assert any(
        source["url"].startswith("https://")
        for finding in right["findings"]
        for source in finding["sources"]
    )


def test_batch_identity_order_and_input_limits_match_single_calls():
    """Batch transport preserves invalid candidates and A-/U-label equivalence."""
    registry = Registry()
    names = ["BÜCHER.DE", "xn--bcher-kva.de", "", "_vanity.com", "a" * 5000]
    batch = registry.assess_many(iter(names))
    assert [item.to_dict() for item in batch] == [
        registry.assess(name).to_dict() for name in names
    ]
    assert batch[0].canonical_ascii == batch[1].canonical_ascii == "xn--bcher-kva.de"
    assert batch[2].status == batch[3].status == "no"
    assert batch[4].to_dict()["findings"][0]["code"] == "input_limit"
    with pytest.raises(ValueError, match="batch_input_limit"):
        registry.assess_many(["vanity.com"] * 10001)
    with pytest.raises(ValueError, match="batch_input_limit"):
        _native.Registry().assess_many([None] * 10001)
    with pytest.raises(TypeError):
        registry.assess_many("vanity.com")


def test_profile_values_stay_private_and_preparation_is_reusable():
    """Neither repr, detailed JSON nor validation errors prints declared values."""
    registry = Registry()
    secret = "private-registrant-value-729613"
    profile = registry.prepare_registrant({"au_trademark_exact_labels": [secret]})
    assert isinstance(profile, PreparedRegistrant)
    assert registry.prepare_registrant(profile) is profile
    result = registry.assess("vanity.au", profile, detailed=True)
    assert secret not in repr(profile) + repr(result) + json.dumps(result.to_dict())
    schema = registry.profile_schema()
    assert schema["google_qualifying_trademark_licensee"]["type"] == "boolean"
    assert schema["citizenships"]["type"] == "string_set"
    assert "organization" in schema["entity_kind"]["allowed_values"]
    assert secret not in json.dumps(schema)
    with pytest.raises(ValueError) as error:
        registry.prepare_registrant({"unsupported_field": secret})
    assert str(error.value) == "unknown_profile_field"
    assert secret not in repr(error.value)
    with pytest.raises(ValueError, match="invalid_profile_type"):
        registry.prepare_registrant({"au_trademark_exact_labels": {"nested": secret}})
    with pytest.raises(ValueError, match="invalid_profile_json"):
        registry.prepare_registrant_json(
            '{"proxy_registration":false,"proxy_registration":true}'
        )
    with pytest.raises(ValueError, match="profile_input_limit"):
        registry.prepare_registrant({"au_trademark_exact_labels": ["a" * 1025]})
    with pytest.raises(ValueError) as invalid_unicode:
        registry.prepare_registrant({"au_trademark_exact_labels": [secret + "\ud800"]})
    assert str(invalid_unicode.value) == "invalid_profile_json"
    assert secret not in repr(invalid_unicode.value)
    with pytest.raises(ValueError) as native_invalid_unicode:
        _native.Registry().prepare_registrant(
            '{"au_trademark_exact_labels":["' + secret + '\ud800"]}'
        )
    assert str(native_invalid_unicode.value) == "invalid_profile_json"
    assert secret not in repr(native_invalid_unicode.value)


def test_inventory_only_info_and_sources_do_not_invent_policy():
    """Discovery-only namespaces expose factual metadata with absent policy."""
    registry = Registry()
    info = registry.namespace_info(".aaa")
    assert info is not None
    payload = info.to_dict()
    assert payload["root_inventory"]["tld"] == "aaa"
    assert payload["policy"] is None
    assert "min_length" not in payload
    source = registry.source("denic-guidelines-de")
    assert source and len(source["sha256"]) == 64
    assertion = registry.assertion("uk.future-2027-policy")
    assert assertion and assertion["active"] is False
    assert registry.source("unknown-source") is None
    result = registry.assess("vanity.aaa")
    assert (
        result.dataset_version
        == info.dataset_version
        == registry.dataset_info()["dataset_version"]
    )
    with pytest.raises(AttributeError):
        result.status = "yes"


def test_native_budget_precedes_large_unicode_utf8_conversion():
    """An existing huge string must not allocate its UTF-8 representation."""

    class MisleadingString(str):
        def __len__(self):
            return 1

    oversized = MisleadingString("😀" * 1_000_000)
    registry = _native.Registry()
    tracemalloc.start()
    try:
        scalar = registry.assess(oversized)
        batch = registry.assess_many([oversized])
        assert registry.check(oversized).status == "unknown"
        assert registry.namespace_info(oversized) is None
        assert registry.tld_info(oversized) is None
        with pytest.raises(ValueError, match="profile_input_limit"):
            registry.prepare_registrant(oversized)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert scalar.to_dict()["findings"][0]["code"] == "input_limit"
    assert batch[0].to_dict() == scalar.to_dict()
    assert peak < 100_000


def test_name_registration_approval_remains_separate_from_psl_discovery():
    """Current form gaps must not erase supported registration routing."""
    registry = Registry()
    supported = registry.assess("firstname.name").to_dict()
    assert supported["registration"]["suffix"] == "name"
    assert supported["registration"]["applicant_labels"] == 1
    assert supported["registration"]["section"] == "reviewed"
    result = registry.assess("firstname.lastname.name").to_dict()
    assert result["policy_selector"] == "name"
    assert result["registration"]["section"] == "icann"
    assert result["registration"]["suffix"] == "name"
    assert result["icann"]["suffix"] == "name"
    assert result["status"] == result["name_validity"] == "unknown"


def test_unpaired_surrogates_produce_structured_invalid_input():
    """Python-only invalid Unicode remains a decision, including in batches."""
    registry = Registry()
    domain = "bad\ud800.com"
    scalar = registry.assess(domain).to_dict()
    assert scalar["name_validity"] == "invalid" and scalar["status"] == "no"
    assert scalar["canonical_ascii"] is None
    assert scalar["findings"][0]["params"]["code"] == "invalid_idna"
    assert registry.assess_many([domain])[0].to_dict() == scalar
    assert _native.Registry().check(domain).status == "no"


@pytest.mark.parametrize("base", [list, tuple, set, frozenset])
def test_profile_collection_budgets_use_builtin_contents(base):
    """Subclass callbacks cannot bypass bounds or induce custom iteration."""

    class CallbackCollection(base):
        def __len__(self):
            raise AssertionError("subclass length callback invoked")

        def __iter__(self):
            raise AssertionError("subclass iterator callback invoked")

    registry = Registry()
    prepared = registry.prepare_registrant(
        {"au_trademark_exact_labels": CallbackCollection(["vanity"])}
    )
    assert isinstance(prepared, PreparedRegistrant)
    excessive = CallbackCollection(str(i) for i in range(257))
    with pytest.raises(ValueError, match="profile_input_limit"):
        registry.prepare_registrant({"au_trademark_exact_labels": excessive})
