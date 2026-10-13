"""Independent text-table fixtures; table publication never approves adoption."""

import hashlib

import pytest
from scripts.data.idn import feature_category, parse_text


def test_text_ranges_versions_and_snapshot_hash_require_adoption() -> None:
    """Parsing a published repertoire supplies no namespace or effective approval."""
    content = b"# Version: 1.2\r\n# Registry: .example\r\n# Effective Date: 2026-01-01\r\nU+0061..U+007A\r\nU+00E9\r\n"
    parsed = parse_text(content)
    assert parsed["ranges"] == [[0x61, 0x7A], [0xE9, 0xE9]]
    assert parsed["version"] == "1.2"
    assert parsed["source_sha256"] == hashlib.sha256(content).hexdigest()
    assert parsed["knowledge"] == "unknown"
    assert parsed["parser_coverage"] == "complete"
    assert parsed["adoption_status"] == "requires_review"
    assert parsed["repertoire_complete"] is False
    assert "namespaces" not in parsed and "effective_from" not in parsed
    assert parsed["metadata"]["headers"]["effective date"] == "2026-01-01"
    assert parsed == parse_text(content)


def test_text_variant_columns_and_prose_cannot_become_complete_policy() -> None:
    """Column position and script prose retain unresolved native relationships."""
    parsed = parse_text(
        "# Table Version 7\n# Never mix scripts\nU+00E9;U+0065 U+0301;preferred\n"
    )
    assert parsed["knowledge"] == parsed["parser_coverage"] == "partial"
    assert parsed["variants"] == [
        {
            "sequence": "é",
            "replacement": "e\u0301",
            "disposition": "unresolved",
        }
    ]
    assert (
        "allocation:variant_allocation_relationship" in parsed["unsupported_features"]
    )
    assert any("text_comment" in feature for feature in parsed["unsupported_features"])
    assert any("text_columns" in feature for feature in parsed["unsupported_features"])


@pytest.mark.parametrize(
    "feature,category",
    [
        ("root_element:extension", "repertoire"),
        ("repertoire_sequence", "repertoire"),
        ("attribute:data:extension", "repertoire"),
        ("attribute:char:unknown-extension", "repertoire"),
        ("uninterpreted_text_record:7", "repertoire"),
        ("context_expression:property", "context"),
        ("attribute:char:tag", "context"),
        ("variant_allocation_relationship", "allocation"),
        ("metadata_element:language", "metadata"),
        ("future_unknown_feature", "repertoire"),
    ],
)
def test_membership_completeness_cannot_ignore_ambiguous_features(
    feature: str, category: str
) -> None:
    """Only explicit context/allocation/metadata families avoid membership ambiguity."""
    assert feature_category(feature) == f"{category}:{feature}"
    assert feature_category(f"{category}:{feature}") == f"{category}:{feature}"


@pytest.mark.parametrize(
    "content",
    [
        "# Version: 1\nU+007A..U+0061\n",
        "# Version: 1\nU+D800\n",
        "# Version: 1\nU+D7FF..U+E000\n",
        "# Version: 1\nU+110000\n",
        "# Version: 1\nU+ZZZZ\n",
        "# Version: 1\nU+0061\nU+0061\n",
        "U+0061\n",
        "# Version: 1\n# Version: 2\nU+0061\n",
    ],
)
def test_malformed_text_repertoires_fail(content: str) -> None:
    """Invalid scalars, overlaps and missing/conflicting versions are not research data."""
    with pytest.raises(ValueError):
        parse_text(content)
