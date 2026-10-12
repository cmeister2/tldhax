"""Representation fingerprints reject incomplete or ambiguous captures."""

import pytest
from tools.evidence_fingerprint import extracted_text


def test_metadata_removal_keeps_source_content_and_unicode():
    """Page labels and tool citation IDs disappear; wording and spaces remain."""
    capture = "Document metadata; Total lines: 3\nL0@P0: Rule ß  retained\nL1@P0-1: \nL2@P1:  two spaces\n"
    assert extracted_text(capture) == "Rule ß  retained\n\n two spaces\n".encode()
    assert (
        extracted_text("Total lines: 2\nL0: source L1: cite17†label\n")
        == b"source\nlabel\n"
    )


@pytest.mark.parametrize(
    "capture",
    [
        "Total lines: 2\nL0: rule\n",
        "Total lines: 1\nL0: a\nL0: b\n",
        "Total lines: 2\nL1: a\nL0: b\n",
        "Total lines: 1\nTotal lines: 1\nL0: a\n",
    ],
)
def test_truncated_duplicate_reordered_or_mixed_sources_fail(capture):
    """Incomplete captures cannot silently acquire a reviewed source fingerprint."""
    with pytest.raises(ValueError):
        extracted_text(capture)
