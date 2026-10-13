"""Bounded parser properties; increase examples only for periodic campaigns."""

import os

from hypothesis import given, settings
from hypothesis import strategies as st
from scripts.data.namespaces import canonical, psl
from scripts.data.sources import PARSERS

from .samples import RAW

EXAMPLES = int(os.environ.get("TLDHAX_FUZZ_EXAMPLES", "80"))
if not 1 <= EXAMPLES <= 5000:
    raise ValueError("TLDHAX_FUZZ_EXAMPLES must be between 1 and 5000")
BOUNDED = settings(max_examples=EXAMPLES, deadline=1500, derandomize=True)


@BOUNDED
@given(st.sampled_from(sorted(PARSERS)), st.text(max_size=2048))
def test_arbitrary_bounded_text_is_a_record_or_a_clean_validation_error(
    source: str, text: str
) -> None:
    """Malformed public source bodies must fail through validation errors."""
    try:
        records, version = PARSERS[source](text)
    except ValueError:
        return
    assert records
    assert isinstance(version, str) and version


@BOUNDED
@given(
    st.sampled_from(sorted(PARSERS)),
    st.integers(min_value=0, max_value=3000),
    st.text(max_size=12),
)
def test_mutated_documents_never_escape_the_validation_error_contract(
    source: str, position: int, insertion: str
) -> None:
    """Exercise near-valid documents with bounded arbitrary corruptions."""
    original = RAW[source]
    offset = position % (len(original) + 1)
    mutated = original[:offset] + insertion + original[offset + 1 :]
    try:
        records, version = PARSERS[source](mutated)
    except ValueError:
        return
    assert records and version


@BOUNDED
@given(st.from_regex(r"[a-z][a-z0-9]{1,20}", fullmatch=True))
def test_private_additions_do_not_change_icann_wildcard_exception_discovery(
    label: str,
) -> None:
    """PRIVATE source additions must preserve independent ICANN routes."""
    original = RAW["psl.list"]
    rows, version = psl(original)
    changed = original.replace("blogspot.com\n", f"blogspot.com\n{label}.fixture.com\n")
    newer, new_version = psl(changed)
    assert [r for r in rows if r["section"] == "ICANN"] == [
        r for r in newer if r["section"] == "ICANN"
    ]
    assert {r["kind"] for r in newer if r["section"] == "ICANN"} == {
        "exact",
        "wildcard",
        "exception",
    }
    assert new_version == version
    assert any(
        r["suffix"] == f"{label}.fixture.com" and r["section"] == "PRIVATE"
        for r in newer
    )


@BOUNDED
@given(st.text(max_size=253))
def test_accepted_inventory_keys_are_ascii_and_idempotent(text: str) -> None:
    """Accepted authoring identities must remain stable when normalized twice."""
    try:
        key = canonical(text)
    except ValueError:
        return
    assert key.isascii() and key == key.lower()
    assert canonical(key) == key
