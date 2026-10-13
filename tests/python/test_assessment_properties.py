"""Bounded independent registration syntax and batch assessment properties."""

import os

from hypothesis import given, settings
from hypothesis import strategies as st

from tldhax import Registry

EXAMPLES = int(os.environ.get("TLDHAX_FUZZ_EXAMPLES", "80"))
if not 1 <= EXAMPLES <= 5000:
    raise ValueError("TLDHAX_FUZZ_EXAMPLES must be between 1 and 5000")
BOUNDED = settings(max_examples=EXAMPLES, deadline=1500, derandomize=True)
LABEL = st.from_regex(r"[a-z][a-z0-9]{0,20}", fullmatch=True)


@BOUNDED
@given(LABEL, st.sampled_from(["com", "de", "co.uk", "a.ck"]))
def test_compact_detailed_and_ascii_input_case_preserve_semantic_identity(
    label: str, suffix: str
) -> None:
    """Explanation formatting and input case cannot change evidence outcomes."""
    registry = Registry()
    name = label + "." + suffix
    results = [
        registry.assess(name),
        registry.assess(name, detailed=True),
        registry.assess(name.upper()),
    ]
    assert (
        len(
            {
                (
                    r.canonical_ascii,
                    r.name_validity,
                    r.policy_coverage,
                    r.dataset_version,
                )
                for r in results
            }
        )
        == 1
    )


@BOUNDED
@given(st.integers(min_value=64, max_value=300))
def test_dns_overlength_label_is_negative_regardless_of_policy_coverage(
    length: int,
) -> None:
    """RFC label octet bounds conclusively reject even unresearched suffixes."""
    registry = Registry()
    for suffix in ("com", "this-root-is-not-delegated"):
        assert registry.assess("a" * length + "." + suffix).name_validity == "invalid"


@BOUNDED
@given(st.lists(LABEL, min_size=1, max_size=40))
def test_batch_results_preserve_single_lookup_order_duplicates_and_fingerprints(
    labels: list[str],
) -> None:
    """Batching must not lose repeated names or move source versions between rows."""
    registry = Registry()
    names = [label + ".com" for label in labels]
    batch = registry.assess_many(names)
    singles = [registry.assess(name) for name in names]
    assert len(batch) == len(names)
    assert [(r.canonical_ascii, r.name_validity, r.dataset_version) for r in batch] == [
        (r.canonical_ascii, r.name_validity, r.dataset_version) for r in singles
    ]
