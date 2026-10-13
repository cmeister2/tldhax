"""Bounded IDN importer properties retain publication and adoption boundaries."""

import hashlib

from hypothesis import given
from hypothesis import strategies as st
from scripts.data.idn import parse_text
from scripts.data.idn_lgr import LGR_NAMESPACE, parse_lgr

from .test_properties import BOUNDED


@BOUNDED
@given(st.sampled_from([parse_text, parse_lgr]), st.binary(max_size=2048))
def test_bounded_idn_bytes_are_research_or_clean_validation_errors(parser, content):
    """Unknown encodings and grammar never become enforcement or parser crashes."""
    try:
        parsed = parser(content)
    except ValueError:
        return
    assert parsed["adoption_status"] == "requires_review"
    assert parsed["repertoire_complete"] is False
    assert parsed["knowledge"] in {"partial", "unknown"}
    assert parsed["source_sha256"] == hashlib.sha256(content).hexdigest()


@BOUNDED
@given(
    st.integers(min_value=0, max_value=0x10FFFF).filter(
        lambda cp: not 0xD800 <= cp <= 0xDFFF
    )
)
def test_same_single_scalar_has_matching_text_and_lgr_research_repertoires(cp):
    """Equivalent finite input formats preserve membership without policy approval."""
    text = f"# Version: fixture-v1\nU+{cp:04X}\n"
    xml = (
        f'<lgr xmlns="{LGR_NAMESPACE}"><meta><version>fixture-v1</version></meta>'
        f'<data><char cp="{cp:04X}"/></data></lgr>'
    )
    results = [parse_text(text), parse_lgr(xml)]
    assert all(result["ranges"] == [[cp, cp]] for result in results)
    assert all(result["version"] == "fixture-v1" for result in results)
    assert all(result["adoption_status"] == "requires_review" for result in results)
    assert all(result["repertoire_complete"] is False for result in results)
