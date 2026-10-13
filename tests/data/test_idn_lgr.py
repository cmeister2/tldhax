"""Independent LGR fixtures covering finite predicates and explicit feature gaps."""

import pytest
from scripts.data.idn_lgr import LGR_NAMESPACE, parse_lgr


def lgr(data: str, rules: str = "", meta: str = "") -> str:
    """Build a tiny versioned LGR document independently of production tables."""
    return (
        f'<lgr xmlns="{LGR_NAMESPACE}"><meta><version>1.2</version>{meta}</meta>'
        f"<data>{data}</data><rules>{rules}</rules></lgr>"
    )


@pytest.mark.parametrize(
    "variant_type,disposition",
    [
        ("blocked", "blocked"),
        ("allocatable", "conditional"),
        ("new-disposition", "unresolved"),
    ],
)
def test_lgr_variants_are_relationship_metadata(
    variant_type: str, disposition: str
) -> None:
    """A blocked variant does not ban every label containing the source character."""
    parsed = parse_lgr(
        lgr(f'<char cp="00E9"><var cp="0065 0301" type="{variant_type}"/></char>')
    )
    assert parsed["ranges"] == [[0xE9, 0xE9]]
    assert parsed["variants"] == [
        {"sequence": "é", "replacement": "e\u0301", "disposition": disposition}
    ]
    assert parsed["knowledge"] == "partial"
    assert (
        "allocation:variant_allocation_relationship" in parsed["unsupported_features"]
    )


@pytest.mark.parametrize(
    "data,rules,feature",
    [
        ('<char cp="0061" tag="Latin"/>', "", "context:attribute:char:tag"),
        (
            '<char cp="0061" when="ordering"/>',
            '<rule name="ordering"><char cp="0061"/><char cp="0062"/></rule>',
            "context:context_rule:ordering",
        ),
        (
            '<char cp="0061" when="script"/>',
            '<class name="Latin" property="sc:Latn"/><rule name="script"><look-behind><class by-ref="Latin"/></look-behind></rule>',
            "context:attribute:class:property",
        ),
        (
            '<char cp="0061"/>',
            '<action disp="invalid" match="label-rule"/>',
            "context:rules_element:action:invalid",
        ),
        (
            '<range first-cp="0061" last-cp="007A" when="context"/>',
            "",
            "context:nonscalar_context_binding",
        ),
        ('<char cp="0061 0301"/>', "", "repertoire:repertoire_sequence"),
        (
            '<char cp="0061" when="large"/>',
            '<class name="large-set"><range first-cp="1000" last-cp="3000"/></class><rule name="large"><look-behind><class by-ref="large-set"/></look-behind></rule>',
            "context:context_set_exceeds_budget",
        ),
    ],
)
def test_every_unhandled_constraint_stays_partial(
    data: str, rules: str, feature: str
) -> None:
    """Script, ordering, whole-label, sequence and unbounded-set features stay gaps."""
    parsed = parse_lgr(lgr(data, rules))
    assert parsed["knowledge"] == parsed["parser_coverage"] == "partial"
    assert feature in parsed["unsupported_features"]


@pytest.mark.parametrize(
    "content",
    [
        "<unknown/>",
        '<lgr xmlns="urn:other"/>',
        "<lgr",
        '<!DOCTYPE lgr [<!ENTITY x "unsafe">]><lgr/>',
        lgr('<range first-cp="007A" last-cp="0061"/>'),
        lgr('<char cp="D800"/>'),
        lgr('<range first-cp="D7FF" last-cp="E000"/>'),
        lgr('<char cp="0061"/><char cp="0061"/>'),
        lgr('<char cp="0061" when="missing"/>'),
        lgr(
            '<char cp="0061" when="cycle"/>',
            '<class name="self"><class by-ref="self"/></class><rule name="cycle"><look-behind><class by-ref="self"/></look-behind></rule>',
        ),
    ],
)
def test_malformed_or_unsafe_lgr_fails(content: str) -> None:
    """Malformed roots, entities, scalar intervals and reference graphs fail closed."""
    with pytest.raises(ValueError):
        parse_lgr(content)


def test_lgr_literal_repertoire_and_finite_contexts() -> None:
    """Preserve distinct positional and adjacent-set predicates, not approximations."""
    parsed = parse_lgr(
        lgr(
            '<range first-cp="0061" last-cp="007A"/>'
            '<char cp="00B7" when="between-l"/>'
            '<char cp="0301" not-when="start" when="after-l"/>'
            '<char cp="0302" not-when="end"/>'
            '<char cp="0303" when="before-l"/>',
            '<class name="letter-l"><char cp="006C"/></class>'
            '<rule name="between-l"><look-behind><class by-ref="letter-l"/></look-behind><look-ahead><char cp="006C"/></look-ahead></rule>'
            '<rule name="start"><start/></rule><rule name="end"><end/></rule>'
            '<rule name="after-l"><look-behind><char cp="006C"/></look-behind></rule>'
            '<rule name="before-l"><look-ahead><char cp="006C"/></look-ahead></rule>',
            "<unicode-version>15.0.0</unicode-version><date>2026-01-01</date>",
        )
    )
    assert parsed["knowledge"] == "unknown" and parsed["unsupported_features"] == []
    assert parsed["repertoire_complete"] is False
    assert parsed["metadata"]["unicode-version"] == "15.0.0"
    assert parsed["contexts"] == [
        {
            "codepoint": 0xB7,
            "condition": {"kind": "between", "left": [0x6C], "right": [0x6C]},
        },
        {"codepoint": 0x301, "condition": {"kind": "not_start"}},
        {"codepoint": 0x301, "condition": {"kind": "preceded_by", "values": [0x6C]}},
        {"codepoint": 0x302, "condition": {"kind": "not_end"}},
        {"codepoint": 0x303, "condition": {"kind": "followed_by", "values": [0x6C]}},
    ]


def test_unknown_metadata_attributes_and_descriptive_prose_require_review() -> None:
    """Uninterpreted policy prose or extension attributes cannot silently disappear."""
    parsed = parse_lgr(
        lgr(
            '<char cp="0061"/>',
            meta='<language script="single">und</language><description>Never mix scripts.</description>',
        )
    )
    assert parsed["knowledge"] == "partial"
    assert (
        "metadata:metadata_attribute:language:script" in parsed["unsupported_features"]
    )
    assert (
        "metadata:uninterpreted_prose_metadata:description"
        in parsed["unsupported_features"]
    )
