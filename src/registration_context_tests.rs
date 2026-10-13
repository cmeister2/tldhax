//! Independent registration-context cases, including Unicode and A-label inputs.
#![allow(clippy::missing_docs_in_private_items)]

use super::{validate, ContextOError};
use crate::normalization::{CanonicalName, NormalizationError};

#[test]
fn positive_contexto_examples_pass_in_unicode_and_alabel_forms() {
    for label in [
        "l·l",
        "\u{0375}α",
        "א׳",
        "א״",
        "ア・a",
        "あ・a",
        "漢・a",
        "ا١٢",
        "ا۱۲",
    ] {
        let name = format!("{label}.com");
        let encoded = idna::domain_to_ascii(&name).unwrap();
        let unicode = CanonicalName::new(&name).unwrap();
        let ascii = CanonicalName::new(&encoded).unwrap();
        assert_eq!(unicode.ascii(), ascii.ascii(), "{name}");
        assert_eq!(unicode.unicode().unwrap(), ascii.unicode().unwrap());
    }
    assert!(CanonicalName::new("L·L.com").is_ok()); // Check contexts after UTS 46 case mapping.
}

#[test]
fn invalid_contexts_have_the_same_failure_for_unicode_and_alabel() {
    for (label, expected) in [
        ("a·b", ContextOError::MiddleDot),
        ("·l", ContextOError::MiddleDot),
        ("l·", ContextOError::MiddleDot),
        ("α\u{0375}", ContextOError::GreekNumeralSign),
        ("\u{0375}a", ContextOError::GreekNumeralSign),
        ("׳א", ContextOError::HebrewGeresh),
        ("״א", ContextOError::HebrewGershayim),
        ("a・b", ContextOError::KatakanaMiddleDot),
        ("・", ContextOError::KatakanaMiddleDot),
        ("ا١۲", ContextOError::MixedArabicIndicDigits),
        ("ا۱٢", ContextOError::MixedArabicIndicDigits),
    ] {
        let name = format!("{label}.com");
        assert_eq!(validate(&name), Err(expected));
        // IDNA Bidi already rejects mixed AN/EN digits before the ContextO hook.
        let normalization_error = if expected == ContextOError::MixedArabicIndicDigits {
            NormalizationError::InvalidIdna
        } else {
            NormalizationError::ContextO(expected)
        };
        assert_eq!(CanonicalName::new(&name), Err(normalization_error));
        // Build A-label probes without permitting UTS 46 to mask a contextual failure.
        let encoded = format!("xn--{}.com", idna::punycode::encode_str(label).unwrap());
        assert_eq!(
            CanonicalName::new(&encoded),
            Err(normalization_error),
            "{name}"
        );
    }
}

#[test]
fn script_properties_do_not_turn_unicode_blocks_into_permitted_scripts() {
    // U+037E sits in the Greek block, but Script=Common; U+05BE is Script=Hebrew.
    assert_eq!(
        validate("\u{0375}\u{037e}"),
        Err(ContextOError::GreekNumeralSign)
    );
    assert!(validate("\u{05be}\u{05f3}").is_ok());
    // U+30FC has Japanese Script_Extensions, but Script=Common, unlike RFC's test.
    assert_eq!(
        validate("\u{30fc}\u{30fb}"),
        Err(ContextOError::KatakanaMiddleDot)
    );
}

#[test]
fn contexts_never_cross_label_boundaries() {
    assert_eq!(validate("l·.l"), Err(ContextOError::MiddleDot));
    assert_eq!(validate("a・b.ア"), Err(ContextOError::KatakanaMiddleDot));
    assert!(validate("ا١.ا۲").is_ok());
}

#[test]
fn contextj_and_bidi_remain_enforced_by_the_idna_engine() {
    for name in ["a\u{200d}b.com", "aא.com"] {
        assert!(CanonicalName::new(name).is_err());
    }
    assert!(CanonicalName::new("क्\u{200d}ष.com").is_ok());
}
