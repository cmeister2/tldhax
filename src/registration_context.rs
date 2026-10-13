//! Registration-only ContextO checks from RFC 5892 Appendix A.3–A.9.
//!
//! UTS 46 handles mapping, ContextJ and Bidi; these additional checks operate on
//! canonical decoded Unicode labels. Script tests use Unicode Script exactly.
//! Source: https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A

use icu_properties::{props::Script, CodePointMapData};

/// A contextual character whose registration rule is not satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextOError {
    /// U+00B7 is not immediately between two lowercase Latin l characters.
    MiddleDot,
    /// U+0375 is not immediately followed by a Greek-script character.
    GreekNumeralSign,
    /// U+05F3 is not immediately preceded by a Hebrew-script character.
    HebrewGeresh,
    /// U+05F4 is not immediately preceded by a Hebrew-script character.
    HebrewGershayim,
    /// U+30FB occurs in a label with no Hiragana, Katakana or Han character.
    KatakanaMiddleDot,
    /// Arabic-Indic and Extended Arabic-Indic digits occur in the same label.
    MixedArabicIndicDigits,
}

impl ContextOError {
    /// Stable diagnostic code for evidence-linked explanations.
    pub const fn code(self) -> &'static str {
        match self {
            Self::MiddleDot => "idna_middle_dot_context",
            Self::GreekNumeralSign => "idna_greek_numeral_context",
            Self::HebrewGeresh => "idna_hebrew_geresh_context",
            Self::HebrewGershayim => "idna_hebrew_gershayim_context",
            Self::KatakanaMiddleDot => "idna_katakana_middle_dot_context",
            Self::MixedArabicIndicDigits => "idna_mixed_arabic_digit_sets",
        }
    }

    /// The controlling RFC clause, independent of registry repertoire policy.
    pub const fn locator(self) -> &'static str {
        match self {
            Self::MiddleDot => "RFC5892 Appendix A.3",
            Self::GreekNumeralSign => "RFC5892 Appendix A.4",
            Self::HebrewGeresh => "RFC5892 Appendix A.5",
            Self::HebrewGershayim => "RFC5892 Appendix A.6",
            Self::KatakanaMiddleDot => "RFC5892 Appendix A.7",
            Self::MixedArabicIndicDigits => "RFC5892 Appendix A.8/A.9",
        }
    }
}

/// Validate the ContextO requirements independently for every Unicode label.
///
/// # Errors
///
/// Returns the first unsatisfied RFC 5892 ContextO rule. This function assumes
/// UTS 46 has already mapped and validated the name; it does not replace IDNA.
pub fn validate(name: &str) -> Result<(), ContextOError> {
    let scripts = CodePointMapData::<Script>::new();
    for label in name.split('.').filter(|label| !label.is_ascii()) {
        let mut previous = None;
        let mut characters = label.chars().peekable();
        let (mut arabic, mut extended, mut japanese) = (false, false, None);
        while let Some(character) = characters.next() {
            let failure = match character {
                '\u{00b7}' if previous != Some('l') || characters.peek() != Some(&'l') => {
                    Some(ContextOError::MiddleDot)
                }
                '\u{0375}'
                    if !characters
                        .peek()
                        .is_some_and(|next| scripts.get(*next) == Script::Greek) =>
                {
                    Some(ContextOError::GreekNumeralSign)
                }
                '\u{05f3}'
                    if !previous.is_some_and(|prior| scripts.get(prior) == Script::Hebrew) =>
                {
                    Some(ContextOError::HebrewGeresh)
                }
                '\u{05f4}'
                    if !previous.is_some_and(|prior| scripts.get(prior) == Script::Hebrew) =>
                {
                    Some(ContextOError::HebrewGershayim)
                }
                '\u{30fb}' => {
                    let allowed = *japanese.get_or_insert_with(|| {
                        label.chars().any(|cp| {
                            matches!(
                                scripts.get(cp),
                                Script::Hiragana | Script::Katakana | Script::Han
                            )
                        })
                    });
                    (!allowed).then_some(ContextOError::KatakanaMiddleDot)
                }
                '\u{0660}'..='\u{0669}' => {
                    arabic = true;
                    extended.then_some(ContextOError::MixedArabicIndicDigits)
                }
                '\u{06f0}'..='\u{06f9}' => {
                    extended = true;
                    arabic.then_some(ContextOError::MixedArabicIndicDigits)
                }
                _ => None,
            };
            if let Some(error) = failure {
                return Err(error);
            }
            previous = Some(character);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "registration_context_tests.rs"]
mod tests;
