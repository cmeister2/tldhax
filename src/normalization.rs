//! Canonical registration-name processing shared by lookups and policy keys.

use std::borrow::Cow;

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

use crate::registration_context::{self, ContextOError};

/// Maximum raw UTF-8 input size before trimming or Unicode processing.
pub const MAX_INPUT_BYTES: usize = 4096;

/// The versioned normalisation contract, independent of registry policy.
pub const NORMALIZATION_PROFILE: &str =
    "uts46-nontransitional-std3-hyphens-contexto-v2/idna-1.1.0/idna-adapter-1.2.2/icu-normalizer-2.2.0/icu-normalizer-data-2.2.0/icu-properties-2.2.0/icu-properties-data-2.2.0";

/// A failure of the input contract, DNS bounds, or strict IDNA processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizationError {
    /// Input exceeds the documented preprocessing budget.
    InputLimit,
    /// Input has no labels after whitespace and one optional root dot.
    Empty,
    /// IDNA, character, contextual, Bidi, or hyphen validation failed.
    InvalidIdna,
    /// A decoded Unicode label violates a registration ContextO rule.
    ContextO(ContextOError),
    /// The canonical name includes an empty label.
    EmptyLabel,
    /// An ASCII label exceeds the DNS wire bound.
    LabelTooLong,
    /// The complete DNS wire name exceeds 255 octets.
    NameTooLong,
}

impl NormalizationError {
    /// Returns a stable diagnostic code for callers and evidence lookup.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InputLimit => "input_limit",
            Self::Empty => "empty_name",
            Self::InvalidIdna => "invalid_idna",
            Self::ContextO(error) => error.code(),
            Self::EmptyLabel => "empty_label",
            Self::LabelTooLong => "label_too_long",
            Self::NameTooLong => "name_too_long",
        }
    }

    /// Describes the input failure without claiming a registry prohibition.
    pub const fn message(self) -> &'static str {
        match self {
            Self::InputLimit => "Input limit: domain exceeds 4096 UTF-8 bytes",
            Self::Empty => "DNS syntax: empty domain",
            Self::InvalidIdna => "DNS syntax: invalid IDNA input",
            Self::ContextO(_) => "DNS syntax: invalid IDNA registration context",
            Self::EmptyLabel => "DNS syntax: empty label",
            Self::LabelTooLong => "DNS syntax: label exceeds 63 octets",
            Self::NameTooLong => "DNS syntax: wire name exceeds 255 octets",
        }
    }
}

/// A validated canonical A-label name with lazy Unicode decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalName<'a> {
    /// ASCII/Punycode identity; unchanged lowercase ASCII can remain borrowed.
    ascii: Cow<'a, str>,
}

impl<'a> CanonicalName<'a> {
    /// Maps a prospective registration name under the pinned strict UTS 46 contract.
    ///
    /// Accepts surrounding whitespace and one terminal root separator, including
    /// UTS 46 dot equivalents. Every ASCII wire label and the total wire name are
    /// bounded independently of any additional registry Unicode-length policy.
    ///
    /// # Errors
    ///
    /// Returns a stable input, IDNA, or DNS-bound diagnostic for invalid input.
    pub fn new(input: &'a str) -> Result<Self, NormalizationError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(NormalizationError::InputLimit);
        }
        let trimmed = input.trim();
        let name = match trimmed.char_indices().next_back() {
            Some((index, '.' | '\u{3002}' | '\u{ff0e}' | '\u{ff61}')) => &trimmed[..index],
            _ => trimmed,
        };
        if name.is_empty() {
            return Err(NormalizationError::Empty);
        }
        let ascii = Uts46::new()
            .to_ascii(
                name.as_bytes(),
                AsciiDenyList::STD3,
                Hyphens::Check,
                DnsLength::Ignore,
            )
            .map_err(|_| NormalizationError::InvalidIdna)?;
        let mut wire_length = 1_usize;
        let mut needs_context = false;
        for label in ascii.split('.') {
            if label.is_empty() {
                return Err(NormalizationError::EmptyLabel);
            }
            if label.len() > 63 {
                return Err(NormalizationError::LabelTooLong);
            }
            wire_length += 1 + label.len();
            needs_context |= label.starts_with("xn--");
        }
        if wire_length > 255 {
            return Err(NormalizationError::NameTooLong);
        }
        if needs_context {
            let (unicode, status) =
                Uts46::new().to_unicode(ascii.as_bytes(), AsciiDenyList::STD3, Hyphens::Check);
            status.map_err(|_| NormalizationError::InvalidIdna)?;
            registration_context::validate(&unicode).map_err(NormalizationError::ContextO)?;
        }
        Ok(Self { ascii })
    }

    /// Own the canonical identity for returned results that outlive the input.
    pub fn into_owned(self) -> CanonicalName<'static> {
        CanonicalName {
            ascii: Cow::Owned(self.ascii.into_owned()),
        }
    }

    /// Returns the canonical name without a terminal root dot.
    pub fn ascii(&self) -> &str {
        &self.ascii
    }

    /// Decodes canonical U-labels rather than reusing the original input.
    ///
    /// # Errors
    ///
    /// Returns an IDNA error if decoding or round-trip validation fails.
    pub fn unicode(&self) -> Result<Cow<'_, str>, NormalizationError> {
        if !self.ascii.split('.').any(|label| label.starts_with("xn--")) {
            return Ok(Cow::Borrowed(self.ascii()));
        }
        let (unicode, status) =
            Uts46::new().to_unicode(self.ascii.as_bytes(), AsciiDenyList::STD3, Hyphens::Check);
        status.map_err(|_| NormalizationError::InvalidIdna)?;
        let round_trip = CanonicalName::new(&unicode)?;
        if round_trip.ascii() != self.ascii() {
            return Err(NormalizationError::InvalidIdna);
        }
        Ok(unicode)
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalName, NormalizationError, MAX_INPUT_BYTES};
    use std::borrow::Cow;

    #[test]
    fn canonical_identity_and_unicode_are_input_independent() {
        let expected = CanonicalName::new("bücher.de").unwrap();
        for input in [
            "BÜCHER.DE",
            "xn--bcher-kva.de",
            "bu\u{308}cher.de",
            "bücher。de",
        ] {
            let actual = CanonicalName::new(input).unwrap();
            assert_eq!(actual.ascii(), expected.ascii());
            assert_eq!(actual.unicode().unwrap(), "bücher.de");
        }
        assert_eq!(
            CanonicalName::new("faß.de").unwrap().ascii(),
            "xn--fa-hia.de"
        );
        assert_ne!(CanonicalName::new("faß.de").unwrap().ascii(), "fass.de");
    }

    #[test]
    fn lowercase_ascii_is_borrowed_and_normalization_is_idempotent() {
        let canonical = CanonicalName::new("  example.com.  ").unwrap();
        assert!(matches!(canonical.ascii, Cow::Borrowed(_)));
        assert_eq!(
            CanonicalName::new(canonical.ascii()).unwrap().ascii(),
            "example.com"
        );
        assert_eq!(canonical.unicode().unwrap(), "example.com");
        assert_eq!(
            CanonicalName::new("example.com。 ").unwrap().ascii(),
            "example.com"
        );
    }

    #[test]
    fn invalid_input_cannot_be_sanitized_into_a_different_domain() {
        for input in [
            "example.com..",
            "example.com.。",
            "example..com",
            "_example.com",
            "-example.com",
            "example-.com",
            "ab--cd.com",
            "xn--0.com",
            "xn--u-ccb.com",
            "\u{301}example.com",
            "a\u{200d}b.com",
            "aא.com",
        ] {
            assert!(CanonicalName::new(input).is_err(), "accepted {input:?}");
        }
        assert_eq!(CanonicalName::new("  "), Err(NormalizationError::Empty));
        assert_eq!(
            CanonicalName::new(&" ".repeat(MAX_INPUT_BYTES + 1)),
            Err(NormalizationError::InputLimit)
        );
    }

    #[test]
    fn dns_wire_limits_include_length_bytes_and_root() {
        assert!(CanonicalName::new(&format!("{}.com", "a".repeat(63))).is_ok());
        assert_eq!(
            CanonicalName::new(&format!("{}.com", "a".repeat(64))),
            Err(NormalizationError::LabelTooLong)
        );
        let at_limit = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert!(CanonicalName::new(&at_limit).is_ok());
        assert!(CanonicalName::new(&format!("{at_limit}.")).is_ok());
        assert_eq!(
            CanonicalName::new(&format!("{at_limit}d")),
            Err(NormalizationError::NameTooLong)
        );
    }
}
