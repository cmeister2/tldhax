//! Immutable protocol provenance for bounded normalizer failures.

use crate::normalization::NormalizationError;

/// Stable protocol-catalog identities matching the documented failure dimension.
pub(crate) fn sources(error: NormalizationError) -> &'static [&'static str] {
    match error {
        NormalizationError::InputLimit => &[],
        NormalizationError::ContextO(_) => &["rfc-5892"],
        NormalizationError::EmptyLabel
        | NormalizationError::LabelTooLong
        | NormalizationError::NameTooLong => &["rfc-1035"],
        NormalizationError::Empty => &["rfc-5891"],
        NormalizationError::InvalidIdna => &[
            "uts46-rev33",
            "rfc-1123",
            "rfc-5890",
            "rfc-5891",
            "rfc-5892",
        ],
    }
}

/// Immutable normalizer specification and exact controlling contextual clauses.
pub(crate) fn references(error: NormalizationError) -> &'static [&'static str] {
    use crate::registration_context::ContextOError::*;
    match error {
        NormalizationError::InputLimit => &[],
        NormalizationError::ContextO(MiddleDot) => {
            &["https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A.3"]
        }
        NormalizationError::ContextO(GreekNumeralSign) => {
            &["https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A.4"]
        }
        NormalizationError::ContextO(HebrewGeresh) => {
            &["https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A.5"]
        }
        NormalizationError::ContextO(HebrewGershayim) => {
            &["https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A.6"]
        }
        NormalizationError::ContextO(KatakanaMiddleDot) => {
            &["https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A.7"]
        }
        NormalizationError::ContextO(MixedArabicIndicDigits) => &[
            "https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A.8",
            "https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A.9",
        ],
        NormalizationError::EmptyLabel
        | NormalizationError::LabelTooLong
        | NormalizationError::NameTooLong => &[
            "https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4",
            "https://www.rfc-editor.org/rfc/rfc1035.html#section-3.1",
        ],
        NormalizationError::Empty => &["https://www.rfc-editor.org/rfc/rfc5891.html#section-4.2"],
        NormalizationError::InvalidIdna => &[
            "https://www.unicode.org/reports/tr46/tr46-33.html",
            "https://www.rfc-editor.org/rfc/rfc5891.html#section-4",
        ],
    }
}
