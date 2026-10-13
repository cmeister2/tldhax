//! Minimal immutable namespace exclusions.

/// A non-public special-use name and its descendant scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecialUse {
    /// Canonical designated complete name, possibly containing multiple labels.
    pub name: &'static str,
    /// Whether the exclusion extends to descendants.
    pub descendants: bool,
}
