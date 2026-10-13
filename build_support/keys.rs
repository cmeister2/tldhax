//! Source identity, canonical keys and temporal evidence validation.

use super::schema::{Assertion, Knowledge};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
/// Assertion activation and effective knowledge at the pinned evaluation date.
pub struct Status {
    /// Whether the assertion is current, reviewed and applicable for enforcement.
    pub active: bool,
    /// Effective evidence state after inactive reviewed claims are downgraded.
    pub knowledge: Knowledge,
    /// Stable explanation of inactivity, absent for active assertions.
    pub reason: Option<String>,
}

/// Check a Gregorian calendar date with fixed ISO spelling.
///
/// # Errors
/// Rejects malformed or impossible calendar dates.
#[allow(clippy::manual_is_multiple_of)] // Keep the compiler usable before Rust 1.87.
pub fn date(value: &str) -> Result<(), String> {
    let fields = value.split('-').collect::<Vec<_>>();
    if fields.len() != 3
        || fields[0].len() != 4
        || fields[1].len() != 2
        || fields[2].len() != 2
        || !fields.iter().all(|x| x.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("invalid YYYY-MM-DD date: {value}"));
    }
    let year: u16 = fields[0].parse().map_err(|_| "invalid date year")?;
    let month: usize = fields[1].parse().map_err(|_| "invalid date month")?;
    let day: u8 = fields[2].parse().map_err(|_| "invalid date day")?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        0,
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if year == 0 || month == 0 || month > 12 || day == 0 || day > days[month] {
        return Err("invalid calendar date".into());
    }
    Ok(())
}

/// Canonicalise a policy key using the runtime's exact normalizer.
///
/// # Errors
/// Rejects invalid IDNA and unsupported wildcard or exception selectors.
pub fn selector(value: &str) -> Result<String, String> {
    let wildcard = value.starts_with("*.");
    let body = if wildcard { &value[2..] } else { value };
    if body.contains('*') || body.starts_with('!') {
        return Err("unsupported policy selector".into());
    }
    let key = crate::normalization::CanonicalName::new(body)
        .map_err(|e| format!("invalid policy key: {}", e.code()))?
        .ascii()
        .to_owned();
    Ok(if wildcard { format!("*.{key}") } else { key })
}

/// Validate stable record identity and uniqueness.
///
/// # Errors
/// Rejects duplicate, empty or non-identifier record keys.
pub fn unique<T>(items: &[T], key: impl Fn(&T) -> &str, kind: &str) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for item in items {
        let id = key(item);
        if id.is_empty()
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            || !seen.insert(id)
        {
            return Err(format!("invalid or duplicate {kind} identity: {id}"));
        }
    }
    Ok(())
}

/// Resolve explicit commencement/current attestation against the pinned date.
///
/// # Errors
/// Rejects invalid dates or inconsistent applicability intervals.
pub fn temporal(
    from: Option<&str>,
    on: Option<&str>,
    until: Option<&str>,
    evaluation_date: &str,
) -> Result<Option<&'static str>, String> {
    for value in [from, on, until].into_iter().flatten() {
        date(value)?;
    }
    if from.is_some_and(|f| until.is_some_and(|u| u <= f))
        || on.is_some_and(|o| from.is_some_and(|f| o < f) || until.is_some_and(|u| o >= u))
    {
        return Err("inconsistent applicability interval".into());
    }
    let Some(start) = from.or(on) else {
        return Ok(Some("applicability_unknown"));
    };
    if start > evaluation_date {
        return Ok(Some("future_effective"));
    }
    if until.is_some_and(|end| evaluation_date >= end) {
        return Ok(Some("no_longer_effective"));
    }
    Ok(None)
}

/// Resolve review status and activation without consulting the local clock.
///
/// # Errors
/// Rejects malformed temporal applicability metadata.
pub fn assertion_status(assertion: &Assertion, evaluation_date: &str) -> Result<Status, String> {
    let mut reason = temporal(
        assertion.effective_from.as_deref(),
        assertion.applicable_on.as_deref(),
        assertion.effective_until.as_deref(),
        evaluation_date,
    )?;
    if reason.is_none() && assertion.reviewed_on.as_str() > evaluation_date {
        reason = Some("future_review");
    }
    if reason.is_none() && assertion.review_due.as_str() < evaluation_date {
        reason = Some("review_expired");
    }
    if reason.is_none()
        && !matches!(
            assertion.knowledge,
            Knowledge::Reviewed | Knowledge::NotApplicable
        )
    {
        reason = Some("research_unresolved");
    }
    let knowledge = if reason.is_some()
        && matches!(
            assertion.knowledge,
            Knowledge::Reviewed | Knowledge::NotApplicable
        ) {
        Knowledge::Unknown
    } else {
        assertion.knowledge
    };
    Ok(Status {
        active: reason.is_none(),
        knowledge,
        reason: reason.map(str::to_owned),
    })
}
