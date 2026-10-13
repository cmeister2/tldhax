//! Validate factual research denominators against pinned root and PSL selectors.

use std::collections::BTreeSet;

/// Count discovered namespaces and PSL sections after checking the research denominator.
///
/// ICANN exact and wildcard rules add selectors; exceptions and private routes
/// do not enlarge the registry research namespace set.
///
/// # Errors
/// Rejects malformed or noncanonical PSL rules, duplicates, unsupported sections
/// and research selectors that differ from the pinned root/ICANN discovery set.
pub(super) fn counts(
    active: &BTreeSet<String>,
    psl: &serde_json::Value,
    queue: &serde_json::Value,
) -> Result<(usize, usize, usize), String> {
    let mut discovered = active.clone();
    let mut rules = BTreeSet::new();
    let (mut icann, mut private) = (0, 0);
    for row in psl["rules"].as_array().ok_or("PSL rules missing")? {
        let suffix = row["suffix"].as_str().ok_or("PSL suffix missing")?;
        let canonical =
            crate::normalization::CanonicalName::new(suffix).map_err(|e| e.code().to_owned())?;
        let kind = row["kind"].as_str().ok_or("PSL kind missing")?;
        let prefix = match kind {
            "exact" => "",
            "wildcard" => "*.",
            "exception" => "!",
            _ => return Err("unsupported PSL rule kind".into()),
        };
        let selector = format!("{prefix}{suffix}");
        let original = row["rule"].as_str().ok_or("PSL original rule missing")?;
        let original = original
            .strip_prefix(prefix)
            .ok_or("PSL rule prefix mismatch")?;
        let original =
            crate::normalization::CanonicalName::new(original).map_err(|e| e.code().to_owned())?;
        let section = row["section"].as_str().ok_or("PSL section missing")?;
        if canonical.ascii() != suffix
            || original.ascii() != suffix
            || !rules.insert((section.to_owned(), selector.clone()))
        {
            return Err("noncanonical or duplicate PSL inventory rule".into());
        }
        match section {
            "ICANN" => {
                icann += 1;
                if kind != "exception" {
                    discovered.insert(selector);
                }
            }
            "PRIVATE" => private += 1,
            _ => return Err("unsupported PSL inventory section".into()),
        }
    }
    let mut actual = BTreeSet::new();
    for group in queue["groups"].as_array().ok_or("research queue missing")? {
        for row in group["namespaces"]
            .as_array()
            .ok_or("research selector list missing")?
        {
            let selector = row["selector"]
                .as_str()
                .ok_or("research selector missing")?;
            if !actual.insert(selector.to_owned()) {
                return Err("duplicate research inventory selector".into());
            }
        }
    }
    if actual != discovered {
        return Err("research inventory disagrees with pinned root/ICANN selectors".into());
    }
    Ok((actual.len(), icann, private))
}

/// Validate a fixed-width ISO inventory retrieval date against the Gregorian calendar.
///
/// # Errors
/// Rejects malformed dates, year zero and impossible month/day combinations.
pub(super) fn date(value: &str) -> Result<(), String> {
    let fields = value.split('-').collect::<Vec<_>>();
    if fields.len() != 3
        || fields[0].len() != 4
        || fields[1].len() != 2
        || fields[2].len() != 2
        || !fields.iter().all(|f| f.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("invalid inventory date".into());
    }
    let year: u16 = fields[0].parse().map_err(|_| "invalid inventory year")?;
    let month: usize = fields[1].parse().map_err(|_| "invalid inventory month")?;
    let day: u8 = fields[2].parse().map_err(|_| "invalid inventory day")?;
    #[allow(clippy::manual_is_multiple_of)]
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
        return Err("invalid inventory calendar date".into());
    }
    Ok(())
}
