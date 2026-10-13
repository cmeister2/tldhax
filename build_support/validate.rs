//! Bound direct predicates and check ordinary schema/reference integrity.

use super::predicates::{Basis, Fact, FactKind, Predicate, Value};
use super::schema::Class;
use super::CompiledInputs;
use crate::normalization::CanonicalName;
use std::collections::BTreeSet;

/// Validate canonical identities, uniqueness, assets and finite predicate work.
///
/// # Errors
/// Rejects malformed, ambiguous, unsupported or inconsistent direct inputs.
pub fn validate(input: &mut CompiledInputs) -> Result<(), String> {
    if input.version.is_empty() || input.version.len() > 128 || input.version.contains(['\n', '\r'])
    {
        return Err("dataset version must be a short single line".into());
    }
    for root in &input.roots {
        canonical(root)?;
        if root.contains('.') {
            return Err("root identity contains multiple labels".into());
        }
    }
    unique(&mut input.roots, "active roots")?;
    for selector in &mut input.routes {
        let (marker, base) = if let Some(base) = selector.strip_prefix("*.") {
            ("*.", base)
        } else if let Some(base) = selector.strip_prefix('!') {
            ("!", base)
        } else {
            ("", selector.as_str())
        };
        let canonical = CanonicalName::new(base)
            .map_err(|_| "invalid discovery selector")?
            .ascii()
            .to_owned();
        *selector = format!("{marker}{canonical}");
        selector_key(selector, true)?;
    }
    unique(&mut input.routes, "ICANN routes")?;
    input
        .special_use
        .sort_by(|left, right| left.name.cmp(&right.name));
    let mut special_names = BTreeSet::new();
    for special in &input.special_use {
        canonical(&special.name)?;
        if !special_names.insert(&special.name) {
            return Err("duplicate special-use name".into());
        }
    }
    input
        .facts
        .sort_by(|left, right| left.field.cmp(&right.field));
    let mut fields = BTreeSet::new();
    for fact in &mut input.facts {
        identifier(&fact.field)?;
        if !fields.insert(&fact.field) {
            return Err("duplicate profile field".into());
        }
        if fact.kind == FactKind::Boolean
            && (!fact.allowed_values.is_empty() || fact.string_format.is_some())
        {
            return Err("boolean facts cannot have string constraints".into());
        }
        unique(&mut fact.allowed_values, "profile enumeration")?;
        if fact.allowed_values.iter().any(|value| {
            value.len() > 1024
                || fact
                    .string_format
                    .is_some_and(|format| !format.matches(value))
        }) {
            return Err("invalid profile enumeration".into());
        }
    }
    input
        .label_sets
        .sort_by(|left, right| left.id.cmp(&right.id));
    let mut set_ids = BTreeSet::new();
    for set in &mut input.label_sets {
        identifier(&set.id)?;
        if !set_ids.insert(&set.id) {
            return Err("duplicate label-set identity".into());
        }
        for label in &mut set.labels {
            let name = CanonicalName::new(label)
                .map_err(|_| "invalid shared label")?
                .ascii()
                .to_owned();
            if name.contains('.') {
                return Err("shared label contains multiple components".into());
            }
            *label = name;
        }
        unique(&mut set.labels, "shared labels")?;
    }
    input
        .idn_profiles
        .sort_by(|left, right| left.id.cmp(&right.id));
    let mut table_ids = BTreeSet::new();
    for profile in &mut input.idn_profiles {
        identifier(&profile.id)?;
        if !table_ids.insert(profile.id.clone()) {
            return Err("duplicate IDN table identity".into());
        }
        super::idn::validate(profile)?;
    }
    input.known_suffixes.extend(input.roots.iter().cloned());
    input.known_suffixes.extend(
        input
            .routes
            .iter()
            .filter(|selector| !selector.starts_with('!'))
            .cloned(),
    );
    input
        .known_suffixes
        .extend(input.policies.iter().map(|policy| policy.selector.clone()));
    for selector in &mut input.known_suffixes {
        let (marker, base) = selector
            .strip_prefix("*.")
            .map_or(("", selector.as_str()), |base| ("*.", base));
        let name = CanonicalName::new(base)
            .map_err(|_| format!("invalid inventory namespace: {selector}"))?
            .ascii()
            .to_owned();
        *selector = format!("{marker}{name}");
    }
    input.known_suffixes.sort();
    input.known_suffixes.dedup();
    input.policies.sort_by(|left, right| {
        left.selector
            .cmp(&right.selector)
            .then(left.form.len().cmp(&right.form.len()))
    });
    let mut ids = BTreeSet::new();
    let mut forms = BTreeSet::new();
    for policy in &input.policies {
        identifier(&policy.id)?;
        selector_key(&policy.selector, false)?;
        if !ids.insert(&policy.id) || !forms.insert((&policy.selector, policy.form.len())) {
            return Err("duplicate policy identity or ambiguous namespace/form".into());
        }
        if policy.form.is_empty()
            || policy.form.len() > 16
            || policy
                .form
                .iter()
                .any(|role| role.is_empty() || role.len() > 128)
        {
            return Err("policy must describe one bounded nonempty applicant form".into());
        }
        if policy.requirements.len() > 128 || policy.gaps.len() > 128 {
            return Err("policy check budget exceeded".into());
        }
        if policy.source_notes.iter().any(|note| note.len() > 16384) {
            return Err("unbounded maintainer note".into());
        }
        for requirement in &policy.requirements {
            diagnostic(&requirement.code, &requirement.message)?;
            if requirement
                .source_notes
                .iter()
                .any(|note| note.len() > 16384)
            {
                return Err("unbounded requirement maintainer note".into());
            }
            predicate(
                &requirement.predicate,
                requirement.input_class,
                policy.form.len(),
                input,
            )?;
        }
        for gap in &policy.gaps {
            diagnostic(&gap.code, &gap.message)?;
            if let Some(condition) = &gap.predicate {
                predicate(condition, gap.input_class, policy.form.len(), input)?;
            }
        }
    }
    Ok(())
}

/// Check a short stable authoring or interface identifier.
fn identifier(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("invalid record identifier".into());
    }
    Ok(())
}

/// Require already canonical namespace keys so accidental remapping is visible.
fn canonical(value: &str) -> Result<(), String> {
    let name = CanonicalName::new(value).map_err(|_| "invalid namespace key")?;
    if name.ascii() != value {
        return Err(format!("noncanonical namespace key: {value}"));
    }
    Ok(())
}

/// Validate a namespace selector, retaining explicit wildcard or exception semantics.
fn selector_key(value: &str, exceptions: bool) -> Result<(), String> {
    let base = value
        .strip_prefix("*.")
        .or_else(|| {
            if exceptions {
                value.strip_prefix('!')
            } else {
                None
            }
        })
        .unwrap_or(value);
    canonical(base)?;
    if base.contains('*') || base.contains('!') {
        return Err("invalid selector marker".into());
    }
    Ok(())
}

/// Sort a vector and reject duplicate identities rather than hiding ambiguous inputs.
fn unique(values: &mut [String], description: &str) -> Result<(), String> {
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(format!("duplicate {description}"));
    }
    Ok(())
}

/// Check that an interface reason has a stable code and useful bounded text.
fn diagnostic(code: &str, message: &str) -> Result<(), String> {
    identifier(code)?;
    if message.trim().is_empty() || message.len() > 4096 {
        return Err("missing or unbounded reason text".into());
    }
    Ok(())
}

/// Check one typed fact literal against its declared type and string constraints.
fn value_matches(value: &Value, fact: &Fact) -> bool {
    match (value, fact.kind) {
        (Value::Boolean(_), FactKind::Boolean) => true,
        (Value::String(value), FactKind::String | FactKind::StringSet) => {
            value.len() <= 1024
                && !fact
                    .string_format
                    .is_some_and(|format| !format.matches(value))
                && (fact.allowed_values.is_empty() || fact.allowed_values.contains(value))
        }
        _ => false,
    }
}

/// Validate finite work, existing shared assets and typed fact references.
fn predicate(
    expression: &Predicate,
    class: Class,
    form: usize,
    input: &CompiledInputs,
) -> Result<(), String> {
    let mut stack = vec![(expression, 1)];
    let mut count = 0;
    while let Some((node, depth)) = stack.pop() {
        count += 1;
        if depth > 16 || count > 128 {
            return Err("predicate depth/node budget exceeded".into());
        }
        if node
            .component()
            .is_some_and(|component| usize::from(component) >= form)
        {
            return Err("predicate component exceeds policy form".into());
        }
        match node {
            Predicate::Unsupported { .. } => {
                return Err("unsupported expressions belong in explicit gaps".into())
            }
            Predicate::All { predicates } | Predicate::Any { predicates }
                if predicates.is_empty() =>
            {
                return Err("empty boolean expression".into())
            }
            Predicate::LabelLength { min, max, .. } if min > max || *max > 4096 => {
                return Err("invalid or unbounded registry length".into())
            }
            Predicate::LabelMinimum { min, .. } if *min > 4096 => {
                return Err("unbounded registry minimum".into())
            }
            Predicate::LabelMaximum { max, .. } if *max > 4096 => {
                return Err("unbounded registry maximum".into())
            }
            Predicate::LabelInSet { set_id, .. }
                if !input.label_sets.iter().any(|set| set.id == *set_id) =>
            {
                return Err("missing shared label set".into())
            }
            Predicate::Idn { .. } if class != Class::Idn => {
                return Err("IDN predicate requires explicit IDN input class".into())
            }
            Predicate::Idn { profile_id, .. }
                if !input
                    .idn_profiles
                    .iter()
                    .any(|profile| profile.id == *profile_id) =>
            {
                return Err("missing adopted IDN table".into())
            }
            Predicate::LabelPattern { value, .. } if value.is_empty() || value.len() > 256 => {
                return Err("empty or unbounded literal pattern".into())
            }
            Predicate::LabelPattern {
                value,
                basis: Basis::Ascii,
                ..
            } if !value.is_ascii() => return Err("non-ASCII literal in ASCII pattern".into()),
            Predicate::LabelPositions {
                positions,
                value,
                basis,
                ..
            } if positions.is_empty()
                || positions.len() > 63
                || positions.iter().any(|position| *position > 62)
                || positions.windows(2).any(|pair| pair[0] >= pair[1])
                || positions.len() != value.chars().count()
                || *basis == Basis::Ascii && !value.is_ascii() =>
            {
                return Err("invalid fixed-position pattern".into())
            }
            Predicate::FieldEquals { field, value } => {
                let fact = input
                    .facts
                    .iter()
                    .find(|fact| fact.field == *field)
                    .ok_or("undeclared profile field")?;
                if !value_matches(value, fact) {
                    return Err("profile comparison type/value mismatch".into());
                }
            }
            Predicate::FieldIn { field, values } => {
                let fact = input
                    .facts
                    .iter()
                    .find(|fact| fact.field == *field)
                    .ok_or("undeclared profile field")?;
                if values.is_empty()
                    || values.len() > 256
                    || !values.iter().all(|value| value_matches(value, fact))
                {
                    return Err("profile membership type/value mismatch".into());
                }
            }
            Predicate::NameEqualsField { field, .. } => {
                let fact = input
                    .facts
                    .iter()
                    .find(|fact| fact.field == *field)
                    .ok_or("undeclared name relationship field")?;
                if fact.kind == FactKind::Boolean {
                    return Err("name relationship requires string or string set".into());
                }
            }
            _ => (),
        }
        stack.extend(node.children().iter().map(|child| (child, depth + 1)));
    }
    Ok(())
}
