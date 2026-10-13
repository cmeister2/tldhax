//! Bound predicate work and validate referenced sets, tables and typed facts.

use super::predicates::{Basis, Fact, FactKind, Predicate, Value};
use super::schema::{Assertion, Class, Document};
use std::collections::BTreeMap;

/// Check one fact literal against its declared type, syntax and finite enumeration.
fn value_matches(value: &Value, fact: &Fact) -> bool {
    match (value, fact.kind) {
        (Value::Boolean(_), FactKind::Boolean) => true,
        (Value::String(s), FactKind::String | FactKind::StringSet) => {
            s.len() <= 512 && (fact.allowed_values.is_empty() || fact.allowed_values.contains(s))
        }
        _ => false,
    }
}

/// Check finite predicate budgets, label components and typed asset references.
///
/// # Errors
/// Rejects excessive depth or work, invalid literals and lengths, missing assets,
/// or comparisons incompatible with the declared applicant fact schema.
pub fn validate(assertion: &Assertion, document: &Document) -> Result<(), String> {
    let Some(predicate) = &assertion.predicate else {
        return Ok(());
    };
    let facts = document
        .facts
        .iter()
        .map(|f| (f.field.as_str(), f))
        .collect::<BTreeMap<_, _>>();
    let mut stack = vec![(predicate, 1)];
    let mut count = 0;
    while let Some((node, depth)) = stack.pop() {
        count += 1;
        if depth > 16 || count > 128 {
            return Err("predicate depth/node budget exceeded".into());
        }
        if node
            .component()
            .is_some_and(|component| assertion.forms.iter().any(|count| component >= *count))
        {
            return Err("predicate component exceeds assertion form".into());
        }
        match node {
            Predicate::All { predicates } | Predicate::Any { predicates }
                if predicates.is_empty() =>
            {
                return Err("empty boolean predicate".into())
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
                if !document.label_sets.iter().any(|s| s.id == *set_id) =>
            {
                return Err("missing named label set".into())
            }
            Predicate::Idn { .. } if assertion.input_class != Class::Idn => {
                return Err("IDN table predicate requires explicit IDN input class".into())
            }
            Predicate::Idn { profile_id, .. }
                if !document.idn_profiles.iter().any(|s| s.id == *profile_id) =>
            {
                return Err("missing IDN profile".into())
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
                positions, value, ..
            } if positions.is_empty()
                || positions.len() > 63
                || positions.iter().any(|p| *p > 62)
                || positions.windows(2).any(|p| p[0] >= p[1])
                || positions.len() != value.chars().count() =>
            {
                return Err("invalid fixed-position pattern".into())
            }
            Predicate::FieldEquals { field, value } => {
                let fact = facts
                    .get(field.as_str())
                    .ok_or("undeclared typed profile field")?;
                if !value_matches(value, fact) {
                    return Err("profile fact comparison type/value mismatch".into());
                }
            }
            Predicate::FieldIn { field, values } => {
                let fact = facts
                    .get(field.as_str())
                    .ok_or("undeclared typed profile field")?;
                if values.is_empty()
                    || values.len() > 256
                    || !values.iter().all(|v| value_matches(v, fact))
                {
                    return Err("profile membership type/value mismatch".into());
                }
            }
            Predicate::NameEqualsField { field, .. } => {
                let fact = facts
                    .get(field.as_str())
                    .ok_or("undeclared typed name relationship field")?;
                if fact.kind == FactKind::Boolean {
                    return Err("name relationship requires String or StringSet".into());
                }
            }
            _ => (),
        }
        stack.extend(node.children().iter().map(|child| (child, depth + 1)));
    }
    Ok(())
}
