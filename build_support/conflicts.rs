//! Bounded propositional conflict analysis for typed effective assertions.

use super::predicates::Predicate;
use super::schema::{Assertion, Effect};
use std::collections::{BTreeMap, BTreeSet};

/// Serialize a non-boolean predicate to a stable propositional identity.
///
/// # Panics
/// Panics if serialization of the typed scalar predicate unexpectedly fails.
fn atom(predicate: &Predicate) -> String {
    serde_json::to_string(predicate).expect("typed predicate serialisation")
}

/// Collect distinct scalar predicate identities beneath boolean operators.
fn atoms(predicate: &Predicate, values: &mut BTreeSet<String>) {
    match predicate {
        Predicate::Constant { .. } => (),
        Predicate::All { predicates } | Predicate::Any { predicates } => {
            for child in predicates {
                atoms(child, values);
            }
        }
        Predicate::Not { predicate } => atoms(predicate, values),
        _ => {
            values.insert(atom(predicate));
        }
    }
}

/// Evaluate an expression under a partial propositional assignment.
///
/// Returns `None` while unset atoms can still change the expression’s truth.
///
/// # Panics
/// Panics if the index omits a scalar atom or its position lies outside `values`.
fn truth(
    predicate: &Predicate,
    index: &BTreeMap<String, usize>,
    values: &[Option<bool>],
) -> Option<bool> {
    match predicate {
        Predicate::Constant { value } => Some(*value),
        Predicate::Not { predicate } => truth(predicate, index, values).map(|v| !v),
        Predicate::All { predicates } | Predicate::Any { predicates } => {
            let all = matches!(predicate, Predicate::All { .. });
            let mut unknown = false;
            for child in predicates {
                match truth(child, index, values) {
                    Some(value) if value != all => return Some(!all),
                    None => unknown = true,
                    _ => (),
                }
            }
            if unknown {
                None
            } else {
                Some(all)
            }
        }
        _ => values[index[&atom(predicate)]],
    }
}

/// Search bounded truth assignments satisfying the selected require and deny effects.
///
/// # Errors
/// Returns an error if the search budget is exhausted or an assignment is inconsistent.
///
/// # Panics
/// Panics if an assertion lacks a predicate or an atom is absent from the assignment index.
fn satisfy(
    assertions: &[&Assertion],
    index: &BTreeMap<String, usize>,
    values: &mut [Option<bool>],
    budget: &mut usize,
) -> Result<bool, String> {
    if *budget == 0 {
        return Err("conflict analysis budget exceeded; split policy scope".into());
    }
    *budget -= 1;
    let mut unresolved = false;
    for assertion in assertions {
        let required = assertion.effect == Effect::Require;
        match truth(assertion.predicate.as_ref().unwrap(), index, values) {
            Some(value) if value != required => return Ok(false),
            None => unresolved = true,
            _ => (),
        }
    }
    if !unresolved {
        return Ok(true);
    }
    let position = values
        .iter()
        .position(Option::is_none)
        .ok_or("invalid conflict assignment")?;
    for value in [false, true] {
        values[position] = Some(value);
        if satisfy(assertions, index, values, budget)? {
            values[position] = None;
            return Ok(true);
        }
    }
    values[position] = None;
    Ok(false)
}

/// Reject simultaneous effective assertions with no consistent propositional assignment.
///
/// Individually unconditional closure is valid policy and does not indicate a conflict.
///
/// # Errors
/// Rejects missing predicates, more than twenty scalar atoms, exhausted search
/// budgets or a combination of independently satisfiable rules that conflicts.
pub fn check(assertions: &[&Assertion]) -> Result<(), String> {
    if assertions.len() < 2 {
        return Ok(());
    }
    let mut set = BTreeSet::new();
    for assertion in assertions {
        atoms(
            assertion
                .predicate
                .as_ref()
                .ok_or("missing conflict predicate")?,
            &mut set,
        );
    }
    if set.len() > 20 {
        return Err("conflict atom budget exceeded; split policy scope".into());
    }
    let index = set
        .into_iter()
        .enumerate()
        .map(|(i, key)| (key, i))
        .collect::<BTreeMap<_, _>>();
    let mut values = vec![None; index.len()];
    // Explicit unconditional closure is supported; it is not an author conflict.
    for assertion in assertions {
        if !satisfy(&[*assertion], &index, &mut values, &mut 65_536)? {
            return Ok(());
        }
    }
    if !satisfy(assertions, &index, &mut values, &mut 65_536)? {
        return Err("simultaneously enforceable propositional conflict".into());
    }
    Ok(())
}
