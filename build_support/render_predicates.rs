//! Emit finite predicates as Rust expressions containing only static literals.

use super::predicates::{Predicate, Value};

/// Render a static string slice using Rust debug literals to preserve exact Unicode text.
pub fn strings(values: &[String]) -> String {
    format!(
        "&[{}]",
        values
            .iter()
            .map(|v| format!("{v:?}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Render an optional static string using escaped Rust literals.
pub fn option(value: Option<&str>) -> String {
    value.map_or_else(|| "None".to_owned(), |v| format!("Some({v:?})"))
}

/// Render one typed fact literal as a static runtime value expression.
pub fn value(value: &Value) -> String {
    match value {
        Value::Boolean(v) => format!("FactValue::Boolean({v})"),
        Value::String(v) => format!("FactValue::String({v:?})"),
    }
}

/// Render a validated finite predicate as a static runtime expression.
///
/// # Errors
/// Returns an error when an unsupported predicate is encountered in the expression tree.
pub fn render(predicate: &Predicate) -> Result<String, String> {
    Ok(match predicate {
        Predicate::Constant { value } => format!("Predicate::Constant({value})"),
        Predicate::All { predicates } | Predicate::Any { predicates } => {
            let kind = if matches!(predicate,Predicate::All {..}) { "All" } else { "Any" };
            let children = predicates.iter().map(render).collect::<Result<Vec<_>,_>>()?.join(",");
            format!("Predicate::{kind}(&[{children}])")
        }
        Predicate::Not { predicate } => format!("Predicate::Not(&{})",render(predicate)?),
        Predicate::LabelLength {component,min,max,basis} => format!("Predicate::LabelLength{{component:{component},min:{min},max:{max},basis:LengthMeasure::{basis:?}}}"),
        Predicate::LabelMinimum {component,min,basis} => format!("Predicate::LabelMinimum{{component:{component},min:{min},basis:LengthMeasure::{basis:?}}}"),
        Predicate::LabelMaximum {component,max,basis} => format!("Predicate::LabelMaximum{{component:{component},max:{max},basis:LengthMeasure::{basis:?}}}"),
        Predicate::LabelInSet {component,set_id} => format!("Predicate::LabelInSet{{component:{component},set_id:{set_id:?}}}"),
        Predicate::AsciiOnly {component} => format!("Predicate::AsciiOnly{{component:{component}}}"),
        Predicate::LabelPattern {component,pattern,value,basis} => format!("Predicate::LabelPattern{{component:{component},pattern:PatternKind::{pattern:?},value:{value:?},basis:LengthMeasure::{basis:?}}}"),
        Predicate::LabelPositions {component,positions,value,basis} => format!("Predicate::LabelPositions{{component:{component},positions:&{positions:?},value:{value:?},basis:LengthMeasure::{basis:?}}}"),
        Predicate::Idn {component,profile_id} => format!("Predicate::Idn{{component:{component},profile_id:{profile_id:?}}}"),
        Predicate::FieldEquals {field,value:v} => format!("Predicate::FieldEquals{{field:{field:?},value:{}}}",value(v)),
        Predicate::FieldIn {field,values} => format!("Predicate::FieldIn{{field:{field:?},values:&[{}]}}",values.iter().map(value).collect::<Vec<_>>().join(",")),
        Predicate::NameEqualsField {component,field} => format!("Predicate::NameEqualsField{{component:{component},field:{field:?}}}"),
        Predicate::Unsupported {..} => return Err("unsupported predicate cannot be emitted for enforcement".into()),
    })
}
