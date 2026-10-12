//! Incrementally tested compiler authoring modules, before build activation.
#![allow(dead_code, missing_docs, clippy::missing_docs_in_private_items)]

mod idn_schema;
mod idn;
mod check_predicates;
mod conflicts;
mod keys;
mod load;
mod predicates;
mod schema;
mod validate;

#[cfg(test)]
mod tests_keys;
#[cfg(test)]
mod tests_inputs;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests_integrity;
#[cfg(test)]
mod tests_predicates;
#[cfg(test)]
mod tests_schema;
