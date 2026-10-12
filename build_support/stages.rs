//! Incrementally tested compiler authoring modules, before build activation.
#![allow(dead_code, missing_docs, clippy::missing_docs_in_private_items)]

mod idn_schema;
mod keys;
mod predicates;
mod schema;

#[cfg(test)]
mod tests_keys;
#[cfg(test)]
mod tests_schema;
