//! Offline domain registrability against direct policy and declared profiles.

pub mod assessment_types;
mod compiled;
pub mod dataset;
mod evaluator;
mod idn_eval;
pub mod inventory_types;
pub mod normalization;
pub mod policy_types;
pub mod predicate_eval;
pub mod predicate_types;
pub mod profile;
pub mod python;
pub mod python_assessment;
pub mod registration_context;
pub mod registry;
pub mod resolver;
pub mod types;

#[cfg(test)]
#[path = "../build_support/mod.rs"]
mod compiler;

pub use assessment_types::{Assessment, Decision, InputError, Reason};
pub use profile::{ProfileError, RegistrantProfile};
pub use registry::Registry;
pub use types::{CheckResult, CheckStatus, RegistryStats, TldRuleSummary};
