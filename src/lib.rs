//! TLD registration rule checks backed by compiled rule data.

pub mod checker;
pub mod assessment_types;
pub mod dataset;
mod compiled;
mod idn_eval;
pub mod inventory_types;
pub mod normalization;
pub mod policy_types;
pub mod predicate_eval;
pub mod predicate_types;
pub mod profile;
pub mod python;
pub mod registration_context;
pub mod resolver;
pub mod registry;
pub mod registry_stats;
pub mod types;

#[cfg(test)]
#[path = "../build_support/mod.rs"]
mod compiler_stages;

/// Compiled legacy TLD rules and known suffixes emitted by the build script.
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated_rules.rs"));
}

pub use generated::{KNOWN_SUFFIXES, TLD_RULES, TOTAL_KNOWN_SUFFIXES};

pub use registry::Registry;
pub use types::{
    Charset, CheckResult, CheckStatus, LengthBasis, Reason, Registerable, RegistryStats, TldRule,
    TldRuleSummary,
};
