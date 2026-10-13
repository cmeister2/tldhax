//! TLD registration rule checks backed by compiled rule data.

pub mod checker;
pub mod normalization;
pub mod policy_types;
pub mod registration_context;
pub mod resolver;
pub mod python;
pub mod registry;
pub mod types;

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