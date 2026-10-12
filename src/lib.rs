//! TLD registration rule checks backed by compiled rule data.

pub mod checker;
mod compiled;
pub mod inventory_types;
pub mod normalization;
pub mod policy_types;
pub mod profile;
#[allow(
    missing_docs,
    clippy::missing_docs_in_private_items,
    clippy::missing_errors_doc
)]
pub mod python;
pub mod registration_context;
pub mod resolver;
pub mod registry;
pub mod types;

#[cfg(test)]
#[path = "../build_support/mod.rs"]
mod compiler_stages;

#[allow(missing_docs, clippy::missing_docs_in_private_items)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated_rules.rs"));
}

pub use generated::{KNOWN_SUFFIXES, TLD_RULES, TOTAL_KNOWN_SUFFIXES};

pub use registry::Registry;
pub use types::{
    Charset, CheckResult, CheckStatus, LengthBasis, Reason, Registerable, RegistryStats, TldRule,
    TldRuleSummary,
};
