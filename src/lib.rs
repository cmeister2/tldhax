//! TLD registration rule checks backed by compiled rule data.

pub mod checker;
#[allow(missing_docs, clippy::missing_docs_in_private_items, clippy::missing_errors_doc)]
pub mod python;
pub mod registry;
pub mod types;

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