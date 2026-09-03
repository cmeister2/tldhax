//! Evidence-aware domain registration assessment over pinned namespace data.
//!
//! Public Suffix List membership and root delegation are topology facts, not
//! proof that a registration product is open. This crate keeps those facts
//! separate and returns [`Verdict::Indeterminate`] whenever decision-critical
//! registry policy has not been verified.

mod checker;
pub mod evaluator;
#[allow(
    missing_docs,
    clippy::missing_docs_in_private_items,
    clippy::missing_errors_doc
)]
pub mod python;
pub mod registry;
mod topology;
pub mod types;

#[allow(missing_docs, clippy::missing_docs_in_private_items)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated_catalog.rs"));
}

pub use registry::Registry;
pub use types::*;
