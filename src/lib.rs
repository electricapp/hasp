//! Internal library face of the `hasp` crate.
//!
//! The binary (`src/main.rs`) keeps its own `mod` declarations — nothing
//! here changes how the binary is built. This file exists so the fuzz
//! harness crate can reach hasp's parsers through a thin, feature-gated
//! re-export surface (`fuzz_api`). Regular consumers see nothing public.
//!
//! Double-compilation of the source files between the bin and lib is
//! accepted as the cost of isolating fuzz-only surface from the shipping
//! binary. Because the lib crate only actually calls a handful of parser
//! entry points via `fuzz_api`, almost every item appears unused from the
//! lib's perspective — we suppress those lints here only.

#![allow(
    dead_code,
    unused_imports,
    unreachable_pub,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction,
    clippy::cargo
)]

pub(crate) mod audit;
pub(crate) mod cli;
pub(crate) mod diff;
pub(crate) mod error;
pub(crate) mod exec;
pub(crate) mod forward_proxy;
pub(crate) mod github;
pub(crate) mod integrity;
pub(crate) mod ipc;
pub(crate) mod manifest;
pub(crate) mod netguard;
pub(crate) mod oidc;
pub(crate) mod policy;
pub(crate) mod proxy;
pub(crate) mod replay;
pub(crate) mod report;
pub(crate) mod sandbox;
pub(crate) mod scanner;
pub(crate) mod selfcheck;
pub(crate) mod supply_chain_graph;
pub(crate) mod token;

/// Fuzz-only re-exports. Only compiled when the fuzz harness crate enables
/// the `fuzz-exports` feature. External consumers otherwise see no public
/// surface from this library.
#[cfg(feature = "fuzz-exports")]
pub mod fuzz_api {
    pub use crate::ipc::{
        percent_decode, read_action_refs, read_scan_payload, read_verifier_input,
    };
}
