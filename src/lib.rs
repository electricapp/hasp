//! Internal library face of the `hasp` crate.
//!
//! The binary (`src/main.rs`) keeps its own `mod` declarations — nothing
//! here changes how the binary is built. This file exists so the fuzz
//! harness crate can reach hasp's parsers through a thin, feature-gated
//! re-export surface (`fuzz_api`). Regular consumers see nothing public.
//!
//! The whole module tree is gated behind the `fuzz-exports` feature, so a
//! normal `cargo build`/`test`/`clippy` compiles an essentially empty lib
//! and pays no double-compilation cost — only the fuzz harness, which enables
//! the feature, compiles the sources a second time through here. Because the
//! lib crate only actually calls a handful of parser entry points via
//! `fuzz_api`, almost every item appears unused from the lib's perspective —
//! we suppress those lints here only.

#![allow(
    dead_code,
    unused_imports,
    unreachable_pub,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction,
    clippy::cargo
)]

// Each module is gated on `fuzz-exports` so a normal build compiles a nearly
// empty lib crate. They stay at crate root (not nested) so the `crate::…`
// paths inside the sources resolve identically to the binary build.
#[cfg(feature = "fuzz-exports")]
pub(crate) mod audit;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod cli;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod diff;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod error;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod exec;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod forward_proxy;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod git_util;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod github;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod integrity;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod ipc;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod manifest;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod netguard;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod oidc;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod policy;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod proxy;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod replay;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod report;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod sandbox;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod scanner;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod selfcheck;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod supply_chain_graph;
#[cfg(feature = "fuzz-exports")]
pub(crate) mod token;

/// Fuzz-only entry points. Only compiled when the fuzz harness crate enables
/// the `fuzz-exports` feature. These are thin `pub` wrappers so the internal
/// parsers stay `pub(crate)` (a `pub use` of a `pub(crate)` item won't compile,
/// and exposing the private return types would leak crate internals): each
/// runs the real parser for its panic-surface and reports only success/failure.
#[cfg(feature = "fuzz-exports")]
pub mod fuzz_api {
    use std::io::Read;

    pub fn read_action_refs(data: impl Read) -> bool {
        crate::ipc::read_action_refs(data).is_ok()
    }

    pub fn read_scan_payload(data: impl Read) -> bool {
        crate::ipc::read_scan_payload(data).is_ok()
    }

    pub fn read_verifier_input(data: impl Read) -> bool {
        crate::ipc::read_verifier_input(data).is_ok()
    }

    pub fn percent_decode(field: &str) -> bool {
        crate::ipc::percent_decode(field).is_ok()
    }
}
