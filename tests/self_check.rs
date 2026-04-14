#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! `--self-check` runs before the sandbox and tries to hash the published
//! release binary. For dev builds we just verify it exits cleanly (no
//! panic / signal).

mod common;
use common::*;
use std::process::Command;

#[test]
fn self_check_does_not_crash() {
    let o = Command::new(hasp_bin())
        .arg("--self-check")
        .env_remove("GITHUB_TOKEN")
        .output()
        .expect("spawn hasp --self-check");
    let code = o.status.code();
    assert!(
        matches!(code, Some(0..=2)),
        "--self-check should exit cleanly, got {code:?}: {}",
        combined(&o)
    );
}
