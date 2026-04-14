#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! CLI surface: flag parsing, exit codes, flag validation, mutual exclusion.

mod common;
use common::*;
use std::path::Path;

#[test]
fn help_and_version_exit_zero() {
    assert!(run(Path::new("/"), &["--help"]).status.success());
    assert!(run(Path::new("/"), &["--version"]).status.success());
}

#[test]
fn unknown_flag_exits_two() {
    assert_eq!(
        run(Path::new("/"), &["--bogus"]).status.code(),
        Some(2)
    );
}

#[test]
fn missing_flag_values_exit_two() {
    for flag in &["--dir", "--min-sha-age", "--diff-base", "--policy", "--max-transitive-depth"] {
        assert_eq!(
            run(Path::new("/"), &[flag]).status.code(),
            Some(2),
            "{flag} without value should exit 2"
        );
    }
}

#[test]
fn bad_duration_exits_two() {
    for bad in &["48y", "-1h", "abc", "123"] {
        assert_eq!(
            run(Path::new("/"), &["--min-sha-age", bad]).status.code(),
            Some(2),
            "--min-sha-age {bad} should exit 2"
        );
    }
}

#[test]
fn bad_transitive_depth_exits_two() {
    for bad in &["0", "11", "abc"] {
        assert_eq!(
            run(Path::new("/"), &["--max-transitive-depth", bad]).status.code(),
            Some(2),
        );
    }
}

#[test]
fn nonexistent_dir_exits_two() {
    assert_eq!(
        run(Path::new("/"), &["--dir", "/nonexistent/path/to/workflows", "--allow-unsandboxed"])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn policy_and_no_policy_are_mutually_exclusive() {
    let dir = fixture("pin_check");
    let o = run(
        &dir,
        &[
            "--dir",
            ".",
            "--allow-unsandboxed",
            "--no-verify",
            "--policy",
            "/tmp/some-policy.yml",
            "--no-policy",
        ],
    );
    assert_eq!(
        o.status.code(),
        Some(2),
        "mixing --policy and --no-policy should exit 2: {}",
        combined(&o)
    );
}
