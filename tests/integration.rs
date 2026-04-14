//! Integration tests for the hasp binary.
//!
//! These tests run the actual binary as a subprocess to verify the full
//! launcher → scan pipeline, exit codes, and end-to-end behavior.

// Integration tests live in tests/ and are only compiled during `cargo test`.
// clippy::tests_outside_test_module is a false positive here — #[cfg(test)]
// applies to unit test modules inside src/, not to integration test crates.
#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn hasp_bin() -> PathBuf {
    // cargo test builds the binary in the same target directory
    let mut path = std::env::current_exe()
        .expect("cannot determine test binary path")
        .parent()
        .expect("test binary has no parent")
        .parent()
        .expect("test binary has no grandparent")
        .to_path_buf();
    path.push("hasp");
    path
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/workflows")
}

fn run_hasp(args: &[&str]) -> std::process::Output {
    Command::new(hasp_bin())
        .args(args)
        .env("GITHUB_TOKEN", "") // ensure no token leaks into tests
        .env_remove("GITHUB_TOKEN")
        .output()
        .expect("failed to execute hasp binary")
}

// ─── Exit code tests ──────────────────────────────────────────────────────────

#[test]
fn help_flag_exits_zero() {
    let output = run_hasp(&["--help"]);
    assert!(output.status.success(), "hasp --help should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("USAGE:"), "help should contain usage info");
}

#[test]
fn version_flag_exits_zero() {
    let output = run_hasp(&["--version"]);
    assert!(output.status.success(), "hasp --version should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hasp"),
        "version output should contain 'hasp'"
    );
}

#[test]
fn unknown_arg_exits_two() {
    let output = run_hasp(&["--nonexistent-flag"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "unknown argument should exit 2"
    );
}

#[test]
fn missing_dir_exits_two() {
    let output = run_hasp(&[
        "--allow-unsandboxed",
        "--no-verify",
        "--dir",
        "/nonexistent/path/to/workflows",
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "missing directory should exit 2"
    );
}

// ─── Scan pipeline tests ──────────────────────────────────────────────────────

#[test]
fn scan_fixtures_detects_mutable_refs() {
    let output = run_hasp(&[
        "--allow-unsandboxed",
        "--no-verify",
        "--no-policy",
        "--dir",
        fixtures_dir().to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should find action references
    assert!(
        stdout.contains("action reference"),
        "scan should report action references: {stdout}"
    );
    // Mutable refs should appear as WARN (not strict mode)
    assert!(
        stdout.contains("WARN") || stdout.contains("mutable ref"),
        "scan should warn about mutable refs: {stdout}"
    );
}

#[test]
fn scan_fixtures_with_paranoid_detects_audit_findings() {
    let output = run_hasp(&[
        "--allow-unsandboxed",
        "--no-verify",
        "--no-policy",
        "--paranoid",
        "--dir",
        fixtures_dir().to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // Paranoid audit should find injection vulnerabilities in vulnerable.yml
    assert!(
        combined.contains("injection") || combined.contains("Paranoid audit"),
        "paranoid mode should run the audit: {combined}"
    );
}

#[test]
fn scan_strict_mode_fails_on_mutable_refs() {
    let output = run_hasp(&[
        "--allow-unsandboxed",
        "--no-verify",
        "--no-policy",
        "--strict",
        "--dir",
        fixtures_dir().to_str().unwrap(),
    ]);

    // --strict should cause exit 1 when mutable refs are found
    assert_eq!(
        output.status.code(),
        Some(1),
        "strict mode should exit 1 on mutable refs"
    );
}

#[test]
fn scan_empty_dir_reports_no_references() {
    let tmp = std::env::temp_dir().join(format!("hasp-empty-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();

    let output = run_hasp(&[
        "--allow-unsandboxed",
        "--no-verify",
        "--no-policy",
        "--dir",
        tmp.to_str().unwrap(),
    ]);

    assert!(output.status.success(), "empty dir should exit 0");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn scan_clean_workflow_exits_zero() {
    let tmp = std::env::temp_dir().join(format!("hasp-clean-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(
        tmp.join("ci.yml"),
        "name: CI\non: [push]\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n",
    ).unwrap();

    let output = run_hasp(&[
        "--allow-unsandboxed",
        "--no-verify",
        "--no-policy",
        "--dir",
        tmp.to_str().unwrap(),
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "clean workflow should exit 0: stdout={stdout}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

// ─── Container image detection ───────────────────────────────────────────────

#[test]
fn scan_detects_container_images() {
    let tmp = std::env::temp_dir().join(format!("hasp-container-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(
        tmp.join("containers.yml"),
        "\
name: Containers
on: [push]
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    container: node:20
    permissions: {}
    steps:
      - uses: docker://alpine:3.20
",
    )
    .unwrap();

    let output = run_hasp(&[
        "--allow-unsandboxed",
        "--no-verify",
        "--no-policy",
        "--dir",
        tmp.to_str().unwrap(),
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("container"),
        "should detect container images: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
