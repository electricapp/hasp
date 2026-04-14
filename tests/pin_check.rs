#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! Pin verification: PASS / WARN / FAIL / SKIP semantics, strict mode,
//! comment/version mismatches.

mod common;
use common::*;

#[test]
fn no_verify_reports_skip_for_sha_refs() {
    let dir = fixture("pin_check");
    let o = run(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--no-verify", "--no-policy"],
    );
    let out = stdout(&o);
    assert!(
        out.matches("SKIP").count() >= 3,
        "expected ≥3 SKIP lines without a token: {out}"
    );
}

#[test]
fn mutable_ref_fails_and_exits_one() {
    let dir = fixture("pin_check");
    let o = run(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--no-verify", "--no-policy"],
    );
    let out = stdout(&o);
    assert!(
        out.contains("FAIL") && out.contains("upload-artifact@v4"),
        "mutable ref should FAIL: {out}"
    );
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn strict_without_token_exits_two() {
    let dir = fixture("pin_check");
    let o = run(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--strict", "--no-policy"],
    );
    assert_eq!(
        o.status.code(),
        Some(2),
        "strict without token must exit 2: {}",
        combined(&o)
    );
}

#[test]
#[ignore = "requires GITHUB_TOKEN — verifies phantom + comment mismatch + mutable all FAIL"]
fn strict_with_token_produces_multiple_fails() {
    let dir = fixture("pin_check");
    let o = run_with_token(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--strict", "--no-policy"],
    );
    let out = stdout(&o);
    let fail_count = out.matches("FAIL").count();
    assert!(
        fail_count >= 3,
        "expected ≥3 FAILs (phantom + comment mismatch + mutable), got {fail_count}: {out}"
    );
    assert_eq!(o.status.code(), Some(1));
}

#[test]
#[ignore = "requires GITHUB_TOKEN for SHA verification"]
fn comment_version_mismatch_is_flagged() {
    let dir = fixture("comment_mismatch");
    let o = run_with_token(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--no-policy"],
    );
    let out = combined(&o);
    assert!(out.to_lowercase().contains("comment"), "{out}");
    assert_eq!(o.status.code(), Some(1));
}
