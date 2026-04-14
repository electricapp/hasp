#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! Policy file loading, suppression, drift, malformed-policy rejection.

mod common;
use common::*;

#[test]
fn policy_suppresses_configured_checks() {
    let dir = fixture("policy_suppress");
    let o = run(
        &dir,
        &["--dir", "workflows", "--allow-unsandboxed", "--no-verify", "--paranoid"],
    );
    let out = combined(&o);
    assert!(out.contains("loaded policy"), "expected policy load log: {out}");
    assert!(
        !out.to_lowercase().contains("expression-injection"),
        "expression-injection should be suppressed by policy: {out}"
    );
}

#[test]
fn no_policy_bypasses_suppressions() {
    let dir = fixture("policy_suppress");
    let o = run(
        &dir,
        &[
            "--dir",
            "workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--paranoid",
            "--no-policy",
        ],
    );
    let out = combined(&o);
    assert!(
        out.to_lowercase().contains("injection"),
        "with --no-policy, injection findings should appear: {out}"
    );
}

#[test]
fn malformed_policy_exits_two() {
    let tmp = std::env::temp_dir().join(format!("hasp-bad-policy-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let policy_path = tmp.join("bad.yml");
    std::fs::write(&policy_path, "version: 99\n").unwrap();

    let dir = fixture("pin_check");
    let o = run(
        &dir,
        &[
            "--dir",
            ".",
            "--allow-unsandboxed",
            "--no-verify",
            "--policy",
            policy_path.to_str().unwrap(),
        ],
    );
    assert_eq!(o.status.code(), Some(2), "{}", combined(&o));

    let _ = std::fs::remove_dir_all(&tmp);
}
