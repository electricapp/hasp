#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! Tests that exercise live GitHub API — require `GITHUB_TOKEN`. All tests
//! here are `#[ignore]` so `cargo test` stays offline by default. CI runs
//! them as a separate step with the workflow's provisioned token.

mod common;
use common::*;
use std::process::Command;

#[test]
#[ignore = "requires GITHUB_TOKEN to fetch commit timestamps"]
fn min_sha_age_flags_young_commits() {
    let repo = make_git_repo("age_generic");
    write_workflow(
        &repo,
        "age.yml",
        "name: A\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    );
    commit_all(&repo, "age fixture");
    let o = run_with_token(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-policy",
            "--min-sha-age",
            "99999d",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("age") || out.contains("fresh") || out.contains("young"),
        "expected age-related warning: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
#[ignore = "requires GITHUB_TOKEN to fetch commit timestamps"]
fn security_action_min_sha_age_fires_for_codeql() {
    let repo = make_git_repo("age_codeql");
    write_workflow(
        &repo,
        "codeql.yml",
        "name: C\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: github/codeql-action/init@v3\n",
    );
    commit_all(&repo, "codeql fixture");

    let o = run_with_token(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-policy",
            "--min-sha-age",
            "1s",
            "--security-action-min-sha-age",
            "99999d",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("cooling-off") || out.contains("privileged") || out.contains("codeql"),
        "expected privileged action age policy to fire: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
#[ignore = "requires GITHUB_TOKEN + network to hit API budget"]
fn exceeding_api_budget_exits_two() {
    let repo = make_git_repo("budget");
    let mut body = String::from(
        "name: CI\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n",
    );
    // Hasp caps API calls per run at 300; 310 unique phantom SHAs comfortably
    // exceeds the budget.
    for i in 0..310 {
        use std::fmt::Write;
        writeln!(body, "      - uses: actions/checkout@{i:040x}").unwrap();
    }
    write_workflow(&repo, "budget.yml", &body);
    commit_all(&repo, "budget");

    let o = run_with_token(
        &repo,
        &["--dir", ".github/workflows", "--allow-unsandboxed", "--no-policy"],
    );
    let out = combined(&o).to_lowercase();
    assert_eq!(
        o.status.code(),
        Some(2),
        "expected exit 2 under budget exhaustion: {out}"
    );
    assert!(
        out.contains("api call")
            || out.contains("limit")
            || out.contains("budget")
            || out.contains("proxy shutting down"),
        "expected budget-exhaustion message: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn invalid_token_exits_two() {
    // Runs WITHOUT --ignored because it doesn't need a *valid* token — just
    // proves we surface 401 cleanly without panicking.
    let repo = make_git_repo("bad_token");
    write_workflow(
        &repo,
        "ci.yml",
        "name: C\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    );
    commit_all(&repo, "bad token");

    let o = Command::new(hasp_bin())
        .current_dir(&repo)
        .args(["--dir", ".github/workflows", "--allow-unsandboxed", "--no-policy"])
        .env("GITHUB_TOKEN", "ghp_obviously_invalid_0000000000000000000")
        .output()
        .expect("spawn hasp");
    let out = combined(&o).to_lowercase();
    assert_eq!(
        o.status.code(),
        Some(2),
        "invalid token should exit 2: {out}"
    );
    assert!(
        out.contains("authentication") || out.contains("401") || out.contains("token"),
        "expected authentication-related error: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
