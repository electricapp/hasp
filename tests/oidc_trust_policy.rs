#![allow(
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::needless_raw_strings
)]
//! OIDC trust-policy integration tests.
//! Pairs an AWS trust policy fixture with a synthesized workflow that declares
//! `id-token: write`, then asserts the audit flags (or doesn't flag) the right
//! combinations.

mod common;
use common::*;

use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/oidc")
        .join(name)
}

#[test]
fn wildcard_repo_flagged_via_cli_flag() {
    let repo = make_git_repo("oidc_wildcard");
    write_workflow(
        &repo,
        "deploy.yml",
        "name: Deploy
on:
  push:
    branches: [main]
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
",
    );
    commit_all(&repo, "add deploy workflow");

    let policy_arg = format!("aws:{}", fixture_path("aws_overbroad.json").display());
    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--paranoid",
            "--oidc-policy",
            &policy_arg,
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("wildcard repository") || out.contains("oidc trust policy"),
        "expected OIDC finding for wildcard repo, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn safe_policy_no_oidc_findings() {
    let repo = make_git_repo("oidc_safe");
    write_workflow(
        &repo,
        "deploy.yml",
        "name: Deploy
on:
  push:
    branches: [main]
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
",
    );
    commit_all(&repo, "add deploy workflow");

    let policy_arg = format!("aws:{}", fixture_path("aws_safe.json").display());
    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--paranoid",
            "--oidc-policy",
            &policy_arg,
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        !out.contains("oidc trust policy"),
        "safe OIDC policy should not produce findings:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn missing_audience_is_flagged() {
    let repo = make_git_repo("oidc_noaud");
    write_workflow(
        &repo,
        "deploy.yml",
        "name: Deploy
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
    );
    commit_all(&repo, "workflow");

    let policy_arg = format!("aws:{}", fixture_path("aws_missing_aud.json").display());
    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--paranoid",
            "--oidc-policy",
            &policy_arg,
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("any audience"),
        "expected 'any audience' finding, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn no_oidc_flag_suppresses_category() {
    let repo = make_git_repo("oidc_noflag");
    write_workflow(
        &repo,
        "deploy.yml",
        "name: Deploy
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
    );
    commit_all(&repo, "workflow");

    let policy_arg = format!("aws:{}", fixture_path("aws_overbroad.json").display());
    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--paranoid",
            "--oidc-policy",
            &policy_arg,
            "--no-oidc",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        !out.contains("oidc trust policy"),
        "--no-oidc should suppress the OIDC check:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
