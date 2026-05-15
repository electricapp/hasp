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

/// Copy a static fixture into the test's repo so that the path containment
/// guard (which canonicalizes and confirms the policy lives under repo root)
/// accepts it. Returns the path that should be passed to `--oidc-policy`.
fn copy_fixture_into_repo(repo: &Path, name: &str) -> PathBuf {
    let dst = repo.join(name);
    std::fs::copy(fixture_path(name), &dst).unwrap();
    dst
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
    let policy = copy_fixture_into_repo(&repo, "aws_overbroad.json");
    commit_all(&repo, "add deploy workflow");

    let policy_arg = format!("aws:{}", policy.display());
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
        out.contains("wildcard repository"),
        "expected wildcard-repo finding specifically, got:\n{out}"
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
    let policy = copy_fixture_into_repo(&repo, "aws_safe.json");
    commit_all(&repo, "add deploy workflow");

    let policy_arg = format!("aws:{}", policy.display());
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
    let policy = copy_fixture_into_repo(&repo, "aws_missing_aud.json");
    commit_all(&repo, "workflow");

    let policy_arg = format!("aws:{}", policy.display());
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
fn gcp_wildcard_repo_flagged() {
    let repo = make_git_repo("oidc_gcp_wildcard");
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
    let policy = copy_fixture_into_repo(&repo, "gcp_overbroad.json");
    commit_all(&repo, "add deploy workflow");

    let policy_arg = format!("gcp:{}", policy.display());
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
        out.contains("any github repository") || out.contains("wildcard repository"),
        "expected over-broad GCP repo finding, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn azure_wildcard_repo_flagged() {
    let repo = make_git_repo("oidc_azure_wildcard");
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
    let policy = copy_fixture_into_repo(&repo, "azure_overbroad.json");
    commit_all(&repo, "add deploy workflow");

    let policy_arg = format!("azure:{}", policy.display());
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
        out.contains("any github repository") || out.contains("wildcard repository"),
        "expected over-broad Azure repo finding, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn aws_single_object_statement_not_dropped() {
    let repo = make_git_repo("oidc_aws_single_stmt");
    write_workflow(
        &repo,
        "deploy.yml",
        "name: Deploy
on:
  push:
    branches: [main]
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
",
    );
    let policy = copy_fixture_into_repo(&repo, "aws_single_statement.json");
    commit_all(&repo, "add deploy workflow");

    let policy_arg = format!("aws:{}", policy.display());
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
        out.contains("wildcard repository"),
        "single-object Statement was dropped — wildcard-repo finding missing:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn hasp_yml_oidc_section_loads_policy() {
    let repo = make_git_repo("oidc_hasp_yml");
    write_workflow(
        &repo,
        "deploy.yml",
        "name: Deploy
on:
  push:
    branches: [main]
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
",
    );
    // Copy the over-broad AWS fixture into the repo so the path is inside it.
    std::fs::copy(fixture_path("aws_overbroad.json"), repo.join("trust.json")).unwrap();
    std::fs::write(
        repo.join(".hasp.yml"),
        "version: 1\noidc:\n  - provider: aws\n    path: trust.json\n",
    )
    .unwrap();
    commit_all(&repo, "add workflow, .hasp.yml, trust.json");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--paranoid",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("wildcard repository"),
        ".hasp.yml oidc: plumbing didn't produce findings:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn hasp_yml_oidc_path_traversal_blocked() {
    let repo = make_git_repo("oidc_path_traversal");
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
      - run: echo deploy
",
    );
    // Path traversal attempting to read /etc/passwd. Containment must block it.
    std::fs::write(
        repo.join(".hasp.yml"),
        "version: 1\noidc:\n  - provider: aws\n    path: ../../../../../etc/passwd\n",
    )
    .unwrap();
    commit_all(&repo, "add workflow + malicious .hasp.yml");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--paranoid",
        ],
    );
    let out = combined(&o).to_lowercase();
    // Two acceptable outcomes — both prove the traversal is blocked:
    //   (a) canonicalize fails because the joined path doesn't exist
    //       (e.g. too many `..` past the repo root) → "cannot resolve … —
    //       skipping".
    //   (b) canonicalize succeeds outside the repo root → "outside repo root
    //       … refusing to load".
    // What MUST NOT happen is hasp actually reading /etc/passwd.
    assert!(
        out.contains("outside repo root")
            || out.contains("path traversal")
            || out.contains("refusing to load")
            || out.contains("cannot resolve oidc policy path"),
        "expected a path-traversal warning, got:\n{out}"
    );
    assert!(
        !out.contains("root:x:") && !out.contains("/bin/bash"),
        "looks like /etc/passwd contents leaked: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

/// Symlink escape: a policy file inside the repo points outside it. Canonicalize
/// must follow the symlink, detect the escape, and skip.
#[test]
fn hasp_yml_oidc_symlink_escape_blocked() {
    use std::os::unix::fs::symlink;
    let repo = make_git_repo("oidc_symlink_escape");
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
    // Plant the symlink AFTER make_git_repo so it's inside the repo dir.
    // /etc/hosts exists on every Unix; we just need any file outside the repo.
    let link = repo.join("evil.json");
    let _ = std::fs::remove_file(&link);
    symlink("/etc/hosts", &link).unwrap();
    std::fs::write(
        repo.join(".hasp.yml"),
        "version: 1\noidc:\n  - provider: aws\n    path: evil.json\n",
    )
    .unwrap();
    commit_all(&repo, "symlink escape attempt");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--paranoid",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("outside repo root") || out.contains("refusing to load"),
        "expected symlink-escape to be blocked, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn pull_request_target_with_id_token_fires_finding() {
    let repo = make_git_repo("oidc_pr_target");
    write_workflow(
        &repo,
        "pr.yml",
        "name: PR
on:
  pull_request_target:
permissions:
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
    );
    commit_all(&repo, "add pr_target workflow");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--paranoid",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("pull_request_target with id-token: write"),
        "expected pull_request_target finding, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn oidc_without_trust_policy_emits_advisory() {
    let repo = make_git_repo("oidc_no_policy");
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

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--paranoid",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("oidc trust policy not configured"),
        "expected no-trust-policy advisory, got:\n{out}"
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
    let policy = copy_fixture_into_repo(&repo, "aws_overbroad.json");
    commit_all(&repo, "workflow");

    let policy_arg = format!("aws:{}", policy.display());
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
