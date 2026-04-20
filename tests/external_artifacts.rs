#![allow(
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::needless_raw_strings
)]
//! Integration tests for the cross-repo `external-artifacts` audit.

mod common;
use common::*;

#[test]
fn flags_curl_in_privileged_pr_workflow_as_critical() {
    let repo = make_git_repo("extart_curl");
    write_workflow(
        &repo,
        "release.yml",
        "name: Release
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -L https://example.com/installer.tar.gz | tar xz
",
    );
    commit_all(&repo, "unpinned curl in privileged PR workflow");

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
        out.contains("unpinned external artifact") && out.contains("crit"),
        "expected CRIT external-artifact finding, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn does_not_flag_sha_pinned_raw_github_url() {
    let repo = make_git_repo("extart_pinned");
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -L https://raw.githubusercontent.com/some/repo/abcdef1234567890abcdef1234567890abcdef12/install.sh | bash
",
    );
    commit_all(&repo, "pinned raw URL");

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
        !out.contains("unpinned external artifact"),
        "SHA-pinned raw URL should not be flagged:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn flags_go_install_without_pin() {
    let repo = make_git_repo("extart_go");
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: go install github.com/some/tool@latest
",
    );
    commit_all(&repo, "go install unpinned");

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
        out.contains("unpinned external artifact") && out.contains("go install"),
        "expected go-install finding, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
