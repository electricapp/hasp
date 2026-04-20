#![allow(
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::needless_raw_strings
)]
//! `hasp tree` integration tests.

mod common;
use common::*;

#[test]
fn ascii_tree_lists_workflow_and_pinned_action() {
    let repo = make_git_repo("tree_ascii");
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
",
    );
    commit_all(&repo, "pinned ci");

    let o = run(
        &repo,
        &[
            "tree",
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
        ],
    );
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(out.contains("ci.yml"), "ASCII tree should name the workflow: {out}");
    assert!(
        out.contains("actions/checkout"),
        "ASCII tree should list the pinned action: {out}"
    );
    assert!(out.contains("score:"), "ASCII tree should emit scores: {out}");
    assert!(out.contains("[pinned]"), "ASCII tree should tag pinned refs: {out}");
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn json_format_has_expected_keys() {
    let repo = make_git_repo("tree_json");
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@2222222222222222222222222222222222222222
",
    );
    commit_all(&repo, "json tree test");

    let o = run(
        &repo,
        &[
            "tree",
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--format",
            "json",
        ],
    );
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(out.contains(r#""nodes":"#));
    assert!(out.contains(r#""edges":"#));
    assert!(out.contains(r#""roots":"#));
    assert!(out.contains(r#""kind":"workflow""#));
    assert!(out.contains(r#""kind":"action""#));
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn min_score_fails_when_aggregate_too_low() {
    let repo = make_git_repo("tree_min_score");
    // Mutable ref -> action node score 0.0 -> workflow aggregate 0.0.
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@v4
",
    );
    commit_all(&repo, "mutable ref");

    let o = run(
        &repo,
        &[
            "tree",
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--min-score",
            "0.5",
        ],
    );
    assert_eq!(
        o.status.code(),
        Some(1),
        "mutable ref should fail --min-score 0.5"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
