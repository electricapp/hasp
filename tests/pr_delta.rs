#![allow(
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::needless_raw_strings
)]
//! `hasp diff <base>` integration tests. Builds a two-commit git repo, runs
//! hasp diff, asserts the new/fixed/unchanged split lands in the output.

mod common;
use common::*;

#[test]
fn emits_new_finding_when_head_adds_problem() {
    let repo = make_git_repo("diff_new");

    // Base: clean workflow.
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          persist-credentials: false
",
    );
    commit_all(&repo, "base");

    // HEAD: add a job with contents: write (new high-severity permissions finding).
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          persist-credentials: false
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: echo release
",
    );
    commit_all(&repo, "add release job with contents: write");

    let o = run(
        &repo,
        &[
            "diff",
            "HEAD~1",
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-policy",
            "--paranoid",
            "--format",
            "terse",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("new findings") && out.contains("contents: write"),
        "expected new findings section including contents: write, got:\n{out}"
    );
    assert_eq!(o.status.code(), Some(1), "new deny findings should exit 1");
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn emits_fixed_finding_when_head_removes_problem() {
    let repo = make_git_repo("diff_fixed");

    // Base: workflow with contents: write.
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: echo release
",
    );
    commit_all(&repo, "base with contents: write");

    // HEAD: tighten to permissions: {}.
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  release:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - run: echo release
",
    );
    commit_all(&repo, "tighten permissions");

    let o = run(
        &repo,
        &[
            "diff",
            "HEAD~1",
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-policy",
            "--paranoid",
            "--format",
            "terse",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("fixed findings"),
        "expected fixed findings section, got:\n{out}"
    );
    assert_eq!(o.status.code(), Some(0), "no new deny findings should exit 0");
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn markdown_format_emits_github_markdown() {
    let repo = make_git_repo("diff_md");

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
      - run: echo hi
",
    );
    commit_all(&repo, "base clean");

    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: echo hi
",
    );
    commit_all(&repo, "add permission");

    let o = run(
        &repo,
        &[
            "diff",
            "HEAD~1",
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-policy",
            "--paranoid",
            "--format",
            "markdown",
        ],
    );
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        out.contains("## hasp audit delta") && out.contains("| Severity |"),
        "expected markdown table, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn json_format_is_valid_one_line() {
    let repo = make_git_repo("diff_json");

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
      - run: echo hi
",
    );
    commit_all(&repo, "base");

    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: echo hi
",
    );
    commit_all(&repo, "head");

    let o = run(
        &repo,
        &[
            "diff",
            "HEAD~1",
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-policy",
            "--paranoid",
            "--format",
            "json",
        ],
    );
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        out.contains(r#""base":"#) && out.contains(r#""new":"#),
        "expected JSON fields, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
