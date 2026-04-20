#![allow(
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::needless_raw_strings
)]
//! `hasp replay` integration tests. Builds a multi-commit git repo whose
//! workflow file fluctuates between vulnerable and clean states, then
//! asserts replay surfaces the vulnerable historical states.

mod common;
use common::*;

#[test]
fn catches_past_vulnerability_that_was_later_fixed() {
    let repo = make_git_repo("replay_fixed");

    // Commit 1: vulnerable workflow (expression injection via PR title).
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: pull_request
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - run: echo ${{ github.event.pull_request.title }}
",
    );
    commit_all(&repo, "vulnerable workflow");

    // Commit 2: fix the injection.
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: pull_request
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: {}
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - run: echo \"$TITLE\"
",
    );
    commit_all(&repo, "use env var to defuse injection");

    let o = run(
        &repo,
        &[
            "replay",
            "--since",
            "1year",
            "--dir",
            ".github/workflows",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("injection"),
        "replay should surface the historical injection finding:\n{out}"
    );
    // Since the vulnerable commit's injection was a deny-level finding,
    // exit should be 1 (signalling "past state would have failed today's audit").
    assert_eq!(
        o.status.code(),
        Some(1),
        "replay should exit 1 when past state has deny findings"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn clean_history_exits_zero() {
    let repo = make_git_repo("replay_clean");
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
    commit_all(&repo, "clean workflow");

    let o = run(
        &repo,
        &[
            "replay",
            "--since",
            "1year",
            "--dir",
            ".github/workflows",
        ],
    );
    assert_eq!(
        o.status.code(),
        Some(0),
        "clean history should exit 0, got:\n{}",
        combined(&o)
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn markdown_format_renders_tables_and_headings() {
    let repo = make_git_repo("replay_md");
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: pull_request
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - run: echo ${{ github.event.pull_request.title }}
",
    );
    commit_all(&repo, "inject");

    let o = run(
        &repo,
        &[
            "replay",
            "--since",
            "1year",
            "--dir",
            ".github/workflows",
            "--format",
            "markdown",
        ],
    );
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        out.contains("## hasp replay"),
        "expected markdown heading, got:\n{out}"
    );
    assert!(
        out.contains("### `"),
        "expected per-file subheading, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn json_format_is_parseable_summary() {
    let repo = make_git_repo("replay_json");
    write_workflow(
        &repo,
        "ci.yml",
        "name: CI
on: pull_request
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - run: echo ${{ github.event.pull_request.title }}
",
    );
    commit_all(&repo, "inject");

    let o = run(
        &repo,
        &[
            "replay",
            "--since",
            "1year",
            "--dir",
            ".github/workflows",
            "--format",
            "json",
        ],
    );
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(out.contains(r#""hits":["#));
    assert!(out.contains(r#""since":"#));
    assert!(out.contains(r#""total_audited":"#));
    let _ = std::fs::remove_dir_all(&repo);
}
