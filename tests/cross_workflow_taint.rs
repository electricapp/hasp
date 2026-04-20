#![allow(
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::needless_raw_strings
)]
//! Cross-workflow taint analysis: artifact flows from untrusted triggers to
//! privileged workflow_run sinks (tj-actions / Ultralytics pattern), unguarded
//! workflow_run triggers, and attacker-controlled workflow_run event reads.

mod common;
use common::*;

#[test]
fn detects_tj_actions_artifact_flow_pattern() {
    let repo = make_git_repo("xflow_tj");

    write_workflow(
        &repo,
        "lint.yml",
        r"name: Lint
on: pull_request
permissions: {}
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
      - run: npm run lint > lint.log
      - uses: actions/upload-artifact@2222222222222222222222222222222222222222
        with:
          name: lint-results
",
    );

    write_workflow(
        &repo,
        "post-lint.yml",
        r"name: Post Lint
on:
  workflow_run:
    workflows: [Lint]
    types: [completed]
permissions:
  contents: write
  pull-requests: write
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@3333333333333333333333333333333333333333
        with:
          name: lint-results
      - run: cat lint-results
",
    );
    commit_all(&repo, "add tj-actions pattern");

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
        out.contains("cross-workflow artifact flow") || out.contains("artifact flow"),
        "expected cross-workflow artifact flow finding, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn does_not_flag_safe_push_triggered_flow() {
    let repo = make_git_repo("xflow_safe");

    write_workflow(
        &repo,
        "ci.yml",
        r"name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@4444444444444444444444444444444444444444
        with:
          name: dist
",
    );
    write_workflow(
        &repo,
        "deploy.yml",
        r"name: Deploy
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  contents: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    steps:
      - uses: actions/download-artifact@5555555555555555555555555555555555555555
        with:
          name: dist
",
    );
    commit_all(&repo, "push-triggered flow");

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
        !out.contains("cross-workflow artifact flow"),
        "push-triggered source should not trigger cross-workflow artifact finding:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn detects_unguarded_workflow_run() {
    let repo = make_git_repo("xflow_unguarded");

    write_workflow(
        &repo,
        "privileged.yml",
        r"name: Privileged
on: workflow_run
permissions:
  contents: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
    );
    commit_all(&repo, "unguarded workflow_run");

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
        out.contains("workflow_run trigger without"),
        "expected unguarded-workflow_run finding, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn detects_workflow_run_event_taint() {
    let repo = make_git_repo("xflow_event_taint");

    write_workflow(
        &repo,
        "pr.yml",
        r"name: PR
on: pull_request
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
    );
    write_workflow(
        &repo,
        "privileged.yml",
        r"name: Privileged
on:
  workflow_run:
    workflows: [PR]
    types: [completed]
permissions:
  contents: write
jobs:
  do:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.workflow_run.head_branch }}
",
    );
    commit_all(&repo, "workflow_run event read");

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
        out.contains("github.event.workflow_run") || out.contains("workflow_run fields"),
        "expected workflow_run-event-taint finding, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
