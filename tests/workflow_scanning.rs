#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! Workflow scanning surface: unauditable refs, subpaths, composite actions,
//! local reusable workflows, multi-file reporting, not-a-git-repo.

mod common;
use common::*;

#[test]
fn remote_reusable_workflow_is_unauditable() {
    let dir = fixture("unauditable");
    let o = run(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--no-verify", "--no-policy"],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("unauditable"),
        "expected 'unauditable' in output: {out}"
    );
}

#[test]
fn local_composite_action_resolves_transitive_refs() {
    let dir = fixture("local_composite");
    let o = run(
        &dir,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
        ],
    );
    let out = stdout(&o);
    assert!(
        out.contains("checkout"),
        "expected transitive actions/checkout ref from composite: {out}"
    );
}

#[test]
fn subpath_action_reports_path() {
    let dir = fixture("subpath");
    let o = run(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--no-verify", "--no-policy"],
    );
    let out = stdout(&o);
    assert!(
        out.contains("subdir") || out.contains("build-push-action"),
        "expected subpath info: {out}"
    );
}

#[test]
fn paranoid_flags_transitive_mutable_refs() {
    let dir = fixture("transitive_composite");
    let o = run(
        &dir,
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
        out.contains("transitive") || out.contains("mutable"),
        "expected transitive/mutable mention: {out}"
    );
}

#[test]
fn scan_outside_git_repo_succeeds() {
    let dir = copy_fixture_outside_repo("outside_git");
    let o = run(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--no-verify", "--no-policy"],
    );
    assert_eq!(
        o.status.code(),
        Some(0),
        "scan should succeed without a git repo: {}",
        combined(&o)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn diff_base_outside_git_repo_warns() {
    let dir = copy_fixture_outside_repo("outside_git");
    let o = run(
        &dir,
        &[
            "--dir",
            ".",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--diff-base",
            "HEAD",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("not a git repository")
            || out.contains("not in a git")
            || out.contains("no git"),
        "expected git-repo warning: {out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn multi_file_reporting_is_per_file() {
    let repo = make_git_repo("multi_file");
    write_workflow(
        &repo,
        "clean.yml",
        "name: C\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    );
    write_workflow(
        &repo,
        "bad.yml",
        "name: B\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/upload-artifact@v4\n",
    );
    commit_all(&repo, "mixed");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
        ],
    );
    let out = stdout(&o);
    assert!(out.contains("clean.yml"), "clean.yml must be listed: {out}");
    assert!(out.contains("bad.yml"), "bad.yml must be listed: {out}");
    assert!(
        out.contains("upload-artifact@v4") && out.contains("FAIL"),
        "bad file must produce a FAIL: {out}"
    );
    assert_eq!(o.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn local_reusable_workflow_is_scanned_transitively() {
    let repo = make_git_repo("local_reusable");
    write_workflow(
        &repo,
        "reusable.yml",
        "name: R\non:\n  workflow_call:\njobs:\n  inner:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/upload-artifact@v4\n",
    );
    write_workflow(
        &repo,
        "caller.yml",
        "name: Caller\non: [push]\npermissions: {}\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n",
    );
    commit_all(&repo, "local reusable");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
        ],
    );
    let out = stdout(&o);
    assert!(
        out.contains("upload-artifact"),
        "local reusable workflow must be scanned transitively: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
