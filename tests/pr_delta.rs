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
    assert_eq!(
        o.status.code(),
        Some(0),
        "no new deny findings should exit 0"
    );
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

/// Regression test for the C1 path-mismatch bug: when base and head are
/// byte-identical the delta must report every finding as unchanged with no
/// "new" or "fixed" entries, and the process must exit 0. The earlier
/// version of `hasp diff` keyed findings on absolute paths, so the temp
/// worktree's `/tmp/...` path never matched HEAD's repo path and every
/// finding ended up as both new AND fixed.
#[test]
fn identical_base_and_head_have_zero_new_and_fixed() {
    let repo = make_git_repo("diff_identical");

    let body = "name: CI
on: push
permissions: {}
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: echo release
";
    write_workflow(&repo, "ci.yml", body);
    commit_all(&repo, "first");
    // Second commit is a no-op rename to force a real diff between HEAD
    // and HEAD~1 in terms of commit SHAs while keeping the workflow tree
    // byte-identical.
    std::fs::write(repo.join("README.md"), "x").unwrap();
    commit_all(&repo, "unrelated commit, workflow unchanged");

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
    let out = combined(&o);
    assert_eq!(
        o.status.code(),
        Some(0),
        "identical workflows must exit 0, got status {:?} with output:\n{out}",
        o.status.code()
    );
    let lower = out.to_lowercase();
    assert!(
        !lower.contains("new findings:"),
        "no new findings should be reported, got:\n{out}"
    );
    assert!(
        !lower.contains("fixed findings:"),
        "no fixed findings should be reported, got:\n{out}"
    );
    assert!(
        lower.contains("no changes in audit findings"),
        "expected the no-change summary line, got:\n{out}"
    );

    // The markdown renderer must not leak the temp worktree directory
    // name (was the previous symptom of C1).
    let m = run(
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
    let md = combined(&m);
    assert!(
        !md.contains("/tmp/"),
        "markdown output should not leak /tmp/ worktree path:\n{md}"
    );
    assert!(
        !md.contains("hasp-diff-worktree-"),
        "markdown output should not leak worktree dir name:\n{md}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

/// Regression test for the C1 bug, integration-flavored: overlapping
/// findings between base and head must split correctly into new/fixed/
/// unchanged, exercising the relative-path keying.
#[test]
fn overlapping_findings_split_into_new_fixed_unchanged() {
    let repo = make_git_repo("diff_overlap");

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
    commit_all(&repo, "base with permissions:write");

    // Head keeps the contents:write finding AND adds a SECOND workflow
    // with the same kind of escalation. The base-only finding remains
    // unchanged (proves relative-path keying); the new workflow's finding
    // shows up as "new".
    write_workflow(
        &repo,
        "release.yml",
        "name: Release
on: push
permissions: {}
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: echo publish
",
    );
    commit_all(&repo, "add second workflow with contents: write");

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
    let out = combined(&o);
    let lower = out.to_lowercase();
    assert!(
        lower.contains("new findings:"),
        "expected a new findings section, got:\n{out}"
    );
    // Pre-fix bug: every base finding also showed up as "fixed". Assert
    // the count is reasonable: there must be at least one unchanged.
    let unchanged_line = out
        .lines()
        .find(|l| l.trim_start().to_lowercase().starts_with("unchanged:"))
        .unwrap_or("");
    let n: usize = unchanged_line
        .split(':')
        .nth(1)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    assert!(
        n >= 1,
        "expected at least one unchanged finding (proves relative-path \
         keying works); full output:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

/// Regression test for C2: `hasp diff` must refuse to run without
/// `--allow-unsandboxed`, since it does an inline (unsandboxed) scan.
#[test]
fn diff_requires_explicit_allow_unsandboxed() {
    let repo = make_git_repo("diff_no_sandbox_flag");
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
    commit_all(&repo, "init");

    let o = run(
        &repo,
        &[
            "diff",
            "HEAD",
            "--dir",
            ".github/workflows",
            "--no-policy",
            "--format",
            "terse",
        ],
    );
    let combined_out = combined(&o);
    assert_eq!(
        o.status.code(),
        Some(2),
        "expected exit 2 without --allow-unsandboxed, got status {:?} with:\n{combined_out}",
        o.status.code()
    );
    assert!(
        combined_out.contains("--allow-unsandboxed"),
        "stderr should mention the required flag, got:\n{combined_out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

/// Regression test for M4: `hasp diff HEAD` must short-circuit to an
/// empty-diff message rather than scanning HEAD twice.
#[test]
fn diff_same_ref_as_head_short_circuits() {
    let repo = make_git_repo("diff_same_ref");
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
    commit_all(&repo, "single commit");

    let o = run(
        &repo,
        &[
            "diff",
            "HEAD",
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-policy",
            "--paranoid",
            "--format",
            "terse",
        ],
    );
    let out = combined(&o);
    assert_eq!(
        o.status.code(),
        Some(0),
        "diff HEAD..HEAD should exit 0, got status {:?}:\n{out}",
        o.status.code()
    );
    assert!(
        out.to_lowercase().contains("no changes in audit findings"),
        "expected empty-diff message, got:\n{out}"
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
