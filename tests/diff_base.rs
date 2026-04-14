#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! `--diff-base` flow: SHA change detection, adversarial refs, range
//! rejection, multi-file deduplication, nonexistent ref handling.

mod common;
use common::*;

#[test]
fn sha_changes_are_reported() {
    let repo = make_git_repo("sha_changes");
    write_workflow(
        &repo,
        "bump.yml",
        "name: B\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    );
    commit_all(&repo, "old sha");
    write_workflow(
        &repo,
        "bump.yml",
        "name: B\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332\n",
    );
    commit_all(&repo, "new sha");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--diff-base",
            "HEAD~1",
        ],
    );
    let out = combined(&o);
    assert!(
        out.contains("1 action SHA change") || out.contains("SHA change"),
        "expected SHA change summary: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn no_changes_reports_cleanly() {
    let repo = make_git_repo("no_changes");
    write_workflow(
        &repo,
        "bump.yml",
        "name: B\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    );
    commit_all(&repo, "stable");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--diff-base",
            "HEAD",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("no sha changes"),
        "expected 'no SHA changes' message: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn multi_file_dedups_same_action() {
    let repo = make_git_repo("dedup");
    let old_body = "name: M\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n";
    let new_body = "name: M\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332\n";
    for f in ["a.yml", "b.yml"] {
        write_workflow(&repo, f, old_body);
    }
    commit_all(&repo, "old multi");
    for f in ["a.yml", "b.yml"] {
        write_workflow(&repo, f, new_body);
    }
    commit_all(&repo, "new multi");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--diff-base",
            "HEAD~1",
        ],
    );
    let out = combined(&o);
    assert!(
        out.contains("2 action SHA change") || out.contains("2 change"),
        "expected 2 changes found: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn adversarial_refs_are_rejected() {
    let dir = fixture("pin_check");
    let malicious = [
        "-x",                    // leading dash (git option injection)
        "refs/../../etc/passwd", // path traversal
        "HEAD\x01",              // control char
        "HEAD\\evil",            // backslash
    ];
    for ref_val in malicious {
        let o = run(
            &dir,
            &[
                "--dir",
                ".",
                "--allow-unsandboxed",
                "--no-verify",
                "--no-policy",
                "--diff-base",
                ref_val,
            ],
        );
        let out = combined(&o);
        assert!(
            out.to_lowercase().contains("invalid"),
            "expected rejection of {ref_val:?}: {out}"
        );
    }
    // NOTE: null-byte refs are blocked by std::process::Command before they
    // reach hasp (argv can't carry interior nulls), so that case is
    // effectively unreachable from userspace.
}

#[test]
fn overlong_ref_is_rejected() {
    let dir = fixture("pin_check");
    let long_ref = "a".repeat(257);
    let o = run(
        &dir,
        &[
            "--dir",
            ".",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--diff-base",
            &long_ref,
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(out.contains("invalid"), "{out}");
}

#[test]
fn empty_ref_is_rejected() {
    let dir = fixture("pin_check");
    let o = run(
        &dir,
        &[
            "--dir",
            ".",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--diff-base",
            "",
        ],
    );
    assert_ne!(
        o.status.code(),
        Some(0),
        "empty --diff-base should not succeed: {}",
        combined(&o)
    );
}

#[test]
fn range_syntax_is_rejected() {
    let repo = make_git_repo("range_syntax");
    write_workflow(
        &repo,
        "bump.yml",
        "name: B\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    );
    commit_all(&repo, "only");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--diff-base",
            "foo..bar",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(out.contains("invalid"), "foo..bar must be rejected: {out}");
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn nonexistent_ref_warns_without_crashing() {
    let repo = make_git_repo("nonexistent");
    write_workflow(
        &repo,
        "ci.yml",
        "name: C\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    );
    commit_all(&repo, "only commit");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--diff-base",
            "does-not-exist-xyz",
        ],
    );
    let code = o.status.code().unwrap_or(255);
    assert!(
        code < 128,
        "non-existent diff-base must not crash, got exit {code}: {}",
        combined(&o)
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("diff-base") || out.contains("resolve"),
        "expected diff-base-related warning: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
#[ignore = "requires GITHUB_TOKEN to fetch upstream compare detail"]
fn with_token_shows_upstream_detail() {
    let repo = make_git_repo("upstream_detail");
    write_workflow(
        &repo,
        "bump.yml",
        "name: B\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    );
    commit_all(&repo, "old sha");
    write_workflow(
        &repo,
        "bump.yml",
        "name: B\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332\n",
    );
    commit_all(&repo, "new sha");

    let o = run_with_token(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-policy",
            "--diff-base",
            "HEAD~1",
        ],
    );
    let out = combined(&o);
    assert!(
        out.contains("Upstream changes") || out.contains("compare"),
        "expected upstream detail from compare API: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
