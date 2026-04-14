#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! File/ref/size limits, YAML parse errors, symlink & hardlink rejection.

mod common;
use common::*;

#[test]
fn oversized_workflow_is_rejected() {
    let repo = make_git_repo("oversized");
    let big = " ".repeat(1024 * 1025);
    write_workflow(&repo, "huge.yml", &big);
    commit_all(&repo, "huge");

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
    assert_eq!(
        o.status.code(),
        Some(2),
        "oversized workflow should exit 2: {}",
        combined(&o)
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn too_many_refs_rejected() {
    let repo = make_git_repo("too_many_refs");
    let mut body = String::from(
        "name: CI\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n",
    );
    for i in 0..501 {
        use std::fmt::Write;
        writeln!(
            body,
            "      - uses: org/action-{i}@0123456789012345678901234567890123456789"
        )
        .unwrap();
    }
    write_workflow(&repo, "flood.yml", &body);
    commit_all(&repo, "flood");

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
    assert_eq!(
        o.status.code(),
        Some(2),
        "ref flood should exit 2: {}",
        combined(&o)
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn file_size_boundary_at_one_mib_accepted() {
    let repo = make_git_repo("size_boundary");
    let header = "name: B\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n";
    let target = 1024 * 1024;
    let mut body = String::with_capacity(target);
    body.push_str(header);
    let filler = "# padding line\n";
    while body.len() + filler.len() <= target {
        body.push_str(filler);
    }
    body.push_str(&" ".repeat(target - body.len()));
    assert_eq!(body.len(), target);

    write_workflow(&repo, "exact.yml", &body);
    commit_all(&repo, "exact 1 MiB");

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
    let code = o.status.code().unwrap_or(255);
    assert!(
        matches!(code, 0 | 1),
        "exact-1-MiB workflow must be accepted, got exit {code}: {}",
        combined(&o)
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn ref_count_boundary_at_500_accepted() {
    let repo = make_git_repo("ref_boundary");
    let mut body = String::from(
        "name: CI\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n",
    );
    for i in 0..500 {
        use std::fmt::Write;
        writeln!(
            body,
            "      - uses: org/action-{i}@0123456789012345678901234567890123456789"
        )
        .unwrap();
    }
    write_workflow(&repo, "exact.yml", &body);
    commit_all(&repo, "exact 500 refs");

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
    let code = o.status.code().unwrap_or(255);
    assert!(
        matches!(code, 0 | 1),
        "500-ref workflow must be accepted (boundary), got exit {code}: {}",
        combined(&o)
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn malformed_yaml_does_not_crash() {
    let repo = make_git_repo("malformed_yaml");
    write_workflow(
        &repo,
        "broken.yml",
        "name: [invalid\n  : : :\njobs: this is not yaml\n- - - -\n",
    );
    commit_all(&repo, "broken yaml");

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
    let code = o.status.code().unwrap_or(255);
    assert!(
        matches!(code, 0..=2),
        "malformed YAML must not crash, got exit {code}: {}",
        combined(&o)
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[cfg(unix)]
#[test]
fn symlink_in_workflows_dir_is_skipped() {
    let repo = make_git_repo("symlink");
    write_workflow(
        &repo,
        "real.yml",
        "name: R\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    );
    let link = repo.join(".github/workflows/evil.yml");
    std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
    commit_all(&repo, "symlink");

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
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("symlink") || out.contains("skipped"),
        "expected symlink/skip message: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

#[cfg(unix)]
#[test]
fn hardlink_in_workflows_dir_is_rejected() {
    let repo = make_git_repo("hardlink");
    let outside = repo.join("outside.yml");
    std::fs::write(
        &outside,
        "name: X\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    )
    .unwrap();
    let linked = repo.join(".github/workflows/hardlinked.yml");
    let Ok(()) = std::fs::hard_link(&outside, &linked) else {
        eprintln!("skipping hardlink test: filesystem does not support hard links here");
        let _ = std::fs::remove_dir_all(&repo);
        return;
    };
    commit_all(&repo, "hardlink");

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
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("hard link") || out.contains("hardlink") || out.contains("skipped"),
        "expected hard-link rejection: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
