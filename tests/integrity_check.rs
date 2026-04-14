#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! Workflow integrity check: a file tampered after commit must be detected.
//! Requires the real Linux sandbox (Landlock + cgroup/BPF), so this is
//! `#[ignore]` even on Linux by default — run manually in a privileged
//! environment.

#![cfg(target_os = "linux")]

mod common;
use common::*;
use std::process::Command;

#[test]
#[ignore = "requires Landlock + BPF sandbox privileges; run manually on Linux"]
fn post_commit_tamper_is_detected() {
    let repo = make_git_repo("integrity");
    write_workflow(
        &repo,
        "clean.yml",
        "name: C\non: [push]\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    );
    commit_all(&repo, "clean");

    let path = repo.join(".github/workflows/clean.yml");
    let mut existing = std::fs::read_to_string(&path).unwrap();
    existing.push_str("# tampered\n");
    std::fs::write(&path, existing).unwrap();

    let o = Command::new(hasp_bin())
        .current_dir(&repo)
        .args(["--dir", ".github/workflows", "--no-verify", "--no-policy"])
        .env_remove("GITHUB_TOKEN")
        .output()
        .expect("spawn hasp");
    assert_eq!(
        o.status.code(),
        Some(2),
        "integrity tamper should exit 2: {}",
        combined(&o)
    );
    let _ = std::fs::remove_dir_all(&repo);
}
