//! Shared helpers for hasp integration tests.
//!
//! Each file under `tests/` is its own crate, so this `common/` module is
//! pulled in with `mod common;` rather than `use`. The `#![allow]` below
//! silences dead-code warnings in files that only use some helpers.

#![allow(dead_code, clippy::tests_outside_test_module, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Absolute path to the compiled `hasp` binary that `cargo test` built for
/// this run. Integration tests can't rely on `$PATH`.
pub(crate) fn hasp_bin() -> PathBuf {
    let mut path = std::env::current_exe()
        .expect("test binary path")
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    path.push("hasp");
    path
}

/// Static fixture under `tests/fixtures/<name>/`.
pub(crate) fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Run hasp in `dir` with `GITHUB_TOKEN` stripped — the default for tests
/// that want to exercise the no-token / SKIP code path.
pub(crate) fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(hasp_bin())
        .current_dir(dir)
        .args(args)
        .env_remove("GITHUB_TOKEN")
        .output()
        .expect("failed to execute hasp")
}

/// Run hasp in `dir` with `GITHUB_TOKEN` inherited from the caller. Used by
/// `#[ignore]` tests that hit the real GitHub API.
pub(crate) fn run_with_token(dir: &Path, args: &[&str]) -> Output {
    Command::new(hasp_bin())
        .current_dir(dir)
        .args(args)
        .output()
        .expect("failed to execute hasp")
}

pub(crate) fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub(crate) fn combined(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

// ─── git helpers for runtime-constructed fixtures ────────────────────────────

/// Run `git <args>` in `dir` with deterministic author/committer env.
pub(crate) fn git(dir: &Path, args: &[&str]) -> Output {
    let o = Command::new("git")
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "hasp-test")
        .env("GIT_AUTHOR_EMAIL", "test@hasp.local")
        .env("GIT_COMMITTER_NAME", "hasp-test")
        .env("GIT_COMMITTER_EMAIL", "test@hasp.local")
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        o.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    o
}

/// Create a fresh git repo in a uniquely-named tmpdir with an initial empty
/// commit on `main`. Each call gets its own directory so tests can run in
/// parallel.
pub(crate) fn make_git_repo(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "hasp-test-{label}-{}-{}",
        std::process::id(),
        C.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(dir.join(".github/workflows")).unwrap();
    git(&dir, &["init", "-q", "-b", "main"]);
    git(&dir, &["commit", "--allow-empty", "-q", "-m", "init"]);
    dir
}

pub(crate) fn write_workflow(repo: &Path, name: &str, body: &str) {
    std::fs::write(repo.join(".github/workflows").join(name), body).unwrap();
}

pub(crate) fn commit_all(repo: &Path, msg: &str) {
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-q", "-m", msg]);
}

/// Copy a static fixture to a fresh tmpdir outside the hasp repo. Used by
/// tests that need the fixture to NOT be inside another git repo's
/// walkup tree (e.g. "scan outside git repo" coverage).
pub(crate) fn copy_fixture_outside_repo(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    let src = fixture(name);
    let dst = std::env::temp_dir().join(format!(
        "hasp-fixture-{name}-{}-{}",
        std::process::id(),
        C.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dst).unwrap();
    copy_dir(&src, &dst);
    dst
}

fn copy_dir(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}
