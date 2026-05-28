//! Small, shared git/repository helpers used by both the launcher and `hasp
//! diff`. Kept here so the two call sites can't drift apart.

use crate::error::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Walk up from `start` looking for `.git` or `.hasp.yml`. Used to anchor
/// policy loading and other repo-relative resolution. Falls back to `start`
/// if neither is found within `MAX_DEPTH` levels.
pub(crate) fn find_repo_root(start: &Path) -> PathBuf {
    const MAX_DEPTH: u32 = 10;
    let mut dir = start.to_path_buf();
    let mut depth = 0_u32;
    loop {
        if dir.join(".git").exists() || dir.join(".hasp.yml").exists() {
            return dir;
        }
        depth += 1;
        if depth > MAX_DEPTH || !dir.pop() {
            return start.to_path_buf();
        }
    }
}

/// Reject obviously hostile git ref strings before passing them to `git`.
/// Bans option-style refs (`-X`), path traversal (`..`), backslashes, null
/// bytes and other control characters.
pub(crate) fn is_sane_git_ref(ref_str: &str) -> bool {
    !ref_str.is_empty()
        && ref_str.len() <= 256
        && !ref_str.starts_with('-')
        && !ref_str.contains('\0')
        && !ref_str.contains("..")
        && !ref_str.contains('\\')
        && !ref_str.bytes().any(|b| b.is_ascii_control())
}

/// Build a `git` `Command` with repo-level hooks disabled, so checking out
/// or otherwise touching attacker-controlled refs cannot run a
/// `post-checkout` / `pre-commit` / ... hook inherited from the local repo.
pub(crate) fn git_cmd() -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-c").arg("core.hooksPath=/dev/null");
    cmd
}

/// `git rev-parse --show-toplevel` from inside `start`.
pub(crate) fn repo_toplevel(start: &Path) -> Result<PathBuf> {
    let out = git_cmd()
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(start)
        .output()
        .context("Failed to run `git rev-parse --show-toplevel`")?;
    if !out.status.success() {
        bail!(
            "`git rev-parse --show-toplevel` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8(out.stdout).context("git rev-parse output was not UTF-8")?;
    Ok(PathBuf::from(text.trim()))
}

/// Resolve `ref_str` to a 40-char hex SHA inside `repo_root`. Errors if the
/// ref doesn't resolve or git returns something unexpected.
pub(crate) fn resolve_ref_sha(repo_root: &Path, ref_str: &str) -> Result<String> {
    let out = git_cmd()
        .args(["rev-parse", "--verify", "--quiet", ref_str])
        .current_dir(repo_root)
        .output()
        .context("Failed to run `git rev-parse`")?;
    if !out.status.success() {
        bail!("ref `{ref_str}` could not be resolved");
    }
    let text = String::from_utf8(out.stdout).context("git rev-parse output was not UTF-8")?;
    let sha = text.trim();
    if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("git rev-parse returned unexpected ref `{sha}`");
    }
    Ok(sha.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_sane_git_ref_accepts_normal_refs() {
        assert!(is_sane_git_ref("main"));
        assert!(is_sane_git_ref("HEAD~1"));
        assert!(is_sane_git_ref("v1.2.3"));
        assert!(is_sane_git_ref("feature/foo"));
    }

    #[test]
    fn is_sane_git_ref_rejects_bad_input() {
        assert!(!is_sane_git_ref(""));
        assert!(!is_sane_git_ref("-x"));
        assert!(!is_sane_git_ref("--upload-pack=evil"));
        assert!(!is_sane_git_ref("../etc/passwd"));
        assert!(!is_sane_git_ref("foo\0bar"));
        assert!(!is_sane_git_ref("foo\tbar"));
        assert!(!is_sane_git_ref("a\\b"));
    }
}
