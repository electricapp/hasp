use crate::error::{Context, Result};
use sha1::{Digest, Sha1};
use std::fmt::Write;
use std::path::Path;

/// Check that every `.yml`/`.yaml` file in `dir` matches the content recorded
/// by git.  If any file's on-disk content has been modified after `git checkout`
/// (e.g. by a prior CI step injecting malicious workflow content), this returns
/// an error so the scan is aborted before trusting those files.
///
/// Gracefully skips the check when git is unavailable or `dir` is not inside a
/// git repository — this is a defense-in-depth measure, not a hard requirement.
///
/// However, if a `.git` directory exists (indicating this *is* a repo) but
/// `git ls-files` fails, that is suspicious and we fail closed rather than
/// silently passing.
pub(crate) fn check_workflow_integrity(dir: &Path) -> Result<()> {
    let entries = match git_ls_files_stage(dir) {
        Ok(entries) if entries.is_empty() => return Ok(()),
        Ok(entries) => entries,
        Err(e) => {
            // If .git doesn't exist anywhere in the directory ancestry,
            // this genuinely isn't a git repo — skip silently.
            if !has_git_dir(dir) {
                return Ok(());
            }
            // .git exists but git ls-files failed — fail closed.
            return Err(e);
        }
    };

    let mut mismatches: Vec<String> = Vec::new();

    for entry in &entries {
        let file_path = dir.join(&entry.path);

        let content = match std::fs::read(&file_path) {
            Ok(c) => c,
            Err(e) => {
                // File tracked by git but missing on disk — flag it
                mismatches.push(format!("  {} (cannot read: {e})", entry.path));
                continue;
            }
        };

        let disk_hash = git_blob_hash(&content);

        if disk_hash != entry.blob_hash {
            mismatches.push(format!(
                "  {} (git: {}, disk: {})",
                entry.path, entry.blob_hash, disk_hash
            ));
        }
    }

    if mismatches.is_empty() {
        return Ok(());
    }

    let detail = mismatches.join("\n");
    crate::error::bail!(
        "CRITICAL: workflow file integrity check failed!\n\
         The following files differ from what git tracks:\n\
         {detail}\n\
         This may indicate a prior CI step tampered with workflow files after checkout.\n\
         Pass --allow-unsandboxed to skip this check (development only)."
    );
}

/// Walk up from `dir` to check whether a `.git` directory (or file, for
/// worktrees) exists in any ancestor.  Returns `true` if we appear to be
/// inside a git repository.
fn has_git_dir(dir: &Path) -> bool {
    let mut current = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        match dir.canonicalize() {
            Ok(p) => p,
            Err(_) => return false,
        }
    };
    let mut depth = 0_u32;
    loop {
        if current.join(".git").exists() {
            return true;
        }
        depth += 1;
        if depth > 20 || !current.pop() {
            return false;
        }
    }
}

/// A single entry from `git ls-files --stage`.
struct GitStageEntry {
    blob_hash: String,
    path: String,
}

/// Run `git ls-files --stage -- <dir>` and parse the output.
///
/// Returns `Err` if git is not found or the command fails (e.g. not a repo).
/// Only returns entries for `.yml` and `.yaml` files.
fn git_ls_files_stage(dir: &Path) -> Result<Vec<GitStageEntry>> {
    // Use `git -C <dir>` so that output paths are relative to `dir`, not the
    // repo root.  This lets the caller simply `dir.join(entry.path)` to get
    // the absolute path, even when subdirectories exist under `dir`.
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .arg("ls-files")
        .arg("--stage")
        .arg("--")
        .arg(".")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .context("Failed to run git ls-files")?;

    if !output.status.success() {
        crate::error::bail!("git ls-files failed (not a git repository?)");
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| crate::error::Error::new("git ls-files produced non-UTF-8 output".into()))?;

    let mut entries = Vec::new();

    for line in stdout.lines() {
        // Format: "<mode> <hash> <stage>\t<path>"
        let Some((meta, path)) = line.split_once('\t') else {
            continue;
        };

        // Only check workflow files
        let is_yml = Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"));
        if !is_yml {
            continue;
        }

        let parts: Vec<&str> = meta.split(' ').collect();
        if parts.len() < 3 {
            continue;
        }

        entries.push(GitStageEntry {
            blob_hash: parts[1].to_string(),
            // Paths are now relative to `dir` thanks to `git -C <dir>`,
            // so the caller can join directly: `dir.join(&entry.path)`.
            path: path.to_string(),
        });
    }

    Ok(entries)
}

/// Compute the SHA-1 hash of content using git's blob format:
/// `blob <size>\0<content>`
fn git_blob_hash(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hasher.finalize().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_blob_hash_matches_known_value() {
        // Verify against `printf "hello" | git hash-object --stdin`
        let hash = git_blob_hash(b"hello");
        assert_eq!(
            hash, "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0",
            "git blob hash of 'hello' should match `git hash-object --stdin`"
        );

        // Verify against `printf "hello world" | git hash-object --stdin`
        let hash = git_blob_hash(b"hello world");
        assert_eq!(
            hash, "95d09f2b10159347eece71399a7e2e907ea3df4f",
            "git blob hash of 'hello world' should match `git hash-object --stdin`"
        );
    }

    #[test]
    fn git_blob_hash_empty_content() {
        // `echo -n "" | git hash-object --stdin` = e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
        let hash = git_blob_hash(b"");
        assert_eq!(
            hash, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
            "git blob hash of empty content should match git's empty blob"
        );
    }
}
