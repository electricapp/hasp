use crate::error::{Context, Result};
use sha1::{Digest, Sha1};
use std::fmt::Write;
use std::path::Path;

/// Env var carrying the committed workflow hashes from the launcher to the scan
/// subprocess (which cannot run git itself — execve is denied by its sandbox).
pub(crate) const INTEGRITY_HASHES_ENV: &str = "HASP_INTEGRITY_HASHES";

/// Check that every `.yml`/`.yaml` file in `dir` matches the content recorded
/// by git.  If any file's on-disk content has been modified after `git checkout`
/// (e.g. by a prior CI step injecting malicious workflow content), this returns
/// an error so the scan is aborted before trusting those files.
///
/// Gracefully skips the check when git is unavailable or `dir` is not inside a
/// git repository — this is a defense-in-depth measure, not a hard requirement.
///
/// However, if a `.git` directory exists (indicating this *is* a repo) but
/// `git ls-tree` fails, that is suspicious and we fail closed rather than
/// silently passing.
/// Convenience wrapper: compute and verify in one call. Production code splits
/// these (see `expected_workflow_hashes` + `verify_entries`) so the same hashes
/// can also be handed to the scan subprocess; kept here for tests.
#[cfg(test)]
pub(crate) fn check_workflow_integrity(dir: &Path) -> Result<()> {
    expected_workflow_hashes(dir)?.map_or(Ok(()), |entries| verify_entries(dir, &entries))
}

/// Return the committed (`HEAD`) blob hashes for every `.yml`/`.yaml` file under
/// `dir`, or `None` when `dir` is not inside a git repository (in which case the
/// integrity check is skipped as defense-in-depth, not a hard requirement).
///
/// Fails closed when a `.git` directory exists but `git ls-tree` errors.
pub(crate) fn expected_workflow_hashes(dir: &Path) -> Result<Option<Vec<GitStageEntry>>> {
    match git_ls_files_stage(dir) {
        Ok(entries) => Ok(Some(entries)),
        Err(e) => {
            // If .git doesn't exist anywhere in the directory ancestry, this
            // genuinely isn't a git repo — skip silently.
            if has_git_dir(dir) { Err(e) } else { Ok(None) }
        }
    }
}

/// Verify that each committed entry's on-disk content still matches `HEAD`.
/// This is the *launcher-side* pre-check; the scanner subprocess additionally
/// verifies the exact bytes it scans (see `scanner`) to close the TOCTOU window
/// between this read and the scan's read.
pub(crate) fn verify_entries(dir: &Path, entries: &[GitStageEntry]) -> Result<()> {
    let mut mismatches: Vec<String> = Vec::new();

    for entry in entries {
        let file_path = dir.join(&entry.path);

        let content = match std::fs::read(&file_path) {
            Ok(c) => c,
            Err(e) => {
                // File tracked by git but missing on disk — flag it
                mismatches.push(format!("  {} (cannot read: {e})", entry.path));
                continue;
            }
        };

        if git_blob_hash(&content) != entry.blob_hash {
            mismatches.push(format!(
                "  {} (git: {}, disk: {})",
                entry.path,
                entry.blob_hash,
                git_blob_hash(&content)
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

/// Serialize expected hashes for transport to the scan subprocess (env var).
/// Each entry is `<blob_hash>:<hex(path)>`, joined by `;`. Hex-encoding the path
/// keeps the format unambiguous regardless of bytes in the filename.
pub(crate) fn encode_expected_hashes(entries: &[GitStageEntry]) -> String {
    let mut out = String::new();
    for entry in entries {
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(&entry.blob_hash);
        out.push(':');
        for b in entry.path.as_bytes() {
            let _ = write!(out, "{b:02x}");
        }
    }
    out
}

/// Inverse of [`encode_expected_hashes`]. Lenient: malformed entries are skipped
/// (the launcher-side check already ran, so this only *adds* verification).
pub(crate) fn decode_expected_hashes(s: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for entry in s.split(';').filter(|e| !e.is_empty()) {
        let Some((hash, hex_path)) = entry.split_once(':') else {
            continue;
        };
        if hex_path.len() % 2 != 0 {
            continue;
        }
        let bytes: Option<Vec<u8>> = (0..hex_path.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_path[i..i + 2], 16).ok())
            .collect();
        if let Some(bytes) = bytes
            && let Ok(path) = String::from_utf8(bytes)
        {
            map.insert(path, hash.to_string());
        }
    }
    map
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

/// A single blob entry from the committed `HEAD` tree.
pub(crate) struct GitStageEntry {
    blob_hash: String,
    path: String,
}

/// Run `git ls-tree -r HEAD -- <dir>` and parse the output.
///
/// We compare against the committed tree (`HEAD`), *not* the staging index:
/// an attacker-controlled CI step that tampers with a workflow file and then
/// runs `git add` would update the index to match the tampered content,
/// silently defeating the check. `ls-tree HEAD` reflects what was actually
/// committed and cannot be masked by re-staging.
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
        .arg("ls-tree")
        .arg("-r")
        // -z: NUL-terminated records with *unquoted* paths. Without it, git
        // C-quotes any path containing non-ASCII/`"`/`\` bytes (e.g.
        // `"d\303\251ploy.yml"`), which would defeat the `.yml` extension check
        // and break `dir.join(path)` — silently skipping integrity checks for
        // workflows with such names (a fail-open hole).
        .arg("-z")
        .arg("HEAD")
        .arg("--")
        .arg(".")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .context("Failed to run git ls-tree")?;

    if !output.status.success() {
        crate::error::bail!("git ls-tree failed (not a git repository or no commits?)");
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| crate::error::Error::new("git ls-tree produced non-UTF-8 output".into()))?;

    let mut entries = Vec::new();

    for record in stdout.split('\0').filter(|r| !r.is_empty()) {
        // Format: "<mode> <type> <hash>\t<path>" (path unquoted thanks to -z).
        let Some((meta, path)) = record.split_once('\t') else {
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
        // Expect "<mode> <type> <hash>"; only consider blobs (skip submodules,
        // trees, etc.).
        if parts.len() < 3 || parts[1] != "blob" {
            continue;
        }

        entries.push(GitStageEntry {
            blob_hash: parts[2].to_string(),
            // Paths are relative to `dir` thanks to `git -C <dir>`, so the
            // caller can join directly: `dir.join(&entry.path)`.
            path: path.to_string(),
        });
    }

    Ok(entries)
}

/// Compute the SHA-1 hash of content using git's blob format:
/// `blob <size>\0<content>`
pub(crate) fn git_blob_hash(content: &[u8]) -> String {
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
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(repo)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("run git");
        assert!(status.success(), "git {args:?} failed");
    }

    fn temp_repo(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hasp-integrity-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(path.join(".github/workflows")).expect("mkdir temp repo");
        git(&path, &["init", "-q"]);
        path
    }

    #[test]
    fn staged_tamper_is_still_detected() {
        // Regression: comparing against the staging index (old behavior) let an
        // attacker mask a tampered workflow by running `git add`. We compare
        // against the committed HEAD tree, so re-staging cannot hide it.
        let repo = temp_repo("staged");
        let wf = repo.join(".github/workflows/ci.yml");
        std::fs::write(&wf, "name: clean\n").expect("write clean");
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "clean"]);

        // Tamper the file AND stage it — index now matches the tampered disk.
        std::fs::write(&wf, "name: tampered\n").expect("write tamper");
        git(&repo, &["add", "."]);

        let result = check_workflow_integrity(&repo.join(".github/workflows"));
        assert!(
            result.is_err(),
            "staged tamper must be detected via HEAD comparison"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn clean_committed_tree_passes() {
        let repo = temp_repo("clean");
        std::fs::write(repo.join(".github/workflows/ci.yml"), "name: clean\n")
            .expect("write clean");
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "clean"]);

        check_workflow_integrity(&repo.join(".github/workflows"))
            .expect("untampered committed tree should pass");
        let _ = std::fs::remove_dir_all(&repo);
    }

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

    #[test]
    fn expected_hashes_encode_decode_round_trips() {
        let entries = vec![
            GitStageEntry {
                blob_hash: "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0".into(),
                path: "ci.yml".into(),
            },
            GitStageEntry {
                // Non-ASCII filename: the hex path encoding must survive it.
                blob_hash: "95d09f2b10159347eece71399a7e2e907ea3df4f".into(),
                path: "déploy.yaml".into(),
            },
        ];
        let encoded = encode_expected_hashes(&entries);
        let decoded = decode_expected_hashes(&encoded);
        assert_eq!(decoded.len(), 2);
        assert_eq!(
            decoded.get("ci.yml").map(String::as_str),
            Some("b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0")
        );
        assert_eq!(
            decoded.get("déploy.yaml").map(String::as_str),
            Some("95d09f2b10159347eece71399a7e2e907ea3df4f")
        );
    }

    #[test]
    fn decode_expected_hashes_skips_malformed_entries() {
        // No panic, and well-formed entries still decode.
        let decoded = decode_expected_hashes("nocolon;deadbeef:zz;abc:6369");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.get("ci").map(String::as_str), Some("abc"));
    }
}
