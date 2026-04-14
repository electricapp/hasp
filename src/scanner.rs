use crate::error::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use yaml_rust2::{Yaml, YamlLoader};

const MAX_FILE_BYTES: u64 = 1024 * 1024; // 1 MiB
const MAX_REFS_PER_SCAN: usize = 500;

// ─── Cached YAML key accessors (avoid repeated heap allocation) ──────────────

macro_rules! yaml_key {
    ($fn_name:ident, $key:expr) => {
        fn $fn_name() -> &'static Yaml {
            static K: std::sync::OnceLock<Yaml> = std::sync::OnceLock::new();
            K.get_or_init(|| Yaml::String($key.to_string()))
        }
    };
}

yaml_key!(key_jobs, "jobs");
yaml_key!(key_steps, "steps");
yaml_key!(key_uses, "uses");
yaml_key!(key_container, "container");
yaml_key!(key_services, "services");
yaml_key!(key_image, "image");
yaml_key!(key_runs, "runs");
yaml_key!(key_using, "using");
/// Maximum directory recursion depth to prevent symlink loops and
/// unreasonably deep trees.
const MAX_DIR_DEPTH: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefKind {
    FullSha,
    Mutable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActionRef {
    pub(crate) file: PathBuf,
    pub(crate) owner: String,
    pub(crate) repo: String,
    pub(crate) path: Option<String>,
    pub(crate) ref_str: String,
    pub(crate) ref_kind: RefKind,
    /// Optional version comment from `# v1.2.3` after the uses: line.
    /// Extracted from the raw YAML text since comments aren't in the AST.
    pub(crate) comment_version: Option<String>,
}

impl ActionRef {
    pub(crate) fn short_ref(&self) -> &str {
        match self.ref_kind {
            RefKind::FullSha => {
                // FullSha should always be 40 hex chars, but be defensive
                if self.ref_str.len() >= 12 {
                    &self.ref_str[..12]
                } else {
                    &self.ref_str
                }
            }
            RefKind::Mutable => &self.ref_str,
        }
    }

    pub(crate) fn target(&self) -> String {
        self.path.as_ref().map_or_else(
            || format!("{}/{}", self.owner, self.repo),
            |path| format!("{}/{}/{}", self.owner, self.repo, path),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActionRefChange {
    pub(crate) file: PathBuf,
    pub(crate) owner: String,
    pub(crate) repo: String,
    pub(crate) path: Option<String>,
    pub(crate) old_sha: String,
    pub(crate) new_sha: String,
    pub(crate) old_comment: Option<String>,
    pub(crate) new_comment: Option<String>,
}

/// Extract action refs from in-memory YAML content (no filesystem access).
/// Used by `--diff-base` to parse old file versions from `git show`.
///
/// `extract_uses` may fail partway through (e.g. unresolvable local refs
/// against the dummy root).  That is fine: remote `owner/repo@sha` refs are
/// parsed *before* any local-ref recursion, so all SHA-pinned remote refs
/// are already collected in `state` by the time a local-ref error occurs.
/// We discard the error and keep whatever was collected, then filter to
/// `FullSha` only.
pub(crate) fn extract_action_refs_from_content(
    content: &str,
    file: &Path,
) -> Result<Vec<ActionRef>> {
    let comment_map = extract_version_comments(content);
    let docs = YamlLoader::load_from_str(content)?;
    let doc = docs.into_iter().next().unwrap_or(Yaml::Null);

    // Use a dummy repo root that won't resolve any local refs —
    // we only care about remote SHA-pinned actions.
    let dummy_root = Path::new("/nonexistent-hasp-diff-base-root");
    let mut state = ScanState::default();

    // Errors here are from local ref resolution against the dummy root;
    // all remote refs were already collected before the failure point.
    if let Err(e) = extract_uses(&doc, file, dummy_root, &comment_map, &mut state) {
        eprintln!(
            "hasp: note: partial parse of {}: {e} (remote refs still collected)",
            file.display()
        );
    }

    // Only keep FullSha refs (mutable refs aren't relevant for diff-base)
    state.action_refs.retain(|r| r.ref_kind == RefKind::FullSha);
    Ok(state.action_refs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContainerRefKind {
    StepDockerUses,
    JobContainer,
    ServiceContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContainerPinKind {
    DigestPinned,
    Mutable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerRef {
    pub(crate) file: PathBuf,
    pub(crate) image: String,
    pub(crate) kind: ContainerRefKind,
    pub(crate) pin_kind: ContainerPinKind,
}

impl ContainerRef {
    pub(crate) const fn is_pinned(&self) -> bool {
        matches!(self.pin_kind, ContainerPinKind::DigestPinned)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SkippedRefKind {
    RemoteReusableWorkflow,
    UnresolvedLocalPath,
    UnsupportedLocalRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkippedRef {
    pub(crate) file: PathBuf,
    pub(crate) uses_str: String,
    pub(crate) kind: SkippedRefKind,
    pub(crate) detail: String,
}

#[derive(Debug)]
pub(crate) struct ScanResult {
    pub(crate) action_refs: Vec<ActionRef>,
    pub(crate) workflow_docs: Vec<(PathBuf, Yaml)>,
    pub(crate) skipped_refs: Vec<SkippedRef>,
    pub(crate) container_refs: Vec<ContainerRef>,
}

#[derive(Default)]
struct ScanState {
    action_refs: Vec<ActionRef>,
    workflow_docs: Vec<(PathBuf, Yaml)>,
    skipped_refs: Vec<SkippedRef>,
    container_refs: Vec<ContainerRef>,
    visited_yaml_files: HashSet<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DocumentKind {
    Workflow,
    ActionMetadata,
}

pub(crate) fn scan_directory(dir: &Path) -> Result<ScanResult> {
    let canonical_dir = dir
        .canonicalize()
        .context("Cannot canonicalize workflow directory")?;
    let repo_root = infer_repo_root(&canonical_dir);

    let mut state = ScanState::default();

    // Recurse into subdirectories so that custom --dir usage picks
    // up YAML files in nested folders (GitHub only uses the top-level
    // .github/workflows/, but other callers may point at wider trees).
    scan_directory_recursive(&canonical_dir, &canonical_dir, &repo_root, 0, &mut state)?;

    Ok(ScanResult {
        action_refs: state.action_refs,
        workflow_docs: state.workflow_docs,
        skipped_refs: state.skipped_refs,
        container_refs: state.container_refs,
    })
}

/// Recursively scan `current_dir` for YAML workflow files, up to
/// `MAX_DIR_DEPTH` levels deep.  `root_dir` is the top-level scan directory
/// used for symlink-escape checks.
fn scan_directory_recursive(
    current_dir: &Path,
    root_dir: &Path,
    repo_root: &Path,
    depth: u32,
    state: &mut ScanState,
) -> Result<()> {
    if depth > MAX_DIR_DEPTH {
        return Ok(());
    }

    let entries = std::fs::read_dir(current_dir).context("Cannot open workflow directory")?;

    for entry in entries {
        let entry = entry.context("Directory read error")?;
        let path = entry.path();

        if path.is_dir() {
            let Ok(canonical_sub_dir) = path.canonicalize() else {
                continue;
            };
            // Prevent traversal outside the root scan directory
            if !canonical_sub_dir.starts_with(root_dir) {
                eprintln!(
                    "hasp: SKIPPED {} — resolves outside workflow directory. \
                     Possible symlink traversal.",
                    path.display()
                );
                continue;
            }
            scan_directory_recursive(&canonical_sub_dir, root_dir, repo_root, depth + 1, state)?;
            continue;
        }

        if !path.is_file() {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str());
        if !matches!(ext, Some("yml" | "yaml")) {
            continue;
        }

        let canonical_file = path.canonicalize().context("Cannot resolve file path")?;
        if !canonical_file.starts_with(root_dir) {
            eprintln!(
                "hasp: SKIPPED {} — resolves outside workflow directory. \
                 Possible symlink traversal.",
                path.display()
            );
            continue;
        }

        // Guard against hardlinks: a hardlink within the directory could point
        // to an inode belonging to a file outside the directory. Check that the
        // hardlink count is 1 (no extra links) to prevent this edge case.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(&canonical_file).context("Cannot stat workflow file")?;
            if meta.nlink() > 1 {
                eprintln!(
                    "hasp: SKIPPED {} — file has {} hard links. \
                     Possible hardlink traversal.",
                    path.display(),
                    meta.nlink()
                );
                continue;
            }
        }

        scan_yaml_file(&canonical_file, repo_root, DocumentKind::Workflow, state)?;
        enforce_ref_limit(state)?;
    }

    Ok(())
}

/// `path` must already be canonicalized by the caller.
fn scan_yaml_file(
    path: &Path,
    repo_root: &Path,
    kind: DocumentKind,
    state: &mut ScanState,
) -> Result<()> {
    if !state.visited_yaml_files.insert(path.to_path_buf()) {
        return Ok(());
    }

    let size = std::fs::metadata(path).context("Cannot stat file")?.len();
    if size > MAX_FILE_BYTES {
        bail!("{} exceeds 1 MiB size limit", path.display());
    }

    let content = std::fs::read_to_string(path).context("Cannot read file")?;
    let comment_map = extract_version_comments(&content);
    let docs = YamlLoader::load_from_str(&content)?;
    let doc = docs.into_iter().next().unwrap_or(Yaml::Null);

    if kind == DocumentKind::Workflow {
        extract_container_refs(&doc, path, &mut state.container_refs);
        state.workflow_docs.push((path.to_path_buf(), doc.clone()));
    }

    extract_uses(&doc, path, repo_root, &comment_map, state)?;
    enforce_ref_limit(state)?;
    Ok(())
}

fn enforce_ref_limit(state: &ScanState) -> Result<()> {
    if state.action_refs.len() > MAX_REFS_PER_SCAN {
        bail!(
            "scan exceeded maximum action reference budget ({} > {})",
            state.action_refs.len(),
            MAX_REFS_PER_SCAN
        );
    }
    Ok(())
}

/// Extract `# vX.Y.Z` comments from `uses:` lines.
/// Returns a map from `owner/repo@ref` → `vX.Y.Z`.
fn extract_version_comments(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Only match lines where `uses:` appears as a YAML key — either at the
        // start of the line or after `- ` (list item).  This avoids false
        // matches inside `run:` blocks or comments.
        let after_uses = if let Some(rest) = trimmed.strip_prefix("uses:") {
            rest.trim()
        } else if let Some(rest) = trimmed.strip_prefix("- uses:") {
            rest.trim()
        } else {
            continue;
        };

        if let Some(hash_pos) = after_uses.find('#') {
            let uses_value = after_uses[..hash_pos].trim();
            let comment = after_uses[hash_pos + 1..].trim();

            if let Some(ver) = extract_version_from_comment(comment) {
                map.insert(uses_value.to_string(), ver);
            }
        }
    }

    map
}

fn extract_version_from_comment(comment: &str) -> Option<String> {
    for (i, _) in comment.match_indices('v') {
        let after_v = &comment[i + 1..];
        let end = after_v
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(after_v.len());
        // Reconstruct "vX.Y.Z" — the 'v' prefix plus the digit/dot run
        let candidate = &comment[i..i + 1 + end];

        if candidate.len() >= 2 && candidate.as_bytes()[1].is_ascii_digit() {
            return Some(candidate.to_string());
        }
    }
    None
}

fn extract_uses(
    yaml: &Yaml,
    file: &Path,
    repo_root: &Path,
    comments: &HashMap<String, String>,
    state: &mut ScanState,
) -> Result<()> {
    #[allow(clippy::wildcard_enum_match_arm)] // Yaml has many non-hash/array variants
    match yaml {
        Yaml::Hash(map) => {
            for (k, v) in map {
                if k.as_str() == Some("uses") {
                    if let Some(uses_str) = v.as_str() {
                        handle_uses_value(uses_str, file, repo_root, comments, state)?;
                    }
                } else {
                    extract_uses(v, file, repo_root, comments, state)?;
                }
            }
        }
        Yaml::Array(arr) => {
            for item in arr {
                extract_uses(item, file, repo_root, comments, state)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn handle_uses_value(
    uses: &str,
    file: &Path,
    repo_root: &Path,
    comments: &HashMap<String, String>,
    state: &mut ScanState,
) -> Result<()> {
    if let Some(image) = uses.strip_prefix("docker://") {
        if let Some(container_ref) =
            parse_container_ref(image, file, ContainerRefKind::StepDockerUses)
        {
            state.container_refs.push(container_ref);
        }
        return Ok(());
    }

    if uses.starts_with("./") || uses.starts_with("../") {
        return scan_local_ref(uses, file, repo_root, state);
    }

    let Some(at) = uses.find('@') else {
        return Ok(());
    };
    let (repo_part, ref_str) = (&uses[..at], &uses[at + 1..]);
    if ref_str.is_empty() {
        return Ok(());
    }

    let mut segments = repo_part.splitn(3, '/');
    let Some(owner) = segments.next().filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let Some(repo) = segments.next().filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let repo_path = segments.next();

    if let Some(path_in_repo) = repo_path
        && looks_like_remote_reusable_workflow(path_in_repo)
    {
        state.skipped_refs.push(SkippedRef {
            file: file.to_path_buf(),
            uses_str: uses.to_string(),
            kind: SkippedRefKind::RemoteReusableWorkflow,
            detail: "remote reusable workflow contents are not audited transitively".into(),
        });
        return Ok(());
    }

    if !is_safe_github_component(owner) || !is_safe_github_component(repo) {
        return Ok(());
    }
    let path = match repo_path {
        Some(path) if !path.is_empty() => {
            if !is_safe_github_subpath(path) {
                return Ok(());
            }
            Some(path.to_string())
        }
        _ => None,
    };
    if ref_str.contains("..") || ref_str.contains('\\') || ref_str.starts_with('/') {
        return Ok(());
    }

    let (ref_kind, normalized_ref) =
        if ref_str.len() == 40 && ref_str.bytes().all(|b| b.is_ascii_hexdigit()) {
            // Normalize SHAs to lowercase so they match proxy's validate_sha()
            (RefKind::FullSha, ref_str.to_ascii_lowercase())
        } else {
            (RefKind::Mutable, ref_str.to_string())
        };

    state.action_refs.push(ActionRef {
        file: file.to_path_buf(),
        owner: owner.to_string(),
        repo: repo.to_string(),
        path,
        ref_str: normalized_ref,
        ref_kind,
        comment_version: comments.get(uses).cloned(),
    });

    Ok(())
}

fn scan_local_ref(uses: &str, file: &Path, repo_root: &Path, state: &mut ScanState) -> Result<()> {
    let candidate = repo_root.join(uses);
    let Ok(canonical) = candidate.canonicalize() else {
        state.skipped_refs.push(SkippedRef {
            file: file.to_path_buf(),
            uses_str: uses.to_string(),
            kind: SkippedRefKind::UnresolvedLocalPath,
            detail: "local action/workflow path does not exist".into(),
        });
        return Ok(());
    };

    if !canonical.starts_with(repo_root) {
        state.skipped_refs.push(SkippedRef {
            file: file.to_path_buf(),
            uses_str: uses.to_string(),
            kind: SkippedRefKind::UnresolvedLocalPath,
            detail: "local path escapes the repository root".into(),
        });
        return Ok(());
    }

    if canonical.is_file() {
        let ext = canonical.extension().and_then(|e| e.to_str());
        if matches!(ext, Some("yml" | "yaml")) {
            return scan_yaml_file(&canonical, repo_root, DocumentKind::Workflow, state);
        }

        state.skipped_refs.push(SkippedRef {
            file: file.to_path_buf(),
            uses_str: uses.to_string(),
            kind: SkippedRefKind::UnsupportedLocalRef,
            detail: "local file ref is not a workflow YAML".into(),
        });
        return Ok(());
    }

    if canonical.is_dir() {
        for name in ["action.yml", "action.yaml"] {
            let action_file = canonical.join(name);
            if action_file.is_file() {
                return scan_yaml_file(
                    &action_file,
                    repo_root,
                    DocumentKind::ActionMetadata,
                    state,
                );
            }
        }

        state.skipped_refs.push(SkippedRef {
            file: file.to_path_buf(),
            uses_str: uses.to_string(),
            kind: SkippedRefKind::UnsupportedLocalRef,
            detail: "local action directory is missing action.yml or action.yaml".into(),
        });
        return Ok(());
    }

    state.skipped_refs.push(SkippedRef {
        file: file.to_path_buf(),
        uses_str: uses.to_string(),
        kind: SkippedRefKind::UnsupportedLocalRef,
        detail: "local ref is neither a workflow file nor an action directory".into(),
    });
    Ok(())
}

fn extract_container_refs(doc: &Yaml, file: &Path, out: &mut Vec<ContainerRef>) {
    let Some(jobs) = doc
        .as_hash()
        .and_then(|m| m.get(key_jobs()))
        .and_then(|j| j.as_hash())
    else {
        return;
    };

    for (_job_name, job_value) in jobs {
        let Some(job_map) = job_value.as_hash() else {
            continue;
        };

        if let Some(image) = extract_image_string(job_map.get(key_container()))
            && let Some(container_ref) =
                parse_container_ref(image, file, ContainerRefKind::JobContainer)
        {
            out.push(container_ref);
        }

        let Some(services) = job_map.get(key_services()).and_then(|s| s.as_hash()) else {
            continue;
        };

        for (_service_name, service_value) in services {
            if let Some(image) = extract_image_string(Some(service_value))
                && let Some(container_ref) =
                    parse_container_ref(image, file, ContainerRefKind::ServiceContainer)
            {
                out.push(container_ref);
            }
        }
    }
}

fn extract_image_string(value: Option<&Yaml>) -> Option<&str> {
    #[allow(clippy::wildcard_enum_match_arm)] // Yaml: only String and Hash are valid here
    match value? {
        Yaml::String(s) if !s.trim().is_empty() => Some(s.as_str()),
        Yaml::Hash(map) => map
            .get(key_image())
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty()),
        _ => None,
    }
}

fn parse_container_ref(image: &str, file: &Path, kind: ContainerRefKind) -> Option<ContainerRef> {
    let trimmed = image.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(ContainerRef {
        file: file.to_path_buf(),
        image: trimmed.to_string(),
        kind,
        pin_kind: if is_digest_pinned_image(trimmed) {
            ContainerPinKind::DigestPinned
        } else {
            ContainerPinKind::Mutable
        },
    })
}

fn is_digest_pinned_image(image: &str) -> bool {
    let Some((_, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };

    digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
}

fn infer_repo_root(workflow_dir: &Path) -> PathBuf {
    if workflow_dir.file_name() == Some(OsStr::new("workflows"))
        && let Some(github_dir) = workflow_dir.parent()
        && github_dir.file_name() == Some(OsStr::new(".github"))
        && let Some(root) = github_dir.parent()
    {
        return root.to_path_buf();
    }

    workflow_dir.parent().unwrap_or(workflow_dir).to_path_buf()
}

fn looks_like_remote_reusable_workflow(path_in_repo: &str) -> bool {
    (path_in_repo.starts_with(".github/workflows/")
        || path_in_repo.starts_with("./.github/workflows/"))
        && matches!(
            Path::new(path_in_repo)
                .extension()
                .and_then(|ext| ext.to_str()),
            Some("yml" | "yaml")
        )
}

fn is_safe_github_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && !s.contains("..")
        && !s.contains('/')
        && !s.contains('\\')
        && !s.contains('\0')
        && !s.contains(' ')
        && !s.contains('?')
        && !s.contains('#')
        && !s.contains('%')
        && s.bytes().all(|b| b.is_ascii_graphic())
}

fn is_safe_github_subpath(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 200
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && !path.contains('?')
        && !path.contains('#')
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.contains('\\')
                && segment.bytes().all(|b| b.is_ascii_graphic())
        })
}

pub(crate) fn parse_composite_uses(yaml: &str) -> Vec<String> {
    let Ok(docs) = YamlLoader::load_from_str(yaml) else {
        return Vec::new();
    };
    let doc = docs.into_iter().next().unwrap_or(Yaml::Null);
    let Some(runs) = doc
        .as_hash()
        .and_then(|m| m.get(key_runs()))
        .and_then(|runs| runs.as_hash())
    else {
        return Vec::new();
    };

    if runs.get(key_using()).and_then(|v| v.as_str()) != Some("composite") {
        return Vec::new();
    }

    let Some(steps) = runs.get(key_steps()).and_then(|steps| steps.as_vec()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for step in steps {
        let Some(uses) = step
            .as_hash()
            .and_then(|m| m.get(key_uses()))
            .and_then(|uses| uses.as_str())
        else {
            continue;
        };
        let uses = uses.trim();
        if !uses.is_empty() {
            out.push(uses.to_string());
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_repo() -> PathBuf {
        let unique = format!(
            "hasp-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn scans_local_composite_actions_transitively() {
        let repo = temp_repo();
        write(
            &repo.join(".github/workflows/ci.yml"),
            "
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/wrapper
",
        );
        write(
            &repo.join(".github/actions/wrapper/action.yml"),
            "
name: wrapper
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
",
        );

        let result = scan_directory(&repo.join(".github/workflows")).unwrap();
        assert!(result.skipped_refs.is_empty());
        assert_eq!(result.action_refs.len(), 1);
        assert_eq!(result.action_refs[0].owner, "actions");
        assert_eq!(result.action_refs[0].repo, "checkout");
        assert_eq!(result.action_refs[0].path, None);
    }

    #[test]
    fn scans_local_reusable_workflows_transitively() {
        let repo = temp_repo();
        write(
            &repo.join(".github/workflows/ci.yml"),
            "
name: CI
on: [push]
jobs:
  call-local:
    uses: ./.github/workflows/reusable.yml
",
        );
        write(
            &repo.join(".github/workflows/reusable.yml"),
            "
on: workflow_call
permissions: {}
jobs:
  nested:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
",
        );

        let result = scan_directory(&repo.join(".github/workflows")).unwrap();
        assert!(result.skipped_refs.is_empty());
        assert_eq!(result.action_refs.len(), 1);
        assert!(
            result
                .workflow_docs
                .iter()
                .any(|(path, _)| path.ends_with(".github/workflows/reusable.yml"))
        );
    }

    #[test]
    fn detects_container_images_from_all_execution_paths() {
        let repo = temp_repo();
        write(
            &repo.join(".github/workflows/ci.yml"),
            "
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:20
    services:
      db:
        image: postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - uses: docker://alpine:3.20
",
        );

        let result = scan_directory(&repo.join(".github/workflows")).unwrap();
        assert_eq!(result.container_refs.len(), 3);
        assert!(
            result
                .container_refs
                .iter()
                .any(|r| r.kind == ContainerRefKind::JobContainer && !r.is_pinned())
        );
        assert!(
            result
                .container_refs
                .iter()
                .any(|r| r.kind == ContainerRefKind::ServiceContainer && r.is_pinned())
        );
        assert!(
            result
                .container_refs
                .iter()
                .any(|r| r.kind == ContainerRefKind::StepDockerUses && !r.is_pinned())
        );
    }

    #[test]
    fn marks_remote_reusable_workflows_as_unauditable() {
        let repo = temp_repo();
        write(
            &repo.join(".github/workflows/ci.yml"),
            "
name: CI
on: [push]
jobs:
  call-remote:
    uses: octo-org/secure-repo/.github/workflows/reusable.yml@main
",
        );

        let result = scan_directory(&repo.join(".github/workflows")).unwrap();
        assert_eq!(result.skipped_refs.len(), 1);
        assert_eq!(
            result.skipped_refs[0].kind,
            SkippedRefKind::RemoteReusableWorkflow
        );
    }

    #[test]
    fn preserves_remote_action_subpaths() {
        let repo = temp_repo();
        write(
            &repo.join(".github/workflows/ci.yml"),
            "
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action/subdir@0123456789012345678901234567890123456789
",
        );

        let result = scan_directory(&repo.join(".github/workflows")).unwrap();
        assert_eq!(result.action_refs.len(), 1);
        assert_eq!(result.action_refs[0].path.as_deref(), Some("subdir"));
    }

    #[test]
    fn parses_composite_uses_from_action_metadata() {
        let uses = parse_composite_uses(
            "
name: wrapper
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - run: echo skip
    - uses: docker://alpine:latest
",
        );

        assert_eq!(
            uses,
            vec![
                "actions/checkout@v4".to_string(),
                "docker://alpine:latest".to_string()
            ]
        );
    }

    #[test]
    fn rejects_excessive_action_ref_counts() {
        let repo = temp_repo();
        let mut workflow = String::from(
            "
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
",
        );
        for idx in 0..=MAX_REFS_PER_SCAN {
            let _ = writeln!(
                workflow,
                "      - uses: octo-org/action-{idx}@0123456789012345678901234567890123456789"
            );
        }
        write(&repo.join(".github/workflows/ci.yml"), &workflow);

        let err = scan_directory(&repo.join(".github/workflows")).unwrap_err();
        assert!(err.to_string().contains("maximum action reference budget"));
    }
}
