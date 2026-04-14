use crate::audit::{self, AuditFinding, Severity};
use crate::scanner::RefKind;
use std::collections::HashSet;
use std::path::Path;
use yaml_rust2::YamlLoader;

use super::client::Api;
use super::json::{
    key_post, key_post_entrypoint, key_pre, key_pre_entrypoint, key_run, key_runs, key_steps,
    key_uses, key_using,
};
use super::verify::{VerificationResult, VerificationStatus};

pub(crate) fn scan_transitive_with_api(
    client: &impl Api,
    results: &[VerificationResult],
    max_depth: u8,
    transitive_level: crate::policy::CheckLevel,
    hidden_execution_level: crate::policy::CheckLevel,
) -> Vec<AuditFinding> {
    if transitive_level.is_off() && hidden_execution_level.is_off() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut visited = HashSet::new();

    for result in results {
        if result.action_ref.ref_kind != RefKind::FullSha {
            continue;
        }
        if !matches!(
            result.status,
            VerificationStatus::Verified | VerificationStatus::CommentMismatch { .. }
        ) {
            continue;
        }

        let root = TransitiveRoot {
            file: &result.action_ref.file,
            target: result.action_ref.target(),
        };
        let mut ctx = TransitiveScanContext {
            client,
            max_depth,
            root,
            visited: &mut visited,
            findings: &mut findings,
            transitive_level,
            hidden_execution_level,
        };
        let action = TransitiveAction {
            owner: &result.action_ref.owner,
            repo: &result.action_ref.repo,
            path: result.action_ref.path.as_deref(),
            sha: &result.action_ref.ref_str,
        };
        scan_transitive_recursive(&mut ctx, &action, 1);
    }

    findings
}

type VisitedActionKey = (String, String, Option<String>, String);

struct TransitiveRoot<'a> {
    file: &'a Path,
    target: String,
}

struct TransitiveAction<'a> {
    owner: &'a str,
    repo: &'a str,
    path: Option<&'a str>,
    sha: &'a str,
}

struct TransitiveScanContext<'a, A: Api + ?Sized> {
    client: &'a A,
    max_depth: u8,
    root: TransitiveRoot<'a>,
    visited: &'a mut HashSet<VisitedActionKey>,
    findings: &'a mut Vec<AuditFinding>,
    transitive_level: crate::policy::CheckLevel,
    hidden_execution_level: crate::policy::CheckLevel,
}

#[derive(Default)]
struct ActionExecutionProfile {
    has_pre: bool,
    has_post: bool,
    composite_run_steps: usize,
    composite_nested_uses: usize,
}

fn scan_transitive_recursive<A: Api + ?Sized>(
    ctx: &mut TransitiveScanContext<'_, A>,
    action: &TransitiveAction<'_>,
    depth: usize,
) {
    if depth > usize::from(ctx.max_depth) {
        return;
    }

    let visit_key = (
        action.owner.to_string(),
        action.repo.to_string(),
        action.path.map(str::to_string),
        action.sha.to_string(),
    );
    if !ctx.visited.insert(visit_key) {
        return;
    }

    let Ok(Some(action_yml)) =
        ctx.client
            .get_action_yml(action.owner, action.repo, action.path, action.sha)
    else {
        return;
    };

    if let Some(finding) = build_hidden_execution_finding(
        action,
        &action_yml,
        ctx.root.file,
        ctx.hidden_execution_level,
    ) {
        ctx.findings.push(finding);
    }

    for uses in crate::scanner::parse_composite_uses(&action_yml) {
        let Some(nested) = parse_remote_action_use(&uses) else {
            continue;
        };

        if nested.ref_kind != RefKind::FullSha {
            ctx.findings.push(AuditFinding {
                file: ctx.root.file.to_path_buf(),
                severity: Severity::High,
                title: format!(
                    "Mutable transitive dependency `{}` in {}",
                    nested.target, ctx.root.target
                ),
                detail: format!(
                    "Pinned action `{}@{}` contains composite step `uses: {}`. \
                     Nested action dependencies should also be pinned to full 40-character \
                     SHAs to prevent upstream retagging or branch moves.",
                    ctx.root.target,
                    &action.sha[..action.sha.len().min(12)],
                    nested.original
                ),
                is_warning: ctx.transitive_level.is_warn(),
            });
            continue;
        }

        let nested_action = TransitiveAction {
            owner: &nested.owner,
            repo: &nested.repo,
            path: nested.path.as_deref(),
            sha: &nested.ref_str,
        };
        scan_transitive_recursive(ctx, &nested_action, depth + 1);
    }
}

fn build_hidden_execution_finding(
    action: &TransitiveAction<'_>,
    action_yml: &str,
    file: &Path,
    level: crate::policy::CheckLevel,
) -> Option<AuditFinding> {
    if level.is_off() {
        return None;
    }
    let profile = parse_action_execution_profile(action_yml);
    if !profile.has_pre && !profile.has_post && profile.composite_run_steps == 0 {
        return None;
    }

    let target = format_action_target(action.owner, action.repo, action.path);
    let short_sha = &action.sha[..action.sha.len().min(12)];
    let trusted_owner = audit::is_trusted_owner(action.owner);
    let privileged_action = audit::is_privileged_action(action.owner, action.repo, action.path);
    let high_risk_execution = (profile.has_post || profile.composite_run_steps > 0)
        && (!trusted_owner || privileged_action);
    let severity = if high_risk_execution {
        Severity::High
    } else {
        Severity::Medium
    };

    let mut features = Vec::new();
    if profile.has_pre {
        features.push("a `pre` hook".to_string());
    }
    if profile.has_post {
        features.push("a `post` hook".to_string());
    }
    if profile.composite_run_steps > 0 {
        features.push(format!(
            "{} internal shell step(s)",
            profile.composite_run_steps
        ));
    }
    if profile.composite_nested_uses > 0 {
        features.push(format!(
            "{} nested action step(s)",
            profile.composite_nested_uses
        ));
    }

    Some(AuditFinding {
        file: file.to_path_buf(),
        severity,
        title: format!("Action `{target}` contains hidden execution paths"),
        detail: format!(
            "Pinned action `{target}@{short_sha}` defines {} inside its action metadata. \
             These paths execute inside the action implementation rather than the visible \
             workflow YAML and inherit the step environment. Review the pinned `action.yml` \
             carefully before trusting this dependency.",
            features.join(", ")
        ),
        is_warning: level.is_warn(),
    })
}

fn parse_action_execution_profile(yaml: &str) -> ActionExecutionProfile {
    let Ok(docs) = YamlLoader::load_from_str(yaml) else {
        return ActionExecutionProfile::default();
    };
    let doc = docs.into_iter().next().unwrap_or(yaml_rust2::Yaml::Null);
    let Some(runs) = doc
        .as_hash()
        .and_then(|map| map.get(key_runs()))
        .and_then(|runs| runs.as_hash())
    else {
        return ActionExecutionProfile::default();
    };

    let mut profile = ActionExecutionProfile {
        has_pre: runs.contains_key(key_pre()) || runs.contains_key(key_pre_entrypoint()),
        has_post: runs.contains_key(key_post()) || runs.contains_key(key_post_entrypoint()),
        ..ActionExecutionProfile::default()
    };

    if runs.get(key_using()).and_then(|value| value.as_str()) != Some("composite") {
        return profile;
    }

    let Some(steps) = runs.get(key_steps()).and_then(|steps| steps.as_vec()) else {
        return profile;
    };

    for step in steps {
        let Some(step_map) = step.as_hash() else {
            continue;
        };
        if step_map
            .get(key_run())
            .and_then(|run| run.as_str())
            .is_some()
        {
            profile.composite_run_steps += 1;
        }
        if step_map
            .get(key_uses())
            .and_then(|uses| uses.as_str())
            .is_some()
        {
            profile.composite_nested_uses += 1;
        }
    }

    profile
}

fn format_action_target(owner: &str, repo: &str, path: Option<&str>) -> String {
    path.map_or_else(
        || format!("{owner}/{repo}"),
        |path| format!("{owner}/{repo}/{path}"),
    )
}

#[derive(Debug)]
struct RemoteActionUse {
    owner: String,
    repo: String,
    path: Option<String>,
    ref_str: String,
    ref_kind: RefKind,
    original: String,
    target: String,
}

fn parse_remote_action_use(uses: &str) -> Option<RemoteActionUse> {
    if uses.starts_with("docker://") || uses.starts_with("./") || uses.starts_with("../") {
        return None;
    }

    let at = uses.find('@')?;
    let repo_part = &uses[..at];
    let ref_str = &uses[at + 1..];
    if ref_str.is_empty()
        || ref_str.contains("..")
        || ref_str.contains('\\')
        || ref_str.starts_with('/')
    {
        return None;
    }

    let mut segments = repo_part.splitn(3, '/');
    let owner = segments.next()?.trim();
    let repo = segments.next()?.trim();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }

    let path = segments
        .next()
        .map(str::trim)
        .filter(|path| !path.is_empty());
    if let Some(path) = path
        && (path.starts_with(".github/workflows/") || path.starts_with("./.github/workflows/"))
        && (Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml")))
    {
        return None;
    }

    let ref_kind = if ref_str.len() == 40 && ref_str.bytes().all(|b| b.is_ascii_hexdigit()) {
        RefKind::FullSha
    } else {
        RefKind::Mutable
    };
    let target = path.map_or_else(
        || format!("{owner}/{repo}"),
        |path| format!("{owner}/{repo}/{path}"),
    );

    // Normalize SHA hex to lowercase for consistent cache lookups
    let normalized_ref = if ref_kind == RefKind::FullSha {
        ref_str.to_ascii_lowercase()
    } else {
        ref_str.to_string()
    };

    Some(RemoteActionUse {
        owner: owner.to_string(),
        repo: repo.to_string(),
        path: path.map(str::to_string),
        ref_str: normalized_ref,
        ref_kind,
        original: uses.to_string(),
        target,
    })
}

#[cfg(test)]
mod tests {
    use super::super::client::{CompareResult, ReachabilityStatus, RepoInfo};
    use super::*;
    use crate::scanner::{ActionRef, RefKind};
    use std::collections::HashMap;
    use std::path::PathBuf;

    struct MockApi {
        action_yml: HashMap<(String, String, Option<String>, String), Option<String>>,
    }

    impl Api for MockApi {
        fn verify_commit(
            &self,
            _owner: &str,
            _repo: &str,
            _sha: &str,
        ) -> crate::error::Result<bool> {
            Ok(true)
        }

        fn resolve_tag(
            &self,
            _owner: &str,
            _repo: &str,
            _tag: &str,
        ) -> crate::error::Result<Option<String>> {
            Ok(None)
        }

        fn find_tag_for_sha(&self, _owner: &str, _repo: &str, _sha: &str) -> Option<String> {
            None
        }

        fn get_repo_info(&self, _owner: &str, _repo: &str) -> crate::error::Result<RepoInfo> {
            Ok(RepoInfo::fallback())
        }

        fn is_commit_reachable(
            &self,
            _owner: &str,
            _repo: &str,
            _sha: &str,
            _default_branch: &str,
        ) -> crate::error::Result<ReachabilityStatus> {
            Ok(ReachabilityStatus::Reachable)
        }

        fn is_commit_signed(
            &self,
            _owner: &str,
            _repo: &str,
            _sha: &str,
        ) -> crate::error::Result<bool> {
            Ok(true)
        }

        fn get_commit_date(
            &self,
            _owner: &str,
            _repo: &str,
            _sha: &str,
        ) -> crate::error::Result<Option<String>> {
            Ok(None)
        }

        fn get_tag_creation_date(
            &self,
            _owner: &str,
            _repo: &str,
            _tag: &str,
        ) -> crate::error::Result<Option<String>> {
            Ok(None)
        }

        fn get_action_yml(
            &self,
            owner: &str,
            repo: &str,
            path: Option<&str>,
            sha: &str,
        ) -> crate::error::Result<Option<String>> {
            Ok(self
                .action_yml
                .get(&(
                    owner.to_string(),
                    repo.to_string(),
                    path.map(str::to_string),
                    sha.to_string(),
                ))
                .cloned()
                .unwrap_or(None))
        }

        fn compare_commits(
            &self,
            _owner: &str,
            _repo: &str,
            _base: &str,
            _head: &str,
        ) -> crate::error::Result<CompareResult> {
            Ok(CompareResult {
                owner: String::new(),
                repo: String::new(),
                old_sha: String::new(),
                new_sha: String::new(),
                ahead_by: 0,
                files_changed: 0,
                commit_summaries: Vec::new(),
                html_url: String::new(),
            })
        }
    }

    fn verified_result(
        owner: &str,
        repo: &str,
        path: Option<&str>,
        sha: &str,
    ) -> VerificationResult {
        VerificationResult {
            action_ref: ActionRef {
                file: PathBuf::from("workflow.yml"),
                owner: owner.to_string(),
                repo: repo.to_string(),
                path: path.map(str::to_string),
                ref_str: sha.to_string(),
                ref_kind: RefKind::FullSha,
                comment_version: None,
            },
            status: VerificationStatus::Verified,
        }
    }

    #[test]
    fn flags_mutable_transitive_dependencies() {
        let sha = "0123456789012345678901234567890123456789";
        let api = MockApi {
            action_yml: HashMap::from([(
                ("actions".into(), "checkout".into(), None, sha.into()),
                Some(
                    "
name: wrapper
runs:
  using: composite
  steps:
    - uses: evilcorp/pwn@main
"
                    .into(),
                ),
            )]),
        };

        let findings = scan_transitive_with_api(
            &api,
            &[verified_result("actions", "checkout", None, sha)],
            3,
            crate::policy::CheckLevel::Deny,
            crate::policy::CheckLevel::Deny,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("Mutable transitive dependency"))
        );
    }

    #[test]
    fn flags_hidden_execution_paths_in_action_metadata() {
        let sha = "0123456789012345678901234567890123456789";
        let api = MockApi {
            action_yml: HashMap::from([(
                ("sneaky".into(), "security-scan".into(), None, sha.into()),
                Some(
                    "
name: scanner
runs:
  using: composite
  pre: bootstrap.sh
  post: cleanup.sh
  steps:
    - run: ./scan.sh
    - uses: actions/checkout@0123456789012345678901234567890123456789
"
                    .into(),
                ),
            )]),
        };

        let findings = scan_transitive_with_api(
            &api,
            &[verified_result("sneaky", "security-scan", None, sha)],
            3,
            crate::policy::CheckLevel::Deny,
            crate::policy::CheckLevel::Deny,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("hidden execution paths"))
        );
    }
}
