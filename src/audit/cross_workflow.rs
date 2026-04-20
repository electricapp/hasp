use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use yaml_rust2::Yaml;

use super::{
    AuditFinding, Severity, find_expressions, key_jobs, key_on, key_permissions, key_steps,
    key_uses, key_with,
};

// ─── Trigger classification ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum TriggerKind {
    Push,
    PullRequest,
    PullRequestTarget,
    WorkflowRun,
    WorkflowDispatch,
    WorkflowCall,
    Schedule,
    IssueComment,
    Issues,
    Release,
    Other,
}

impl TriggerKind {
    const fn parse(name: &str) -> Self {
        match name.as_bytes() {
            b"push" => Self::Push,
            b"pull_request" => Self::PullRequest,
            b"pull_request_target" => Self::PullRequestTarget,
            b"workflow_run" => Self::WorkflowRun,
            b"workflow_dispatch" => Self::WorkflowDispatch,
            b"workflow_call" => Self::WorkflowCall,
            b"schedule" => Self::Schedule,
            b"issue_comment" => Self::IssueComment,
            b"issues" => Self::Issues,
            b"release" => Self::Release,
            _ => Self::Other,
        }
    }

    /// Triggers that run with attacker-influenced content (PR fork, comment, etc.)
    /// but, unlike `pull_request_target`, typically execute in an unprivileged
    /// context (no write token, no secrets by default).
    const fn is_untrusted_input(self) -> bool {
        matches!(
            self,
            Self::PullRequest
                | Self::PullRequestTarget
                | Self::IssueComment
                | Self::Issues
        )
    }
}

// ─── Permission summary ─────────────────────────────────────────────────────

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone, Copy)]
struct PermissionSummary {
    has_any_write: bool,
    has_id_token_write: bool,
    has_contents_write: bool,
    is_write_all: bool,
}

impl PermissionSummary {
    const fn is_privileged(self) -> bool {
        self.has_any_write || self.has_id_token_write || self.is_write_all
    }

    const fn absorb(&mut self, other: Self) {
        self.has_any_write |= other.has_any_write;
        self.has_id_token_write |= other.has_id_token_write;
        self.has_contents_write |= other.has_contents_write;
        self.is_write_all |= other.is_write_all;
    }
}

fn parse_permissions_value(value: Option<&Yaml>) -> PermissionSummary {
    let Some(value) = value else {
        // Missing permissions block — inherits repo default, which in many
        // configurations is write-all. Treat as privileged for taint purposes.
        return PermissionSummary {
            has_any_write: true,
            has_id_token_write: false,
            has_contents_write: true,
            is_write_all: true,
        };
    };

    if let Some(s) = value.as_str() {
        return if s == "write-all" {
            PermissionSummary {
                has_any_write: true,
                has_id_token_write: true,
                has_contents_write: true,
                is_write_all: true,
            }
        } else {
            PermissionSummary::default()
        };
    }

    let Some(map) = value.as_hash() else {
        return PermissionSummary::default();
    };

    if map.is_empty() {
        return PermissionSummary::default();
    }

    let mut summary = PermissionSummary::default();
    for (k, v) in map {
        let Some(scope) = k.as_str() else {
            continue;
        };
        let Some(level) = v.as_str() else {
            continue;
        };
        if level == "write" {
            summary.has_any_write = true;
            if scope == "id-token" {
                summary.has_id_token_write = true;
            }
            if scope == "contents" {
                summary.has_contents_write = true;
            }
        }
    }
    summary
}

// ─── Artifact op extraction ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ArtifactOp {
    name: String,
    is_upload: bool,
}

fn artifact_op_from_uses(uses: &str) -> Option<bool> {
    // `actions/upload-artifact@...` or `actions/download-artifact@...`
    let head = uses.split('@').next().unwrap_or("");
    match head {
        "actions/upload-artifact" => Some(true),
        "actions/download-artifact" => Some(false),
        _ => None,
    }
}

fn artifact_name_from_with(with: Option<&Yaml>) -> String {
    with.and_then(|w| w.as_hash())
        .and_then(|m| {
            m.iter().find_map(|(k, v)| {
                if k.as_str() == Some("name") {
                    v.as_str().map(str::to_string)
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| "*".to_string())
}

// ─── Per-workflow information ───────────────────────────────────────────────

#[derive(Debug, Clone)]
struct WorkflowInfo {
    file: PathBuf,
    /// Value of top-level `name:` if present.
    name: Option<String>,
    triggers: HashSet<TriggerKind>,
    /// For `on.workflow_run.workflows:` — names of workflows that trigger this one.
    workflow_run_parents: Vec<String>,
    /// Whether the `workflow_run` trigger has `types:` including success/guard.
    workflow_run_has_success_guard: bool,
    permissions: PermissionSummary,
    /// Reserved for Feature 2 (OIDC trust-policy linting) — set when any job
    /// or top-level permissions block grants `id-token: write`.
    #[allow(dead_code)]
    uses_oidc: bool,
    artifact_ops: Vec<ArtifactOp>,
    /// Whether any `if:` or `${{ ... }}` expression references
    /// `github.event.workflow_run.*`.
    reads_workflow_run_event: bool,
}

fn extract_workflow_info(file: &Path, doc: &Yaml) -> Option<WorkflowInfo> {
    let map = doc.as_hash()?;

    // ── name ────────────────────────────────────────────────────────────
    let name = map
        .get(&Yaml::String("name".to_string()))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // ── triggers + workflow_run parents ─────────────────────────────────
    let (triggers, workflow_run_parents, workflow_run_has_success_guard) =
        parse_triggers(map.get(key_on()));

    // ── permissions (top-level merged with per-job) ─────────────────────
    let mut permissions = parse_permissions_value(map.get(key_permissions()));

    // ── walk jobs ───────────────────────────────────────────────────────
    let mut artifact_ops = Vec::new();
    let mut reads_workflow_run_event = false;

    if let Some(Yaml::Hash(jobs)) = map.get(key_jobs()) {
        for (_job_name, job_value) in jobs {
            let Some(job_map) = job_value.as_hash() else {
                continue;
            };

            if let Some(job_perm) = job_map.get(key_permissions()) {
                permissions.absorb(parse_permissions_value(Some(job_perm)));
            } else if !map.contains_key(key_permissions()) {
                // Neither top-level nor job-level permissions — inherits defaults,
                // which are often write-all. Treat as privileged for taint analysis.
                permissions.absorb(PermissionSummary {
                    has_any_write: true,
                    has_contents_write: true,
                    ..PermissionSummary::default()
                });
            }

            if let Some(Yaml::Array(steps)) = job_map.get(key_steps()) {
                for step in steps {
                    let Some(step_map) = step.as_hash() else {
                        continue;
                    };
                    let uses = step_map.get(key_uses()).and_then(Yaml::as_str).unwrap_or("");
                    if let Some(is_upload) = artifact_op_from_uses(uses) {
                        let with = step_map.get(key_with());
                        artifact_ops.push(ArtifactOp {
                            name: artifact_name_from_with(with),
                            is_upload,
                        });
                    }
                }
            }

            if yaml_references_workflow_run_event(job_value) {
                reads_workflow_run_event = true;
            }
        }
    }

    let uses_oidc = permissions.has_id_token_write;

    Some(WorkflowInfo {
        file: file.to_path_buf(),
        name,
        triggers,
        workflow_run_parents,
        workflow_run_has_success_guard,
        permissions,
        uses_oidc,
        artifact_ops,
        reads_workflow_run_event,
    })
}

fn parse_triggers(on_value: Option<&Yaml>) -> (HashSet<TriggerKind>, Vec<String>, bool) {
    let mut triggers = HashSet::new();
    let mut parents = Vec::new();
    let mut has_success_guard = false;

    let Some(on) = on_value else {
        return (triggers, parents, has_success_guard);
    };

    #[allow(clippy::wildcard_enum_match_arm)] // Yaml has many non-string/array/hash variants
    match on {
        Yaml::String(s) => {
            triggers.insert(TriggerKind::parse(s));
        }
        Yaml::Array(arr) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    triggers.insert(TriggerKind::parse(s));
                }
            }
        }
        Yaml::Hash(map) => {
            for (k, v) in map {
                let Some(name) = k.as_str() else { continue };
                let kind = TriggerKind::parse(name);
                triggers.insert(kind);
                if kind == TriggerKind::WorkflowRun
                    && let Some(wf_map) = v.as_hash()
                {
                    if let Some(workflows) = wf_map
                        .get(&Yaml::String("workflows".to_string()))
                        .and_then(Yaml::as_vec)
                    {
                        for w in workflows {
                            if let Some(name) = w.as_str() {
                                parents.push(name.to_string());
                            }
                        }
                    }
                    if let Some(types) = wf_map
                        .get(&Yaml::String("types".to_string()))
                        .and_then(Yaml::as_vec)
                    {
                        let only_completed =
                            types.iter().all(|t| t.as_str() == Some("completed"));
                        if only_completed {
                            has_success_guard = true;
                        }
                    }
                }
            }
        }
        _ => {}
    }

    (triggers, parents, has_success_guard)
}

fn yaml_references_workflow_run_event(y: &Yaml) -> bool {
    #[allow(clippy::wildcard_enum_match_arm)] // Yaml has many non-string/array/hash variants
    match y {
        Yaml::String(s) => {
            for expr in find_expressions(s) {
                if expr.contains("github.event.workflow_run.") {
                    return true;
                }
            }
            false
        }
        Yaml::Hash(m) => m.iter().any(|(_, v)| yaml_references_workflow_run_event(v)),
        Yaml::Array(a) => a.iter().any(yaml_references_workflow_run_event),
        _ => false,
    }
}

// ─── Graph assembly ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct Graph<'a> {
    workflows: Vec<WorkflowInfo>,
    /// Map from normalized workflow identity (file stem or `name:`) to index.
    #[allow(dead_code)]
    by_identity: HashMap<String, usize>,
    _marker: std::marker::PhantomData<&'a ()>,
}

fn build_graph(workflows: Vec<WorkflowInfo>) -> Graph<'static> {
    let mut by_identity = HashMap::new();
    for (idx, w) in workflows.iter().enumerate() {
        if let Some(ref name) = w.name {
            by_identity.insert(name.clone(), idx);
        }
        // Also index by file stem to handle workflow_run.workflows: referencing filenames.
        if let Some(stem) = w
            .file
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        {
            by_identity.entry(stem).or_insert(idx);
        }
    }
    Graph {
        workflows,
        by_identity,
        _marker: std::marker::PhantomData,
    }
}

fn resolve_parent<'g>(graph: &'g Graph<'static>, parent: &str) -> Option<&'g WorkflowInfo> {
    // Try exact match on name, then on file stem.
    if let Some(idx) = graph.by_identity.get(parent) {
        return Some(&graph.workflows[*idx]);
    }
    None
}

// ─── Checks ─────────────────────────────────────────────────────────────────

/// Check 1: `pull_request`-triggered uploader feeds privileged `workflow_run`
/// downloader (tj-actions / Ultralytics pattern).
fn check_artifact_flow(
    graph: &Graph<'static>,
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    for sink in &graph.workflows {
        // Sinks are workflows that are themselves triggered by workflow_run and
        // have privileged permissions.
        if !sink.triggers.contains(&TriggerKind::WorkflowRun) {
            continue;
        }
        if !sink.permissions.is_privileged() {
            continue;
        }

        // Figure out which workflows can trigger this sink.
        let parent_workflows: Vec<&WorkflowInfo> = sink
            .workflow_run_parents
            .iter()
            .filter_map(|p| resolve_parent(graph, p))
            .collect();

        // If the parents list is empty (dynamic / cross-repo), fall back to any
        // workflow with untrusted triggers in this repo.
        let candidates: Vec<&WorkflowInfo> = if parent_workflows.is_empty() {
            graph
                .workflows
                .iter()
                .filter(|w| w.triggers.iter().any(|t| t.is_untrusted_input()))
                .collect()
        } else {
            parent_workflows
                .into_iter()
                .filter(|w| w.triggers.iter().any(|t| t.is_untrusted_input()))
                .collect()
        };

        if candidates.is_empty() {
            continue;
        }

        // Any download in the sink that matches an upload in a candidate source?
        for download in sink.artifact_ops.iter().filter(|op| !op.is_upload) {
            for source in &candidates {
                for upload in source.artifact_ops.iter().filter(|op| op.is_upload) {
                    if artifact_names_overlap(&download.name, &upload.name) {
                        findings.push(AuditFinding {
                            file: sink.file.clone(),
                            severity: Severity::Critical,
                            title: format!(
                                "Cross-workflow artifact flow from untrusted source `{}`",
                                source.file.display()
                            ),
                            detail: format!(
                                "Workflow {} (triggered by workflow_run with privileged \
                                 permissions) downloads artifact `{}` that is produced by \
                                 workflow {} under an untrusted trigger \
                                 (pull_request / issue_comment / issues). An attacker can \
                                 poison the artifact in the source workflow and have it \
                                 consumed in the privileged sink — this is the tj-actions / \
                                 Ultralytics exploit pattern. Verify the artifact's SHA or \
                                 gate the workflow_run on a trusted conclusion.",
                                sink.file.display(),
                                upload.name,
                                source.file.display(),
                            ),
                            is_warning,
                        });
                    }
                }
            }
        }
    }
}

fn artifact_names_overlap(a: &str, b: &str) -> bool {
    // Wildcard names (dynamic ${{ }} or *) overlap with anything.
    if a == "*" || b == "*" || a.contains("${{") || b.contains("${{") {
        return true;
    }
    a == b
}

/// Check 2: `workflow_run` trigger with no explicit allowlist of triggering
/// workflows, or no conclusion-success guard, in a privileged workflow.
fn check_unguarded_workflow_run(
    graph: &Graph<'static>,
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    for wf in &graph.workflows {
        if !wf.triggers.contains(&TriggerKind::WorkflowRun) {
            continue;
        }
        if !wf.permissions.is_privileged() {
            continue;
        }
        if wf.workflow_run_parents.is_empty() {
            findings.push(AuditFinding {
                file: wf.file.clone(),
                severity: Severity::High,
                title: "workflow_run trigger without explicit source workflows".to_string(),
                detail:
                    "This workflow is triggered by `workflow_run` but does not restrict the \
                     set of upstream workflows that can trigger it (no `workflows:` filter). \
                     Combined with privileged permissions, any workflow run in this repo — \
                     including PR-triggered ones — can cause this workflow to fire. List \
                     the specific trusted workflows under `on.workflow_run.workflows:`."
                        .to_string(),
                is_warning,
            });
        }
        if !wf.workflow_run_has_success_guard {
            findings.push(AuditFinding {
                file: wf.file.clone(),
                severity: Severity::High,
                title: "workflow_run trigger without conclusion guard".to_string(),
                detail:
                    "This workflow is triggered by `workflow_run` and does not restrict to \
                     `types: [completed]` or gate on `github.event.workflow_run.conclusion \
                     == 'success'`. Failed/cancelled runs can still trigger this privileged \
                     workflow. Add a top-level `if:` check."
                        .to_string(),
                is_warning,
            });
        }
    }
}

/// Check 3: workflow reads `github.event.workflow_run.*` fields — if the
/// upstream triggering workflow is PR-triggered, these fields are attacker-controlled.
fn check_workflow_run_event_taint(
    graph: &Graph<'static>,
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    for wf in &graph.workflows {
        if !wf.reads_workflow_run_event {
            continue;
        }
        if !wf.triggers.contains(&TriggerKind::WorkflowRun) {
            continue;
        }

        // Is any upstream triggering workflow PR-triggered?
        let tainted_upstream = if wf.workflow_run_parents.is_empty() {
            // No allowlist: any repo workflow could be upstream. Flag conservatively.
            graph
                .workflows
                .iter()
                .any(|w| w.triggers.iter().any(|t| t.is_untrusted_input()))
        } else {
            wf.workflow_run_parents
                .iter()
                .filter_map(|p| resolve_parent(graph, p))
                .any(|w| w.triggers.iter().any(|t| t.is_untrusted_input()))
        };

        if tainted_upstream {
            findings.push(AuditFinding {
                file: wf.file.clone(),
                severity: Severity::High,
                title: "Workflow reads attacker-controlled github.event.workflow_run fields"
                    .to_string(),
                detail:
                    "This workflow references `github.event.workflow_run.*` fields (e.g. \
                     head_branch, head_sha, head_repository) that are attacker-controlled \
                     when the upstream workflow was triggered by a pull request. Do not \
                     pass these values to `run:` blocks, `actions/checkout`, or any step \
                     that evaluates them as code or identities."
                        .to_string(),
                is_warning,
            });
        }
    }
}

// ─── Entry point ────────────────────────────────────────────────────────────

pub(crate) fn run(
    docs: &[(PathBuf, Yaml)],
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    if level.is_off() {
        return;
    }
    let workflows: Vec<WorkflowInfo> = docs
        .iter()
        .filter_map(|(path, doc)| extract_workflow_info(path, doc))
        .collect();
    if workflows.is_empty() {
        return;
    }
    let graph = build_graph(workflows);
    let is_warning = level.is_warn();
    check_artifact_flow(&graph, findings, is_warning);
    check_unguarded_workflow_run(&graph, findings, is_warning);
    check_workflow_run_event_taint(&graph, findings, is_warning);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use yaml_rust2::YamlLoader;

    fn parse_named(name: &str, src: &str) -> (PathBuf, Yaml) {
        let doc = YamlLoader::load_from_str(src).unwrap().remove(0);
        (PathBuf::from(name), doc)
    }

    fn run_check(docs: &[(PathBuf, Yaml)]) -> Vec<AuditFinding> {
        let mut findings = Vec::new();
        run(docs, &mut findings, crate::policy::CheckLevel::Deny);
        findings
    }

    #[test]
    fn detects_tj_actions_artifact_flow_pattern() {
        // Source workflow: PR-triggered, uploads artifact.
        let source = parse_named(
            "lint.yml",
            "
name: Lint
on: pull_request
permissions: {}
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@abcd
      - run: npm run lint > lint.log
      - uses: actions/upload-artifact@efgh
        with:
          name: lint-results
",
        );
        // Sink workflow: workflow_run-triggered, privileged, downloads same artifact.
        let sink = parse_named(
            "post-lint.yml",
            "
name: Post Lint
on:
  workflow_run:
    workflows: [Lint]
    types: [completed]
permissions:
  contents: write
  pull-requests: write
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@ijkl
        with:
          name: lint-results
      - run: cat lint-results
",
        );

        let findings = run_check(&[source, sink]);
        assert!(
            findings.iter().any(|f| f.title.contains("artifact flow")),
            "expected cross-workflow artifact flow finding, got: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_safe_flow() {
        // Source: push (trusted), uploads artifact. Sink: workflow_run, privileged, downloads.
        // Should be safe because the source is push-triggered.
        let source = parse_named(
            "ci.yml",
            "
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@abcd
        with:
          name: dist
",
        );
        let sink = parse_named(
            "deploy.yml",
            "
name: Deploy
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  contents: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    steps:
      - uses: actions/download-artifact@abcd
        with:
          name: dist
",
        );
        let findings = run_check(&[source, sink]);
        assert!(
            !findings.iter().any(|f| f.title.contains("artifact flow")),
            "push-triggered source should not be an artifact-flow finding"
        );
    }

    #[test]
    fn detects_unguarded_workflow_run() {
        let wf = parse_named(
            "privileged.yml",
            "
name: Privileged
on: workflow_run
permissions:
  contents: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
        );
        let findings = run_check(&[wf]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("without explicit source workflows")
                    || f.title.contains("without conclusion guard")),
            "expected unguarded-workflow_run finding, got: {findings:?}"
        );
    }

    #[test]
    fn detects_workflow_run_event_taint() {
        let parent = parse_named(
            "pr.yml",
            "
name: PR
on: pull_request
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
        );
        let sink = parse_named(
            "privileged.yml",
            "
name: Privileged
on:
  workflow_run:
    workflows: [PR]
    types: [completed]
permissions:
  contents: write
jobs:
  do:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.workflow_run.head_branch }}
",
        );
        let findings = run_check(&[parent, sink]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("workflow_run fields")),
            "expected workflow_run event taint finding, got: {findings:?}"
        );
    }

    #[test]
    fn off_level_emits_nothing() {
        let wf = parse_named(
            "privileged.yml",
            "
name: Privileged
on: workflow_run
permissions:
  contents: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
        );
        let mut findings = Vec::new();
        run(&[wf], &mut findings, crate::policy::CheckLevel::Off);
        assert!(findings.is_empty());
    }
}
