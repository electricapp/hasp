use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use yaml_rust2::Yaml;

use super::{
    AuditFinding, Severity, find_expressions, key_if, key_jobs, key_on, key_permissions, key_run,
    key_steps, key_uses, key_with,
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

    const fn paranoid_default() -> Self {
        Self {
            has_any_write: true,
            has_id_token_write: true,
            has_contents_write: true,
            is_write_all: true,
        }
    }
}

// MED-1: A missing `permissions:` block is treated as the paranoid maximum
// (`write-all`). GitHub's default-for-new-repos is `contents: read`, but org
// settings can flip that to permissive and individual users can opt in per
// repo — so assuming the worst avoids a whole class of silent false
// negatives. If your org enforces
// `default_workflow_permissions: restricted` and you want to suppress
// noisy cross-workflow findings on workflows without an explicit
// `permissions:` block, add `permissions: read-all` (or scoped permissions)
// to the workflow. A future `.hasp.yml` knob
// (`cross_workflow.assume_default_token_write: false`) could make this
// configurable; see TODO in `docs/POLICY.md`.
fn parse_permissions_value(value: Option<&Yaml>) -> PermissionSummary {
    let Some(value) = value else {
        return PermissionSummary::paranoid_default();
    };

    if let Some(s) = value.as_str() {
        // Documented read-only shorthands: no writes. Anything else —
        // including unknown literals (LOW-2: paranoid-default) — treat as
        // worst-case.
        return match s {
            "read-all" | "read" | "none" | "" => PermissionSummary::default(),
            _ => PermissionSummary::paranoid_default(),
        };
    }

    let Some(map) = value.as_hash() else {
        return PermissionSummary::default();
    };

    if map.is_empty() {
        // `permissions: {}` explicitly disables every scope.
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

/// Known artifact actions. Returns `Some(is_upload)` if the `uses:` string
/// looks like an upload/download-artifact action.
///
/// HIGH-2: the naive match on `actions/upload-artifact` +
/// `actions/download-artifact` missed every third-party downloader.
/// `dawidd6/action-download-artifact` is the primary lever used in the
/// tj-actions / Ultralytics family of attacks — it downloads artifacts
/// from *other* workflow runs by `run_id`, which is exactly the primitive
/// a poisoned `workflow_run` sink needs. The explicit allowlist covers the
/// popular forks; the trailing `ends_with` catches typosquats and mirrors
/// whose repo path still ends in `/download-artifact`.
fn artifact_op_from_uses(uses: &str) -> Option<bool> {
    let head = uses.split('@').next().unwrap_or("");
    if head == "actions/upload-artifact" {
        return Some(true);
    }
    match head {
        "actions/download-artifact"
        | "dawidd6/action-download-artifact"
        | "aochmann/actions-download-artifact"
        | "bettermarks/action-artifact-download" => Some(false),
        _ => {
            if head.ends_with("/download-artifact")
                || head.ends_with("/action-download-artifact")
            {
                Some(false)
            } else {
                None
            }
        }
    }
}

/// Extract the artifact name from a step's `with:` mapping.
///
/// HIGH-2: `actions/download-artifact@v4` replaced `name:` with `pattern:`
/// for multi-artifact downloads. The earlier implementation only read
/// `name:` and fell back to `"*"` when missing — which was conservative
/// for most shapes but silently turned `pattern: coverage-*` into a
/// wildcard match. We now read either key. Absent both, `"*"` remains
/// the conservative fallback.
fn artifact_name_from_with(with: Option<&Yaml>) -> String {
    let Some(map) = with.and_then(|w| w.as_hash()) else {
        return "*".to_string();
    };
    for key in ["name", "pattern"] {
        if let Some((_, v)) = map.iter().find(|(k, _)| k.as_str() == Some(key))
            && let Some(s) = v.as_str()
            && !s.is_empty()
        {
            return s.to_string();
        }
    }
    "*".to_string()
}

/// HIGH-3: detect shell-level artifact downloads that bypass the `uses:`
/// pattern entirely. `gh run download $RUN_ID` is the canonical bypass —
/// trivially swapped in for `actions/download-artifact` and invisible to
/// an audit that only inspects `uses:` strings. Treat any match as a
/// wildcard-name download since we can't tell from the shell string which
/// artifact it's after.
fn run_step_implies_artifact_download(run: &str) -> bool {
    // Be generous about whitespace / flag position — intent detection, not
    // argument parsing. False positives here are acceptable.
    run.contains("gh run download") || run.contains("gh artifact download")
}

// ─── Per-workflow information ───────────────────────────────────────────────

#[derive(Debug, Clone)]
struct WorkflowInfo {
    file: PathBuf,
    /// Value of top-level `name:` if present.
    name: Option<String>,
    triggers: HashSet<TriggerKind>,
    /// For `on.workflow_run.workflows:` — names, filenames, or repo-relative
    /// paths of workflows that trigger this one. Resolution is done lazily
    /// via `resolve_parent` / `candidate_parent_ids` (see MED-2).
    workflow_run_parents: Vec<String>,
    permissions: PermissionSummary,
    /// Reserved for Feature 2 (OIDC trust-policy linting) — set when any job
    /// or top-level permissions block grants `id-token: write`.
    #[allow(dead_code)]
    uses_oidc: bool,
    artifact_ops: Vec<ArtifactOp>,
    /// HIGH-1: true iff any `${{ ... }}` expression references one of the
    /// attacker-controlled subfields of `github.event.workflow_run.*`
    /// (`head_branch`, `head_sha`, `head_repository`, `event`,
    /// `pull_requests`, `display_title`, `triggering_actor`, `actor`,
    /// `head_commit`, `referenced_workflows`). GitHub-set subfields like
    /// `.conclusion`, `.status`, `.id`, `.run_number`, `.workflow_id`,
    /// `.created_at` do NOT set this bit — they are safe to read, and
    /// flagging them creates a false positive on the exact mitigation the
    /// tool recommends.
    reads_attacker_controlled_event_fields: bool,
    /// CRIT-1: true iff the workflow gates privileged work on the upstream
    /// having succeeded. The previous heuristic inferred this from
    /// `on.workflow_run.types: [completed]`, which was wrong: `completed`
    /// is the event-timing filter, not a conclusion filter — it fires on
    /// success AND failure AND cancelled AND skipped. Now we walk all
    /// `if:` expressions at the top level and on every job, looking for
    /// `github.event.workflow_run.conclusion == 'success'` (preferred) or
    /// `github.event.workflow_run.conclusion != 'failure'` (tolerated),
    /// with any whitespace and with either single or double quotes.
    has_conclusion_success_gate: bool,
}

fn extract_workflow_info(file: &Path, doc: &Yaml) -> Option<WorkflowInfo> {
    let map = doc.as_hash()?;

    // ── name ────────────────────────────────────────────────────────────
    let name = map
        .get(&Yaml::String("name".to_string()))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // ── triggers + workflow_run parents ─────────────────────────────────
    let (triggers, workflow_run_parents) = parse_triggers(map.get(key_on()));

    // ── permissions (top-level merged with per-job) ─────────────────────
    let mut permissions = parse_permissions_value(map.get(key_permissions()));

    // ── walk jobs ───────────────────────────────────────────────────────
    let mut artifact_ops = Vec::new();
    let mut reads_attacker_controlled_event_fields = false;
    // CRIT-1: accept a gate at any level — top-level `if:` (rare but legal),
    // job-level `if:` (the usual place), or step-level `if:` (finer-grained
    // but still a gate the user wrote deliberately).
    let mut has_conclusion_success_gate = yaml_contains_conclusion_gate(doc);

    if let Some(Yaml::Hash(jobs)) = map.get(key_jobs()) {
        for (_job_name, job_value) in jobs {
            let Some(job_map) = job_value.as_hash() else {
                continue;
            };

            if let Some(job_perm) = job_map.get(key_permissions()) {
                permissions.absorb(parse_permissions_value(Some(job_perm)));
            } else if !map.contains_key(key_permissions()) {
                // Neither top-level nor job-level permissions — inherits
                // repo default. See MED-1 note above `parse_permissions_value`.
                permissions.absorb(PermissionSummary::paranoid_default());
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
                        continue;
                    }
                    // HIGH-3: also catch shell-level downloaders.
                    if let Some(run) = step_map.get(key_run()).and_then(Yaml::as_str)
                        && run_step_implies_artifact_download(run)
                    {
                        artifact_ops.push(ArtifactOp {
                            name: "*".to_string(),
                            is_upload: false,
                        });
                    }
                }
            }

            if yaml_reads_attacker_controlled_event_field(job_value) {
                reads_attacker_controlled_event_fields = true;
            }
            if !has_conclusion_success_gate && yaml_contains_conclusion_gate(job_value) {
                has_conclusion_success_gate = true;
            }
        }
    }

    let uses_oidc = permissions.has_id_token_write;

    Some(WorkflowInfo {
        file: file.to_path_buf(),
        name,
        triggers,
        workflow_run_parents,
        permissions,
        uses_oidc,
        artifact_ops,
        reads_attacker_controlled_event_fields,
        has_conclusion_success_gate,
    })
}

// CRIT-1: this function used to return a `has_success_guard` bool derived
// from `on.workflow_run.types: [completed]` — which was semantically wrong
// (`completed` is the event-timing filter, not a conclusion filter). The
// guard is now detected separately by `yaml_contains_conclusion_gate`
// walking real `if:` expressions, and `parse_triggers` is back to its
// proper job: extracting trigger kinds and parent names.
fn parse_triggers(on_value: Option<&Yaml>) -> (HashSet<TriggerKind>, Vec<String>) {
    let mut triggers = HashSet::new();
    let mut parents = Vec::new();

    let Some(on) = on_value else {
        return (triggers, parents);
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
                    && let Some(workflows) = wf_map
                        .get(&Yaml::String("workflows".to_string()))
                        .and_then(Yaml::as_vec)
                {
                    for w in workflows {
                        if let Some(name) = w.as_str() {
                            parents.push(name.to_string());
                        }
                    }
                }
            }
        }
        _ => {}
    }

    (triggers, parents)
}

// ─── HIGH-1: attacker-controlled event-field allowlist ──────────────────────

/// Subfields of `github.event.workflow_run.*` that are attacker-controlled
/// when the upstream workflow was triggered by a fork PR.
///
/// Anything NOT in this list (`.conclusion`, `.status`, `.id`, `.run_id`,
/// `.run_number`, `.workflow_id`, `.created_at`, `.updated_at`,
/// `.run_started_at`, `.html_url`, `.jobs_url`, `.logs_url`, `.path`, etc.)
/// is set by GitHub, not by the attacker. Reading those fields is safe
/// and is exactly how a user would write the conclusion-guard mitigation
/// our own artifact-flow finding recommends. The previous implementation
/// flagged *any* `github.event.workflow_run.*` read, which penalised the
/// recommended fix.
const DANGEROUS_WORKFLOW_RUN_FIELDS: &[&str] = &[
    "head_branch",
    "head_sha",
    "head_repository",
    "head_commit",
    "display_title",
    "pull_requests",
    "event",
    "triggering_actor",
    "actor",
    "referenced_workflows",
];

fn yaml_reads_attacker_controlled_event_field(y: &Yaml) -> bool {
    #[allow(clippy::wildcard_enum_match_arm)] // Yaml has many non-string/array/hash variants
    match y {
        Yaml::String(s) => find_expressions(s).iter().any(|expr| {
            DANGEROUS_WORKFLOW_RUN_FIELDS
                .iter()
                .any(|field| expr.contains(&format!("github.event.workflow_run.{field}")))
        }),
        Yaml::Hash(m) => m
            .iter()
            .any(|(_, v)| yaml_reads_attacker_controlled_event_field(v)),
        Yaml::Array(a) => a.iter().any(yaml_reads_attacker_controlled_event_field),
        _ => false,
    }
}

// ─── CRIT-1: conclusion-success gate walker ─────────────────────────────────

/// Walks the doc for an `if:` expression at any level that gates on
/// the upstream workflow having succeeded. See the doc-comment on
/// `WorkflowInfo::has_conclusion_success_gate` for accepted forms.
fn yaml_contains_conclusion_gate(y: &Yaml) -> bool {
    #[allow(clippy::wildcard_enum_match_arm)] // Yaml has many non-string/array/hash variants
    match y {
        Yaml::Hash(m) => m.iter().any(|(k, v)| {
            if k == key_if()
                && let Some(s) = v.as_str()
                && expr_is_conclusion_gate(s)
            {
                true
            } else {
                yaml_contains_conclusion_gate(v)
            }
        }),
        Yaml::Array(a) => a.iter().any(yaml_contains_conclusion_gate),
        _ => false,
    }
}

/// Canonical conclusion-success gate patterns, whitespace-stripped. See
/// `expr_is_conclusion_gate` for the matcher that normalises before
/// comparing against these.
const CONCLUSION_GATE_PATTERNS: &[&str] = &[
    "github.event.workflow_run.conclusion=='success'",
    "github.event.workflow_run.conclusion==\"success\"",
    // Weaker but tolerated — excludes the unsafe 'failure' conclusion.
    "github.event.workflow_run.conclusion!='failure'",
    "github.event.workflow_run.conclusion!=\"failure\"",
];

/// True if an expression string gates on the upstream having succeeded.
/// Accepts the expression with or without the `${{ ... }}` wrapper, with
/// either single or double quotes, and with any amount of whitespace.
fn expr_is_conclusion_gate(s: &str) -> bool {
    let trimmed = s.trim();
    let body = trimmed
        .strip_prefix("${{")
        .and_then(|t| t.strip_suffix("}}"))
        .map_or(trimmed, str::trim);
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    CONCLUSION_GATE_PATTERNS
        .iter()
        .any(|pat| compact.contains(pat))
}

// ─── Graph assembly ─────────────────────────────────────────────────────────

// LOW-1: dropped the never-used `'a` lifetime parameter and the
// `PhantomData<&'a ()>` marker — `Graph` was only ever constructed as
// `Graph<'static>`, so the parameter served no purpose.
#[derive(Debug)]
struct Graph {
    workflows: Vec<WorkflowInfo>,
    /// Map from a normalized workflow identity to its index. A single
    /// workflow is indexed under every form a user might plausibly write
    /// in `on.workflow_run.workflows:` — see `index_forms_for_self` for
    /// the full set.
    by_identity: HashMap<String, usize>,
}

fn build_graph(workflows: Vec<WorkflowInfo>) -> Graph {
    let mut by_identity = HashMap::new();
    for (idx, w) in workflows.iter().enumerate() {
        if let Some(ref name) = w.name {
            by_identity.entry(name.clone()).or_insert(idx);
        }
        for form in index_forms_for_self(&w.file) {
            by_identity.entry(form).or_insert(idx);
        }
    }
    Graph {
        workflows,
        by_identity,
    }
}

/// MED-2: produce every identity form a workflow file should be indexable
/// under — filename, file stem, repo-relative path with and without
/// extension. The `on.workflow_run.workflows:` GitHub docs say the list
/// accepts workflow `name:` values or filenames; real-world configs also
/// use repo-relative paths, so we normalise all of them.
fn index_forms_for_self(file: &Path) -> Vec<String> {
    let mut v = Vec::new();
    let as_string = file.to_string_lossy().to_string();
    v.push(as_string.clone());
    if let Some(name) = file.file_name().and_then(|n| n.to_str()) {
        v.push(name.to_string());
    }
    if let Some(stem) = file.file_stem().and_then(|s| s.to_str()) {
        v.push(stem.to_string());
    }
    if let Some(no_ext) = as_string
        .strip_suffix(".yml")
        .or_else(|| as_string.strip_suffix(".yaml"))
    {
        v.push(no_ext.to_string());
    }
    v
}

/// MED-2: produce every identity string to try for a parent reference.
/// The GitHub docs accept workflow `name:` OR filename; real configs also
/// use `./.github/workflows/<file>.yml` paths, so we strip common prefixes
/// and extensions before lookup.
fn candidate_parent_ids(parent: &str) -> Vec<String> {
    let mut out = vec![parent.to_string()];
    let trimmed = parent
        .trim_start_matches("./")
        .trim_start_matches(".github/workflows/");
    if trimmed != parent {
        out.push(trimmed.to_string());
    }
    for base in [parent, trimmed] {
        if let Some(no_ext) = base
            .strip_suffix(".yml")
            .or_else(|| base.strip_suffix(".yaml"))
        {
            out.push(no_ext.to_string());
        }
    }
    out
}

fn resolve_parent<'g>(graph: &'g Graph, parent: &str) -> Option<&'g WorkflowInfo> {
    for id in candidate_parent_ids(parent) {
        if let Some(idx) = graph.by_identity.get(&id) {
            return Some(&graph.workflows[*idx]);
        }
    }
    None
}

// ─── PERF-1: upload-name index ──────────────────────────────────────────────

struct UploadIndex {
    /// Exact-name uploads: name → list of `(workflow_idx, op_idx)`.
    by_name: HashMap<String, Vec<(usize, usize)>>,
    /// Uploads whose name is `*` or contains a `${{ }}` expression — treated
    /// as matching any download name.
    wildcard: Vec<(usize, usize)>,
}

fn build_upload_index(graph: &Graph) -> UploadIndex {
    let mut by_name: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    let mut wildcard: Vec<(usize, usize)> = Vec::new();
    for (w_idx, w) in graph.workflows.iter().enumerate() {
        for (op_idx, op) in w.artifact_ops.iter().enumerate() {
            if !op.is_upload {
                continue;
            }
            if op.name == "*" || op.name.contains("${{") {
                wildcard.push((w_idx, op_idx));
            } else {
                by_name
                    .entry(op.name.clone())
                    .or_default()
                    .push((w_idx, op_idx));
            }
        }
    }
    UploadIndex { by_name, wildcard }
}

// ─── Checks ─────────────────────────────────────────────────────────────────

/// Check 1: untrusted-triggered uploader feeds a privileged `workflow_run`
/// downloader (tj-actions / Ultralytics pattern).
///
/// PERF-1: the previous implementation scanned every
/// `(sink_download, source, upload)` triple — O(W²·D·U). We now index
/// uploads by name up-front, so each sink download does one hash lookup
/// plus a scan over wildcard uploads (typically very few).
fn check_artifact_flow(graph: &Graph, findings: &mut Vec<AuditFinding>, is_warning: bool) {
    let index = build_upload_index(graph);

    for (sink_idx, sink) in graph.workflows.iter().enumerate() {
        if !sink.triggers.contains(&TriggerKind::WorkflowRun)
            || !sink.permissions.is_privileged()
        {
            continue;
        }

        // Resolve upstream parents once per sink.
        let resolved_parents: Vec<usize> = sink
            .workflow_run_parents
            .iter()
            .filter_map(|p| {
                candidate_parent_ids(p)
                    .into_iter()
                    .find_map(|id| graph.by_identity.get(&id).copied())
            })
            .collect();

        let source_is_eligible = |source_idx: usize| -> bool {
            if source_idx == sink_idx {
                return false;
            }
            let source = &graph.workflows[source_idx];
            let untrusted = source.triggers.iter().any(|t| t.is_untrusted_input());
            if !untrusted {
                return false;
            }
            if sink.workflow_run_parents.is_empty() {
                // No allowlist — any untrusted-triggered workflow could reach
                // this sink via a dynamic `workflow_run` dispatch.
                true
            } else {
                resolved_parents.contains(&source_idx)
            }
        };

        for download in sink.artifact_ops.iter().filter(|op| !op.is_upload) {
            let download_is_wildcard =
                download.name == "*" || download.name.contains("${{");

            // Candidate uploads: wildcard downloads see all uploads; exact
            // downloads see same-name uploads plus any wildcard uploads.
            let candidates: Vec<(usize, usize)> = if download_is_wildcard {
                let mut all = Vec::new();
                for (w_idx, w) in graph.workflows.iter().enumerate() {
                    for (op_idx, op) in w.artifact_ops.iter().enumerate() {
                        if op.is_upload {
                            all.push((w_idx, op_idx));
                        }
                    }
                }
                all
            } else {
                let mut hits = index
                    .by_name
                    .get(&download.name)
                    .cloned()
                    .unwrap_or_default();
                hits.extend(index.wildcard.iter().copied());
                hits
            };

            for (source_idx, op_idx) in candidates {
                if !source_is_eligible(source_idx) {
                    continue;
                }
                let source = &graph.workflows[source_idx];
                let upload = &source.artifact_ops[op_idx];
                findings.push(AuditFinding {
                    file: sink.file.clone(),
                    severity: Severity::Critical,
                    title: format!(
                        "Cross-workflow artifact flow from untrusted source `{}`",
                        source.file.display()
                    ),
                    detail: format!(
                        "Workflow {} (triggered by workflow_run with privileged \
                         permissions) downloads artifact `{}` produced by \
                         workflow {} under an untrusted trigger \
                         (pull_request / pull_request_target / issue_comment / \
                         issues). An attacker can poison the artifact in the \
                         source workflow and have it consumed in the privileged \
                         sink — this is the tj-actions / Ultralytics exploit \
                         shape. Verify the artifact's contents (hash or \
                         re-sign before consumption) or restructure so the \
                         privileged work does not depend on untrusted inputs. \
                         NOTE: this audit assumes a missing `permissions:` \
                         block inherits the paranoid repo default (write-all). \
                         If your org enforces `default_workflow_permissions: \
                         restricted`, add `permissions: read-all` to suppress.",
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

/// Check 2: privileged `workflow_run`-triggered workflow lacks an explicit
/// `workflows:` allowlist OR a conclusion-success `if:` gate.
///
/// CRIT-1: the "success guard" now requires a real `if:` expression; the
/// broken `types: [completed]` heuristic is gone.
/// LOW-3: when BOTH guards are missing, emit a single compound finding
/// rather than two separate ones — they share one root cause, and emitting
/// two lines for one cleanly-missing configuration was noise.
fn check_unguarded_workflow_run(
    graph: &Graph,
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    for wf in &graph.workflows {
        if !wf.triggers.contains(&TriggerKind::WorkflowRun)
            || !wf.permissions.is_privileged()
        {
            continue;
        }
        let no_allowlist = wf.workflow_run_parents.is_empty();
        let no_gate = !wf.has_conclusion_success_gate;

        if no_allowlist && no_gate {
            findings.push(AuditFinding {
                file: wf.file.clone(),
                severity: Severity::High,
                title:
                    "workflow_run trigger without explicit source workflows or conclusion guard"
                        .to_string(),
                detail:
                    "This privileged `workflow_run` workflow has neither a \
                     `workflows:` allowlist nor an `if: github.event.workflow_run.\
                     conclusion == 'success'` gate on any job. Any upstream \
                     run in the repo — including one triggered by a fork PR — \
                     can fire it, and it runs regardless of the upstream's \
                     outcome. Fix: add a `workflows:` filter naming the \
                     trusted upstream(s), AND add the conclusion gate at the \
                     top level or per-job so only successful upstream runs \
                     propagate. Note: `types: [completed]` is NOT a success \
                     guard — it is the event-timing filter, and fires on \
                     every terminal conclusion."
                        .to_string(),
                is_warning,
            });
        } else if no_allowlist {
            findings.push(AuditFinding {
                file: wf.file.clone(),
                severity: Severity::High,
                title: "workflow_run trigger without explicit source workflows".to_string(),
                detail:
                    "This workflow is triggered by `workflow_run` but does not restrict \
                     the set of upstream workflows that can trigger it (no `workflows:` \
                     filter). Combined with privileged permissions, any workflow run in \
                     this repo — including PR-triggered ones — can cause this workflow \
                     to fire. List the specific trusted workflows under \
                     `on.workflow_run.workflows:`."
                        .to_string(),
                is_warning,
            });
        } else if no_gate {
            findings.push(AuditFinding {
                file: wf.file.clone(),
                severity: Severity::High,
                title: "workflow_run trigger without conclusion guard".to_string(),
                detail:
                    "This workflow is triggered by `workflow_run` and does not gate \
                     its jobs on `github.event.workflow_run.conclusion == 'success'` \
                     (or `!= 'failure'`). Failed, cancelled, or skipped upstream runs \
                     can still fire this privileged workflow. Note: `types: [completed]` \
                     is NOT a success guard — it is the event-timing filter, and fires \
                     on every terminal conclusion. Add a top-level or per-job `if:` \
                     that checks `.conclusion` explicitly."
                        .to_string(),
                is_warning,
            });
        }
    }
}

/// Check 3: privileged workflow reads attacker-controlled
/// `github.event.workflow_run.*` subfields. HIGH-1: the allowlist of
/// dangerous subfields is `DANGEROUS_WORKFLOW_RUN_FIELDS`; GitHub-set
/// subfields like `.conclusion`, `.status`, `.id`, `.run_number`,
/// `.workflow_id` no longer trigger this finding.
fn check_workflow_run_event_taint(
    graph: &Graph,
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    for wf in &graph.workflows {
        if !wf.reads_attacker_controlled_event_fields {
            continue;
        }
        if !wf.triggers.contains(&TriggerKind::WorkflowRun) {
            continue;
        }

        let tainted_upstream = if wf.workflow_run_parents.is_empty() {
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
                    "This workflow references one of the attacker-controlled subfields of \
                     `github.event.workflow_run.*` (head_branch, head_sha, head_repository, \
                     head_commit, event, pull_requests, display_title, triggering_actor, \
                     actor, referenced_workflows) when the upstream workflow was triggered \
                     by a pull request. Do not pass these values to `run:` blocks, \
                     `actions/checkout`, or any step that evaluates them as code or \
                     identities. Note: `.conclusion`, `.status`, `.id`, `.run_number`, \
                     `.workflow_id`, `.created_at`, and other GitHub-set subfields are safe \
                     to read and are NOT flagged — they are exactly how you implement the \
                     conclusion-success guard the artifact-flow finding recommends."
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

    // ─── Adversarial fixture matrix ────────────────────────────────────────
    //
    // Each case loads all `*.yml` files from
    // `tests/fixtures/cross_workflow/<case.dir>/` and asserts on the titles
    // of findings the audit emits.
    //
    //   * `expect_any`  — at least one finding title must contain one of
    //                     these substrings. Empty ⇒ no lower bound.
    //   * `expect_none` — no finding title may contain any of these.
    //
    // Two tables:
    //   * PASSING_CASES — behavior believed correct today. Regression guards.
    //   * KNOWN_BUGS    — shapes where the check is WRONG. Assertions describe
    //                     the CURRENT buggy output so CI is green. Each case's
    //                     doc-comment states the INTENDED behavior; when the
    //                     bug is fixed, flip the `expect_*` lists and move
    //                     the entry into PASSING_CASES.
    //
    // Title-fragment constants mirror detail strings in the checks — update
    // here if a check's title changes.
    const TITLE_ARTIFACT_FLOW: &str = "Cross-workflow artifact flow";
    const TITLE_UNGUARDED_PARENTS: &str = "without explicit source workflows";
    const TITLE_UNGUARDED_CONCLUSION: &str = "without conclusion guard";
    const TITLE_EVENT_TAINT: &str = "attacker-controlled github.event.workflow_run";

    struct Case {
        name: &'static str,
        dir: &'static str,
        expect_any: &'static [&'static str],
        expect_none: &'static [&'static str],
    }

    fn load_case_docs(dir: &str) -> Vec<(PathBuf, Yaml)> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cross_workflow")
            .join(dir);
        let mut entries: Vec<_> = std::fs::read_dir(&root)
            .unwrap_or_else(|e| panic!("open fixture dir {root:?}: {e}"))
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("yml"))
            .collect();
        entries.sort();
        entries
            .into_iter()
            .map(|p| {
                let src = std::fs::read_to_string(&p)
                    .unwrap_or_else(|e| panic!("read {p:?}: {e}"));
                let doc = YamlLoader::load_from_str(&src)
                    .unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
                    .remove(0);
                (p, doc)
            })
            .collect()
    }

    fn assert_case(c: &Case) {
        let docs = load_case_docs(c.dir);
        let findings = run_check(&docs);
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        if !c.expect_any.is_empty() {
            assert!(
                c.expect_any
                    .iter()
                    .any(|sub| titles.iter().any(|t| t.contains(sub))),
                "[{}] expected a finding title containing any of {:?}; got titles = {:?}",
                c.name,
                c.expect_any,
                titles,
            );
        }
        for sub in c.expect_none {
            assert!(
                titles.iter().all(|t| !t.contains(sub)),
                "[{}] expected no finding title containing {:?}; got titles = {:?}",
                c.name,
                sub,
                titles,
            );
        }
    }

    const PASSING_CASES: &[Case] = &[
        // ── Baseline regression guards ─────────────────────────────────────
        //
        // Push-only source → workflow_run sink: no untrusted upstream, no CRIT.
        Case {
            name: "push-only source is not an artifact-flow source",
            dir: "pass_push_only",
            expect_any: &[],
            expect_none: &[TITLE_ARTIFACT_FLOW, TITLE_EVENT_TAINT],
        },
        // pull_request_target is classified as untrusted — artifact-flow fires.
        Case {
            name: "pull_request_target upstream taints the sink",
            dir: "pass_prt_source",
            expect_any: &[TITLE_ARTIFACT_FLOW],
            expect_none: &[],
        },
        // `on: workflow_run` with no allowlist AND no conclusion gate — the
        // LOW-3 compound finding's title still contains the
        // "without explicit source workflows" substring.
        Case {
            name: "workflow_run with no allowlist fires unguarded-parents",
            dir: "pass_no_allowlist",
            expect_any: &[TITLE_UNGUARDED_PARENTS],
            expect_none: &[],
        },
        // ── Previously-known bugs, now fixed ───────────────────────────────
        //
        // HIGH-1: `.conclusion` is GitHub-controlled and must NOT trigger
        // event-taint. Using the recommended `if: conclusion == 'success'`
        // mitigation now produces zero cross-workflow findings — no more
        // penalty on the exact shape the CRIT detail recommends.
        Case {
            name: "HIGH-1 fixed: conclusion-guard expression does not trigger event-taint",
            dir: "bug_conclusion_flagged",
            expect_any: &[],
            expect_none: &[
                TITLE_EVENT_TAINT,
                TITLE_ARTIFACT_FLOW,
                TITLE_UNGUARDED_PARENTS,
                TITLE_UNGUARDED_CONCLUSION,
            ],
        },
        // CRIT-1: `types: [completed]` is no longer treated as a success
        // guard. A sink with `types: [completed]` but no `if:` on
        // `conclusion == 'success'` now correctly fires the conclusion-
        // guard HIGH.
        Case {
            name: "CRIT-1 fixed: types:[completed] without if-check fires conclusion-guard",
            dir: "bug_completed_not_guard",
            expect_any: &[TITLE_UNGUARDED_CONCLUSION],
            expect_none: &[TITLE_UNGUARDED_PARENTS, TITLE_ARTIFACT_FLOW],
        },
        // HIGH-2: `dawidd6/action-download-artifact` is now recognised as
        // an artifact downloader. Reading `github.event.workflow_run.id`
        // (needed by dawidd6) is GitHub-set and MUST NOT trigger the
        // event-taint check (HIGH-1 overlap).
        Case {
            name: "HIGH-2 fixed: dawidd6/action-download-artifact is a recognised downloader",
            dir: "bug_dawidd6_downloader",
            expect_any: &[TITLE_ARTIFACT_FLOW],
            expect_none: &[TITLE_EVENT_TAINT],
        },
        // HIGH-3: a `gh run download` inside a `run:` block now synthesises
        // a wildcard-name download op, making the shell-level flow visible.
        Case {
            name: "HIGH-3 fixed: `gh run download` is a recognised downloader",
            dir: "bug_gh_run_download",
            expect_any: &[TITLE_ARTIFACT_FLOW],
            expect_none: &[TITLE_EVENT_TAINT],
        },
        // MED-2: `.github/workflows/ci.yml` in `workflows:` now resolves
        // via `candidate_parent_ids`. Because the resolved CI is push-only,
        // the sink no longer mis-ingests the unrelated PR-triggered
        // workflow as a candidate upstream — no artifact-flow CRIT.
        Case {
            name: "MED-2 fixed: repo-relative path in workflows: resolves correctly",
            dir: "bug_path_ref_unresolved",
            expect_any: &[],
            expect_none: &[TITLE_ARTIFACT_FLOW],
        },
    ];

    // Deliberately empty — populated when future regressions / audit gaps
    // are discovered. Each entry's assertions describe CURRENT (buggy)
    // output; fixing the bug flips the assertion and forces whoever fixes
    // it to move the entry into PASSING_CASES above.
    const KNOWN_BUGS: &[Case] = &[];

    #[test]
    fn matrix_regression_guards() {
        for c in PASSING_CASES {
            assert_case(c);
        }
    }

    #[test]
    fn matrix_known_bugs() {
        // Assertions here describe CURRENT (buggy) output, not the ideal
        // spec — fixing a bug will break its case, at which point flip the
        // `expect_*` lists and move the case into PASSING_CASES. See each
        // case's doc comment for the intended behavior.
        for c in KNOWN_BUGS {
            assert_case(c);
        }
    }

    // ─── Structure-generating fuzz harness ─────────────────────────────────
    //
    // Builds random (source, sink) workflow pairs from typed spec enums, so
    // every generated input is syntactically valid. Each iteration runs the
    // audit and checks invariants that must hold regardless of the specific
    // shape.
    //
    // Reproduce a failure:  HASP_FUZZ_SEED=0xDEADBEEF cargo test fuzz_
    // Increase coverage:    HASP_FUZZ_ITERS=5000      cargo test fuzz_

    #[derive(Debug, Clone, Copy)]
    enum UpTrigger {
        Push,
        PullRequest,
        PullRequestTarget,
        IssueComment,
        Schedule,
        WorkflowDispatch,
        Release,
        WorkflowCall,
    }
    #[derive(Debug, Clone, Copy)]
    enum Perms {
        Absent,
        Empty,
        ReadAll,
        WriteAll,
        ContentsWrite,
        IdTokenWrite,
    }
    #[derive(Debug, Clone, Copy)]
    enum SrcArtifact {
        None,
        UploadNamed,
        UploadExpr,
        UploadWildcardOmittedName,
    }
    #[derive(Debug, Clone, Copy)]
    enum SinkArtifact {
        None,
        DownloadSame,
        DownloadOther,
        DownloadNoName,
    }
    #[derive(Debug, Clone, Copy)]
    enum Types {
        Absent,
        Completed,
        Requested,
        CompletedAndRequested,
    }
    #[derive(Debug, Clone, Copy)]
    enum EventReads {
        None,
        Conclusion,
        HeadBranch,
        HeadSha,
    }
    #[derive(Debug, Clone, Copy)]
    enum ParentsList {
        None,
        NamesSource,
        NamesBogus,
    }
    #[derive(Debug, Clone, Copy)]
    enum IfCheck {
        None,
        ConclusionSuccess,
    }

    #[derive(Debug, Clone, Copy)]
    struct SrcSpec {
        trigger: UpTrigger,
        perms: Perms,
        artifact: SrcArtifact,
    }
    #[derive(Debug, Clone, Copy)]
    struct SinkSpec {
        parents: ParentsList,
        types: Types,
        perms: Perms,
        if_check: IfCheck,
        artifact: SinkArtifact,
        reads: EventReads,
    }

    fn render_perms(p: Perms) -> &'static str {
        match p {
            Perms::Absent => "",
            Perms::Empty => "permissions: {}\n",
            Perms::ReadAll => "permissions: read-all\n",
            Perms::WriteAll => "permissions: write-all\n",
            Perms::ContentsWrite => "permissions:\n  contents: write\n",
            Perms::IdTokenWrite => "permissions:\n  id-token: write\n",
        }
    }

    fn render_src(s: SrcSpec) -> String {
        let on = match s.trigger {
            UpTrigger::Push => "on: push",
            UpTrigger::PullRequest => "on: pull_request",
            UpTrigger::PullRequestTarget => "on: pull_request_target",
            UpTrigger::IssueComment => "on: issue_comment",
            UpTrigger::Schedule => "on:\n  schedule:\n    - cron: '0 0 * * *'",
            UpTrigger::WorkflowDispatch => "on: workflow_dispatch",
            UpTrigger::Release => "on: release",
            UpTrigger::WorkflowCall => "on: workflow_call",
        };
        let art = match s.artifact {
            SrcArtifact::None => String::new(),
            SrcArtifact::UploadNamed => "      - uses: actions/upload-artifact@a\n        with:\n          name: blob\n".to_string(),
            SrcArtifact::UploadExpr => "      - uses: actions/upload-artifact@a\n        with:\n          name: \"blob-${{ matrix.os }}\"\n".to_string(),
            SrcArtifact::UploadWildcardOmittedName => "      - uses: actions/upload-artifact@a\n".to_string(),
        };
        format!(
            "name: Source\n{on}\n{perms}jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n{art}",
            on = on,
            perms = render_perms(s.perms),
            art = art,
        )
    }

    fn render_sink(s: SinkSpec) -> String {
        let parents = match s.parents {
            ParentsList::None => String::new(),
            ParentsList::NamesSource => "    workflows: [Source]\n".to_string(),
            ParentsList::NamesBogus => "    workflows: ['.github/workflows/nope.yml']\n".to_string(),
        };
        let types = match s.types {
            Types::Absent => String::new(),
            Types::Completed => "    types: [completed]\n".to_string(),
            Types::Requested => "    types: [requested]\n".to_string(),
            Types::CompletedAndRequested => "    types: [completed, requested]\n".to_string(),
        };
        let on = if parents.is_empty() && types.is_empty() {
            "on: workflow_run\n".to_string()
        } else {
            format!("on:\n  workflow_run:\n{parents}{types}")
        };
        let job_if = match s.if_check {
            IfCheck::None => String::new(),
            IfCheck::ConclusionSuccess => {
                "    if: ${{ github.event.workflow_run.conclusion == 'success' }}\n".to_string()
            }
        };
        let art = match s.artifact {
            SinkArtifact::None => String::new(),
            SinkArtifact::DownloadSame => "      - uses: actions/download-artifact@b\n        with:\n          name: blob\n".to_string(),
            SinkArtifact::DownloadOther => "      - uses: actions/download-artifact@b\n        with:\n          name: something-else\n".to_string(),
            SinkArtifact::DownloadNoName => "      - uses: actions/download-artifact@b\n".to_string(),
        };
        let reads = match s.reads {
            EventReads::None => String::new(),
            EventReads::Conclusion => "      - run: echo ${{ github.event.workflow_run.conclusion }}\n".to_string(),
            EventReads::HeadBranch => "      - run: echo ${{ github.event.workflow_run.head_branch }}\n".to_string(),
            EventReads::HeadSha => "      - run: echo ${{ github.event.workflow_run.head_sha }}\n".to_string(),
        };
        format!(
            "name: Sink\n{on}{perms}jobs:\n  d:\n{job_if}    runs-on: ubuntu-latest\n    steps:\n      - run: echo start\n{art}{reads}",
            on = on,
            perms = render_perms(s.perms),
            job_if = job_if,
            art = art,
            reads = reads,
        )
    }

    /// Xorshift64* — deterministic, dependency-free, adequate for fuzzing
    /// distribution over small enum spaces.
    struct Rng64(u64);
    impl Rng64 {
        fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
            let n = usize::try_from(self.next() & 0xFFFF_FFFF).unwrap_or(0);
            xs[n % xs.len()]
        }
    }

    fn random_src(rng: &mut Rng64) -> SrcSpec {
        SrcSpec {
            trigger: rng.pick(&[
                UpTrigger::Push,
                UpTrigger::PullRequest,
                UpTrigger::PullRequestTarget,
                UpTrigger::IssueComment,
                UpTrigger::Schedule,
                UpTrigger::WorkflowDispatch,
                UpTrigger::Release,
                UpTrigger::WorkflowCall,
            ]),
            perms: rng.pick(&[
                Perms::Absent,
                Perms::Empty,
                Perms::ReadAll,
                Perms::WriteAll,
                Perms::ContentsWrite,
                Perms::IdTokenWrite,
            ]),
            artifact: rng.pick(&[
                SrcArtifact::None,
                SrcArtifact::UploadNamed,
                SrcArtifact::UploadExpr,
                SrcArtifact::UploadWildcardOmittedName,
            ]),
        }
    }

    fn random_sink(rng: &mut Rng64) -> SinkSpec {
        SinkSpec {
            parents: rng.pick(&[
                ParentsList::None,
                ParentsList::NamesSource,
                ParentsList::NamesBogus,
            ]),
            types: rng.pick(&[
                Types::Absent,
                Types::Completed,
                Types::Requested,
                Types::CompletedAndRequested,
            ]),
            perms: rng.pick(&[
                Perms::Absent,
                Perms::Empty,
                Perms::ReadAll,
                Perms::WriteAll,
                Perms::ContentsWrite,
                Perms::IdTokenWrite,
            ]),
            if_check: rng.pick(&[IfCheck::None, IfCheck::ConclusionSuccess]),
            artifact: rng.pick(&[
                SinkArtifact::None,
                SinkArtifact::DownloadSame,
                SinkArtifact::DownloadOther,
                SinkArtifact::DownloadNoName,
            ]),
            reads: rng.pick(&[
                EventReads::None,
                EventReads::Conclusion,
                EventReads::HeadBranch,
                EventReads::HeadSha,
            ]),
        }
    }

    fn env_u64(name: &str, default: u64) -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|s| {
                s.strip_prefix("0x").map_or_else(
                    || s.parse::<u64>().ok(),
                    |hex| u64::from_str_radix(hex, 16).ok(),
                )
            })
            .unwrap_or(default)
    }

    #[test]
    fn fuzz_invariants_hold_across_random_pairs() {
        let seed = env_u64("HASP_FUZZ_SEED", 0x00C0_FFEE);
        let iters = usize::try_from(env_u64("HASP_FUZZ_ITERS", 500)).unwrap_or(usize::MAX);
        let mut rng = Rng64::new(seed);
        println!("fuzz: seed=0x{seed:x} iters={iters}");

        for i in 0..iters {
            let src = random_src(&mut rng);
            let sink = random_sink(&mut rng);
            let src_yaml = render_src(src);
            let sink_yaml = render_sink(sink);

            let docs = vec![
                parse_named("source.yml", &src_yaml),
                parse_named("sink.yml", &sink_yaml),
            ];

            // (1) Deterministic: same input → identical findings.
            let a = run_check(&docs);
            let b = run_check(&docs);
            assert_eq!(
                a, b,
                "non-deterministic at iter {i}\nsrc={src:?}\nsink={sink:?}\nsrc_yaml=\n{src_yaml}\nsink_yaml=\n{sink_yaml}"
            );

            // (2) `Off` level short-circuits: must emit zero findings.
            let mut off = Vec::new();
            run(&docs, &mut off, crate::policy::CheckLevel::Off);
            assert!(off.is_empty(), "Off-level emitted findings at iter {i}");

            // (3) Every finding is one of the four known titles.
            for f in &a {
                let known = f.title.contains(TITLE_ARTIFACT_FLOW)
                    || f.title.contains(TITLE_UNGUARDED_PARENTS)
                    || f.title.contains(TITLE_UNGUARDED_CONCLUSION)
                    || f.title.contains(TITLE_EVENT_TAINT);
                assert!(
                    known,
                    "unknown finding title at iter {i}: {:?}\nsrc={src:?}\nsink={sink:?}",
                    f.title,
                );
            }

            // (4) Every finding's file is one of the two input files.
            for f in &a {
                let fname = f.file.file_name().and_then(|n| n.to_str()).unwrap_or("");
                assert!(
                    fname == "source.yml" || fname == "sink.yml",
                    "finding attributed to foreign file {fname:?} at iter {i}"
                );
            }

            // (5) Findings are sorted by severity (Critical=0 < High < Medium).
            for w in a.windows(2) {
                assert!(
                    w[0].severity <= w[1].severity,
                    "severity out of order at iter {i}: {:?} then {:?}",
                    w[0].severity,
                    w[1].severity,
                );
            }

            // (6) `workflow_run` checks only fire on sinks whose `on:` has
            //     workflow_run. Source-side false-positives on these titles
            //     would indicate mis-attribution. The sink-only titles:
            let sink_only = [
                TITLE_UNGUARDED_PARENTS,
                TITLE_UNGUARDED_CONCLUSION,
                TITLE_EVENT_TAINT,
            ];
            for f in &a {
                if sink_only.iter().any(|t| f.title.contains(t)) {
                    let fname = f.file.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    assert_eq!(
                        fname, "sink.yml",
                        "sink-only finding attributed to source.yml at iter {i}: {:?}",
                        f.title,
                    );
                }
            }
        }
    }

    #[test]
    fn fuzz_idempotent_add_safe_unrelated_workflow() {
        // Metamorphic: adding a third, unrelated push-only workflow that
        // neither uploads nor downloads artifacts and has no workflow_run
        // trigger must NOT change the findings produced by the original
        // (source, sink) pair. If it does, parent-resolution is leaking.
        let seed = env_u64("HASP_FUZZ_SEED", 0x00C0_FFEE).wrapping_mul(0x2862_9335_5577_7941);
        let iters = usize::try_from(env_u64("HASP_FUZZ_ITERS", 200)).unwrap_or(usize::MAX);
        let mut rng = Rng64::new(seed);

        let extra_yaml = "name: Unrelated\n\
            on: push\npermissions:\n  contents: read\n\
            jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";

        for i in 0..iters {
            let src = random_src(&mut rng);
            let sink = random_sink(&mut rng);

            let src_yaml = render_src(src);
            let sink_yaml = render_sink(sink);
            let base = vec![
                parse_named("source.yml", &src_yaml),
                parse_named("sink.yml", &sink_yaml),
            ];
            let extended = vec![
                parse_named("source.yml", &src_yaml),
                parse_named("sink.yml", &sink_yaml),
                parse_named("unrelated.yml", extra_yaml),
            ];
            let a = run_check(&base);
            let b = run_check(&extended);

            // Filter out findings attributable to the unrelated file — should
            // be none, but keep the assertion narrow.
            let b_filtered: Vec<_> = b
                .into_iter()
                .filter(|f| {
                    f.file.file_name().and_then(|n| n.to_str()) != Some("unrelated.yml")
                })
                .collect();
            assert_eq!(
                a, b_filtered,
                "adding an unrelated push-only workflow changed findings at iter {i}\nsrc={src:?}\nsink={sink:?}"
            );
        }
    }
}
