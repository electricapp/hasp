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
    PullRequestReview,
    PullRequestReviewComment,
    WorkflowRun,
    WorkflowDispatch,
    WorkflowCall,
    Schedule,
    IssueComment,
    Issues,
    Discussion,
    DiscussionComment,
    RepositoryDispatch,
    Release,
    Other,
}

impl TriggerKind {
    const fn parse(name: &str) -> Self {
        match name.as_bytes() {
            b"push" => Self::Push,
            b"pull_request" => Self::PullRequest,
            b"pull_request_target" => Self::PullRequestTarget,
            b"pull_request_review" => Self::PullRequestReview,
            b"pull_request_review_comment" => Self::PullRequestReviewComment,
            b"workflow_run" => Self::WorkflowRun,
            b"workflow_dispatch" => Self::WorkflowDispatch,
            b"workflow_call" => Self::WorkflowCall,
            b"schedule" => Self::Schedule,
            b"issue_comment" => Self::IssueComment,
            b"issues" => Self::Issues,
            b"discussion" => Self::Discussion,
            b"discussion_comment" => Self::DiscussionComment,
            b"repository_dispatch" => Self::RepositoryDispatch,
            b"release" => Self::Release,
            _ => Self::Other,
        }
    }

    /// Triggers that can carry attacker-influenced content into a workflow:
    /// fork PRs, issue/discussion bodies, review bodies,
    /// `repository_dispatch` `client_payload`, and `workflow_dispatch`
    /// `inputs`. The executing token is typically unprivileged for these
    /// events, but any payload they produce can later be consumed by a
    /// privileged `workflow_run` sink — so for cross-workflow taint
    /// analysis they're all sources of untrusted data. `workflow_dispatch`
    /// is included because many repos proxy dispatch via chatops bots or
    /// external triggers that effectively make inputs attacker-controllable.
    const fn is_untrusted_input(self) -> bool {
        matches!(
            self,
            Self::PullRequest
                | Self::PullRequestTarget
                | Self::PullRequestReview
                | Self::PullRequestReviewComment
                | Self::IssueComment
                | Self::Issues
                | Self::Discussion
                | Self::DiscussionComment
                | Self::RepositoryDispatch
                | Self::WorkflowDispatch
        )
    }

    /// Subset of `is_untrusted_input` that requires write access to fire
    /// (or a write-equivalent integration like a chatops dispatch bot).
    /// These are still untrusted in the paranoid model — anyone who
    /// proxies them effectively makes the inputs attacker-controllable —
    /// but they're noticeably less reachable than fork-PR sources, so the
    /// artifact-flow finding downgrades from Critical to High when the
    /// *only* untrusted triggers on a source are dispatch-class events.
    const fn is_dispatch_only_input(self) -> bool {
        matches!(self, Self::WorkflowDispatch | Self::RepositoryDispatch)
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

// A missing `permissions:` block is treated as the paranoid maximum
// (`write-all`). GitHub's default-for-new-repos is `contents: read`, but
// org settings can flip that to permissive and individual users can opt in
// per repo — so assuming the worst avoids a whole class of silent false
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
        // Documented read-only shorthands: no writes. Any other string —
        // typos, future GitHub extensions, anything we don't recognise —
        // gets the paranoid default.
        return match s {
            "read-all" | "read" | "none" | "" => PermissionSummary::default(),
            _ => PermissionSummary::paranoid_default(),
        };
    }

    let Some(map) = value.as_hash() else {
        // Neither a recognised shorthand string nor a hash (e.g.
        // `permissions: 42`, `permissions: null`, `permissions: - foo`).
        // Treat malformed input as paranoid rather than silently passing
        // it through as no-writes.
        return PermissionSummary::paranoid_default();
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
/// `dawidd6/action-download-artifact` is the primary third-party lever
/// used in the tj-actions / Ultralytics family of attacks — it downloads
/// artifacts from *other* workflow runs by `run_id`, which is exactly
/// the primitive a poisoned `workflow_run` sink needs. The explicit
/// allowlist covers the popular forks; the trailing `ends_with` catches
/// typosquats and mirrors whose repo path still ends in `/download-artifact`.
fn artifact_op_from_uses(uses: &str) -> Option<bool> {
    let head = uses.split('@').next().unwrap_or("").to_ascii_lowercase();
    if head == "actions/upload-artifact" {
        return Some(true);
    }
    match head.as_str() {
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

/// Extract the artifact name from a step's `with:` mapping. Reads `name:`
/// (used by `actions/download-artifact` ≤ v3) or `pattern:` (introduced
/// in v4 for multi-artifact downloads). Falls back to `"*"` — a wildcard
/// that matches any upload — when neither is present.
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

/// Detect shell-level artifact downloads that bypass the `uses:` pattern.
/// Three classes are recognised:
///   * `gh run download <run-id>` and `gh artifact download` — the
///     canonical `gh`-CLI bypass.
///   * `gh api .../artifacts/<id>/zip` — pulls the artifact zip via the
///     REST API without any artifact-action wrapper.
///   * `curl` against `api.github.com` (or `$GITHUB_API_URL`) hitting an
///     artifacts URL — the equivalent without `gh`.
///
/// Match is intent-detection on the run string, not argument parsing;
/// false positives are acceptable. The synthesised artifact op is always
/// a wildcard name, because the shell string doesn't reliably tell us
/// which artifact is being fetched.
fn run_step_implies_artifact_download(run: &str) -> bool {
    if run.contains("gh run download") || run.contains("gh artifact download") {
        return true;
    }
    let touches_artifacts = run.contains("/artifacts/")
        || run.contains("/actions/artifacts")
        || run.contains("artifacts/");
    if !touches_artifacts {
        return false;
    }
    if run.contains("gh api") {
        return true;
    }
    if run.contains("curl") && (run.contains("api.github.com") || run.contains("GITHUB_API_URL"))
    {
        return true;
    }
    false
}

// ─── Per-workflow information ───────────────────────────────────────────────

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
struct WorkflowInfo {
    file: PathBuf,
    /// Value of top-level `name:` if present.
    name: Option<String>,
    triggers: HashSet<TriggerKind>,
    /// For `on.workflow_run.workflows:` — names, filenames, or repo-relative
    /// paths of workflows that trigger this one. Resolution is deferred to
    /// `resolve_parents` / `candidate_parent_ids`, which try every plausible
    /// identity form (case-insensitive, `.yml`/`.yaml` interchangeable,
    /// `./.github/workflows/` prefix stripped) and return every workflow
    /// matching the chosen form.
    workflow_run_parents: Vec<String>,
    permissions: PermissionSummary,
    artifact_ops: Vec<ArtifactOp>,
    /// True iff any `${{ ... }}` expression references one of the
    /// attacker-controlled subfields of `github.event.workflow_run.*`
    /// (`head_branch`, `head_sha`, `head_repository`, `event`,
    /// `pull_requests`, `display_title`, `triggering_actor`, `actor`,
    /// `head_commit`, `referenced_workflows`). GitHub-set subfields like
    /// `.conclusion`, `.status`, `.id`, `.run_number`, `.workflow_id`,
    /// `.created_at` are safe — they're the building blocks of the
    /// conclusion-success guard the artifact-flow finding recommends, and
    /// flagging them would penalise the exact mitigation we suggest.
    reads_attacker_controlled_event_fields: bool,
    /// True iff any step is a recognised checkout action (`actions/checkout`,
    /// `gitea/checkout-action`, `forgejo-actions/checkout`) with one of
    /// `with.{ref,repository,path,token}` containing an attacker-controlled
    /// `${{ github.event.workflow_run.<dangerous> }}` expression. This is
    /// the canonical privileged-context RCE pattern: the tainted value is
    /// interpreted as a git ref / clone target and immediately checked out
    /// into the privileged workspace.
    has_tainted_checkout_ref: bool,
    /// True iff the workflow gates privileged work on the upstream having
    /// succeeded. We walk all `if:` expressions at the top level, on every
    /// job, and on every step looking for `github.event.workflow_run.
    /// conclusion == 'success'` (with either quote style and any
    /// whitespace). The weaker `!= 'failure'` form is NOT accepted because
    /// `cancelled`, `skipped`, `timed_out`, `neutral`, `action_required`,
    /// and `stale` all satisfy it and are reachable by an attacker who
    /// can force the upstream to cancel. `types: [completed]` is also NOT
    /// a gate — it's the event-timing filter and fires on every terminal
    /// conclusion.
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
    let mut has_tainted_checkout_ref = false;
    // A conclusion gate is accepted at any level — top-level `if:` (rare
    // but legal), job-level `if:` (the usual place), or step-level `if:`.
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
                // the repo default (assumed paranoid; see the block comment
                // on `parse_permissions_value`).
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
                    // Shell-level downloaders (`gh run download`, `curl
                    // .../artifacts/...`) bypass `uses:` entirely.
                    if let Some(run) = step_map.get(key_run()).and_then(Yaml::as_str)
                        && run_step_implies_artifact_download(run)
                    {
                        artifact_ops.push(ArtifactOp {
                            name: "*".to_string(),
                            is_upload: false,
                        });
                    }
                    if step_uses_tainted_checkout(uses, step_map.get(key_with())) {
                        has_tainted_checkout_ref = true;
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

    Some(WorkflowInfo {
        file: file.to_path_buf(),
        name,
        triggers,
        workflow_run_parents,
        permissions,
        artifact_ops,
        reads_attacker_controlled_event_fields,
        has_tainted_checkout_ref,
        has_conclusion_success_gate,
    })
}

/// Known checkout-action identifiers. We deliberately require an exact
/// match here rather than a `/checkout` suffix because the suffix would
/// over-match unrelated org actions like `myorg/checkout-cache`.
const CHECKOUT_ACTIONS: &[&str] = &[
    "actions/checkout",
    "gitea/checkout",
    "gitea/checkout-action",
    "forgejo-actions/checkout",
];

/// `with.*` keys that, set to an attacker-controlled expression, turn
/// `actions/checkout` into an arbitrary-fetch primitive:
///   * `ref` — git ref to check out → code execution under the privileged
///     token when the upstream is a fork.
///   * `repository` — owner/repo to clone → attacker substitutes an
///     entirely different repo whose default branch is malicious.
///   * `path` — workspace path to clone into → pairs trivially with later
///     steps that `cd $path && do_something`.
///   * `token` — credential used for the clone.
const CHECKOUT_RISK_KEYS: &[&str] = &["ref", "repository", "path", "token"];

/// Is this step a recognised checkout-action whose `with.<risk-key>`
/// contains an attacker-controlled `github.event.workflow_run.*`
/// expression?
fn step_uses_tainted_checkout(uses: &str, with: Option<&Yaml>) -> bool {
    let head = uses.split('@').next().unwrap_or("").to_ascii_lowercase();
    if !CHECKOUT_ACTIONS.contains(&head.as_str()) {
        return false;
    }
    let Some(with_map) = with.and_then(|w| w.as_hash()) else {
        return false;
    };
    for risk_key in CHECKOUT_RISK_KEYS {
        let Some((_, val)) = with_map.iter().find(|(k, _)| k.as_str() == Some(*risk_key)) else {
            continue;
        };
        let Some(s) = val.as_str() else { continue };
        let tainted = find_expressions(s).iter().any(|expr| {
            DANGEROUS_WORKFLOW_RUN_FIELDS
                .iter()
                .any(|field| expr_references_workflow_run_field(expr, field))
        });
        if tainted {
            return true;
        }
    }
    false
}

/// Extract trigger kinds and `workflow_run.workflows:` parent references
/// from the `on:` block. Conclusion-success gating is NOT detected here —
/// it's a property of `if:` expressions, walked separately by
/// `yaml_contains_conclusion_gate`. (Notably, `on.workflow_run.types:
/// [completed]` is the event-timing filter, NOT a conclusion gate.)
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

// ─── Attacker-controlled event-field allowlist ──────────────────────────────

/// Subfields of `github.event.workflow_run.*` that are attacker-controlled
/// when the upstream workflow was triggered by a fork PR. Anything NOT in
/// this list (`.conclusion`, `.status`, `.id`, `.run_id`, `.run_number`,
/// `.workflow_id`, `.created_at`, `.updated_at`, `.run_started_at`,
/// `.html_url`, `.jobs_url`, `.logs_url`, `.path`, etc.) is set by GitHub,
/// not by the attacker, and is safe to read — that's how a user writes
/// the conclusion-success guard the artifact-flow finding recommends.
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
                .any(|field| expr_references_workflow_run_field(expr, field))
        }),
        Yaml::Hash(m) => m
            .iter()
            .any(|(_, v)| yaml_reads_attacker_controlled_event_field(v)),
        Yaml::Array(a) => a.iter().any(yaml_reads_attacker_controlled_event_field),
        _ => false,
    }
}

/// Does an expression body reference `github.event.workflow_run.<field>`
/// on a real identifier boundary? A bare `contains` would over-match
/// `head_branch_other` or `xgithub.event.workflow_run.head_branch`; we
/// require a non-identifier byte (or string edge) on either side of the
/// needle.
///
/// `field` must be non-empty: passing `""` would degenerate the needle to
/// `github.event.workflow_run.` (trailing dot), and the boundary check
/// would always reject the next byte (typically an identifier char), so
/// no expression would ever match. A debug assert guards against caller
/// bugs.
fn expr_references_workflow_run_field(expr: &str, field: &str) -> bool {
    debug_assert!(
        !field.is_empty(),
        "field name must be non-empty; an empty needle would silently never match"
    );
    let needle = format!("github.event.workflow_run.{field}");
    let bytes = expr.as_bytes();
    let mut start = 0;
    while let Some(pos) = expr[start..].find(needle.as_str()) {
        let abs = start + pos;
        let after = abs + needle.len();
        let prev_ok = abs == 0 || {
            let c = bytes[abs - 1];
            !c.is_ascii_alphanumeric() && c != b'_'
        };
        let next_ok = after >= bytes.len() || {
            let c = bytes[after];
            !c.is_ascii_alphanumeric() && c != b'_'
        };
        if prev_ok && next_ok {
            return true;
        }
        start = after;
    }
    false
}

// ─── Conclusion-success gate walker ─────────────────────────────────────────

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

/// Canonical conclusion-success gate patterns, whitespace-stripped.
///
/// We deliberately accept only the strict `conclusion == 'success'` form
/// and NOT `conclusion != 'failure'` — `cancelled`, `skipped`, `timed_out`,
/// `neutral`, `action_required`, and `stale` all satisfy the `!= 'failure'`
/// predicate, and an attacker who can force the upstream to cancel (e.g.
/// via `cancel-in-progress` concurrency) bypasses the looser form.
const CONCLUSION_GATE_PATTERNS: &[&str] = &[
    "github.event.workflow_run.conclusion=='success'",
    "github.event.workflow_run.conclusion==\"success\"",
];

/// True if an expression string gates on the upstream having succeeded.
/// Accepts the expression with or without the `${{ ... }}` wrapper, with
/// either single or double quotes, and with any amount of whitespace.
///
/// An expression like `${{ !(github.event.workflow_run.conclusion ==
/// 'success') }}` runs *unless* the upstream succeeded — the inverse of
/// a gate. Any occurrence of the success pattern preceded by `!`, `!(`,
/// or `not(` is rejected via `pattern_negated`.
fn expr_is_conclusion_gate(s: &str) -> bool {
    let trimmed = s.trim();
    let body = trimmed
        .strip_prefix("${{")
        .and_then(|t| t.strip_suffix("}}"))
        .map_or(trimmed, str::trim);
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = compact.as_bytes();
    for pat in CONCLUSION_GATE_PATTERNS {
        let mut start = 0;
        while let Some(pos) = compact[start..].find(pat) {
            let abs = start + pos;
            if !pattern_negated(compact.as_str(), bytes, abs) {
                return true;
            }
            start = abs + pat.len();
        }
    }
    false
}

/// Is the conclusion-gate pattern at `pat_start` inside `compact`
/// (whitespace-stripped expression body) wrapped in a logical negation?
///
/// Walks backwards through any number of `(` opens, then counts trailing
/// `!` characters. An odd number of `!` is a real negation; an even
/// number (including zero) is a positive expression (`!!x` is logically
/// `x`). The `not(...)` form is rejected via substring search on the
/// prefix.
fn pattern_negated(compact: &str, bytes: &[u8], pat_start: usize) -> bool {
    let prefix = &compact[..pat_start];
    if prefix.contains("not(") {
        return true;
    }
    let mut i = pat_start;
    while i > 0 && bytes[i - 1] == b'(' {
        i -= 1;
    }
    let mut bangs: usize = 0;
    while i > 0 && bytes[i - 1] == b'!' {
        bangs += 1;
        i -= 1;
    }
    bangs % 2 == 1
}

// ─── Graph assembly ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct Graph {
    workflows: Vec<WorkflowInfo>,
    /// Map from a normalized workflow identity to the workflows that
    /// claim that identity. Lookup is case-insensitive (all keys are
    /// lowercased). Two workflows can share an identity legitimately
    /// when filesystems are case-sensitive — `CI.yml` and `ci.yml`
    /// both lowercase to `ci.yml` — so the value is a `Vec` and a
    /// reference to that identity resolves to ALL matching workflows.
    by_identity: HashMap<String, Vec<usize>>,
}

fn build_graph(workflows: Vec<WorkflowInfo>) -> Graph {
    let mut by_identity: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, w) in workflows.iter().enumerate() {
        if let Some(ref name) = w.name {
            by_identity
                .entry(name.to_lowercase())
                .or_default()
                .push(idx);
        }
        for form in index_forms_for_self(&w.file) {
            by_identity
                .entry(form.to_lowercase())
                .or_default()
                .push(idx);
        }
    }
    // Each workflow inserts multiple identity forms — dedupe per-key so a
    // single workflow doesn't appear multiple times in its own entry list.
    for indices in by_identity.values_mut() {
        indices.sort_unstable();
        indices.dedup();
    }
    Graph {
        workflows,
        by_identity,
    }
}

/// Produce every identity form a workflow file should be indexable under:
/// the workflow's `name:`, the filename, the file stem, the repo-relative
/// path with and without extension, plus the `.yml`↔`.yaml` cross-pair so
/// a sink that wrote `workflows: [ci.yaml]` resolves to `ci.yml` on disk.
/// All forms are lowercased at the indexing site (`build_graph` /
/// `resolve_parents`) for case-insensitive matching.
fn index_forms_for_self(file: &Path) -> Vec<String> {
    let mut v = Vec::new();
    let as_string = file.to_string_lossy().to_string();
    v.push(as_string.clone());
    if let Some(name) = file.file_name().and_then(|n| n.to_str()) {
        v.push(name.to_string());
        // The `.yml`↔`.yaml` cross-pair is only meaningful at the filename
        // level — synthesising a swapped extension on the full path would
        // claim an identity for a file that doesn't exist on disk, which
        // can shadow a real same-stem workflow in a different directory.
        push_extension_variants(&mut v, name);
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

/// Push `stem.yaml` for a `stem.yml` input and vice versa, so a
/// `.yml`/`.yaml` mismatch between the file on disk and the parent
/// reference doesn't break resolution.
fn push_extension_variants(v: &mut Vec<String>, s: &str) {
    if let Some(stem) = s.strip_suffix(".yml") {
        v.push(format!("{stem}.yaml"));
    } else if let Some(stem) = s.strip_suffix(".yaml") {
        v.push(format!("{stem}.yml"));
    }
}

/// Produce every identity string to try for a parent reference. GitHub
/// accepts workflow `name:` OR filename, but real configs also use
/// repo-relative paths and may write the wrong file extension or
/// inconsistent case. The reference is lowercased first so the path-
/// prefix strip (`./`, `.github/workflows/`) works regardless of case.
fn candidate_parent_ids(parent: &str) -> Vec<String> {
    let lower = parent.to_lowercase();
    let mut out = vec![lower.clone()];
    push_extension_variants(&mut out, &lower);
    let trimmed = lower
        .trim_start_matches("./")
        .trim_start_matches(".github/workflows/");
    if trimmed != lower {
        out.push(trimmed.to_string());
        push_extension_variants(&mut out, trimmed);
    }
    for base in [lower.as_str(), trimmed] {
        if let Some(no_ext) = base
            .strip_suffix(".yml")
            .or_else(|| base.strip_suffix(".yaml"))
        {
            out.push(no_ext.to_string());
        }
    }
    out
}

/// Resolve a parent reference to every workflow whose identity matches.
/// A single reference may match multiple workflows when filenames
/// collide case-insensitively. Returns an empty `Vec` if no identity form
/// matches.
fn resolve_parents<'g>(graph: &'g Graph, parent: &str) -> Vec<&'g WorkflowInfo> {
    for id in candidate_parent_ids(parent) {
        if let Some(indices) = graph.by_identity.get(&id) {
            return indices.iter().map(|&i| &graph.workflows[i]).collect();
        }
    }
    Vec::new()
}

// ─── Upload-name index ──────────────────────────────────────────────────────

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
/// downloader (tj-actions / Ultralytics pattern). Uploads are indexed by
/// name up-front; each sink download does a single hash lookup plus a
/// scan over wildcard uploads (typically very few).
#[allow(clippy::too_many_lines)]
fn check_artifact_flow(graph: &Graph, findings: &mut Vec<AuditFinding>, is_warning: bool) {
    let index = build_upload_index(graph);

    for (sink_idx, sink) in graph.workflows.iter().enumerate() {
        if !sink.triggers.contains(&TriggerKind::WorkflowRun)
            || !sink.permissions.is_privileged()
        {
            continue;
        }

        // Resolve upstream parents once per sink. A single reference can
        // match multiple workflows on case-insensitive filesystems, so
        // every match is collected.
        let resolved_parents: Vec<usize> = sink
            .workflow_run_parents
            .iter()
            .flat_map(|p| {
                candidate_parent_ids(p)
                    .into_iter()
                    .find_map(|id| graph.by_identity.get(&id).cloned())
                    .unwrap_or_default()
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
                // If the source's *only* untrusted trigger kinds are
                // dispatch-class (`workflow_dispatch`/`repository_dispatch`)
                // — which require write access or a proxy to fire — the
                // exploit chain is meaningfully less reachable than a
                // fork-PR shape. Emit at High in that case so the more
                // dangerous PR-fork flow stands out from common
                // build-then-sign release patterns.
                let untrusted_triggers: Vec<TriggerKind> = source
                    .triggers
                    .iter()
                    .copied()
                    .filter(|t| t.is_untrusted_input())
                    .collect();
                let dispatch_only = !untrusted_triggers.is_empty()
                    && untrusted_triggers
                        .iter()
                        .all(|t| t.is_dispatch_only_input());
                let (severity, source_kind_phrase) = if dispatch_only {
                    (
                        Severity::High,
                        "workflow_dispatch / repository_dispatch (write-gated, \
                         but reachable via chatops bots or proxied triggers)",
                    )
                } else {
                    (
                        Severity::Critical,
                        "pull_request / pull_request_target / issue_comment / \
                         issues / pull_request_review / discussion / \
                         workflow_dispatch / repository_dispatch",
                    )
                };
                findings.push(AuditFinding {
                    file: sink.file.clone(),
                    severity,
                    title: format!(
                        "Cross-workflow artifact flow from untrusted source `{}`",
                        source.file.display()
                    ),
                    detail: format!(
                        "Workflow {} (triggered by workflow_run with privileged \
                         permissions) downloads artifact `{}` produced by \
                         workflow {} under an untrusted trigger ({source_kind_phrase}). \
                         An attacker can poison the artifact in the source workflow \
                         and have it consumed in the privileged sink — this is the \
                         tj-actions / Ultralytics exploit shape. Verify the \
                         artifact's contents (hash or re-sign before consumption) \
                         or restructure so the privileged work does not depend on \
                         untrusted inputs. NOTE: this audit assumes a missing \
                         `permissions:` block inherits the paranoid repo default \
                         (write-all). If your org enforces \
                         `default_workflow_permissions: restricted`, add \
                         `permissions: read-all` to suppress.",
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
/// `workflows:` allowlist OR a conclusion-success `if:` gate. When BOTH
/// are missing we emit a single compound finding rather than two — same
/// root cause. The conclusion guard must be a real `if:` expression;
/// `types: [completed]` is NOT a guard (it's the event-timing filter and
/// fires on every terminal conclusion).
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
                     its jobs on `github.event.workflow_run.conclusion == 'success'`. \
                     Failed, cancelled, or skipped upstream runs can still fire this \
                     privileged workflow. Note: `types: [completed]` is NOT a success \
                     guard — it is the event-timing filter, and fires on every terminal \
                     conclusion. The weaker `!= 'failure'` form is NOT sufficient \
                     because `cancelled`, `skipped`, `timed_out`, and `neutral` all \
                     satisfy it. Add a top-level or per-job `if:` that checks \
                     `.conclusion == 'success'` explicitly."
                        .to_string(),
                is_warning,
            });
        }
    }
}

/// Check 3: privileged workflow reads one of the attacker-controlled
/// `github.event.workflow_run.*` subfields (`DANGEROUS_WORKFLOW_RUN_FIELDS`)
/// AND has at least one untrusted upstream parent. GitHub-set subfields
/// (`.conclusion`, `.status`, `.id`, `.run_number`, `.workflow_id`, ...)
/// do not trigger this finding — they're the safe building blocks of the
/// conclusion-success guard.
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
        // A tainted checkout already raised a Critical finding for this
        // workflow that names the same root cause; the generic event-read
        // HIGH would be duplicative.
        if wf.has_tainted_checkout_ref && wf.permissions.is_privileged() {
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
                .flat_map(|p| resolve_parents(graph, p))
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

/// Check 4: checkout-with-tainted-ref RCE. A privileged `workflow_run`-
/// triggered workflow whose `actions/checkout` (or recognised clone) has
/// any of `with.{ref,repository,path,token}` set to an attacker-controlled
/// `github.event.workflow_run.*` expression will fetch attacker source
/// into the workspace and run it under the privileged token. This is the
/// canonical exploit pattern from GitHub's "Keeping your GitHub Actions
/// secure" guidance — emitted at Critical because the tainted value is
/// evaluated as a git ref / clone target and immediately executed.
fn check_workflow_run_checkout_taint(
    graph: &Graph,
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    for wf in &graph.workflows {
        if !wf.has_tainted_checkout_ref {
            continue;
        }
        if !wf.triggers.contains(&TriggerKind::WorkflowRun) {
            continue;
        }
        if !wf.permissions.is_privileged() {
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
                .flat_map(|p| resolve_parents(graph, p))
                .any(|w| w.triggers.iter().any(|t| t.is_untrusted_input()))
        };
        if !tainted_upstream {
            continue;
        }
        findings.push(AuditFinding {
            file: wf.file.clone(),
            severity: Severity::Critical,
            title: "Cross-workflow checkout of attacker-controlled ref in privileged sink"
                .to_string(),
            detail:
                "This privileged `workflow_run`-triggered workflow checks out a git ref \
                 derived from `github.event.workflow_run.<head_branch|head_sha|head_repository\
                 |head_commit|...>` — fields populated by the upstream PR fork. The fork's \
                 code is fetched into the workspace and executed under the sink's privileged \
                 token (write-all by default in the paranoid model). Fix: pin the checkout \
                 ref to the trusted base branch / SHA (NOT the workflow_run head_*), or \
                 restructure so the privileged work runs only against trusted source. \
                 Variants of this pattern (gitea/forgejo `checkout`, third-party \
                 `*-action`) are also flagged."
                    .to_string(),
            is_warning,
        });
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
    // Sort our own findings by severity once, after every check has run,
    // so output order doesn't depend on the order the checks happen to
    // fire in. Findings already in the slice (from other audit modules)
    // are not touched — `audit::run` re-sorts the full set afterwards.
    let start = findings.len();
    check_artifact_flow(&graph, findings, is_warning);
    check_workflow_run_checkout_taint(&graph, findings, is_warning);
    check_unguarded_workflow_run(&graph, findings, is_warning);
    check_workflow_run_event_taint(&graph, findings, is_warning);
    findings[start..].sort_by_key(|f| f.severity);
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
    fn detects_workflow_run_checkout_ref_rce() {
        // Privileged workflow_run sink does `actions/checkout` with
        // `ref: ${{ github.event.workflow_run.head_branch }}` — the
        // canonical RCE pattern (attacker fork's code is checked out
        // into the privileged workspace).
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
  d:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          ref: ${{ github.event.workflow_run.head_branch }}
      - run: ./run-build.sh
",
        );
        let findings = run_check(&[parent, sink]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("checkout of attacker-controlled ref")),
            "expected checkout-taint finding, got: {findings:?}"
        );
    }

    #[test]
    fn action_uses_matching_is_case_insensitive() {
        // GitHub resolves `uses:` owner/repo case-insensitively, so the
        // analyzer must too — otherwise `Actions/Checkout@...` or
        // `Actions/Upload-Artifact@...` silently bypasses every check.
        assert_eq!(
            artifact_op_from_uses("Actions/Upload-Artifact@v4"),
            Some(true)
        );
        assert_eq!(
            artifact_op_from_uses("ACTIONS/DOWNLOAD-ARTIFACT@v4"),
            Some(false)
        );
        assert_eq!(
            artifact_op_from_uses("DAWIDD6/Action-Download-Artifact@v4"),
            Some(false)
        );
        // `uses: Actions/Checkout@... with: { ref: ${{ workflow_run.head_branch }} }`
        // must still register as a tainted checkout.
        let with_doc = YamlLoader::load_from_str(
            "ref: ${{ github.event.workflow_run.head_branch }}\n",
        )
        .unwrap()
        .remove(0);
        assert!(step_uses_tainted_checkout(
            "Actions/Checkout@v4",
            Some(&with_doc)
        ));
        assert!(step_uses_tainted_checkout(
            "actions/CHECKOUT@v4",
            Some(&with_doc)
        ));
    }

    #[test]
    fn rejects_negated_conclusion_gate() {
        // `if: !(conclusion == 'success')` is the *inverse* of a gate
        // (runs unless upstream succeeded). Must NOT be accepted.
        assert!(!expr_is_conclusion_gate(
            "${{ !(github.event.workflow_run.conclusion == 'success') }}"
        ));
        assert!(!expr_is_conclusion_gate(
            "${{ not(github.event.workflow_run.conclusion == 'success') }}"
        ));
        // Plain `== 'success'` still accepted.
        assert!(expr_is_conclusion_gate(
            "${{ github.event.workflow_run.conclusion == 'success' }}"
        ));
        // Compound `&&` / `||` still accepted as long as a positive
        // success gate is present somewhere.
        assert!(expr_is_conclusion_gate(
            "${{ github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.head_branch == 'main' }}"
        ));
        // Double-negation `!!x` is logically `x` — must remain accepted.
        assert!(expr_is_conclusion_gate(
            "${{ !!(github.event.workflow_run.conclusion == 'success') }}"
        ));
        // Triple-negation is still negation.
        assert!(!expr_is_conclusion_gate(
            "${{ !!!(github.event.workflow_run.conclusion == 'success') }}"
        ));
    }

    #[test]
    fn rejects_not_failure_conclusion_gate() {
        // `conclusion != 'failure'` is a real bypass (cancelled, skipped,
        // timed_out, neutral all pass it). It is NOT a gate.
        assert!(!expr_is_conclusion_gate(
            "${{ github.event.workflow_run.conclusion != 'failure' }}"
        ));
        assert!(!expr_is_conclusion_gate(
            "${{ github.event.workflow_run.conclusion != \"failure\" }}"
        ));
    }

    #[test]
    fn word_boundary_on_dangerous_field_match() {
        // Substring match must not bleed across identifier boundaries:
        // `head_branch` should NOT match `head_branch_other` or
        // `xgithub.event.workflow_run.head_branch`.
        assert!(!expr_references_workflow_run_field(
            "github.event.workflow_run.head_branch_other",
            "head_branch"
        ));
        assert!(!expr_references_workflow_run_field(
            "xgithub.event.workflow_run.head_branch",
            "head_branch"
        ));
        assert!(expr_references_workflow_run_field(
            "echo ${{ github.event.workflow_run.head_branch }}",
            "head_branch"
        ));
    }

    #[test]
    fn malformed_permissions_is_paranoid_default() {
        // A `permissions:` block that's neither a recognised shorthand
        // string nor a hash (e.g. `permissions: 42`) must inherit the
        // paranoid default rather than silently passing as no-writes.
        let wf = parse_named(
            "p.yml",
            "
name: P
on: workflow_run
permissions: 42
jobs:
  d:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
        );
        let findings = run_check(&[wf]);
        // Workflow is treated as privileged → unguarded compound HIGH fires.
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("without explicit source workflows")),
            "malformed permissions block should be treated as paranoid; got: {findings:?}"
        );
    }

    #[test]
    fn gh_api_artifact_download_recognised() {
        // `gh api .../artifacts/<id>/zip` and `curl ... api.github.com ...
        // /artifacts/...` both synthesise an artifact-download op.
        assert!(run_step_implies_artifact_download(
            "gh api /repos/o/r/actions/artifacts/123/zip > out.zip"
        ));
        assert!(run_step_implies_artifact_download(
            "curl -sL https://api.github.com/repos/o/r/actions/artifacts/123/zip"
        ));
        // Pure shell math, etc., must NOT be recognised.
        assert!(!run_step_implies_artifact_download("echo gh hello"));
    }

    #[test]
    fn dispatch_and_review_triggers_are_untrusted() {
        // workflow_dispatch / repository_dispatch / pull_request_review /
        // pull_request_review_comment / discussion / discussion_comment
        // all classify as untrusted sources.
        let src = parse_named(
            "src.yml",
            "
name: Src
on: workflow_dispatch
permissions: {}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          name: blob
",
        );
        let sink = parse_named(
            "sink.yml",
            "
name: Sink
on:
  workflow_run:
    workflows: [Src]
    types: [completed]
permissions:
  contents: write
jobs:
  d:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    steps:
      - uses: actions/download-artifact@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        with:
          name: blob
",
        );
        let findings = run_check(&[src, sink]);
        assert!(
            findings.iter().any(|f| f.title.contains("artifact flow")),
            "workflow_dispatch upstream should be untrusted; got: {findings:?}"
        );
    }

    #[test]
    fn case_insensitive_workflow_name_resolution() {
        // `workflows: [CI]` against a workflow named `ci` must match.
        let src = parse_named(
            "ci.yml",
            "
name: ci
on: pull_request
permissions: {}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          name: blob
",
        );
        let sink = parse_named(
            "sink.yml",
            "
name: Sink
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  contents: write
jobs:
  d:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    steps:
      - uses: actions/download-artifact@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        with:
          name: blob
",
        );
        let findings = run_check(&[src, sink]);
        assert!(
            findings.iter().any(|f| f.title.contains("artifact flow")),
            "case-insensitive resolution: got: {findings:?}"
        );
    }

    #[test]
    fn yml_yaml_cross_extension_resolution() {
        // `workflows: ['ci.yaml']` against a file on disk named `ci.yml`
        // (or vice versa) must match.
        let src = parse_named(
            "ci.yml",
            "
name: CI
on: pull_request
permissions: {}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          name: blob
",
        );
        let sink = parse_named(
            "sink.yml",
            "
name: Sink
on:
  workflow_run:
    workflows: ['ci.yaml']
    types: [completed]
permissions:
  contents: write
jobs:
  d:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    steps:
      - uses: actions/download-artifact@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        with:
          name: blob
",
        );
        let findings = run_check(&[src, sink]);
        assert!(
            findings.iter().any(|f| f.title.contains("artifact flow")),
            ".yml↔.yaml cross-extension resolution: got: {findings:?}"
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
    const TITLE_CHECKOUT_TAINT: &str = "checkout of attacker-controlled ref";

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
        // `on: workflow_run` with no allowlist AND no conclusion gate.
        // The compound finding's title still contains the
        // "without explicit source workflows" substring. Fixture prefix
        // `flag_` means "analyzer SHOULD flag"; contrast with `pass_*`
        // (analyzer should remain silent on safe code).
        Case {
            name: "workflow_run with no allowlist fires unguarded-parents",
            dir: "flag_no_allowlist",
            expect_any: &[TITLE_UNGUARDED_PARENTS],
            expect_none: &[],
        },
        // ── Sink shapes that look risky but are safe ───────────────────────
        //
        // `.conclusion` is a GitHub-set field — reading it (as in the
        // recommended `if: conclusion == 'success'` mitigation) must NOT
        // trigger event-taint. The sink here is fully gated and produces
        // zero cross-workflow findings.
        Case {
            name: "conclusion-guard expression does not trigger event-taint",
            dir: "bug_conclusion_flagged",
            expect_any: &[],
            expect_none: &[
                TITLE_EVENT_TAINT,
                TITLE_ARTIFACT_FLOW,
                TITLE_UNGUARDED_PARENTS,
                TITLE_UNGUARDED_CONCLUSION,
            ],
        },
        // ── Sink shapes that must fire a specific finding ──────────────────
        //
        // `types: [completed]` is the event-timing filter, NOT a success
        // guard. A sink with `types: [completed]` but no `if:` on
        // `conclusion == 'success'` must fire the conclusion-guard HIGH.
        Case {
            name: "types:[completed] without if-check fires conclusion-guard",
            dir: "bug_completed_not_guard",
            expect_any: &[TITLE_UNGUARDED_CONCLUSION],
            expect_none: &[TITLE_UNGUARDED_PARENTS, TITLE_ARTIFACT_FLOW],
        },
        // `dawidd6/action-download-artifact` is a recognised third-party
        // downloader and must produce an artifact-flow finding when fed
        // from an untrusted upstream. Reading `workflow_run.id` (which
        // dawidd6 needs) is GitHub-set and must NOT trip event-taint.
        Case {
            name: "dawidd6/action-download-artifact is a recognised downloader",
            dir: "bug_dawidd6_downloader",
            expect_any: &[TITLE_ARTIFACT_FLOW],
            expect_none: &[TITLE_EVENT_TAINT],
        },
        // A `gh run download` inside a `run:` block synthesises a
        // wildcard-name download op, exposing the shell-level flow.
        Case {
            name: "`gh run download` is a recognised downloader",
            dir: "bug_gh_run_download",
            expect_any: &[TITLE_ARTIFACT_FLOW],
            expect_none: &[TITLE_EVENT_TAINT],
        },
        // `.github/workflows/ci.yml` in `workflows:` resolves to `ci.yml`
        // on disk. The resolved CI is PR-triggered (untrusted) and
        // uploads `report`, which the sink downloads — artifact-flow CRIT
        // must fire AND be attributed to the sink. The `unrelated_pr.yml`
        // in the same dir also uploads `report` but is NOT in the
        // `workflows:` allowlist; it must NOT produce a finding, which
        // exercises the parent-resolution path.
        Case {
            name: "repo-relative path in workflows: resolves correctly",
            dir: "bug_path_ref_unresolved",
            expect_any: &[TITLE_ARTIFACT_FLOW],
            expect_none: &[TITLE_EVENT_TAINT, TITLE_UNGUARDED_CONCLUSION],
        },
    ];

    // Cases whose CURRENT output is wrong but expected. Each entry's
    // assertions describe the buggy output so CI stays green; fixing
    // the underlying bug breaks the case, which is the signal to flip
    // the `expect_*` lists and move it into PASSING_CASES above.
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
        // Exercise every identity form a user might write in
        // `on.workflow_run.workflows:` against a source named `Source`
        // saved as `source.yml`: filename, repo-relative path, the
        // `.yaml` cross-extension form, and an uppercase repo-relative
        // path so the path-form lowercasing in `index_forms_for_self`
        // is actually exercised (uppercasing the bare `Source` name
        // would only hit the name-based index path).
        FilenameSource,
        PathSource,
        YamlExtSource,
        UppercasePathSource,
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
            ParentsList::FilenameSource => "    workflows: [source.yml]\n".to_string(),
            ParentsList::PathSource => {
                "    workflows: ['.github/workflows/source.yml']\n".to_string()
            }
            ParentsList::YamlExtSource => "    workflows: [source.yaml]\n".to_string(),
            ParentsList::UppercasePathSource => {
                "    workflows: ['.GITHUB/WORKFLOWS/SOURCE.YML']\n".to_string()
            }
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
                ParentsList::FilenameSource,
                ParentsList::PathSource,
                ParentsList::YamlExtSource,
                ParentsList::UppercasePathSource,
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

            // (3) Every finding is one of the five known titles.
            for f in &a {
                let known = f.title.contains(TITLE_ARTIFACT_FLOW)
                    || f.title.contains(TITLE_UNGUARDED_PARENTS)
                    || f.title.contains(TITLE_UNGUARDED_CONCLUSION)
                    || f.title.contains(TITLE_EVENT_TAINT)
                    || f.title.contains(TITLE_CHECKOUT_TAINT);
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
                TITLE_CHECKOUT_TAINT,
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
