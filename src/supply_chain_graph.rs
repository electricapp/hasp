//! Supply-chain graph + per-node trust scoring.
//!
//! `hasp tree` emits a DAG of workflows -> pinned `uses:` dependencies with
//! a per-node trust score rolled up from available signals (pin kind,
//! signatures, reachability, SLSA attestation, repo reputation, age).  The
//! aim is a `cargo audit tree`-style view specifically for GitHub Actions
//! dependencies.

use crate::audit::AuditFinding;
use crate::scanner::{ActionRef, RefKind};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;

// ─── Types ──────────────────────────────────────────────────────────────────

pub(crate) type NodeId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeKind {
    /// A workflow file (the root of its dependency tree).
    Workflow,
    /// A pinned `uses:` reference.
    Action,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TrustSignals {
    pub(crate) pinned_full_sha: bool,
    /// How many static-audit findings hit this specific node (workflow file
    /// or action ref). We use this as a negative signal.
    pub(crate) findings_here: u32,
    /// Set when we have online evidence that the pinned SHA exists.
    pub(crate) sha_exists: Option<bool>,
    /// Set when reachability from the default branch was checked.
    pub(crate) reachable: Option<bool>,
    /// Set when signature verification was performed.
    pub(crate) signed: Option<bool>,
    /// Set when SLSA attestation verification was performed.
    pub(crate) slsa_verified: Option<bool>,
    /// Pinned-commit age in days, when known.
    pub(crate) commit_age_days: Option<i64>,
    /// Repo age in days, when known.
    pub(crate) repo_age_days: Option<i64>,
    /// Star count, when known.
    pub(crate) repo_stars: Option<u32>,
}

#[derive(Debug, Clone)]
pub(crate) struct ActionNode {
    pub(crate) id: NodeId,
    pub(crate) kind: NodeKind,
    pub(crate) label: String,
    pub(crate) short_sha: Option<String>,
    pub(crate) depth: u8,
    pub(crate) signals: TrustSignals,
    pub(crate) score: f32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Edge {
    pub(crate) from: NodeId,
    pub(crate) to: NodeId,
}

#[derive(Debug, Clone)]
pub(crate) struct ActionGraph {
    pub(crate) nodes: Vec<ActionNode>,
    pub(crate) edges: Vec<Edge>,
    pub(crate) roots: Vec<NodeId>,
}

// ─── Scoring ────────────────────────────────────────────────────────────────

/// Compute the trust score from the current signals, saturated to [0, 1].
///
/// Weights are documented inline. A node with a full-SHA pin that exists on
/// a reachable default branch, signed, SLSA-attested, from a well-established
/// repo should land near 1.0.  Mutable refs, phantom SHAs, or newly created
/// repos collapse to near 0.
pub(crate) fn score_signals(signals: &TrustSignals) -> f32 {
    let mut score: f32 = 0.0;

    if signals.pinned_full_sha {
        score += 0.3;
    }
    match signals.sha_exists {
        Some(true) => score += 0.15,
        Some(false) => score -= 0.3, // phantom SHA is worse than "unknown"
        None => {}
    }
    if matches!(signals.reachable, Some(true)) {
        score += 0.15;
    }
    if matches!(signals.signed, Some(true)) {
        score += 0.10;
    }
    if matches!(signals.slsa_verified, Some(true)) {
        score += 0.10;
    }
    // Repository established (age > 180d AND stars > 10) is a single composite signal
    let established = matches!(signals.repo_age_days, Some(days) if days > 180)
        && matches!(signals.repo_stars, Some(stars) if stars > 10);
    if established {
        score += 0.2;
    }

    // Penalties
    if matches!(signals.commit_age_days, Some(days) if days < 2) {
        score -= 0.3;
    }
    if matches!(signals.repo_age_days, Some(days) if days < 30) {
        score -= 0.2;
    }
    let finding_penalty = 0.05 * f32::from(u16::try_from(signals.findings_here.min(6)).unwrap_or(0));
    score -= finding_penalty;

    score.clamp(0.0, 1.0)
}

/// Aggregate a parent node's score with its children.
///
/// `min(self_score, mean(child_scores))` — one bad child drags the parent
/// down, but the parent's own signals still matter.
pub(crate) fn aggregate_score(self_score: f32, child_scores: &[f32]) -> f32 {
    if child_scores.is_empty() {
        return self_score;
    }
    // f32 precision is ample here: we never aggregate more than a few hundred
    // children per node, far below the 2^24 safe integer range of f32.
    #[allow(clippy::cast_precision_loss)]
    let denom = child_scores.len() as f32;
    let mean: f32 = child_scores.iter().sum::<f32>() / denom;
    self_score.min(mean)
}

// ─── Graph construction ─────────────────────────────────────────────────────

/// Build the graph from a scan's workflow files + action refs. Each workflow
/// file becomes a root node; each unique pinned action (by owner/repo/path)
/// becomes a child node of the workflows it appears in.
///
/// `node_findings` counts how many audit findings targeted a given file path.
/// `per_ref_signals` optionally provides online signals per (owner,repo,sha).
pub(crate) fn build(
    workflow_files: &[PathBuf],
    refs: &[ActionRef],
    findings: &[AuditFinding],
    per_ref_signals: &HashMap<RefKey, TrustSignals>,
) -> ActionGraph {
    let mut nodes: Vec<ActionNode> = Vec::new();
    let mut edges: Vec<Edge> = Vec::new();
    let mut roots: Vec<NodeId> = Vec::new();

    let findings_by_file = count_findings_by_file(findings);

    // Create a node per workflow file.
    let mut workflow_ids: HashMap<PathBuf, NodeId> = HashMap::new();
    for file in workflow_files {
        let id = nodes.len();
        let label = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("workflow")
            .to_string();
        let signals = TrustSignals {
            findings_here: findings_by_file.get(file).copied().unwrap_or(0),
            ..TrustSignals::default()
        };
        // Workflows start at 1.0 (no positive-signal dimensions apply to them)
        // and only carry the finding penalty. The aggregate with children then
        // determines the displayed root score.
        let finding_penalty =
            0.1 * f32::from(u16::try_from(signals.findings_here.min(10)).unwrap_or(0));
        let score = (1.0_f32 - finding_penalty).clamp(0.0, 1.0);
        nodes.push(ActionNode {
            id,
            kind: NodeKind::Workflow,
            label,
            short_sha: None,
            depth: 0,
            signals,
            score,
        });
        workflow_ids.insert(file.clone(), id);
        roots.push(id);
    }

    // Create a node per unique action ref, edge from each workflow that uses it.
    let mut ref_ids: HashMap<RefKey, NodeId> = HashMap::new();
    for r in refs {
        let key = RefKey::from(r);
        let node_id = if let Some(&existing) = ref_ids.get(&key) {
            existing
        } else {
            let id = nodes.len();
            let label = r.target();
            let short_sha = if r.ref_kind == RefKind::FullSha {
                Some(r.short_ref().to_string())
            } else {
                None
            };
            let mut signals = per_ref_signals.get(&key).copied().unwrap_or_default();
            signals.pinned_full_sha = r.ref_kind == RefKind::FullSha;
            let score = score_signals(&signals);
            nodes.push(ActionNode {
                id,
                kind: NodeKind::Action,
                label,
                short_sha,
                depth: 1,
                signals,
                score,
            });
            ref_ids.insert(key, id);
            id
        };

        if let Some(&workflow_id) = workflow_ids.get(&r.file) {
            // Avoid duplicate edges (workflow → same action listed twice).
            if !edges.iter().any(|e| e.from == workflow_id && e.to == node_id) {
                edges.push(Edge {
                    from: workflow_id,
                    to: node_id,
                });
            }
        }
    }

    // Roll up child scores into each root's aggregate.
    for &root_id in &roots {
        let child_scores: Vec<f32> = edges
            .iter()
            .filter(|e| e.from == root_id)
            .map(|e| nodes[e.to].score)
            .collect();
        let self_score = nodes[root_id].score;
        nodes[root_id].score = aggregate_score(self_score, &child_scores);
    }

    ActionGraph {
        nodes,
        edges,
        roots,
    }
}

fn count_findings_by_file(findings: &[AuditFinding]) -> HashMap<PathBuf, u32> {
    let mut map: HashMap<PathBuf, u32> = HashMap::new();
    for f in findings {
        *map.entry(f.file.clone()).or_insert(0) += 1;
    }
    map
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct RefKey {
    pub(crate) owner: String,
    pub(crate) repo: String,
    pub(crate) path: Option<String>,
    pub(crate) sha: String,
}

impl From<&ActionRef> for RefKey {
    fn from(r: &ActionRef) -> Self {
        Self {
            owner: r.owner.clone(),
            repo: r.repo.clone(),
            path: r.path.clone(),
            sha: r.ref_str.clone(),
        }
    }
}

// ─── Renderers ──────────────────────────────────────────────────────────────

pub(crate) fn render_ascii(graph: &ActionGraph) -> String {
    let mut out = String::new();
    for &root in &graph.roots {
        render_ascii_node(graph, root, "", true, &mut out);
    }
    out
}

fn render_ascii_node(
    graph: &ActionGraph,
    id: NodeId,
    prefix: &str,
    is_root: bool,
    out: &mut String,
) {
    let node = &graph.nodes[id];
    let score_str = format!("score: {:.2}", node.score);
    let label = node
        .short_sha
        .as_ref()
        .map_or_else(|| node.label.clone(), |sha| format!("{}@{sha}", node.label));
    let signals_suffix = signals_tags(&node.signals);
    if is_root {
        let _ = writeln!(out, "{label}  {score_str}{signals_suffix}");
    } else {
        let _ = writeln!(out, "{prefix}{label}  {score_str}{signals_suffix}");
    }

    let children: Vec<NodeId> = graph
        .edges
        .iter()
        .filter(|e| e.from == id)
        .map(|e| e.to)
        .collect();
    let last_idx = children.len().saturating_sub(1);
    for (i, child) in children.iter().enumerate() {
        let is_last = i == last_idx;
        let marker = if is_last { "└── " } else { "├── " };
        let child_prefix = if is_root {
            String::new()
        } else {
            let segment = if is_last { "    " } else { "│   " };
            format!("{prefix}{segment}")
        };
        let line_prefix = format!("{child_prefix}{marker}");
        render_ascii_node(graph, *child, &line_prefix, false, out);
    }
}

fn signals_tags(signals: &TrustSignals) -> String {
    let mut parts = Vec::new();
    if signals.pinned_full_sha {
        parts.push("pinned");
    }
    if matches!(signals.signed, Some(true)) {
        parts.push("signed");
    }
    if matches!(signals.slsa_verified, Some(true)) {
        parts.push("slsa");
    }
    if matches!(signals.reachable, Some(true)) {
        parts.push("reachable");
    }
    if matches!(signals.sha_exists, Some(false)) {
        parts.push("phantom-sha");
    }
    if matches!(signals.commit_age_days, Some(days) if days < 2) {
        parts.push("very-fresh");
    }
    if matches!(signals.repo_age_days, Some(days) if days < 30) {
        parts.push("recent-repo");
    }
    if signals.findings_here > 0 {
        parts.push("has-findings");
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("  [{}]", parts.join(", "))
    }
}

pub(crate) fn render_json(graph: &ActionGraph) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("{\"nodes\":[");
    for (i, n) in graph.nodes.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"id\":{},\"kind\":{},\"label\":{},\"depth\":{},\"score\":{:.4}}}",
            n.id,
            json_str(match n.kind {
                NodeKind::Workflow => "workflow",
                NodeKind::Action => "action",
            }),
            json_str(&n.label),
            n.depth,
            n.score
        );
    }
    out.push_str("],\"edges\":[");
    for (i, e) in graph.edges.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"from\":{},\"to\":{}}}", e.from, e.to);
    }
    out.push_str("],\"roots\":[");
    for (i, r) in graph.roots.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{r}");
    }
    out.push_str("]}");
    out
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Minimum score across all root nodes, used with `--min-score` to fail a
/// run if any workflow's aggregate supply-chain trust dips below a threshold.
pub(crate) fn min_root_score(graph: &ActionGraph) -> Option<f32> {
    graph
        .roots
        .iter()
        .map(|&id| graph.nodes[id].score)
        .fold(None, |acc, s| Some(acc.map_or(s, |prev| prev.min(s))))
}

// ─── Entry point for `hasp tree` ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeFormat {
    Ascii,
    Json,
}

impl TreeFormat {
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        match s {
            "ascii" | "text" => Ok(Self::Ascii),
            "json" => Ok(Self::Json),
            other => Err(format!("Invalid --format `{other}`: expected ascii or json")),
        }
    }
}

pub(crate) fn run_tree(args: &crate::cli::Args) -> crate::error::Result<()> {
    use crate::error::Context;
    let canonical_dir = args
        .dir
        .canonicalize()
        .context("Cannot resolve workflow dir")?;
    let scan = crate::scanner::scan_directory(&canonical_dir)?;

    // Load policy for consistent audit behavior (reuses diff helper).
    let policy = crate::policy::Policy::load(&canonical_dir)?.unwrap_or_default();
    let mut findings = crate::audit::run(&scan.workflow_docs, &scan.action_refs, &policy.checks);
    if !policy.checks.untrusted_sources.is_off() {
        let owners = crate::policy::Policy::effective_list(
            policy.trust.owners.as_ref(),
            crate::audit::builtin_trusted_owners(),
        );
        crate::audit::check_untrusted_sources(
            &scan.action_refs,
            &mut findings,
            policy.checks.untrusted_sources,
            &owners,
        );
    }

    let workflow_files: Vec<PathBuf> = scan
        .workflow_docs
        .iter()
        .map(|(p, _)| p.clone())
        .collect();

    // Offline variant: no per-ref online signals. The pinned_full_sha and
    // findings_here signals drive the score. Users wanting online signals can
    // chain `hasp --paranoid` -> `hasp tree` in the future.
    let per_ref_signals: HashMap<RefKey, TrustSignals> = HashMap::new();

    let graph = build(&workflow_files, &scan.action_refs, &findings, &per_ref_signals);

    let format = args.tree_format.unwrap_or(TreeFormat::Ascii);
    match format {
        TreeFormat::Ascii => println!("{}", render_ascii(&graph)),
        TreeFormat::Json => println!("{}", render_json(&graph)),
    }

    if let Some(min) = args.tree_min_score
        && let Some(actual) = min_root_score(&graph)
        && actual < min
    {
        eprintln!(
            "hasp tree: lowest root score {actual:.2} is below --min-score {min:.2}"
        );
        std::process::exit(1);
    }

    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use crate::scanner::{ActionRef, RefKind};
    use std::path::PathBuf;

    fn r(owner: &str, repo: &str, sha: &str, file: &str, kind: RefKind) -> ActionRef {
        ActionRef {
            file: PathBuf::from(file),
            owner: owner.to_string(),
            repo: repo.to_string(),
            path: None,
            ref_str: sha.to_string(),
            ref_kind: kind,
            comment_version: None,
        }
    }

    #[test]
    fn pinned_full_sha_with_clean_signals_scores_high() {
        let signals = TrustSignals {
            pinned_full_sha: true,
            findings_here: 0,
            sha_exists: Some(true),
            reachable: Some(true),
            signed: Some(true),
            slsa_verified: Some(true),
            commit_age_days: Some(180),
            repo_age_days: Some(720),
            repo_stars: Some(2000),
        };
        assert!(score_signals(&signals) >= 0.9);
    }

    #[test]
    fn mutable_ref_scores_low() {
        let signals = TrustSignals {
            pinned_full_sha: false,
            ..TrustSignals::default()
        };
        assert_eq!(score_signals(&signals), 0.0);
    }

    #[test]
    fn phantom_sha_penalizes_heavily() {
        let signals = TrustSignals {
            pinned_full_sha: true,
            sha_exists: Some(false),
            ..TrustSignals::default()
        };
        assert!(score_signals(&signals) <= 0.05);
    }

    #[test]
    fn fresh_commit_in_recent_repo_scores_below_half() {
        let signals = TrustSignals {
            pinned_full_sha: true,
            sha_exists: Some(true),
            reachable: Some(true),
            repo_age_days: Some(10),
            commit_age_days: Some(1),
            ..TrustSignals::default()
        };
        assert!(score_signals(&signals) < 0.5);
    }

    #[test]
    fn aggregate_score_takes_min_of_self_or_child_mean() {
        assert_eq!(aggregate_score(1.0, &[0.5, 0.5]), 0.5);
        assert_eq!(aggregate_score(0.2, &[0.9, 0.9]), 0.2);
        assert!((aggregate_score(0.8, &[]) - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn build_graph_creates_one_node_per_workflow_and_per_ref() {
        let workflows = vec![
            PathBuf::from("/repo/.github/workflows/ci.yml"),
            PathBuf::from("/repo/.github/workflows/release.yml"),
        ];
        let refs = vec![
            r("actions", "checkout", "aaaa", "/repo/.github/workflows/ci.yml", RefKind::FullSha),
            r("actions", "checkout", "aaaa", "/repo/.github/workflows/release.yml", RefKind::FullSha),
            r("actions", "setup-node", "bbbb", "/repo/.github/workflows/ci.yml", RefKind::FullSha),
        ];
        let graph = build(&workflows, &refs, &[], &HashMap::new());
        assert_eq!(graph.roots.len(), 2);
        // 2 workflows + 2 unique actions = 4 nodes
        assert_eq!(graph.nodes.len(), 4);
        // ci.yml -> checkout, ci.yml -> setup-node, release.yml -> checkout
        assert_eq!(graph.edges.len(), 3);
    }

    #[test]
    fn render_ascii_includes_score_and_signal_tags() {
        let wf = PathBuf::from("/repo/.github/workflows/ci.yml");
        let refs = vec![r(
            "actions",
            "checkout",
            "aaaa",
            "/repo/.github/workflows/ci.yml",
            RefKind::FullSha,
        )];
        let graph = build(&[wf], &refs, &[], &HashMap::new());
        let out = render_ascii(&graph);
        assert!(out.contains("ci.yml"));
        assert!(out.contains("actions/checkout"));
        assert!(out.contains("score:"));
        assert!(out.contains("[pinned]"));
    }

    #[test]
    fn render_json_is_machine_parseable() {
        let wf = PathBuf::from("/repo/.github/workflows/ci.yml");
        let refs = vec![r(
            "actions",
            "checkout",
            "aaaa",
            "/repo/.github/workflows/ci.yml",
            RefKind::FullSha,
        )];
        let graph = build(&[wf], &refs, &[], &HashMap::new());
        let json = render_json(&graph);
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"nodes\""));
        assert!(json.contains("\"edges\""));
        assert!(json.contains("\"roots\""));
    }

    #[test]
    fn min_root_score_returns_the_minimum() {
        let wf1 = PathBuf::from("a.yml");
        let wf2 = PathBuf::from("b.yml");
        let refs = vec![
            r("actions", "checkout", "aaaa", "a.yml", RefKind::FullSha),
            r("random", "stuff", "mutable", "b.yml", RefKind::Mutable),
        ];
        let graph = build(&[wf1, wf2], &refs, &[], &HashMap::new());
        let minimum = min_root_score(&graph).unwrap();
        // b.yml's child is mutable -> child score 0.0 -> root score 0.0
        assert!((minimum - 0.0).abs() < f32::EPSILON);
    }
}
