//! OIDC trust-policy audit.
//!
//! Given a set of `OidcAcceptance` records (parsed from AWS/GCP/Azure trust
//! policies) and the set of workflows in the repository, flag cases where the
//! trust policy accepts patterns broader than any workflow actually produces.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use yaml_rust2::Yaml;

use crate::oidc::{GlobToken, OidcAcceptance, SubKind, SubPattern};

use super::{AuditFinding, Severity, key_jobs, key_on, key_permissions, key_steps, key_uses};

/// Per-workflow facts relevant to OIDC audit.
#[allow(clippy::struct_excessive_bools)] // trigger/permission flags are inherently boolean
#[derive(Debug, Clone, Default)]
struct OidcWorkflowFacts {
    file: PathBuf,
    uses_oidc: bool,
    /// True when the workflow consumes its `id-token` solely for Sigstore-
    /// based signing / SLSA provenance (Fulcio identity), rather than for
    /// AWS/GCP/Azure cloud federation. The "configure a trust policy"
    /// advisory must not fire on such workflows — Sigstore has no
    /// cloud-side trust policy to audit, and flagging it would be a false
    /// positive for the common signing pattern.
    uses_sigstore: bool,
    /// Triggered by `pull_request` OR `pull_request_target`.
    pr_triggered: bool,
    /// Triggered specifically by `pull_request_target` — the most dangerous
    /// GitHub trigger because it runs in the context of the base repository
    /// with access to secrets, while checking out attacker-controlled code by
    /// default. Tracked separately so we can fire an independent finding
    /// regardless of trust-policy contents.
    pr_target_triggered: bool,
    /// Branches/tags the workflow can run on (from `on.push.branches`,
    /// `on.pull_request.branches`, etc.). Empty = no branch filter (any branch).
    branches: HashSet<String>,
    /// `environment:` declarations (from any job).
    environments: HashSet<String>,
}

/// Action `uses:` references that consume `id-token` for Sigstore Fulcio
/// signing or SLSA provenance attestation. Match is against the bare
/// `owner/repo` (or `owner/repo/path`) — version pin stripped before lookup.
const SIGSTORE_ACTIONS: &[&str] = &[
    "sigstore/cosign-installer",
    "sigstore/gh-action-sigstore-python",
    "sigstore/sigstore-python",
    "actions/attest",
    "actions/attest-build-provenance",
    "actions/attest-sbom",
];

fn is_sigstore_uses(uses: &str) -> bool {
    // `owner/repo@ref` → `owner/repo`; also handles `owner/repo/path@ref`.
    let bare = uses.split_once('@').map_or(uses, |(b, _)| b);
    SIGSTORE_ACTIONS.contains(&bare)
}

fn extract_facts(file: &Path, doc: &Yaml) -> OidcWorkflowFacts {
    let mut facts = OidcWorkflowFacts {
        file: file.to_path_buf(),
        ..OidcWorkflowFacts::default()
    };
    let Some(map) = doc.as_hash() else {
        return facts;
    };

    // id-token: write at top-level
    if permissions_grant_id_token(map.get(key_permissions())) {
        facts.uses_oidc = true;
    }

    // Triggers + branch filters
    if let Some(on) = map.get(key_on()) {
        extract_triggers(on, &mut facts);
    }

    // Per-job: permissions + environment
    if let Some(Yaml::Hash(jobs)) = map.get(key_jobs()) {
        for (_name, job) in jobs {
            let Some(job_map) = job.as_hash() else {
                continue;
            };
            if permissions_grant_id_token(job_map.get(key_permissions())) {
                facts.uses_oidc = true;
            }
            if let Some(env) = job_map.get(&Yaml::String("environment".to_string())) {
                collect_environments(env, &mut facts.environments);
            }
            if let Some(Yaml::Array(steps)) = job_map.get(key_steps()) {
                for step in steps {
                    let Some(step_map) = step.as_hash() else {
                        continue;
                    };
                    if let Some(env) = step_map.get(&Yaml::String("environment".to_string())) {
                        collect_environments(env, &mut facts.environments);
                    }
                    if let Some(uses) = step_map.get(key_uses()).and_then(Yaml::as_str)
                        && is_sigstore_uses(uses)
                    {
                        facts.uses_sigstore = true;
                    }
                }
            }
        }
    }

    facts
}

fn permissions_grant_id_token(value: Option<&Yaml>) -> bool {
    let Some(value) = value else {
        return false;
    };
    if value.as_str() == Some("write-all") {
        return true;
    }
    let Some(map) = value.as_hash() else {
        return false;
    };
    map.get(&Yaml::String("id-token".to_string()))
        .and_then(Yaml::as_str)
        == Some("write")
}

fn extract_triggers(on: &Yaml, facts: &mut OidcWorkflowFacts) {
    #[allow(clippy::wildcard_enum_match_arm)] // Yaml has many non-string/array/hash variants
    match on {
        Yaml::String(s) => classify_trigger(s, facts),
        Yaml::Array(arr) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    classify_trigger(s, facts);
                }
            }
        }
        Yaml::Hash(map) => {
            for (k, v) in map {
                let Some(name) = k.as_str() else { continue };
                classify_trigger(name, facts);
                if let Some(filter_map) = v.as_hash() {
                    collect_branch_filter(filter_map, &mut facts.branches);
                }
            }
        }
        _ => {}
    }
}

fn classify_trigger(name: &str, facts: &mut OidcWorkflowFacts) {
    match name {
        "pull_request" => facts.pr_triggered = true,
        "pull_request_target" => {
            facts.pr_triggered = true;
            facts.pr_target_triggered = true;
        }
        _ => {}
    }
}

fn collect_branch_filter(map: &yaml_rust2::yaml::Hash, out: &mut HashSet<String>) {
    for key in ["branches", "branches-ignore", "tags", "tags-ignore"] {
        if let Some(list) = map
            .get(&Yaml::String(key.to_string()))
            .and_then(Yaml::as_vec)
        {
            for v in list {
                if let Some(s) = v.as_str() {
                    out.insert(s.to_string());
                }
            }
        }
    }
}

fn collect_environments(value: &Yaml, out: &mut HashSet<String>) {
    if let Some(s) = value.as_str() {
        out.insert(s.to_string());
        return;
    }
    if let Some(map) = value.as_hash()
        && let Some(name) = map
            .get(&Yaml::String("name".to_string()))
            .and_then(Yaml::as_str)
    {
        out.insert(name.to_string());
    }
}

// ─── Checks ─────────────────────────────────────────────────────────────────

/// Check: trust policy has no `aud` pin.
fn check_missing_audience(
    acceptances: &[OidcAcceptance],
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    for acc in acceptances {
        // A wildcard `aud` (e.g. `StringLike` with `"*"` or `"sts.*"`) is
        // functionally identical to having no `aud` pin at all — anyone can
        // mint a token whose audience matches — so treat it the same as absent.
        let wildcard_aud = acc.audiences.iter().any(|a| a.contains('*'));
        if acc.audiences.is_empty() || wildcard_aud {
            findings.push(AuditFinding {
                file: acc.file.clone(),
                severity: Severity::Medium,
                title: format!("OIDC trust policy ({}) accepts any audience", acc.provider),
                detail: format!(
                    "The trust policy at {} ({}) does not meaningfully constrain the \
                     `aud` claim of GitHub OIDC tokens ({}). Any GitHub Actions workflow \
                     that declares `id-token: write` can mint a matching token. Pin \
                     `aud` to an exact provider-specific audience string.",
                    acc.file.display(),
                    acc.location,
                    if wildcard_aud {
                        "the pinned value is a wildcard"
                    } else {
                        "no `aud` pin"
                    },
                ),
                is_warning,
            });
        }
    }
}

/// Check: trust policy sub pattern accepts broader identities than any
/// workflow actually produces (over-broad repo pattern, unused env, etc.).
fn check_pattern_breadth(
    acceptances: &[OidcAcceptance],
    facts: &[OidcWorkflowFacts],
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    // Only workflows that actually mint OIDC tokens are relevant.
    let oidc_workflows: Vec<&OidcWorkflowFacts> = facts.iter().filter(|f| f.uses_oidc).collect();

    for acc in acceptances {
        for sp in &acc.sub_patterns {
            if sub_is_universal(sp) {
                findings.push(AuditFinding {
                    file: acc.file.clone(),
                    severity: Severity::High,
                    title: format!(
                        "OIDC trust policy ({}) accepts any GitHub repository",
                        acc.provider
                    ),
                    detail: format!(
                        "The trust policy at {} ({}) accepts GitHub OIDC tokens \
                         with an unbounded `sub` claim ({}). This grants access \
                         to any workflow in any repository hosted on GitHub. Pin \
                         `sub` to `repo:your-org/your-repo:...`.",
                        acc.file.display(),
                        acc.location,
                        sp.raw,
                    ),
                    is_warning,
                });
                continue;
            }

            // Repo wildcard (`repo:org/*:*` or `repo:*:*`)
            if sp.repo.contains_wildcard() {
                findings.push(AuditFinding {
                    file: acc.file.clone(),
                    severity: Severity::High,
                    title: format!(
                        "OIDC trust policy ({}) accepts a wildcard repository",
                        acc.provider
                    ),
                    detail: format!(
                        "The trust policy at {} ({}) accepts OIDC tokens from \
                         `{}` — a wildcard repository pattern. Any workflow under \
                         this owner/pattern can assume the federated identity. \
                         Pin to a specific `owner/repo`.",
                        acc.file.display(),
                        acc.location,
                        sp.repo.raw,
                    ),
                    is_warning,
                });
            }

            // Environment wildcard when no workflow uses `environment:` declarations.
            if sp.kind == SubKind::Environment
                && sp.value.as_ref().is_some_and(GlobToken::contains_wildcard)
                && oidc_workflows.iter().all(|f| f.environments.is_empty())
            {
                findings.push(AuditFinding {
                    file: acc.file.clone(),
                    severity: Severity::Medium,
                    title: format!(
                        "OIDC trust policy ({}) accepts any environment, but no workflow declares one",
                        acc.provider
                    ),
                    detail: format!(
                        "The trust policy at {} ({}) accepts `environment:*` in the sub \
                         claim, but no OIDC-minting workflow in this repository uses \
                         an `environment:` declaration. The wildcard expands the exploit \
                         surface without a corresponding control. Remove the environment \
                         component or pin to a specific environment name.",
                        acc.file.display(),
                        acc.location,
                    ),
                    is_warning,
                });
            }

            // Ref wildcard + no PR-triggered OIDC workflow AND we have at least one OIDC workflow
            // that runs only on a specific branch like main.
            if sp.kind == SubKind::Ref
                && sp.value.as_ref().is_some_and(GlobToken::contains_wildcard)
                && !oidc_workflows.is_empty()
                && oidc_workflows
                    .iter()
                    .all(|f| !f.pr_triggered && !f.branches.is_empty())
            {
                findings.push(AuditFinding {
                    file: acc.file.clone(),
                    severity: Severity::High,
                    title: format!(
                        "OIDC trust policy ({}) accepts any ref, but workflows run on specific branches",
                        acc.provider
                    ),
                    detail: format!(
                        "The trust policy at {} ({}) accepts `ref:*`, but every OIDC-minting \
                         workflow in this repository declares explicit branch filters and \
                         none are PR-triggered. Pin `ref` to the same branches those \
                         workflows run on (e.g. `ref:refs/heads/main`).",
                        acc.file.display(),
                        acc.location,
                    ),
                    is_warning,
                });
            }
        }
    }
}

/// Check: trust policy accepts PR refs (`refs/pull/*`).
///
/// We emit one of two related findings:
///
/// * If NO PR-triggered workflow declares `id-token: write`, this is a dead
///   entry at best, latent exploit path at worst — flag it.
/// * If a PR-triggered workflow ALSO declares `id-token: write`, the situation
///   is materially worse: a PR event can mint a federated identity. Flag it
///   with a louder title. This is the case where the finding matters most,
///   and previous versions short-circuited it away.
fn check_pr_ref_accepted(
    acceptances: &[OidcAcceptance],
    facts: &[OidcWorkflowFacts],
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    let pr_oidc_exists = facts.iter().any(|f| f.uses_oidc && f.pr_triggered);

    for acc in acceptances {
        for sp in &acc.sub_patterns {
            let accepts_pr_ref = sp.kind == SubKind::PullRequest
                || (sp.kind == SubKind::Ref
                    && sp
                        .value
                        .as_ref()
                        .is_some_and(|g| g.raw.contains("refs/pull")));
            if accepts_pr_ref {
                emit_pr_ref_finding(acc, sp, findings, is_warning, pr_oidc_exists);
            }
        }
    }
}

fn emit_pr_ref_finding(
    acc: &OidcAcceptance,
    sp: &SubPattern,
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
    pr_oidc_exists: bool,
) {
    let (title, detail) = if pr_oidc_exists {
        (
            format!(
                "OIDC trust policy ({}) accepts PR refs and a PR workflow mints OIDC tokens",
                acc.provider
            ),
            format!(
                "The trust policy at {} ({}) accepts `{}` — a pull-request ref — \
                 AND a pull-request-triggered workflow in this repository declares \
                 `id-token: write`. This combination lets a pull request assume the \
                 federated identity, including PRs from forks. Remove the PR ref \
                 from the accepted `sub` patterns or restrict the PR workflow's \
                 `id-token` permission.",
                acc.file.display(),
                acc.location,
                sp.raw,
            ),
        )
    } else {
        (
            format!(
                "OIDC trust policy ({}) accepts PR refs, but no PR workflow mints OIDC tokens",
                acc.provider
            ),
            format!(
                "The trust policy at {} ({}) accepts `{}` — a pull-request ref — \
                 but no PR-triggered workflow in this repository declares \
                 `id-token: write`. Either this is a dead entry (remove it) or an \
                 attacker-reachable exploit path waiting to be enabled (most \
                 projects don't want PR events to assume federated identities). \
                 Remove the PR ref from the accepted `sub` patterns.",
                acc.file.display(),
                acc.location,
                sp.raw,
            ),
        )
    };
    findings.push(AuditFinding {
        file: acc.file.clone(),
        severity: Severity::High,
        title,
        detail,
        is_warning,
    });
}

/// Check: any workflow with `pull_request_target` AND `id-token: write`.
///
/// This is independent of trust-policy contents — even with a perfectly safe
/// trust policy, the combo is itself a strong red flag because
/// `pull_request_target` runs in the base repo's context (with secrets) while
/// the PR head is attacker-controlled by default.
fn check_pull_request_target_with_oidc(
    facts: &[OidcWorkflowFacts],
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    for f in facts {
        if f.pr_target_triggered && f.uses_oidc {
            findings.push(AuditFinding {
                file: f.file.clone(),
                severity: Severity::High,
                title: "pull_request_target with id-token: write".to_string(),
                detail: format!(
                    "Workflow {} is triggered by `pull_request_target` AND grants \
                     `id-token: write`. `pull_request_target` runs with the base \
                     repository's secrets and tokens while the PR head ref is \
                     attacker-controlled, so any code path that checks out or \
                     evaluates the head ref can be made to mint a federated OIDC \
                     token. Either drop `pull_request_target`, drop `id-token: \
                     write`, or guard token issuance behind an explicit \
                     `if:` that excludes fork PRs.",
                    f.file.display(),
                ),
                is_warning,
            });
        }
    }
}

/// Informational: a workflow declares `id-token: write` but no trust policy is
/// configured. We can't audit acceptance breadth without one, so the user
/// should point hasp at the relevant policy files.
///
/// Workflows whose only `id-token: write` consumer is a Sigstore action
/// (Fulcio signing, SLSA attestation) are excluded — there is no
/// cloud-side trust policy to audit for that case, and flagging it would
/// be a false positive against the standard release-signing pattern.
fn check_oidc_without_trust_policy(
    facts: &[OidcWorkflowFacts],
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    let Some(culprit) = facts.iter().find(|f| f.uses_oidc && !f.uses_sigstore) else {
        return;
    };
    findings.push(AuditFinding {
        file: culprit.file.clone(),
        severity: Severity::Medium,
        title: "OIDC trust policy not configured".to_string(),
        detail: "At least one workflow declares `id-token: write` (and does not \
                 appear to use it solely for Sigstore signing or SLSA attestation) \
                 but no OIDC trust policy is configured for hasp to audit. Without \
                 a trust policy hasp cannot detect over-broad acceptance patterns \
                 on the cloud side. Pass `--oidc-policy <provider>:<path>` or add \
                 an `oidc:` section to `.hasp.yml` referencing the AWS/GCP/Azure \
                 trust policy file(s) you deploy to."
            .to_string(),
        is_warning,
    });
}

fn sub_is_universal(sp: &SubPattern) -> bool {
    sp.repo.is_wildcard()
        && (sp.kind == SubKind::Any || sp.value.as_ref().is_some_and(GlobToken::is_wildcard))
}

// ─── Entry point ────────────────────────────────────────────────────────────

pub(crate) fn run(
    docs: &[(PathBuf, Yaml)],
    acceptances: &[OidcAcceptance],
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    if level.is_off() {
        return;
    }
    let is_warning = level.is_warn();
    let facts: Vec<OidcWorkflowFacts> = docs.iter().map(|(p, d)| extract_facts(p, d)).collect();

    // Fires regardless of whether a trust policy was supplied — the
    // pull_request_target + id-token: write combo is itself dangerous.
    check_pull_request_target_with_oidc(&facts, findings, is_warning);

    if acceptances.is_empty() {
        // Without a trust policy we can't audit cloud-side acceptance breadth.
        // Surface that gap as a single informational finding.
        check_oidc_without_trust_policy(&facts, findings, is_warning);
        return;
    }

    check_missing_audience(acceptances, findings, is_warning);
    check_pattern_breadth(acceptances, &facts, findings, is_warning);
    check_pr_ref_accepted(acceptances, &facts, findings, is_warning);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::needless_raw_strings)]
mod tests {
    use super::*;
    use crate::oidc::{OidcProvider, load_trust_policy};
    use std::io::Write;
    use yaml_rust2::YamlLoader;

    fn workflow(name: &str, src: &str) -> (PathBuf, Yaml) {
        let doc = YamlLoader::load_from_str(src).unwrap().remove(0);
        (PathBuf::from(name), doc)
    }

    fn write_tmp(src: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "hasp-oidc-{}-{}.json",
            std::process::id(),
            C.fetch_add(1, Ordering::Relaxed)
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(src.as_bytes()).unwrap();
        path
    }

    #[test]
    fn missing_audience_flags_medium() {
        let path = write_tmp(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" },
                "Condition": { "StringLike": { "token.actions.githubusercontent.com:sub": "repo:a/b:*" } }
              }]
            }"#,
        );
        let acc = load_trust_policy(OidcProvider::Aws, &path).unwrap();
        let mut findings = Vec::new();
        run(&[], &acc, &mut findings, crate::policy::CheckLevel::Deny);
        assert!(findings.iter().any(|f| f.title.contains("any audience")));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wildcard_repo_flagged_as_high() {
        let path = write_tmp(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" },
                "Condition": {
                  "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
                  "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:my-org/*:*" }
                }
              }]
            }"#,
        );
        let acc = load_trust_policy(OidcProvider::Aws, &path).unwrap();
        let mut findings = Vec::new();
        run(&[], &acc, &mut findings, crate::policy::CheckLevel::Deny);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("wildcard repository"))
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pr_ref_accepted_without_pr_oidc_workflow() {
        let path = write_tmp(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" },
                "Condition": {
                  "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
                  "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:a/b:ref:refs/pull/*" }
                }
              }]
            }"#,
        );
        let acc = load_trust_policy(OidcProvider::Aws, &path).unwrap();
        let docs = vec![workflow(
            "push.yml",
            r"
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
",
        )];
        let mut findings = Vec::new();
        run(&docs, &acc, &mut findings, crate::policy::CheckLevel::Deny);
        assert!(findings.iter().any(|f| f.title.contains("accepts PR refs")));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn universal_sub_flagged() {
        let path = write_tmp(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" },
                "Condition": {
                  "StringEquals": { "token.actions.githubusercontent.com:aud": "sts" },
                  "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:*:*" }
                }
              }]
            }"#,
        );
        let acc = load_trust_policy(OidcProvider::Aws, &path).unwrap();
        let mut findings = Vec::new();
        run(&[], &acc, &mut findings, crate::policy::CheckLevel::Deny);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("any GitHub repository"))
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn safe_policy_no_findings() {
        let path = write_tmp(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" },
                "Condition": {
                  "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
                  "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main" }
                }
              }]
            }"#,
        );
        let acc = load_trust_policy(OidcProvider::Aws, &path).unwrap();
        let mut findings = Vec::new();
        run(&[], &acc, &mut findings, crate::policy::CheckLevel::Deny);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pull_request_target_with_id_token_fires_independent_finding() {
        // Trust policy is perfectly safe; the workflow combo alone is the
        // issue.
        let path = write_tmp(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" },
                "Condition": {
                  "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
                  "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main" }
                }
              }]
            }"#,
        );
        let acc = load_trust_policy(OidcProvider::Aws, &path).unwrap();
        let docs = vec![workflow(
            "pr.yml",
            r"
on:
  pull_request_target:
permissions:
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
        )];
        let mut findings = Vec::new();
        run(&docs, &acc, &mut findings, crate::policy::CheckLevel::Deny);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("pull_request_target")),
            "expected pull_request_target finding, got: {findings:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pull_request_target_job_level_id_token_also_fires() {
        let docs = vec![workflow(
            "pr.yml",
            r"
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: echo hi
",
        )];
        let mut findings = Vec::new();
        run(&docs, &[], &mut findings, crate::policy::CheckLevel::Deny);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("pull_request_target")),
            "expected pull_request_target finding, got: {findings:?}"
        );
    }

    #[test]
    fn plain_pull_request_does_not_fire_pr_target_finding() {
        // `pull_request` is much less dangerous than `pull_request_target`;
        // make sure we don't conflate them.
        let docs = vec![workflow(
            "pr.yml",
            r"
on:
  pull_request:
permissions:
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
        )];
        let mut findings = Vec::new();
        run(&docs, &[], &mut findings, crate::policy::CheckLevel::Deny);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("pull_request_target")),
            "pull_request must NOT trigger the pull_request_target finding: {findings:?}"
        );
    }

    #[test]
    fn pr_ref_accepted_with_pr_oidc_workflow_still_fires() {
        // Previously this case was short-circuited away. Reinstating it is
        // the whole point of this fix — it's the highest-risk combination.
        let path = write_tmp(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" },
                "Condition": {
                  "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
                  "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:a/b:ref:refs/pull/*" }
                }
              }]
            }"#,
        );
        let acc = load_trust_policy(OidcProvider::Aws, &path).unwrap();
        let docs = vec![workflow(
            "pr.yml",
            r"
on:
  pull_request:
permissions:
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
        )];
        let mut findings = Vec::new();
        run(&docs, &acc, &mut findings, crate::policy::CheckLevel::Deny);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("accepts PR refs")
                    && f.title.contains("PR workflow mints")),
            "expected combined PR-refs + PR OIDC finding, got: {findings:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn oidc_without_trust_policy_emits_medium_advisory() {
        let docs = vec![workflow(
            "deploy.yml",
            r"
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
        )];
        let mut findings = Vec::new();
        run(&docs, &[], &mut findings, crate::policy::CheckLevel::Deny);
        let advisories: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("trust policy not configured"))
            .collect();
        assert_eq!(
            advisories.len(),
            1,
            "expected exactly one advisory, got: {findings:?}"
        );
        assert_eq!(advisories[0].severity, Severity::Medium);
    }

    #[test]
    fn no_oidc_workflow_means_no_advisory() {
        let docs = vec![workflow(
            "build.yml",
            r"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
",
        )];
        let mut findings = Vec::new();
        run(&docs, &[], &mut findings, crate::policy::CheckLevel::Deny);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn off_level_emits_nothing() {
        let path = write_tmp(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" },
                "Condition": { "StringLike": { "token.actions.githubusercontent.com:sub": "repo:*:*" } }
              }]
            }"#,
        );
        let acc = load_trust_policy(OidcProvider::Aws, &path).unwrap();
        let mut findings = Vec::new();
        run(&[], &acc, &mut findings, crate::policy::CheckLevel::Off);
        assert!(findings.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
