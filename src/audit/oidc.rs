//! OIDC trust-policy audit.
//!
//! Given a set of `OidcAcceptance` records (parsed from AWS/GCP/Azure trust
//! policies) and the set of workflows in the repository, flag cases where the
//! trust policy accepts patterns broader than any workflow actually produces.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use yaml_rust2::Yaml;

use crate::oidc::{GlobToken, OidcAcceptance, SubKind, SubPattern};

use super::{AuditFinding, Severity, key_jobs, key_on, key_permissions, key_steps};

/// Per-workflow facts relevant to OIDC audit.
#[derive(Debug, Clone, Default)]
struct OidcWorkflowFacts {
    uses_oidc: bool,
    pr_triggered: bool,
    #[allow(dead_code)]
    workflow_dispatch: bool,
    /// Branches/tags the workflow can run on (from `on.push.branches`,
    /// `on.pull_request.branches`, etc.). Empty = no branch filter (any branch).
    branches: HashSet<String>,
    /// `environment:` declarations (from any job).
    environments: HashSet<String>,
}

fn extract_facts(_file: &Path, doc: &Yaml) -> OidcWorkflowFacts {
    let mut facts = OidcWorkflowFacts::default();
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
                    if let Some(step_map) = step.as_hash()
                        && let Some(env) =
                            step_map.get(&Yaml::String("environment".to_string()))
                    {
                        collect_environments(env, &mut facts.environments);
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
        "pull_request" | "pull_request_target" => facts.pr_triggered = true,
        "workflow_dispatch" => facts.workflow_dispatch = true,
        _ => {}
    }
}

fn collect_branch_filter(map: &yaml_rust2::yaml::Hash, out: &mut HashSet<String>) {
    for key in ["branches", "branches-ignore", "tags", "tags-ignore"] {
        if let Some(list) = map.get(&Yaml::String(key.to_string())).and_then(Yaml::as_vec) {
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
        && let Some(name) = map.get(&Yaml::String("name".to_string())).and_then(Yaml::as_str)
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
        if acc.audiences.is_empty() {
            findings.push(AuditFinding {
                file: acc.file.clone(),
                severity: Severity::Medium,
                title: format!(
                    "OIDC trust policy ({}) accepts any audience",
                    acc.provider
                ),
                detail: format!(
                    "The trust policy at {} ({}) does not constrain the `aud` \
                     claim of GitHub OIDC tokens. Any GitHub Actions workflow that \
                     declares `id-token: write` can mint a matching token. Pin \
                     `aud` to a provider-specific audience string.",
                    acc.file.display(),
                    acc.location,
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
    let oidc_workflows: Vec<&OidcWorkflowFacts> =
        facts.iter().filter(|f| f.uses_oidc).collect();

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

/// Check: trust policy accepts PR refs (`refs/pull/*`) but no PR-triggered
/// workflow declares `id-token: write` — dead entry at best, latent exploit
/// path at worst.
fn check_pr_ref_accepted(
    acceptances: &[OidcAcceptance],
    facts: &[OidcWorkflowFacts],
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    let pr_oidc_exists = facts.iter().any(|f| f.uses_oidc && f.pr_triggered);
    if pr_oidc_exists {
        // PR workflow with id-token: write deserves its own investigation, but
        // it's not a "dead entry" situation here.
        return;
    }

    for acc in acceptances {
        for sp in &acc.sub_patterns {
            if sp.kind == SubKind::PullRequest {
                emit_pr_ref_finding(acc, sp, findings, is_warning);
                continue;
            }
            if sp.kind == SubKind::Ref
                && sp
                    .value
                    .as_ref()
                    .is_some_and(|g| g.raw.contains("refs/pull"))
            {
                emit_pr_ref_finding(acc, sp, findings, is_warning);
            }
        }
    }
}

fn emit_pr_ref_finding(
    acc: &OidcAcceptance,
    sp: &SubPattern,
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    findings.push(AuditFinding {
        file: acc.file.clone(),
        severity: Severity::High,
        title: format!(
            "OIDC trust policy ({}) accepts PR refs, but no PR workflow mints OIDC tokens",
            acc.provider
        ),
        detail: format!(
            "The trust policy at {} ({}) accepts `{}` — a pull-request ref — but no \
             PR-triggered workflow in this repository declares `id-token: write`. \
             Either this is a dead entry (remove it) or an attacker-reachable \
             exploit path waiting to be enabled (most projects don't want PR \
             events to assume federated identities). Remove the PR ref from the \
             accepted `sub` patterns.",
            acc.file.display(),
            acc.location,
            sp.raw,
        ),
        is_warning,
    });
}

fn sub_is_universal(sp: &SubPattern) -> bool {
    sp.repo.is_wildcard()
        && (sp.kind == SubKind::Any
            || sp
                .value
                .as_ref()
                .is_some_and(GlobToken::is_wildcard))
}

// ─── Entry point ────────────────────────────────────────────────────────────

pub(crate) fn run(
    docs: &[(PathBuf, Yaml)],
    acceptances: &[OidcAcceptance],
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    if level.is_off() || acceptances.is_empty() {
        return;
    }
    let is_warning = level.is_warn();
    let facts: Vec<OidcWorkflowFacts> = docs
        .iter()
        .map(|(p, d)| extract_facts(p, d))
        .collect();

    check_missing_audience(acceptances, findings, is_warning);
    check_pattern_breadth(acceptances, &facts, findings, is_warning);
    check_pr_ref_accepted(acceptances, &facts, findings, is_warning);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::needless_raw_strings)]
mod tests {
    use super::*;
    use crate::oidc::{load_trust_policy, OidcProvider};
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
        assert!(findings.iter().any(|f| f.title.contains("wildcard repository")));
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
        assert!(findings.iter().any(|f| f.title.contains("any GitHub repository")));
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
