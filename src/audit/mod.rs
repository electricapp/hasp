mod injection;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

pub(super) fn find_expressions(s: &str) -> Vec<&str> {
    let mut exprs = Vec::new();
    let mut start = 0;
    while let Some(begin) = s[start..].find("${{") {
        let abs = start + begin + 3;
        if let Some(end) = s[abs..].find("}}") {
            exprs.push(&s[abs..abs + end]);
            start = abs + end + 2;
        } else {
            break;
        }
    }
    exprs
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
    // Sort by severity: Critical < High < Medium (ascending order)
    // Severity derives Ord based on declaration order: Critical=0, High=1, Medium=2
    findings.sort_by(|a, b| a.severity.cmp(&b.severity));
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
