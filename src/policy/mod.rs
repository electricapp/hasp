mod parse;
use parse::{
    parse_action_override, parse_check_config, parse_duration, parse_suppression,
    parse_trust_config,
};

use crate::error::{Context, Result, bail};
use std::path::{Path, PathBuf};
use yaml_rust2::{Yaml, YamlLoader};

/// All recognized check names in the policy schema.
pub(super) const KNOWN_CHECK_NAMES: &[&str] = &[
    "expression-injection",
    "permissions",
    "secret-exposure",
    "privileged-triggers",
    "github-env-writes",
    "secrets-inherit",
    "contains-bypass",
    "persist-credentials",
    "typosquatting",
    "untrusted-sources",
    "reachability",
    "signatures",
    "fresh-commit",
    "tag-age-gap",
    "repo-reputation",
    "recent-repo",
    "transitive",
    "hidden-execution",
];

// ─── Check level ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckLevel {
    Deny,
    Warn,
    Off,
}

impl CheckLevel {
    pub(super) fn parse(s: &str) -> Result<Self> {
        match s {
            "deny" => Ok(Self::Deny),
            "warn" => Ok(Self::Warn),
            "off" => Ok(Self::Off),
            other => bail!("Invalid check level `{other}`: expected deny, warn, or off"),
        }
    }

    /// Most-restrictive-wins merge.
    #[allow(dead_code)] // used in tests
    pub(crate) const fn merge_restrictive(self, other: Self) -> Self {
        match (self, other) {
            (Self::Deny, _) | (_, Self::Deny) => Self::Deny,
            (Self::Warn, _) | (_, Self::Warn) => Self::Warn,
            (Self::Off, Self::Off) => Self::Off,
        }
    }

    pub(crate) const fn is_off(self) -> bool {
        matches!(self, Self::Off)
    }

    pub(crate) const fn is_warn(self) -> bool {
        matches!(self, Self::Warn)
    }
}

// ─── Pin policy ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinPolicy {
    Deny,
    Warn,
    Off,
}

impl PinPolicy {
    pub(super) fn parse(s: &str) -> Result<Self> {
        match s {
            "deny" => Ok(Self::Deny),
            "warn" => Ok(Self::Warn),
            "off" => Ok(Self::Off),
            other => bail!("Invalid pin policy `{other}`: expected deny, warn, or off"),
        }
    }
}

// ─── Check configuration ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct ProvenanceCheckConfig {
    pub(crate) reachability: CheckLevel,
    pub(crate) signatures: CheckLevel,
    pub(crate) fresh_commit: CheckLevel,
    pub(crate) tag_age_gap: CheckLevel,
    pub(crate) repo_reputation: CheckLevel,
    pub(crate) recent_repo: CheckLevel,
    pub(crate) transitive: CheckLevel,
    pub(crate) hidden_execution: CheckLevel,
}

impl Default for ProvenanceCheckConfig {
    fn default() -> Self {
        Self {
            reachability: CheckLevel::Deny,
            signatures: CheckLevel::Warn,
            fresh_commit: CheckLevel::Warn,
            tag_age_gap: CheckLevel::Deny,
            repo_reputation: CheckLevel::Warn,
            recent_repo: CheckLevel::Deny,
            transitive: CheckLevel::Deny,
            hidden_execution: CheckLevel::Deny,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CheckConfig {
    pub(crate) expression_injection: CheckLevel,
    pub(crate) permissions: CheckLevel,
    pub(crate) secret_exposure: CheckLevel,
    pub(crate) privileged_triggers: CheckLevel,
    pub(crate) github_env_writes: CheckLevel,
    pub(crate) secrets_inherit: CheckLevel,
    pub(crate) contains_bypass: CheckLevel,
    pub(crate) persist_credentials: CheckLevel,
    pub(crate) typosquatting: CheckLevel,
    pub(crate) untrusted_sources: CheckLevel,
    pub(crate) provenance: ProvenanceCheckConfig,
}

impl Default for CheckConfig {
    fn default() -> Self {
        Self {
            expression_injection: CheckLevel::Deny,
            permissions: CheckLevel::Deny,
            secret_exposure: CheckLevel::Deny,
            privileged_triggers: CheckLevel::Deny,
            github_env_writes: CheckLevel::Deny,
            secrets_inherit: CheckLevel::Deny,
            contains_bypass: CheckLevel::Deny,
            persist_credentials: CheckLevel::Warn,
            typosquatting: CheckLevel::Deny,
            untrusted_sources: CheckLevel::Warn,
            provenance: ProvenanceCheckConfig::default(),
        }
    }
}

// ─── Partial check config (for per-action overrides) ─────────────────────────

#[derive(Debug, Clone, Default)]
pub(super) struct PartialCheckConfig {
    pub(super) expression_injection: Option<CheckLevel>,
    pub(super) permissions: Option<CheckLevel>,
    pub(super) secret_exposure: Option<CheckLevel>,
    pub(super) privileged_triggers: Option<CheckLevel>,
    pub(super) github_env_writes: Option<CheckLevel>,
    pub(super) secrets_inherit: Option<CheckLevel>,
    pub(super) contains_bypass: Option<CheckLevel>,
    pub(super) persist_credentials: Option<CheckLevel>,
    pub(super) typosquatting: Option<CheckLevel>,
    pub(super) untrusted_sources: Option<CheckLevel>,
    pub(super) provenance: Option<PartialProvenanceConfig>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct PartialProvenanceConfig {
    pub(super) reachability: Option<CheckLevel>,
    pub(super) signatures: Option<CheckLevel>,
    pub(super) fresh_commit: Option<CheckLevel>,
    pub(super) tag_age_gap: Option<CheckLevel>,
    pub(super) repo_reputation: Option<CheckLevel>,
    pub(super) recent_repo: Option<CheckLevel>,
    pub(super) transitive: Option<CheckLevel>,
    pub(super) hidden_execution: Option<CheckLevel>,
}

// ─── Trust configuration ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListMode {
    Extend,
    Replace,
}

impl ListMode {
    pub(super) fn parse(s: &str) -> Result<Self> {
        match s {
            "extend" => Ok(Self::Extend),
            "replace" => Ok(Self::Replace),
            other => bail!("Invalid list mode `{other}`: expected extend or replace"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ListOverride {
    pub(crate) mode: ListMode,
    pub(crate) list: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TrustConfig {
    pub(crate) owners: Option<ListOverride>,
    pub(crate) privileged_actions: Option<ListOverride>,
    pub(crate) high_impact_secrets: Option<ListOverride>,
}

// ─── Action override ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(super) struct ActionOverride {
    pub(super) pattern: String,
    pub(super) pin: Option<PinPolicy>,
    pub(super) min_sha_age: Option<i64>,
    pub(super) checks: Option<PartialCheckConfig>,
}

// ─── Suppression ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(super) struct Suppression {
    pub(super) check: String,
    pub(super) pattern: String,
    pub(super) file: Option<String>,
    pub(super) reason: String,
}

// ─── Resolved policy (after cascade for a specific action) ───────────────────

#[derive(Debug, Clone)]
pub(crate) struct ResolvedPolicy {
    pub(crate) pin: PinPolicy,
    pub(crate) min_sha_age_seconds: Option<i64>,
    pub(crate) security_action_min_sha_age_seconds: Option<i64>,
    pub(crate) checks: CheckConfig,
}

// ─── Policy ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct Policy {
    pub(crate) pin: PinPolicy,
    pub(crate) min_sha_age_seconds: Option<i64>,
    pub(crate) security_action_min_sha_age_seconds: Option<i64>,
    pub(crate) max_transitive_depth: Option<u8>,
    pub(crate) checks: CheckConfig,
    pub(crate) trust: TrustConfig,
    actions: Vec<ActionOverride>,
    suppressions: Vec<Suppression>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            pin: PinPolicy::Deny,
            min_sha_age_seconds: None,
            security_action_min_sha_age_seconds: None,
            max_transitive_depth: None,
            checks: CheckConfig::default(),
            trust: TrustConfig::default(),
            actions: Vec::new(),
            suppressions: Vec::new(),
        }
    }
}

impl Policy {
    /// Maximum policy file size (1 MiB).
    const MAX_POLICY_SIZE: u64 = 1024 * 1024;

    /// Try to load `.hasp.yml` from the given directory. Returns `None` if the
    /// file does not exist.
    pub(crate) fn load(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(".hasp.yml");
        if !path.is_file() {
            return Ok(None);
        }
        Self::check_file_size(&path)?;
        let text =
            std::fs::read_to_string(&path).context(format!("Failed to read {}", path.display()))?;
        Self::parse(&text, &path).map(Some)
    }

    /// Load from an explicit path.
    pub(crate) fn load_from(path: &Path) -> Result<Self> {
        Self::check_file_size(path)?;
        let text =
            std::fs::read_to_string(path).context(format!("Failed to read {}", path.display()))?;
        Self::parse(&text, path)
    }

    /// Reject policy files larger than `MAX_POLICY_SIZE`.
    fn check_file_size(path: &Path) -> Result<()> {
        let meta = std::fs::metadata(path)
            .context(format!("Failed to read metadata for {}", path.display()))?;
        if meta.len() > Self::MAX_POLICY_SIZE {
            bail!(
                "Policy file {} is too large ({} bytes, max {} bytes)",
                path.display(),
                meta.len(),
                Self::MAX_POLICY_SIZE
            );
        }
        Ok(())
    }

    fn parse(text: &str, path: &Path) -> Result<Self> {
        let docs = YamlLoader::load_from_str(text)
            .context(format!("Invalid YAML in {}", path.display()))?;
        let doc = docs
            .into_iter()
            .next()
            .context(format!("Empty YAML document in {}", path.display()))?;
        let map = doc.as_hash().context(format!(
            "Expected mapping at top level in {}",
            path.display()
        ))?;

        let mut policy = Self::default();

        // version (required)
        let version_key = Yaml::String("version".to_string());
        let version = map
            .get(&version_key)
            .context(format!("`version` is required in {}", path.display()))?
            .as_i64()
            .context("version must be an integer")?;
        if version != 1 {
            bail!("Unsupported policy version {version} (only version 1 is supported)");
        }

        // pin
        let pin_key = Yaml::String("pin".to_string());
        if let Some(v) = map.get(&pin_key).and_then(|v| v.as_str()) {
            policy.pin = PinPolicy::parse(v)?;
        }

        // min-sha-age
        let age_key = Yaml::String("min-sha-age".to_string());
        if let Some(v) = map.get(&age_key).and_then(|v| v.as_str()) {
            policy.min_sha_age_seconds = Some(parse_duration(v)?);
        }

        // security-action-min-sha-age
        let sec_age_key = Yaml::String("security-action-min-sha-age".to_string());
        if let Some(v) = map.get(&sec_age_key).and_then(|v| v.as_str()) {
            policy.security_action_min_sha_age_seconds = Some(parse_duration(v)?);
        }

        // max-transitive-depth
        let depth_key = Yaml::String("max-transitive-depth".to_string());
        if let Some(v) = map.get(&depth_key).and_then(Yaml::as_i64) {
            if !(1..=10).contains(&v) {
                bail!("max-transitive-depth must be between 1 and 10, got {v}");
            }
            policy.max_transitive_depth =
                Some(u8::try_from(v).expect("range already validated to 1..=10"));
        }

        // checks
        let checks_key = Yaml::String("checks".to_string());
        if let Some(checks_val) = map.get(&checks_key) {
            policy.checks = parse_check_config(checks_val)?;
        }

        // trust
        let trust_key = Yaml::String("trust".to_string());
        if let Some(trust_val) = map.get(&trust_key) {
            policy.trust = parse_trust_config(trust_val)?;
        }

        // actions
        let actions_key = Yaml::String("actions".to_string());
        if let Some(actions_val) = map.get(&actions_key).and_then(|v| v.as_vec()) {
            for item in actions_val {
                policy.actions.push(parse_action_override(item)?);
            }
        }

        // ignore
        let ignore_key = Yaml::String("ignore".to_string());
        if let Some(ignore_val) = map.get(&ignore_key).and_then(|v| v.as_vec()) {
            for item in ignore_val {
                policy.suppressions.push(parse_suppression(item)?);
            }
        }

        // Reject unknown top-level keys
        let known_keys: &[&str] = &[
            "version",
            "pin",
            "min-sha-age",
            "security-action-min-sha-age",
            "max-transitive-depth",
            "checks",
            "trust",
            "actions",
            "ignore",
        ];
        for key in map.keys() {
            if let Some(k) = key.as_str()
                && !known_keys.contains(&k)
            {
                bail!(
                    "Unknown top-level key `{k}` in policy file {}",
                    path.display()
                );
            }
        }

        Ok(policy)
    }

    /// Resolve the effective policy for a specific action (owner/repo).
    pub(crate) fn resolve_for_action(
        &self,
        owner: &str,
        repo: &str,
        path: Option<&str>,
    ) -> ResolvedPolicy {
        let target = path.map_or_else(
            || format!("{owner}/{repo}"),
            |p| format!("{owner}/{repo}/{p}"),
        );
        let mut resolved = ResolvedPolicy {
            pin: self.pin,
            min_sha_age_seconds: self.min_sha_age_seconds,
            security_action_min_sha_age_seconds: self.security_action_min_sha_age_seconds,
            checks: self.checks.clone(),
        };

        // First match wins
        for action_override in &self.actions {
            if glob_match(&action_override.pattern, &target) {
                if let Some(pin) = action_override.pin {
                    resolved.pin = pin;
                }
                if let Some(age) = action_override.min_sha_age {
                    resolved.min_sha_age_seconds = Some(age);
                }
                if let Some(partial) = &action_override.checks {
                    apply_partial_checks(&mut resolved.checks, partial);
                }
                break;
            }
        }

        resolved
    }

    /// Check if a finding should be suppressed.
    ///
    /// `action_target` is `Some("owner/repo")` when the finding is tied to a
    /// specific action, or `None` for findings without action context (e.g.
    /// missing permissions). When `None`, a suppression pattern of `"*"` matches.
    pub(crate) fn is_suppressed(
        &self,
        check: &str,
        action_target: Option<&str>,
        file: &Path,
    ) -> Option<&str> {
        for s in &self.suppressions {
            if s.check != check {
                continue;
            }
            // Match the action pattern
            let pattern_matches = action_target.map_or_else(
                // No action context: only broad patterns ("*", "*/*") match
                || s.pattern == "*" || s.pattern == "*/*",
                |target| glob_match(&s.pattern, target),
            );
            if !pattern_matches {
                continue;
            }
            if let Some(file_filter) = &s.file {
                let file_str = file.to_string_lossy();
                // If the filter has no path separator, match against the
                // basename so `file: release.yml` works regardless of the
                // absolute/relative path in the finding.
                let target: &str = if file_filter.contains('/') {
                    &file_str
                } else {
                    file.file_name().map_or(&*file_str, |n| {
                        n.to_str().unwrap_or(&file_str)
                    })
                };
                if !glob_match(file_filter, target) {
                    continue;
                }
            }
            return Some(&s.reason);
        }
        None
    }

    /// Compute effective list by composing policy overrides with built-in values.
    pub(crate) fn effective_list(
        override_cfg: Option<&ListOverride>,
        builtin: &[String],
    ) -> Vec<String> {
        override_cfg.map_or_else(
            || builtin.to_vec(),
            |lo| match lo.mode {
                ListMode::Extend => {
                    let mut list: Vec<String> = builtin.to_vec();
                    for item in &lo.list {
                        if !list
                            .iter()
                            .any(|existing| existing.eq_ignore_ascii_case(item))
                        {
                            list.push(item.to_lowercase());
                        }
                    }
                    list
                }
                ListMode::Replace => lo.list.iter().map(|s| s.to_lowercase()).collect(),
            },
        )
    }

    /// Merge CLI flags into the policy (most restrictive wins).
    pub(crate) fn merge_cli(&mut self, args: &crate::cli::Args) {
        if args.strict {
            self.pin = PinPolicy::Deny;
        }
        if args.paranoid {
            // All checks become deny (most restrictive wins)
            set_all_checks_deny(&mut self.checks);
            // Set default age policies if not already set
            if self.min_sha_age_seconds.is_none() {
                self.min_sha_age_seconds = Some(48 * 60 * 60);
            }
            if self.security_action_min_sha_age_seconds.is_none() {
                self.security_action_min_sha_age_seconds = Some(30 * 24 * 60 * 60);
            }
        }
        // CLI duration flags override policy values (most restrictive wins)
        if let Some(cli_age) = args.min_sha_age_seconds {
            self.min_sha_age_seconds =
                Some(self.min_sha_age_seconds.map_or(cli_age, |p| cli_age.max(p)));
        }
        if let Some(cli_age) = args.security_action_min_sha_age_seconds {
            self.security_action_min_sha_age_seconds = Some(
                self.security_action_min_sha_age_seconds
                    .map_or(cli_age, |p| cli_age.max(p)),
            );
        }
    }

    /// Returns true if any check is not `Off`.
    pub(crate) const fn has_any_enabled_check(&self) -> bool {
        let c = &self.checks;
        !c.expression_injection.is_off()
            || !c.permissions.is_off()
            || !c.secret_exposure.is_off()
            || !c.privileged_triggers.is_off()
            || !c.github_env_writes.is_off()
            || !c.secrets_inherit.is_off()
            || !c.contains_bypass.is_off()
            || !c.persist_credentials.is_off()
            || !c.typosquatting.is_off()
            || !c.untrusted_sources.is_off()
            || !c.provenance.reachability.is_off()
            || !c.provenance.signatures.is_off()
            || !c.provenance.fresh_commit.is_off()
            || !c.provenance.tag_age_gap.is_off()
            || !c.provenance.repo_reputation.is_off()
            || !c.provenance.recent_repo.is_off()
            || !c.provenance.transitive.is_off()
            || !c.provenance.hidden_execution.is_off()
    }

    /// Returns true if any provenance sub-check is enabled.
    pub(crate) const fn has_any_provenance_check(&self) -> bool {
        let p = &self.checks.provenance;
        !p.reachability.is_off()
            || !p.signatures.is_off()
            || !p.fresh_commit.is_off()
            || !p.tag_age_gap.is_off()
            || !p.repo_reputation.is_off()
            || !p.recent_repo.is_off()
            || !p.transitive.is_off()
            || !p.hidden_execution.is_off()
    }

    /// Returns true if the policy has any suppressions configured.
    pub(crate) const fn has_suppressions(&self) -> bool {
        !self.suppressions.is_empty()
    }

    /// Returns true if any suppression uses a wildcard-all pattern.
    pub(crate) fn has_broad_suppressions(&self) -> bool {
        self.suppressions
            .iter()
            .any(|s| s.pattern == "*" || s.pattern == "*/*")
    }

    /// Parse a policy from text content (for drift comparison against base branch).
    pub(crate) fn parse_text(text: &str) -> Result<Self> {
        Self::parse(text, Path::new("<base-branch>"))
    }

    /// Path to the policy file (for display only).
    pub(crate) fn policy_path(dir: &Path) -> PathBuf {
        dir.join(".hasp.yml")
    }
}

// ─── Policy drift detection ──────────────────────────────────────────────────

/// A single policy change that weakens security posture.
#[derive(Debug)]
pub(crate) struct PolicyDrift {
    pub(crate) description: String,
}

/// Compare two policies and return a list of changes where the `new` policy
/// is weaker than the `old` one. Used by `--diff-base` to detect policy
/// weakening in a PR.
#[allow(clippy::too_many_lines)]
pub(crate) fn detect_policy_drift(old: &Policy, new: &Policy) -> Vec<PolicyDrift> {
    let mut drifts = Vec::new();

    // Pin policy weakened
    drift_pin(&mut drifts, "pin", old.pin, new.pin);

    // Age policies removed or shortened
    drift_age(
        &mut drifts,
        "min-sha-age",
        old.min_sha_age_seconds,
        new.min_sha_age_seconds,
    );
    drift_age(
        &mut drifts,
        "security-action-min-sha-age",
        old.security_action_min_sha_age_seconds,
        new.security_action_min_sha_age_seconds,
    );

    // Check levels weakened
    drift_check(
        &mut drifts,
        "expression-injection",
        old.checks.expression_injection,
        new.checks.expression_injection,
    );
    drift_check(
        &mut drifts,
        "permissions",
        old.checks.permissions,
        new.checks.permissions,
    );
    drift_check(
        &mut drifts,
        "secret-exposure",
        old.checks.secret_exposure,
        new.checks.secret_exposure,
    );
    drift_check(
        &mut drifts,
        "privileged-triggers",
        old.checks.privileged_triggers,
        new.checks.privileged_triggers,
    );
    drift_check(
        &mut drifts,
        "github-env-writes",
        old.checks.github_env_writes,
        new.checks.github_env_writes,
    );
    drift_check(
        &mut drifts,
        "secrets-inherit",
        old.checks.secrets_inherit,
        new.checks.secrets_inherit,
    );
    drift_check(
        &mut drifts,
        "contains-bypass",
        old.checks.contains_bypass,
        new.checks.contains_bypass,
    );
    drift_check(
        &mut drifts,
        "persist-credentials",
        old.checks.persist_credentials,
        new.checks.persist_credentials,
    );
    drift_check(
        &mut drifts,
        "typosquatting",
        old.checks.typosquatting,
        new.checks.typosquatting,
    );
    drift_check(
        &mut drifts,
        "untrusted-sources",
        old.checks.untrusted_sources,
        new.checks.untrusted_sources,
    );

    // Provenance sub-checks
    drift_check(
        &mut drifts,
        "provenance.reachability",
        old.checks.provenance.reachability,
        new.checks.provenance.reachability,
    );
    drift_check(
        &mut drifts,
        "provenance.signatures",
        old.checks.provenance.signatures,
        new.checks.provenance.signatures,
    );
    drift_check(
        &mut drifts,
        "provenance.fresh-commit",
        old.checks.provenance.fresh_commit,
        new.checks.provenance.fresh_commit,
    );
    drift_check(
        &mut drifts,
        "provenance.tag-age-gap",
        old.checks.provenance.tag_age_gap,
        new.checks.provenance.tag_age_gap,
    );
    drift_check(
        &mut drifts,
        "provenance.repo-reputation",
        old.checks.provenance.repo_reputation,
        new.checks.provenance.repo_reputation,
    );
    drift_check(
        &mut drifts,
        "provenance.recent-repo",
        old.checks.provenance.recent_repo,
        new.checks.provenance.recent_repo,
    );
    drift_check(
        &mut drifts,
        "provenance.transitive",
        old.checks.provenance.transitive,
        new.checks.provenance.transitive,
    );
    drift_check(
        &mut drifts,
        "provenance.hidden-execution",
        old.checks.provenance.hidden_execution,
        new.checks.provenance.hidden_execution,
    );

    // Suppressions added
    let old_count = old.suppressions.len();
    let new_count = new.suppressions.len();
    if new_count > old_count {
        drifts.push(PolicyDrift {
            description: format!(
                "{} new suppression(s) added (was {old_count}, now {new_count})",
                new_count - old_count
            ),
        });
    }

    drifts
}

fn drift_check(drifts: &mut Vec<PolicyDrift>, name: &str, old: CheckLevel, new: CheckLevel) {
    let weakened = matches!(
        (old, new),
        (CheckLevel::Deny, CheckLevel::Warn | CheckLevel::Off)
            | (CheckLevel::Warn, CheckLevel::Off)
    );
    if weakened {
        drifts.push(PolicyDrift {
            description: format!(
                "`{name}` weakened from {old} to {new}",
                old = level_str(old),
                new = level_str(new)
            ),
        });
    }
}

fn drift_pin(drifts: &mut Vec<PolicyDrift>, name: &str, old: PinPolicy, new: PinPolicy) {
    let weakened = matches!(
        (old, new),
        (PinPolicy::Deny, PinPolicy::Warn | PinPolicy::Off) | (PinPolicy::Warn, PinPolicy::Off)
    );
    if weakened {
        drifts.push(PolicyDrift {
            description: format!(
                "`{name}` weakened from {old} to {new}",
                old = pin_str(old),
                new = pin_str(new)
            ),
        });
    }
}

fn drift_age(drifts: &mut Vec<PolicyDrift>, name: &str, old: Option<i64>, new: Option<i64>) {
    match (old, new) {
        (Some(_), None) => {
            drifts.push(PolicyDrift {
                description: format!("`{name}` removed (was set, now absent)"),
            });
        }
        (Some(old_val), Some(new_val)) if new_val < old_val => {
            drifts.push(PolicyDrift {
                description: format!("`{name}` shortened from {old_val}s to {new_val}s"),
            });
        }
        _ => {}
    }
}

const fn level_str(level: CheckLevel) -> &'static str {
    match level {
        CheckLevel::Deny => "deny",
        CheckLevel::Warn => "warn",
        CheckLevel::Off => "off",
    }
}

const fn pin_str(pin: PinPolicy) -> &'static str {
    match pin {
        PinPolicy::Deny => "deny",
        PinPolicy::Warn => "warn",
        PinPolicy::Off => "off",
    }
}

// ─── Glob matching ───────────────────────────────────────────────────────────

/// Simple glob matching: `*` matches any characters within a segment (no `/`
/// crossing). The match is case-insensitive. Patterns are expected to be
/// pre-lowercased at parse time; only the target is lowercased here.
pub(crate) fn glob_match(pattern: &str, target: &str) -> bool {
    let target_lower = target.to_lowercase();
    glob_match_inner(pattern.as_bytes(), target_lower.as_bytes())
}

fn glob_match_inner(pattern: &[u8], target: &[u8]) -> bool {
    let mut pat_idx = 0;
    let mut tgt_idx = 0;
    let mut saved_pat = usize::MAX;
    let mut saved_tgt = 0;

    while tgt_idx < target.len() {
        if pat_idx < pattern.len() && pattern[pat_idx] == b'*' {
            saved_pat = pat_idx;
            saved_tgt = tgt_idx;
            pat_idx += 1;
        } else if pat_idx < pattern.len() && pattern[pat_idx] == target[tgt_idx] {
            pat_idx += 1;
            tgt_idx += 1;
        } else if saved_pat != usize::MAX && target[saved_tgt] != b'/' {
            pat_idx = saved_pat + 1;
            saved_tgt += 1;
            tgt_idx = saved_tgt;
        } else {
            return false;
        }
    }

    while pat_idx < pattern.len() && pattern[pat_idx] == b'*' {
        pat_idx += 1;
    }

    pat_idx == pattern.len()
}

/// Apply a partial override to a single check level, warning if a deny-level
/// check is weakened by the override.
fn apply_level(full: &mut CheckLevel, partial: Option<CheckLevel>, name: &str) {
    if let Some(v) = partial {
        if *full == CheckLevel::Deny && v != CheckLevel::Deny {
            eprintln!("hasp: warning: action override weakens `{name}` from deny");
        }
        *full = v;
    }
}

fn apply_partial_checks(full: &mut CheckConfig, partial: &PartialCheckConfig) {
    apply_level(
        &mut full.expression_injection,
        partial.expression_injection,
        "expression-injection",
    );
    apply_level(&mut full.permissions, partial.permissions, "permissions");
    apply_level(
        &mut full.secret_exposure,
        partial.secret_exposure,
        "secret-exposure",
    );
    apply_level(
        &mut full.privileged_triggers,
        partial.privileged_triggers,
        "privileged-triggers",
    );
    apply_level(
        &mut full.github_env_writes,
        partial.github_env_writes,
        "github-env-writes",
    );
    apply_level(
        &mut full.secrets_inherit,
        partial.secrets_inherit,
        "secrets-inherit",
    );
    apply_level(
        &mut full.contains_bypass,
        partial.contains_bypass,
        "contains-bypass",
    );
    apply_level(
        &mut full.persist_credentials,
        partial.persist_credentials,
        "persist-credentials",
    );
    apply_level(
        &mut full.typosquatting,
        partial.typosquatting,
        "typosquatting",
    );
    apply_level(
        &mut full.untrusted_sources,
        partial.untrusted_sources,
        "untrusted-sources",
    );
    if let Some(prov) = &partial.provenance {
        apply_level(
            &mut full.provenance.reachability,
            prov.reachability,
            "reachability",
        );
        apply_level(
            &mut full.provenance.signatures,
            prov.signatures,
            "signatures",
        );
        apply_level(
            &mut full.provenance.fresh_commit,
            prov.fresh_commit,
            "fresh-commit",
        );
        apply_level(
            &mut full.provenance.tag_age_gap,
            prov.tag_age_gap,
            "tag-age-gap",
        );
        apply_level(
            &mut full.provenance.repo_reputation,
            prov.repo_reputation,
            "repo-reputation",
        );
        apply_level(
            &mut full.provenance.recent_repo,
            prov.recent_repo,
            "recent-repo",
        );
        apply_level(
            &mut full.provenance.transitive,
            prov.transitive,
            "transitive",
        );
        apply_level(
            &mut full.provenance.hidden_execution,
            prov.hidden_execution,
            "hidden-execution",
        );
    }
}

const fn set_all_checks_deny(checks: &mut CheckConfig) {
    checks.expression_injection = CheckLevel::Deny;
    checks.permissions = CheckLevel::Deny;
    checks.secret_exposure = CheckLevel::Deny;
    checks.privileged_triggers = CheckLevel::Deny;
    checks.github_env_writes = CheckLevel::Deny;
    checks.secrets_inherit = CheckLevel::Deny;
    checks.contains_bypass = CheckLevel::Deny;
    checks.persist_credentials = CheckLevel::Deny;
    checks.typosquatting = CheckLevel::Deny;
    checks.untrusted_sources = CheckLevel::Deny;
    checks.provenance.reachability = CheckLevel::Deny;
    checks.provenance.signatures = CheckLevel::Deny;
    checks.provenance.fresh_commit = CheckLevel::Deny;
    checks.provenance.tag_age_gap = CheckLevel::Deny;
    checks.provenance.repo_reputation = CheckLevel::Deny;
    checks.provenance.recent_repo = CheckLevel::Deny;
    checks.provenance.transitive = CheckLevel::Deny;
    checks.provenance.hidden_execution = CheckLevel::Deny;
}

/// Map a finding title to its policy check name for suppression matching.
///
/// More specific patterns are checked first to prevent false matches. Where
/// possible, `starts_with` is preferred over `contains` to reduce ambiguity.
pub(crate) fn check_name_for_finding(title: &str) -> &'static str {
    // ── Most-specific patterns first ────────────────────────────────────

    // "Privileged checkout of attacker code in ..."
    if title.starts_with("Privileged checkout") {
        return "privileged-triggers";
    }

    // "Dangerous write to $GITHUB_ENV" / "Dangerous write to $GITHUB_PATH"
    if title.starts_with("Dangerous write to GITHUB_")
        || title.starts_with("Dangerous write to $GITHUB_")
    {
        return "github-env-writes";
    }

    // "Reusable workflow call uses `secrets: inherit` in job ..."
    if title.contains("secrets: inherit") {
        return "secrets-inherit";
    }

    // "Bypassable `contains()` check on attacker-controlled input"
    if title.contains("contains()") {
        return "contains-bypass";
    }

    // "actions/checkout persists credentials on disk"
    if title.contains("persists credentials") {
        return "persist-credentials";
    }

    // "Possible typosquatting of popular action `...`"
    if title.starts_with("Possible typosquatting") {
        return "typosquatting";
    }

    // "Unverified action source: ..."
    if title.starts_with("Unverified action source") {
        return "untrusted-sources";
    }

    // "Recently created repository `...`"
    if title.starts_with("Recently created repository") {
        return "recent-repo";
    }

    // "Tag `...` may have been retroactively applied to an old commit in ..."
    if title.contains("retroactively") {
        return "tag-age-gap";
    }

    // "Very fresh commit ... in ..." / "... newer than policy"
    if title.starts_with("Very fresh commit") || title.contains("newer than policy") {
        return "fresh-commit";
    }

    // "Unsigned commit ... in ..."
    if title.starts_with("Unsigned") {
        return "signatures";
    }

    // "Commit ... is unreachable/diverged/ahead of ... default branch"
    if title.starts_with("Commit") && title.contains("default branch") {
        return "reachability";
    }

    // "Very low-signal repository ..." / "Low-reputation repository ..."
    if title.contains("low-signal") || title.starts_with("Low-reputation") {
        return "repo-reputation";
    }

    // "Mutable transitive dependency ..." / "Transitive ..."
    if title.contains("transitive") || title.starts_with("Transitive") {
        return "transitive";
    }

    // "Action `...` contains hidden execution paths"
    if title.contains("hidden execution") {
        return "hidden-execution";
    }

    // ── Broader patterns (checked after specific ones) ──────────────────

    // "Script injection via ..." / "Potential injection in action input via ..."
    if title.contains("injection") {
        return "expression-injection";
    }

    // "High-risk secret exposure to ..." / "Secrets visible to ..."
    if title.starts_with("High-risk secret exposure") || title.starts_with("Secrets visible") {
        return "secret-exposure";
    }

    // "Missing top-level permissions block" / "write-all permissions at ..."
    // / "...: ...: write" (granular permission findings, e.g.
    // "jobs.release: contents: write")
    if title.contains("permissions")
        || title.contains("write-all")
        || title.ends_with(": write")
    {
        return "permissions";
    }

    "unknown"
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_exact() {
        assert!(glob_match("actions/checkout", "actions/checkout"));
        assert!(!glob_match("actions/checkout", "actions/setup-node"));
    }

    #[test]
    fn glob_matches_wildcard() {
        assert!(glob_match("my-org/*", "my-org/deploy-action"));
        assert!(glob_match("my-org/*", "my-org/anything"));
        assert!(!glob_match("my-org/*", "other-org/deploy-action"));
    }

    #[test]
    fn glob_is_case_insensitive_on_target() {
        // Patterns are expected pre-lowercased; only the target is lowercased.
        assert!(glob_match("actions/checkout", "Actions/Checkout"));
        assert!(glob_match("my-org/*", "MY-ORG/Deploy"));
    }

    #[test]
    fn glob_star_does_not_cross_slash() {
        assert!(!glob_match("*", "anything/here"));
        assert!(glob_match("*/*", "a/b"));
        assert!(glob_match("*", "anything"));
        assert!(!glob_match("*", "a/b/c"));
    }

    #[test]
    fn parse_minimal_policy() {
        let yaml = "version: 1\npin: warn\n";
        let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse failed");
        assert_eq!(policy.pin, PinPolicy::Warn);
    }

    #[test]
    fn parse_full_policy() {
        let yaml = r#"
version: 1
pin: deny
min-sha-age: 48h
security-action-min-sha-age: 30d
checks:
  expression-injection: deny
  permissions: deny
  secret-exposure: deny
  privileged-triggers: deny
  github-env-writes: deny
  secrets-inherit: deny
  contains-bypass: deny
  persist-credentials: warn
  typosquatting: deny
  untrusted-sources: warn
  provenance:
    reachability: deny
    signatures: warn
    fresh-commit: warn
    tag-age-gap: deny
    repo-reputation: warn
    recent-repo: deny
    transitive: deny
    hidden-execution: deny
trust:
  owners:
    mode: extend
    list: [my-org]
  privileged-actions:
    mode: extend
    list: [my-org/deploy-action]
  high-impact-secrets:
    mode: extend
    list: [MY_CUSTOM_TOKEN]
actions:
  - match: "my-org/*"
    pin: warn
    min-sha-age: 0s
    checks:
      untrusted-sources: off
  - match: "actions/checkout"
    checks:
      persist-credentials: off
ignore:
  - check: persist-credentials
    match: "actions/checkout"
    reason: "v4 cleans up in post-step"
  - check: expression-injection
    match: "*"
    file: ".github/workflows/label-sync.yml"
    reason: "Schedule-only trigger"
"#;
        let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse failed");
        assert_eq!(policy.pin, PinPolicy::Deny);
        assert_eq!(policy.min_sha_age_seconds, Some(172_800));
        assert_eq!(policy.security_action_min_sha_age_seconds, Some(2_592_000));
        assert_eq!(policy.checks.persist_credentials, CheckLevel::Warn);
        assert_eq!(policy.checks.untrusted_sources, CheckLevel::Warn);
        assert_eq!(policy.checks.provenance.reachability, CheckLevel::Deny);
        assert_eq!(
            policy.trust.owners.as_ref().map(|o| o.mode),
            Some(ListMode::Extend)
        );
        assert_eq!(policy.actions.len(), 2);
        assert_eq!(policy.suppressions.len(), 2);
    }

    #[test]
    fn resolve_action_override_first_match_wins() {
        let yaml = r#"
version: 1
checks:
  untrusted-sources: deny
actions:
  - match: "my-org/*"
    checks:
      untrusted-sources: off
  - match: "my-org/special"
    checks:
      untrusted-sources: warn
"#;
        let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse failed");
        let resolved = policy.resolve_for_action("my-org", "special", None);
        // First match wins: my-org/* matches before my-org/special
        assert_eq!(resolved.checks.untrusted_sources, CheckLevel::Off);
    }

    #[test]
    fn resolve_action_no_match_inherits_global() {
        let yaml = r#"
version: 1
checks:
  persist-credentials: warn
actions:
  - match: "my-org/*"
    checks:
      persist-credentials: off
"#;
        let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse failed");
        let resolved = policy.resolve_for_action("other-org", "something", None);
        assert_eq!(resolved.checks.persist_credentials, CheckLevel::Warn);
    }

    #[test]
    fn suppression_matching() {
        let yaml = r#"
version: 1
ignore:
  - check: persist-credentials
    match: "actions/checkout"
    reason: "v4 cleans up"
  - check: expression-injection
    match: "*/*"
    file: "ci.yml"
    reason: "schedule only"
"#;
        let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse failed");

        assert!(
            policy
                .is_suppressed(
                    "persist-credentials",
                    Some("actions/checkout"),
                    Path::new("any.yml")
                )
                .is_some()
        );
        assert!(
            policy
                .is_suppressed(
                    "persist-credentials",
                    Some("other/repo"),
                    Path::new("any.yml")
                )
                .is_none()
        );
        assert!(
            policy
                .is_suppressed("expression-injection", None, Path::new("ci.yml"))
                .is_some()
        );
        assert!(
            policy
                .is_suppressed("expression-injection", None, Path::new("other.yml"))
                .is_none()
        );
    }

    #[test]
    fn effective_list_extend() {
        let builtin = vec!["builtin".to_string()];
        let override_cfg = ListOverride {
            mode: ListMode::Extend,
            list: vec!["extra".to_string()],
        };
        let result = Policy::effective_list(Some(&override_cfg), &builtin);
        assert_eq!(result, vec!["builtin".to_string(), "extra".to_string()]);
    }

    #[test]
    fn effective_list_replace() {
        let builtin = vec!["builtin".to_string()];
        let override_cfg = ListOverride {
            mode: ListMode::Replace,
            list: vec!["only-this".to_string()],
        };
        let result = Policy::effective_list(Some(&override_cfg), &builtin);
        assert_eq!(result, vec!["only-this".to_string()]);
    }

    #[test]
    fn effective_list_no_override() {
        let builtin = vec!["builtin".to_string()];
        let result = Policy::effective_list(None, &builtin);
        assert_eq!(result, vec!["builtin".to_string()]);
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration("0").expect("parse"), 0);
        assert_eq!(parse_duration("null").expect("parse"), 0);
        assert_eq!(parse_duration("48h").expect("parse"), 172_800);
        assert_eq!(parse_duration("30d").expect("parse"), 2_592_000);
        assert_eq!(parse_duration("0s").expect("parse"), 0);
    }

    #[test]
    fn check_level_merge_restrictive() {
        assert_eq!(
            CheckLevel::Deny.merge_restrictive(CheckLevel::Off),
            CheckLevel::Deny
        );
        assert_eq!(
            CheckLevel::Off.merge_restrictive(CheckLevel::Warn),
            CheckLevel::Warn
        );
        assert_eq!(
            CheckLevel::Off.merge_restrictive(CheckLevel::Off),
            CheckLevel::Off
        );
    }

    #[test]
    fn rejects_unknown_version() {
        let yaml = "version: 99\n";
        let err = Policy::parse(yaml, Path::new("test.yml")).unwrap_err();
        assert!(err.to_string().contains("Unsupported policy version"));
    }

    #[test]
    fn rejects_unknown_check() {
        let yaml = "version: 1\nchecks:\n  made-up-check: deny\n";
        let err = Policy::parse(yaml, Path::new("test.yml")).unwrap_err();
        assert!(err.to_string().contains("Unknown check"));
    }

    // ── Integration tests: policy + audit ────────────────────────────────

    mod integration {
        use super::*;
        use crate::audit::{self, AuditFinding};
        use crate::scanner::{ActionRef, RefKind};
        use std::path::PathBuf;
        use yaml_rust2::YamlLoader;

        fn workflow(src: &str) -> Vec<(PathBuf, Yaml)> {
            let doc = YamlLoader::load_from_str(src)
                .expect("bad test YAML")
                .remove(0);
            vec![(PathBuf::from("ci.yml"), doc)]
        }

        fn action_ref(owner: &str, repo: &str) -> ActionRef {
            ActionRef {
                file: PathBuf::from("ci.yml"),
                owner: owner.to_string(),
                repo: repo.to_string(),
                path: None,
                ref_str: "0123456789012345678901234567890123456789".to_string(),
                ref_kind: RefKind::FullSha,
                comment_version: None,
            }
        }

        /// With all checks at default (deny), a vulnerable workflow produces findings.
        #[test]
        fn default_policy_produces_findings() {
            let policy = Policy::default();
            let docs = workflow(
                "
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
",
            );
            let findings = audit::run(&docs, &[], &policy.checks);
            // Should find: missing permissions, persist-credentials
            assert!(
                findings.iter().any(|f| f.title.contains("permissions")),
                "expected a permissions finding"
            );
            assert!(
                findings.iter().any(|f| f.title.contains("persist")),
                "expected a persist-credentials finding"
            );
            // Default persist-credentials is Warn, so those findings should be warnings
            assert!(
                findings
                    .iter()
                    .filter(|f| f.title.contains("persist"))
                    .all(|f| f.is_warning),
                "persist-credentials findings should be warnings at default level"
            );
        }

        /// Setting a check to `off` suppresses its findings entirely.
        #[test]
        fn off_check_produces_no_findings() {
            let yaml = "\
version: 1
checks:
  persist-credentials: off
  permissions: off
";
            let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse");
            let docs = workflow(
                "
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
",
            );
            let findings = audit::run(&docs, &[], &policy.checks);
            assert!(
                !findings.iter().any(|f| f.title.contains("persist")),
                "persist-credentials should be suppressed by off"
            );
            assert!(
                !findings.iter().any(|f| f.title.contains("permissions")),
                "permissions should be suppressed by off"
            );
        }

        /// Setting a check to `warn` marks its findings as warnings (non-blocking).
        #[test]
        fn warn_check_marks_findings_as_warnings() {
            let yaml = "\
version: 1
checks:
  permissions: warn
  persist-credentials: warn
";
            let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse");
            let docs = workflow(
                "
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
",
            );
            let findings = audit::run(&docs, &[], &policy.checks);
            assert!(!findings.is_empty(), "should still produce findings");
            assert!(
                findings.iter().all(|f| f.is_warning),
                "all findings should be warnings"
            );
        }

        /// Setting a check to `deny` makes findings non-warning (blocking).
        #[test]
        fn deny_check_marks_findings_as_blocking() {
            let yaml = "\
version: 1
checks:
  permissions: deny
  persist-credentials: deny
";
            let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse");
            let docs = workflow(
                "
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
",
            );
            let findings = audit::run(&docs, &[], &policy.checks);
            assert!(!findings.is_empty(), "should produce findings");
            assert!(
                findings.iter().all(|f| !f.is_warning),
                "all findings should be blocking (deny)"
            );
        }

        /// Per-action override changes check behavior for matching actions.
        #[test]
        fn per_action_override_resolves_correctly() {
            let yaml = r#"
version: 1
checks:
  untrusted-sources: deny
actions:
  - match: "my-org/*"
    checks:
      untrusted-sources: off
"#;
            let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse");

            // For my-org/deploy, untrusted-sources should be off
            let resolved = policy.resolve_for_action("my-org", "deploy", None);
            assert!(
                resolved.checks.untrusted_sources.is_off(),
                "my-org/* should have untrusted-sources off"
            );

            // For other-org/something, untrusted-sources should remain deny
            let resolved = policy.resolve_for_action("other-org", "something", None);
            assert_eq!(
                resolved.checks.untrusted_sources,
                CheckLevel::Deny,
                "other-org should inherit global deny"
            );
        }

        /// Untrusted-sources check respects `CheckLevel`.
        #[test]
        fn untrusted_sources_off_suppresses_findings() {
            let refs = vec![action_ref("unknown-org", "sketchy-action")];
            let builtin_owners = audit::builtin_trusted_owners();
            let mut findings = Vec::new();

            // With deny: should produce a finding
            audit::check_untrusted_sources(&refs, &mut findings, CheckLevel::Deny, builtin_owners);
            assert!(
                !findings.is_empty(),
                "deny should produce untrusted-sources findings"
            );
            assert!(
                !findings[0].is_warning,
                "deny findings should not be warnings"
            );

            // With warn: should produce a warning finding
            findings.clear();
            audit::check_untrusted_sources(&refs, &mut findings, CheckLevel::Warn, builtin_owners);
            assert!(!findings.is_empty(), "warn should still produce findings");
            assert!(findings[0].is_warning, "warn findings should be warnings");
        }

        /// Typosquatting check respects `CheckLevel`.
        #[test]
        fn typosquatting_off_suppresses_findings() {
            let refs = vec![action_ref("action", "checkout")];

            // With deny: should find typosquatting
            let findings = audit::run(
                &[],
                &refs,
                &CheckConfig {
                    typosquatting: CheckLevel::Deny,
                    ..CheckConfig::default()
                },
            );
            assert!(
                findings.iter().any(|f| f.title.contains("typosquatting")),
                "deny should find typosquatting"
            );

            // With off: no typosquatting findings
            let findings = audit::run(
                &[],
                &refs,
                &CheckConfig {
                    typosquatting: CheckLevel::Off,
                    ..CheckConfig::default()
                },
            );
            assert!(
                !findings.iter().any(|f| f.title.contains("typosquatting")),
                "off should suppress typosquatting"
            );
        }

        /// Suppression filters findings post-hoc.
        #[test]
        fn suppression_filters_matching_findings() {
            let yaml = r#"
version: 1
ignore:
  - check: persist-credentials
    match: "*"
    reason: "We handle this differently"
"#;
            let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse");
            let docs = workflow(
                "
on: push
permissions: {}
jobs:
  build:
    permissions: {}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
",
            );
            let mut findings = audit::run(&docs, &[], &policy.checks);
            let initial_count = findings.len();
            assert!(
                findings.iter().any(|f| f.title.contains("persist")),
                "should initially have persist-credentials findings"
            );

            // Apply suppressions
            findings.retain(|f| {
                let check_name = check_name_for_finding(&f.title);
                policy.is_suppressed(check_name, None, &f.file).is_none()
            });

            assert!(
                findings.len() < initial_count,
                "suppression should have removed some findings"
            );
            assert!(
                !findings.iter().any(|f| f.title.contains("persist")),
                "persist-credentials findings should be suppressed"
            );
        }

        /// Expression injection check respects the policy level.
        #[test]
        fn expression_injection_check_with_levels() {
            let docs = workflow(
                "
on: pull_request
permissions: {}
jobs:
  test:
    permissions: {}
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.pull_request.title }}
",
            );

            // deny: should find injection, not marked as warning
            let findings = audit::run(
                &docs,
                &[],
                &CheckConfig {
                    expression_injection: CheckLevel::Deny,
                    ..CheckConfig::default()
                },
            );
            let injection_findings: Vec<&AuditFinding> = findings
                .iter()
                .filter(|f| f.title.contains("injection"))
                .collect();
            assert!(!injection_findings.is_empty(), "deny should find injection");
            assert!(
                !injection_findings[0].is_warning,
                "deny should not be warning"
            );

            // warn: should find injection, marked as warning
            let findings = audit::run(
                &docs,
                &[],
                &CheckConfig {
                    expression_injection: CheckLevel::Warn,
                    ..CheckConfig::default()
                },
            );
            let injection_findings: Vec<&AuditFinding> = findings
                .iter()
                .filter(|f| f.title.contains("injection"))
                .collect();
            assert!(!injection_findings.is_empty(), "warn should find injection");
            assert!(injection_findings[0].is_warning, "warn should be warning");

            // off: no injection findings
            let findings = audit::run(
                &docs,
                &[],
                &CheckConfig {
                    expression_injection: CheckLevel::Off,
                    ..CheckConfig::default()
                },
            );
            assert!(
                !findings.iter().any(|f| f.title.contains("injection")),
                "off should suppress injection"
            );
        }

        /// CLI merge: --paranoid forces all checks to deny.
        #[test]
        fn cli_merge_paranoid_forces_deny() {
            let yaml = "\
version: 1
checks:
  persist-credentials: off
  untrusted-sources: off
";
            let mut policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse");
            let args = crate::cli::Args {
                paranoid: true,
                ..crate::cli::Args::default()
            };
            policy.merge_cli(&args);
            assert_eq!(
                policy.checks.persist_credentials,
                CheckLevel::Deny,
                "--paranoid should override off to deny"
            );
            assert_eq!(
                policy.checks.untrusted_sources,
                CheckLevel::Deny,
                "--paranoid should override off to deny"
            );
        }

        /// Trust list extend adds to built-in list.
        #[test]
        fn trust_list_extend_adds_owner() {
            let yaml = "\
version: 1
trust:
  owners:
    mode: extend
    list: [my-custom-org]
";
            let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse");
            let builtin = vec!["actions".to_string(), "github".to_string()];
            let effective = Policy::effective_list(policy.trust.owners.as_ref(), &builtin);
            assert!(
                effective.contains(&"actions".to_string()),
                "should keep built-in"
            );
            assert!(
                effective.contains(&"github".to_string()),
                "should keep built-in"
            );
            assert!(
                effective.contains(&"my-custom-org".to_string()),
                "should add custom org"
            );
        }

        /// Trust list replace removes built-in list.
        #[test]
        fn trust_list_replace_removes_builtin() {
            let yaml = "\
version: 1
trust:
  owners:
    mode: replace
    list: [only-this-org]
";
            let policy = Policy::parse(yaml, Path::new("test.yml")).expect("parse");
            let builtin = vec!["actions".to_string(), "github".to_string()];
            let effective = Policy::effective_list(policy.trust.owners.as_ref(), &builtin);
            assert_eq!(effective, vec!["only-this-org".to_string()]);
            assert!(
                !effective.contains(&"actions".to_string()),
                "should not contain built-in"
            );
        }

        /// Full e2e: parse policy, run audit, apply suppressions, check output.
        #[test]
        fn full_e2e_policy_workflow_scan() {
            let policy_yaml = r#"
version: 1
checks:
  permissions: deny
  persist-credentials: warn
  expression-injection: deny
  secrets-inherit: off
ignore:
  - check: persist-credentials
    match: "*"
    file: "ci.yml"
    reason: "Acceptable in this workflow"
"#;
            let policy = Policy::parse(policy_yaml, Path::new(".hasp.yml")).expect("parse");

            let docs = workflow(
                "
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    secrets: inherit
    steps:
      - uses: actions/checkout@v4
      - run: echo ${{ github.event.pull_request.title }}
",
            );

            let mut findings = audit::run(&docs, &[], &policy.checks);

            // secrets-inherit is off, so no finding for it
            assert!(
                !findings
                    .iter()
                    .any(|f| f.title.contains("secrets: inherit")),
                "secrets-inherit should be off"
            );

            // expression-injection is deny, so finding should exist and not be warning
            let injection = findings.iter().find(|f| f.title.contains("injection"));
            assert!(injection.is_some(), "injection should be found");
            assert!(
                !injection.expect("checked").is_warning,
                "injection should be deny"
            );

            // persist-credentials is warn, finding exists but is warning
            let persist: Vec<&AuditFinding> = findings
                .iter()
                .filter(|f| f.title.contains("persist"))
                .collect();
            assert!(
                !persist.is_empty(),
                "persist finding should exist before suppression"
            );
            assert!(persist[0].is_warning, "persist should be a warning");

            // permissions is deny
            let perms = findings.iter().find(|f| f.title.contains("permissions"));
            assert!(perms.is_some(), "permissions finding should exist");
            assert!(
                !perms.expect("checked").is_warning,
                "permissions should be deny"
            );

            // Now apply suppressions - persist-credentials for ci.yml should be removed
            let before = findings.len();
            findings.retain(|f| {
                let cn = check_name_for_finding(&f.title);
                policy.is_suppressed(cn, None, &f.file).is_none()
            });
            assert!(
                findings.len() < before,
                "suppression should have removed persist-credentials"
            );
            assert!(
                !findings.iter().any(|f| f.title.contains("persist")),
                "persist-credentials should be gone after suppression"
            );
        }
    }

    // ─── Policy drift tests ──────────────────────────────────────────

    mod drift {
        use super::*;

        fn parse(yaml: &str) -> Policy {
            Policy::parse_text(yaml).expect("test policy should parse")
        }

        #[test]
        fn no_drift_for_identical_policies() {
            let p = parse("version: 1\n");
            let drifts = detect_policy_drift(&p, &p);
            assert!(drifts.is_empty(), "identical policies should have no drift");
        }

        #[test]
        fn detects_weakened_check_level() {
            let old = parse(
                "\
version: 1
checks:
  expression-injection: deny
",
            );
            let new = parse(
                "\
version: 1
checks:
  expression-injection: off
",
            );
            let drifts = detect_policy_drift(&old, &new);
            assert_eq!(drifts.len(), 1, "should detect one drift");
            assert!(
                drifts[0].description.contains("expression-injection"),
                "should name the weakened check: {}",
                drifts[0].description
            );
            assert!(
                drifts[0].description.contains("deny") && drifts[0].description.contains("off"),
                "should describe the change: {}",
                drifts[0].description
            );
        }

        #[test]
        fn detects_weakened_pin_policy() {
            let old = parse("version: 1\npin: deny\n");
            let new = parse("version: 1\npin: warn\n");
            let drifts = detect_policy_drift(&old, &new);
            assert!(
                drifts.iter().any(|d| d.description.contains("pin")),
                "should detect weakened pin policy"
            );
        }

        #[test]
        fn detects_removed_age_policy() {
            let old = parse("version: 1\nmin-sha-age: 48h\n");
            let new = parse("version: 1\n");
            let drifts = detect_policy_drift(&old, &new);
            assert!(
                drifts.iter().any(|d| d.description.contains("min-sha-age")),
                "should detect removed age policy"
            );
        }

        #[test]
        fn detects_shortened_age_policy() {
            let old = parse("version: 1\nmin-sha-age: 48h\n");
            let new = parse("version: 1\nmin-sha-age: 1h\n");
            let drifts = detect_policy_drift(&old, &new);
            assert!(
                drifts.iter().any(|d| d.description.contains("shortened")),
                "should detect shortened age policy"
            );
        }

        #[test]
        fn detects_added_suppressions() {
            let old = parse("version: 1\n");
            let new = parse(
                "\
version: 1
ignore:
  - check: expression-injection
    match: \"*\"
    reason: testing
",
            );
            let drifts = detect_policy_drift(&old, &new);
            assert!(
                drifts.iter().any(|d| d.description.contains("suppression")),
                "should detect added suppressions"
            );
        }

        #[test]
        fn no_drift_for_strengthened_policy() {
            let old = parse(
                "\
version: 1
checks:
  persist-credentials: off
",
            );
            let new = parse(
                "\
version: 1
checks:
  persist-credentials: deny
",
            );
            let drifts = detect_policy_drift(&old, &new);
            assert!(
                drifts.is_empty(),
                "strengthening a check should not be drift"
            );
        }
    }
}
