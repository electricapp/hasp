use crate::error::{Context, Result, bail};
use yaml_rust2::Yaml;

use super::{
    ActionOverride, CheckConfig, CheckLevel, KNOWN_CHECK_NAMES, ListMode, ListOverride,
    PartialCheckConfig, PartialProvenanceConfig, PinPolicy, ProvenanceCheckConfig, Suppression,
    TrustConfig,
};

// ─── Duration parsing ────────────────────────────────────────────────────────

pub(super) fn parse_duration(raw: &str) -> Result<i64> {
    if raw == "null" || raw == "0" {
        return Ok(0);
    }
    if raw.len() < 2 || !raw.is_ascii() {
        bail!("Invalid duration `{raw}`: expected format like 48h, 30d, 15m, or 3600s");
    }
    let (number, unit) = raw.split_at(raw.len() - 1);
    let value: i64 = number
        .parse()
        .map_err(|_| crate::error::Error::new(format!("Invalid duration number in `{raw}`")))?;
    if value < 0 {
        bail!("Duration must be non-negative: `{raw}`");
    }
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => bail!("Unknown duration unit in `{raw}`: expected s, m, h, d, or w"),
    };
    value
        .checked_mul(multiplier)
        .context(format!("Duration overflow in `{raw}`"))
}

// ─── YAML parsing helpers ────────────────────────────────────────────────────

pub(super) fn yaml_str<'a>(v: &'a Yaml, field: &str) -> Result<&'a str> {
    v.as_str().context(format!("`{field}` must be a string"))
}

pub(super) fn parse_check_config(val: &Yaml) -> Result<CheckConfig> {
    let map = val.as_hash().context("checks must be a mapping")?;
    let mut config = CheckConfig::default();

    for (key, value) in map {
        let key_str = key.as_str().context("check key must be a string")?;
        match key_str {
            "expression-injection" => {
                config.expression_injection = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "permissions" => {
                config.permissions = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "secret-exposure" => {
                config.secret_exposure = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "privileged-triggers" => {
                config.privileged_triggers = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "github-env-writes" => {
                config.github_env_writes = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "secrets-inherit" => {
                config.secrets_inherit = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "contains-bypass" => {
                config.contains_bypass = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "persist-credentials" => {
                config.persist_credentials = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "typosquatting" => {
                config.typosquatting = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "untrusted-sources" => {
                config.untrusted_sources = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "cross-workflow" => {
                config.cross_workflow = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "oidc" => {
                config.oidc = CheckLevel::parse(yaml_str(value, key_str)?)?;
            }
            "provenance" => {
                config.provenance = parse_provenance_config(value)?;
            }
            other => bail!("Unknown check `{other}` in policy"),
        }
    }

    Ok(config)
}

pub(super) fn parse_provenance_config(val: &Yaml) -> Result<ProvenanceCheckConfig> {
    let map = val.as_hash().context("provenance must be a mapping")?;
    let mut config = ProvenanceCheckConfig::default();

    for (key, value) in map {
        let key_str = key
            .as_str()
            .context("provenance check key must be a string")?;
        let level = CheckLevel::parse(yaml_str(value, key_str)?)?;
        match key_str {
            "reachability" => config.reachability = level,
            "signatures" => config.signatures = level,
            "fresh-commit" => config.fresh_commit = level,
            "tag-age-gap" => config.tag_age_gap = level,
            "repo-reputation" => config.repo_reputation = level,
            "recent-repo" => config.recent_repo = level,
            "transitive" => config.transitive = level,
            "hidden-execution" => config.hidden_execution = level,
            "slsa-attestation" => config.slsa_attestation = level,
            other => bail!("Unknown provenance check `{other}` in policy"),
        }
    }

    Ok(config)
}

pub(super) fn parse_partial_checks(val: &Yaml) -> Result<PartialCheckConfig> {
    let map = val.as_hash().context("checks must be a mapping")?;
    let mut config = PartialCheckConfig::default();

    for (key, value) in map {
        let key_str = key.as_str().context("check key must be a string")?;
        match key_str {
            "expression-injection" => {
                config.expression_injection = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "permissions" => {
                config.permissions = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "secret-exposure" => {
                config.secret_exposure = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "privileged-triggers" => {
                config.privileged_triggers = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "github-env-writes" => {
                config.github_env_writes = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "secrets-inherit" => {
                config.secrets_inherit = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "contains-bypass" => {
                config.contains_bypass = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "persist-credentials" => {
                config.persist_credentials = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "typosquatting" => {
                config.typosquatting = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "untrusted-sources" => {
                config.untrusted_sources = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "cross-workflow" => {
                config.cross_workflow = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "oidc" => {
                config.oidc = Some(CheckLevel::parse(yaml_str(value, key_str)?)?);
            }
            "provenance" => {
                config.provenance = Some(parse_partial_provenance(value)?);
            }
            other => bail!("Unknown check `{other}` in action override"),
        }
    }

    Ok(config)
}

pub(super) fn parse_partial_provenance(val: &Yaml) -> Result<PartialProvenanceConfig> {
    let map = val.as_hash().context("provenance must be a mapping")?;
    let mut config = PartialProvenanceConfig::default();

    for (key, value) in map {
        let key_str = key
            .as_str()
            .context("provenance check key must be a string")?;
        let level = CheckLevel::parse(yaml_str(value, key_str)?)?;
        match key_str {
            "reachability" => config.reachability = Some(level),
            "signatures" => config.signatures = Some(level),
            "fresh-commit" => config.fresh_commit = Some(level),
            "tag-age-gap" => config.tag_age_gap = Some(level),
            "repo-reputation" => config.repo_reputation = Some(level),
            "recent-repo" => config.recent_repo = Some(level),
            "transitive" => config.transitive = Some(level),
            "hidden-execution" => config.hidden_execution = Some(level),
            "slsa-attestation" => config.slsa_attestation = Some(level),
            other => bail!("Unknown provenance check `{other}` in action override"),
        }
    }

    Ok(config)
}

pub(super) fn parse_trust_config(val: &Yaml) -> Result<TrustConfig> {
    let map = val.as_hash().context("trust must be a mapping")?;
    let mut config = TrustConfig::default();

    for (key, value) in map {
        let key_str = key.as_str().context("trust key must be a string")?;
        match key_str {
            "owners" => config.owners = Some(parse_list_override(value, "owners")?),
            "privileged-actions" => {
                config.privileged_actions = Some(parse_list_override(value, "privileged-actions")?);
            }
            "high-impact-secrets" => {
                config.high_impact_secrets =
                    Some(parse_list_override(value, "high-impact-secrets")?);
            }
            other => bail!("Unknown trust key `{other}` in policy"),
        }
    }

    Ok(config)
}

pub(super) fn parse_list_override(val: &Yaml, label: &str) -> Result<ListOverride> {
    let map = val
        .as_hash()
        .context(format!("trust.{label} must be a mapping"))?;

    let mode_key = Yaml::String("mode".to_string());
    let list_key = Yaml::String("list".to_string());

    let mode = map
        .get(&mode_key)
        .and_then(|v| v.as_str())
        .context(format!("trust.{label}.mode is required"))?;
    let mode = ListMode::parse(mode)?;

    let list = map
        .get(&list_key)
        .and_then(|v| v.as_vec())
        .context(format!("trust.{label}.list must be a sequence"))?;

    let items: Vec<String> = list
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    Ok(ListOverride { mode, list: items })
}

pub(super) fn parse_action_override(val: &Yaml) -> Result<ActionOverride> {
    let map = val.as_hash().context("action override must be a mapping")?;

    let match_key = Yaml::String("match".to_string());
    let pin_key = Yaml::String("pin".to_string());
    let age_key = Yaml::String("min-sha-age".to_string());
    let checks_key = Yaml::String("checks".to_string());

    let pattern = map
        .get(&match_key)
        .and_then(|v| v.as_str())
        .context("action override requires a `match` field")?
        .to_lowercase();

    let pin = map
        .get(&pin_key)
        .and_then(|v| v.as_str())
        .map(PinPolicy::parse)
        .transpose()?;

    let min_sha_age = map
        .get(&age_key)
        .and_then(|v| v.as_str())
        .map(parse_duration)
        .transpose()?;

    let checks = map.get(&checks_key).map(parse_partial_checks).transpose()?;

    Ok(ActionOverride {
        pattern,
        pin,
        min_sha_age,
        checks,
    })
}

pub(super) fn parse_suppression(val: &Yaml) -> Result<Suppression> {
    let map = val.as_hash().context("suppression must be a mapping")?;

    let check_key = Yaml::String("check".to_string());
    let match_key = Yaml::String("match".to_string());
    let file_key = Yaml::String("file".to_string());
    let reason_key = Yaml::String("reason".to_string());

    let check = map
        .get(&check_key)
        .and_then(|v| v.as_str())
        .context("suppression requires `check` field")?
        .to_string();

    if !KNOWN_CHECK_NAMES.contains(&check.as_str()) {
        bail!(
            "Unknown check name `{check}` in suppression. Known checks: {}",
            KNOWN_CHECK_NAMES.join(", ")
        );
    }

    let pattern = map
        .get(&match_key)
        .and_then(|v| v.as_str())
        .context("suppression requires `match` field")?
        .to_lowercase();

    let file = map
        .get(&file_key)
        .and_then(|v| v.as_str())
        .map(str::to_lowercase);

    let reason = map
        .get(&reason_key)
        .and_then(|v| v.as_str())
        .context("suppression requires `reason` field")?
        .to_string();

    Ok(Suppression {
        check,
        pattern,
        file,
        reason,
    })
}
