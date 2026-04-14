use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use yaml_rust2::Yaml;

use super::{
    AuditFinding, Severity, find_expressions, high_impact_secret_hints, is_privileged_action,
    is_trusted_owner, key_env, key_jobs, key_name, key_steps, key_uses, key_with, popular_actions,
};

// ─── Untrusted sources ───────────────────────────────────────────────────────

pub(crate) fn check_untrusted_sources(
    refs: &[crate::scanner::ActionRef],
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
    effective_owners: &[String],
) {
    let mut seen: std::collections::HashSet<(&str, &str)> = std::collections::HashSet::new();
    for r in refs {
        if !seen.insert((&r.owner, &r.repo)) {
            continue;
        }
        if !super::is_trusted_owner_in(&r.owner, effective_owners) {
            findings.push(AuditFinding {
                file: r.file.clone(),
                severity: Severity::Medium,
                title: format!("Unverified action source: {}/{}", r.owner, r.repo),
                detail: format!(
                    "Action {}/{} is not from a GitHub-verified publisher. \
                     Verify the source repository is trustworthy before use.",
                    r.owner, r.repo
                ),
                is_warning: level.is_warn(),
            });
        }
    }
}

// ─── Typosquatting ───────────────────────────────────────────────────────────

pub(super) fn check_typosquatting(
    refs: &[crate::scanner::ActionRef],
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    let mut seen = std::collections::HashSet::new();

    // popular_actions() already returns precomputed "owner/repo" strings
    let popular_list = popular_actions();

    // Pre-allocate Levenshtein row buffers, reused across all comparisons
    let max_popular_len = popular_list.iter().map(|s| s.len()).max().unwrap_or(0);
    let mut prev_buf = vec![0_usize; max_popular_len + 1];
    let mut curr_buf = vec![0_usize; max_popular_len + 1];

    for action_ref in refs {
        let candidate_owner = action_ref.owner.to_lowercase();
        let candidate_repo = action_ref.repo.to_lowercase();
        let candidate = format!("{candidate_owner}/{candidate_repo}");
        if candidate.len() > 64 || !seen.insert(candidate.clone()) {
            continue;
        }

        let mut best_match: Option<(Severity, &str)> = None;

        for popular in popular_list.iter().copied() {
            if popular == candidate {
                best_match = None;
                break;
            }

            let distance = bounded_levenshtein(
                candidate.as_bytes(),
                popular.as_bytes(),
                2,
                &mut prev_buf,
                &mut curr_buf,
            );
            if distance == 1 {
                best_match = Some((Severity::High, popular));
                break;
            }

            if distance == 2
                && candidate_repo == popular.split('/').nth(1).unwrap_or("")
                && candidate_owner != popular.split('/').next().unwrap_or("")
                && best_match.is_none()
            {
                best_match = Some((Severity::Medium, popular));
            }
        }

        if let Some((severity, popular)) = best_match {
            findings.push(AuditFinding {
                file: action_ref.file.clone(),
                severity,
                title: format!("Possible typosquatting of popular action `{popular}`"),
                detail: format!(
                    "Action `{candidate}` is edit-distance {} from well-known action \
                     `{popular}`. This is a common typosquatting pattern. Verify the \
                     publisher and repository name very carefully before trusting it.",
                    if severity == Severity::High { 1 } else { 2 }
                ),
                is_warning: level.is_warn(),
            });
        }
    }
}

// ─── Secret exposure ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub(super) struct ExternalActionUse {
    pub(super) owner: String,
    pub(super) repo: String,
    pub(super) path: Option<String>,
    pub(super) original: String,
}

pub(super) fn check_secret_exposure(
    file: &Path,
    doc: &Yaml,
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    let Some(workflow_map) = doc.as_hash() else {
        return;
    };
    let Some(jobs) = workflow_map.get(key_jobs()).and_then(|jobs| jobs.as_hash()) else {
        return;
    };

    let mut workflow_secrets = BTreeMap::new();
    collect_named_credentials(
        workflow_map.get(key_env()),
        "workflow env",
        &mut workflow_secrets,
    );

    for (job_name, job_value) in jobs {
        let Some(job_map) = job_value.as_hash() else {
            continue;
        };
        let job_label = job_name.as_str().unwrap_or("unknown");
        let mut job_secrets = workflow_secrets.clone();
        collect_named_credentials(
            job_map.get(key_env()),
            &format!("jobs.{job_label}.env"),
            &mut job_secrets,
        );

        let Some(steps) = job_map.get(key_steps()).and_then(|steps| steps.as_vec()) else {
            continue;
        };

        for (step_index, step) in steps.iter().enumerate() {
            let Some(step_map) = step.as_hash() else {
                continue;
            };
            let Some(uses) = step_map.get(key_uses()).and_then(|uses| uses.as_str()) else {
                continue;
            };
            let Some(action) = parse_external_action_use(uses) else {
                continue;
            };

            let step_name = step_map
                .get(key_name())
                .and_then(|name| name.as_str())
                .unwrap_or("<unnamed step>");

            let mut visible_secrets = job_secrets.clone();
            collect_named_credentials(
                step_map.get(key_env()),
                &format!("jobs.{job_label}.steps[{step_index}].env"),
                &mut visible_secrets,
            );
            collect_named_credentials(
                step_map.get(key_with()),
                &format!("jobs.{job_label}.steps[{step_index}].with"),
                &mut visible_secrets,
            );

            if visible_secrets.is_empty() {
                continue;
            }

            let secret_names: Vec<String> = visible_secrets.keys().cloned().collect();
            let sources: Vec<String> = visible_secrets
                .values()
                .flat_map(|locations| locations.iter().cloned())
                .collect();
            let severity =
                classify_secret_exposure(&action, &secret_names, is_trusted_owner(&action.owner));
            let title = match severity {
                Severity::Critical => {
                    format!(
                        "High-risk secret exposure to external action `{}`",
                        action.original
                    )
                }
                Severity::High => {
                    format!("Secrets visible to untrusted action `{}`", action.original)
                }
                Severity::Medium => {
                    format!("Secrets visible to external action `{}`", action.original)
                }
            };

            findings.push(AuditFinding {
                file: file.to_path_buf(),
                severity,
                title,
                detail: format!(
                    "Step \"{step_name}\" exposes credential(s) {} to `{}` via {}. \
                     That action inherits these values for its full execution lifetime, \
                     including any pre/post hooks or internal composite steps. Move secrets \
                     to the narrowest possible step, prefer trusted publishers, and avoid \
                     passing high-impact publish or deploy credentials to third-party actions.",
                    secret_names.join(", "),
                    action.original,
                    sources.join(", ")
                ),
                is_warning: level.is_warn(),
            });
        }
    }
}

pub(super) fn classify_secret_exposure(
    action: &ExternalActionUse,
    secret_names: &[String],
    trusted_owner: bool,
) -> Severity {
    let high_impact_secret = secret_names.iter().any(|name| is_high_impact_secret(name));
    let privileged_action =
        is_privileged_action(&action.owner, &action.repo, action.path.as_deref());

    if !trusted_owner && (privileged_action || high_impact_secret) {
        Severity::Critical
    } else if !trusted_owner {
        Severity::High
    } else {
        Severity::Medium
    }
}

pub(super) fn is_high_impact_secret(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    high_impact_secret_hints()
        .iter()
        .any(|hint| upper.contains(hint))
}

pub(super) fn collect_named_credentials(
    value: Option<&Yaml>,
    source_prefix: &str,
    out: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let Some(map) = value.and_then(|value| value.as_hash()) else {
        return;
    };

    for (key, value) in map {
        let field = key.as_str().unwrap_or("unknown");
        collect_credentials_from_value(value, &format!("{source_prefix}.{field}"), out);
    }
}

pub(super) fn collect_credentials_from_value(
    value: &Yaml,
    source: &str,
    out: &mut BTreeMap<String, BTreeSet<String>>,
) {
    #[allow(clippy::wildcard_enum_match_arm)] // Yaml has many non-map/array/string variants
    match value {
        Yaml::String(text) => {
            for secret in extract_credential_names(text) {
                out.entry(secret).or_default().insert(source.to_string());
            }
        }
        Yaml::Array(items) => {
            for item in items {
                collect_credentials_from_value(item, source, out);
            }
        }
        Yaml::Hash(map) => {
            for (key, nested) in map {
                let field = key.as_str().unwrap_or("unknown");
                collect_credentials_from_value(nested, &format!("{source}.{field}"), out);
            }
        }
        _ => {}
    }
}

pub(super) fn extract_credential_names(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for expr in find_expressions(text) {
        let trimmed = expr.trim();
        if let Some(secret) = extract_context_name(trimmed, "secrets") {
            names.insert(secret);
        }
        if trimmed.contains("github.token") {
            names.insert("GITHUB_TOKEN".to_string());
        }
    }
    names
}

pub(super) fn extract_context_name(expr: &str, context: &str) -> Option<String> {
    let dotted = format!("{context}.");
    if let Some(start) = expr.find(&dotted) {
        let name = &expr[start + dotted.len()..];
        let end = name
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(name.len());
        let name = &name[..end];
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    for opener in [format!("{context}['"), format!("{context}[\"")] {
        if let Some(start) = expr.find(&opener) {
            let rest = &expr[start + opener.len()..];
            let terminator = if opener.ends_with('\'') { '\'' } else { '"' };
            let end = rest.find(terminator)?;
            let name = &rest[..end];
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }

    None
}

pub(super) fn parse_external_action_use(uses: &str) -> Option<ExternalActionUse> {
    if uses.starts_with("docker://") || uses.starts_with("./") || uses.starts_with("../") {
        return None;
    }

    let at = uses.find('@')?;
    let repo_part = &uses[..at];
    let mut segments = repo_part.splitn(3, '/');
    let owner = segments.next()?.trim();
    let repo = segments.next()?.trim();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }

    Some(ExternalActionUse {
        owner: owner.to_string(),
        repo: repo.to_string(),
        path: segments.next().map(str::trim).map(str::to_string),
        original: uses.to_string(),
    })
}

pub(super) fn bounded_levenshtein(
    a: &[u8],
    b: &[u8],
    limit: usize,
    prev: &mut Vec<usize>,
    curr: &mut Vec<usize>,
) -> usize {
    if a == b {
        return 0;
    }

    // No truncation needed — the caller already rejects candidates > 64 chars,
    // and popular action strings are well under 64 chars.
    if a.len().abs_diff(b.len()) > limit {
        return limit + 1;
    }

    prev.resize(b.len() + 1, 0);
    for (i, val) in prev.iter_mut().enumerate() {
        *val = i;
    }
    curr.resize(b.len() + 1, 0);

    for (i, &a_byte) in a.iter().enumerate() {
        curr[0] = i + 1;
        let mut row_min = curr[0];

        for (j, &b_byte) in b.iter().enumerate() {
            let cost = usize::from(a_byte != b_byte);
            curr[j + 1] =
                std::cmp::min(std::cmp::min(prev[j + 1] + 1, curr[j] + 1), prev[j] + cost);
            row_min = row_min.min(curr[j + 1]);
        }

        if row_min > limit {
            return limit + 1;
        }

        std::mem::swap(prev, curr);
    }

    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::super::tests_common::{action_ref, run_audit};
    use super::super::{Severity, run};
    use super::extract_credential_names;

    #[test]
    fn flags_high_confidence_typosquatting() {
        let findings = run(
            &[],
            &[
                action_ref("action", "checkout"),
                action_ref("actions", "checkout"),
            ],
            &crate::policy::CheckConfig::default(),
        );

        assert!(findings.iter().any(|finding| {
            finding.severity == Severity::High
                && finding.title.contains("Possible typosquatting")
                && finding.detail.contains("action/checkout")
        }));
    }

    #[test]
    fn flags_medium_owner_only_typosquatting() {
        let findings = run(
            &[],
            &[action_ref("acti0nss", "checkout")],
            &crate::policy::CheckConfig::default(),
        );

        assert!(findings.iter().any(|finding| {
            finding.severity == Severity::Medium
                && finding.title.contains("Possible typosquatting")
                && finding.detail.contains("actions/checkout")
        }));
    }

    #[test]
    fn flags_secret_exposure_to_untrusted_action() {
        let findings = run_audit(
            "
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    env:
      PYPI_PUBLISH_TOKEN: ${{ secrets.PYPI_PUBLISH_TOKEN }}
    steps:
      - name: Scan
        uses: sneaky/security-scan@0123456789012345678901234567890123456789
",
        );

        assert!(findings.iter().any(|finding| {
            finding.severity == Severity::Critical
                && finding.title.contains("secret exposure")
                && finding.detail.contains("PYPI_PUBLISH_TOKEN")
        }));
    }

    #[test]
    fn extracts_secret_names_from_dot_and_bracket_contexts() {
        let names = extract_credential_names(
            "${{ secrets.PYPI_TOKEN }} ${{ secrets['AWS_ROLE'] }} ${{ github.token }}",
        );

        assert!(names.contains("PYPI_TOKEN"));
        assert!(names.contains("AWS_ROLE"));
        assert!(names.contains("GITHUB_TOKEN"));
    }
}
