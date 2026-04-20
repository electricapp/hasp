//! GCP Workload Identity Federation provider parser.
//!
//! Two common JSON shapes exist:
//!
//! 1. The `gcloud iam workload-identity-pools providers describe` output
//!    (has `name`, `oidc`, `attributeCondition`, `attributeMapping`).
//! 2. The Terraform-generated provider resource representation
//!    (same fields under different casing in some tools).
//!
//! We parse the common case: an object with `oidc.allowedAudiences` and an
//! `attributeCondition` CEL expression. The CEL expression is parsed lightly
//! to extract repository/ref literal equality checks — enough to determine
//! whether the provider over-accepts patterns.

use crate::error::Result;
use std::path::Path;
use yaml_rust2::Yaml;

use super::{GlobToken, OidcAcceptance, OidcProvider, SubKind, SubPattern};

#[allow(clippy::unnecessary_wraps)] // uniform signature with aws/azure
pub(crate) fn parse(doc: &Yaml, path: &Path) -> Result<Vec<OidcAcceptance>> {
    let Some(map) = doc.as_hash() else {
        return Ok(Vec::new());
    };

    // Audiences
    let audiences = map
        .get(&Yaml::String("oidc".to_string()))
        .and_then(Yaml::as_hash)
        .and_then(|oidc| oidc.get(&Yaml::String("allowedAudiences".to_string())))
        .and_then(Yaml::as_vec)
        .map(|vec| {
            vec.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let condition = map
        .get(&Yaml::String("attributeCondition".to_string()))
        .and_then(Yaml::as_str)
        .unwrap_or("");

    let sub_patterns = parse_attribute_condition(condition);

    // If no attributeCondition is set AND no sub patterns, this provider
    // accepts any GitHub OIDC token — flag as wildcard.
    let sub_patterns = if sub_patterns.is_empty() {
        vec![SubPattern {
            raw: condition.to_string(),
            repo: GlobToken::new("*"),
            kind: SubKind::Any,
            value: Some(GlobToken::new("*")),
        }]
    } else {
        sub_patterns
    };

    Ok(vec![OidcAcceptance {
        provider: OidcProvider::Gcp,
        file: path.to_path_buf(),
        sub_patterns,
        audiences,
        location: "attributeCondition".to_string(),
    }])
}

/// Parse a CEL-ish attribute condition for GitHub identity constraints.
///
/// We recognize the conjunction-of-equalities form that `gcloud` emits:
/// `assertion.repository=='org/repo' && assertion.ref=='refs/heads/main'`
/// and their `== "..."` / `in [...]` variants. Anything we don't recognize
/// degrades to a wildcard (conservative for breadth-checking).
fn parse_attribute_condition(cond: &str) -> Vec<SubPattern> {
    if cond.trim().is_empty() {
        return Vec::new();
    }

    let mut repo: Option<String> = None;
    let mut ref_value: Option<String> = None;
    let mut env_value: Option<String> = None;

    for term in cond.split("&&") {
        let term = term.trim();
        if let Some((lhs, rhs)) = split_eq(term) {
            let value = strip_quotes(rhs);
            let lhs = lhs.trim();
            if lhs.ends_with("repository") {
                repo = Some(value);
            } else if lhs.ends_with("ref") {
                ref_value = Some(value);
            } else if lhs.ends_with("environment") {
                env_value = Some(value);
            }
        }
    }

    let Some(repo) = repo else {
        // No repo pin at all. Treat as wildcard.
        return Vec::new();
    };

    let repo = GlobToken::new(repo);
    if let Some(value) = ref_value {
        return vec![SubPattern {
            raw: cond.to_string(),
            repo,
            kind: SubKind::Ref,
            value: Some(GlobToken::new(value)),
        }];
    }
    if let Some(value) = env_value {
        return vec![SubPattern {
            raw: cond.to_string(),
            repo,
            kind: SubKind::Environment,
            value: Some(GlobToken::new(value)),
        }];
    }
    vec![SubPattern {
        raw: cond.to_string(),
        repo,
        kind: SubKind::Any,
        value: None,
    }]
}

fn split_eq(term: &str) -> Option<(&str, &str)> {
    // Prefer `==` over `=` to avoid matching `>=` etc.
    term.find("==").map(|idx| (&term[..idx], &term[idx + 2..]))
}

fn strip_quotes(s: &str) -> String {
    let trimmed = s.trim();
    if (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with('"') && trimmed.ends_with('"'))
    {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use yaml_rust2::YamlLoader;

    fn parse_text(src: &str) -> Vec<OidcAcceptance> {
        let doc = YamlLoader::load_from_str(src).unwrap().remove(0);
        parse(&doc, &PathBuf::from("wif.json")).unwrap()
    }

    #[test]
    fn extracts_repo_and_ref_from_condition() {
        let acceptances = parse_text(
            r#"{
              "name": "projects/123/locations/global/workloadIdentityPools/p/providers/gh",
              "oidc": { "allowedAudiences": ["https://iam.googleapis.com/..."] },
              "attributeCondition": "assertion.repository=='my-org/my-repo' && assertion.ref=='refs/heads/main'"
            }"#,
        );
        assert_eq!(acceptances.len(), 1);
        let sp = &acceptances[0].sub_patterns[0];
        assert_eq!(sp.repo.raw, "my-org/my-repo");
        assert_eq!(sp.kind, SubKind::Ref);
        assert_eq!(
            sp.value.as_ref().map(|g| g.raw.as_str()),
            Some("refs/heads/main")
        );
    }

    #[test]
    fn missing_attribute_condition_is_wildcard() {
        let acceptances = parse_text(
            r#"{
              "oidc": { "allowedAudiences": ["aud"] }
            }"#,
        );
        assert_eq!(acceptances.len(), 1);
        assert!(acceptances[0].sub_patterns[0].repo.is_wildcard());
    }

    #[test]
    fn repository_without_ref_is_any() {
        let acceptances = parse_text(
            r#"{
              "oidc": { "allowedAudiences": ["aud"] },
              "attributeCondition": "assertion.repository=='my-org/my-repo'"
            }"#,
        );
        assert_eq!(acceptances.len(), 1);
        assert_eq!(acceptances[0].sub_patterns[0].kind, SubKind::Any);
    }
}
