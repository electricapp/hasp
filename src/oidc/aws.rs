//! AWS IAM trust-policy parser for GitHub OIDC federation.
//!
//! Shape:
//! ```json
//! {
//!   "Version": "2012-10-17",
//!   "Statement": [
//!     {
//!       "Effect": "Allow",
//!       "Principal": { "Federated": "arn:aws:iam::...:oidc-provider/token.actions.githubusercontent.com" },
//!       "Action": "sts:AssumeRoleWithWebIdentity",
//!       "Condition": {
//!         "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
//!         "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:org/*:*" }
//!       }
//!     }
//!   ]
//! }
//! ```

use crate::error::Result;
use std::path::Path;
use yaml_rust2::Yaml;

use super::{OidcAcceptance, OidcProvider, SubPattern};

const GH_ISSUER_SUFFIX: &str = "token.actions.githubusercontent.com";
const SUB_KEY: &str = "token.actions.githubusercontent.com:sub";
const AUD_KEY: &str = "token.actions.githubusercontent.com:aud";

#[allow(clippy::unnecessary_wraps)] // uniform signature with gcp/azure
pub(crate) fn parse(doc: &Yaml, path: &Path) -> Result<Vec<OidcAcceptance>> {
    let Some(map) = doc.as_hash() else {
        return Ok(Vec::new());
    };

    let statements = map
        .get(&Yaml::String("Statement".to_string()))
        .and_then(Yaml::as_vec)
        .cloned()
        .unwrap_or_default();

    let mut acceptances = Vec::new();

    for (idx, stmt) in statements.iter().enumerate() {
        let Some(stmt_map) = stmt.as_hash() else {
            continue;
        };

        let effect = stmt_map
            .get(&Yaml::String("Effect".to_string()))
            .and_then(Yaml::as_str)
            .unwrap_or("");
        if effect != "Allow" {
            continue;
        }

        // Only interested in statements that federate GitHub's issuer.
        if !statement_trusts_github(stmt_map) {
            continue;
        }

        let (sub_patterns, audiences) = extract_conditions(stmt_map);

        // A statement with no sub constraint at all is maximally permissive.
        let sub_patterns = if sub_patterns.is_empty() {
            vec![SubPattern {
                raw: "<no sub constraint>".to_string(),
                repo: super::GlobToken::new("*"),
                kind: super::SubKind::Any,
                value: Some(super::GlobToken::new("*")),
            }]
        } else {
            sub_patterns
        };

        acceptances.push(OidcAcceptance {
            provider: OidcProvider::Aws,
            file: path.to_path_buf(),
            sub_patterns,
            audiences,
            location: format!("Statement[{idx}]"),
        });
    }

    Ok(acceptances)
}

fn statement_trusts_github(stmt: &yaml_rust2::yaml::Hash) -> bool {
    let Some(principal) = stmt.get(&Yaml::String("Principal".to_string())) else {
        return false;
    };

    // Principal can be {Federated: "arn..."} or {Federated: ["arn1", "arn2"]}
    let Some(principal_map) = principal.as_hash() else {
        return false;
    };
    let Some(federated) = principal_map.get(&Yaml::String("Federated".to_string())) else {
        return false;
    };

    #[allow(clippy::wildcard_enum_match_arm)]
    match federated {
        Yaml::String(s) => s.contains(GH_ISSUER_SUFFIX),
        Yaml::Array(arr) => arr
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s.contains(GH_ISSUER_SUFFIX))),
        _ => false,
    }
}

fn extract_conditions(stmt: &yaml_rust2::yaml::Hash) -> (Vec<SubPattern>, Vec<String>) {
    let mut sub_patterns = Vec::new();
    let mut audiences = Vec::new();

    let Some(condition) = stmt.get(&Yaml::String("Condition".to_string())) else {
        return (sub_patterns, audiences);
    };
    let Some(condition_map) = condition.as_hash() else {
        return (sub_patterns, audiences);
    };

    // Walk all operator blocks. `StringEquals`, `StringLike`, `ForAllValues:*`,
    // `ForAnyValue:*` are the common ones. We treat Equals and Like uniformly
    // for sub-pattern extraction; wildcards in Equals values would be literal,
    // but that's still within our breadth-check logic.
    for (_op, op_value) in condition_map {
        let Some(op_map) = op_value.as_hash() else {
            continue;
        };
        for (key, value) in op_map {
            let Some(key_str) = key.as_str() else {
                continue;
            };
            let values = collect_strings(value);
            if key_str == SUB_KEY {
                for raw in values {
                    if let Some(sp) = SubPattern::parse(&raw) {
                        sub_patterns.push(sp);
                    }
                }
            } else if key_str == AUD_KEY {
                audiences.extend(values);
            }
        }
    }

    (sub_patterns, audiences)
}

fn collect_strings(value: &Yaml) -> Vec<String> {
    #[allow(clippy::wildcard_enum_match_arm)]
    match value {
        Yaml::String(s) => vec![s.clone()],
        Yaml::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
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
        parse(&doc, &PathBuf::from("trust.json")).unwrap()
    }

    #[test]
    fn extracts_aws_sub_and_aud() {
        let acceptances = parse_text(
            r#"{
              "Version": "2012-10-17",
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com" },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                  "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
                  "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:*" }
                }
              }]
            }"#,
        );
        assert_eq!(acceptances.len(), 1);
        assert_eq!(acceptances[0].audiences, vec!["sts.amazonaws.com"]);
        assert_eq!(acceptances[0].sub_patterns.len(), 1);
        assert_eq!(acceptances[0].sub_patterns[0].repo.raw, "my-org/my-repo");
    }

    #[test]
    fn ignores_deny_statements() {
        let acceptances = parse_text(
            r#"{
              "Statement": [{
                "Effect": "Deny",
                "Principal": { "Federated": "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com" },
                "Condition": { "StringLike": { "token.actions.githubusercontent.com:sub": "repo:evil/*:*" } }
              }]
            }"#,
        );
        assert!(acceptances.is_empty());
    }

    #[test]
    fn ignores_non_github_federations() {
        let acceptances = parse_text(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::123:oidc-provider/gitlab.com" },
                "Condition": { "StringLike": { "sub": "repo:group/proj:*" } }
              }]
            }"#,
        );
        assert!(acceptances.is_empty());
    }

    #[test]
    fn array_sub_and_aud_values() {
        let acceptances = parse_text(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com" },
                "Condition": {
                  "StringEquals": { "token.actions.githubusercontent.com:aud": ["aud-a", "aud-b"] },
                  "StringLike":   { "token.actions.githubusercontent.com:sub": ["repo:a/b:*", "repo:c/d:*"] }
                }
              }]
            }"#,
        );
        assert_eq!(acceptances.len(), 1);
        assert_eq!(acceptances[0].audiences.len(), 2);
        assert_eq!(acceptances[0].sub_patterns.len(), 2);
    }

    #[test]
    fn missing_sub_yields_wildcard_acceptance() {
        let acceptances = parse_text(
            r#"{
              "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com" }
              }]
            }"#,
        );
        assert_eq!(acceptances.len(), 1);
        assert!(acceptances[0].sub_patterns[0].repo.is_wildcard());
        assert!(acceptances[0].audiences.is_empty());
    }
}
