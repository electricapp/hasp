//! Azure federated identity credential parser.
//!
//! Shape:
//! ```json
//! {
//!   "name": "gh-actions",
//!   "issuer": "https://token.actions.githubusercontent.com",
//!   "subject": "repo:my-org/my-repo:ref:refs/heads/main",
//!   "audiences": ["api://AzureADTokenExchange"]
//! }
//! ```
//!
//! Some tenants return an array under `value:` -- we handle either top-level
//! shape. A single `subject` is exact (no wildcards) -- Azure does not support
//! glob patterns the way AWS `StringLike` does -- but we still model it as a
//! `SubPattern` so the breadth-check code is uniform.

use crate::error::Result;
use std::path::Path;
use yaml_rust2::Yaml;

use super::{OidcAcceptance, OidcProvider, SubPattern};

const GH_ISSUER: &str = "token.actions.githubusercontent.com";

#[allow(clippy::unnecessary_wraps)] // uniform signature with aws/gcp
pub(crate) fn parse(doc: &Yaml, path: &Path) -> Result<Vec<OidcAcceptance>> {
    let entries = collect_entries(doc);
    let mut acceptances = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        let Some(map) = entry.as_hash() else { continue };

        let issuer = map
            .get(&Yaml::String("issuer".to_string()))
            .and_then(Yaml::as_str)
            .unwrap_or("");
        if !issuer.contains(GH_ISSUER) {
            continue;
        }

        let subject = map
            .get(&Yaml::String("subject".to_string()))
            .and_then(Yaml::as_str)
            .unwrap_or("");

        let audiences = map
            .get(&Yaml::String("audiences".to_string()))
            .and_then(Yaml::as_vec)
            .map(|vec| {
                vec.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let sub_patterns = if let Some(sp) = SubPattern::parse(subject) {
            vec![sp]
        } else {
            continue;
        };

        acceptances.push(OidcAcceptance {
            provider: OidcProvider::Azure,
            file: path.to_path_buf(),
            sub_patterns,
            audiences,
            location: format!("credential[{idx}]"),
        });
    }

    Ok(acceptances)
}

fn collect_entries(doc: &Yaml) -> Vec<Yaml> {
    // Array of credentials at top level, or { "value": [...] } Graph API shape.
    if let Some(arr) = doc.as_vec() {
        return arr.clone();
    }
    if let Some(map) = doc.as_hash() {
        if let Some(arr) = map
            .get(&Yaml::String("value".to_string()))
            .and_then(Yaml::as_vec)
        {
            return arr.clone();
        }
        return vec![doc.clone()];
    }
    Vec::new()
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
        parse(&doc, &PathBuf::from("azure.json")).unwrap()
    }

    #[test]
    fn extracts_single_credential() {
        let acceptances = parse_text(
            r#"{
              "issuer": "https://token.actions.githubusercontent.com",
              "subject": "repo:my-org/my-repo:environment:production",
              "audiences": ["api://AzureADTokenExchange"]
            }"#,
        );
        assert_eq!(acceptances.len(), 1);
        assert_eq!(acceptances[0].sub_patterns[0].repo.raw, "my-org/my-repo");
        assert_eq!(
            acceptances[0].sub_patterns[0].kind,
            super::super::SubKind::Environment
        );
    }

    #[test]
    fn extracts_graph_api_array() {
        let acceptances = parse_text(
            r#"{
              "value": [
                {
                  "issuer": "https://token.actions.githubusercontent.com",
                  "subject": "repo:a/b:ref:refs/heads/main",
                  "audiences": ["api://AzureADTokenExchange"]
                },
                {
                  "issuer": "https://token.actions.githubusercontent.com",
                  "subject": "repo:a/c:environment:prod",
                  "audiences": ["api://AzureADTokenExchange"]
                }
              ]
            }"#,
        );
        assert_eq!(acceptances.len(), 2);
    }

    #[test]
    fn skips_non_github_issuer() {
        let acceptances = parse_text(
            r#"{
              "issuer": "https://token.actions.gitlab.com",
              "subject": "project:a",
              "audiences": ["aud"]
            }"#,
        );
        assert!(acceptances.is_empty());
    }
}
