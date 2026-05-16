//! OIDC trust-policy parsing.
//!
//! Extracts normalized `OidcAcceptance` records from cloud provider trust
//! policies (AWS IAM, GCP Workload Identity Federation, Azure federated
//! credentials) so the audit layer can cross-check them against the
//! workflows that mint GitHub Actions OIDC tokens.

use crate::error::{Context, Result, bail};
use std::path::{Path, PathBuf};
use yaml_rust2::YamlLoader;

pub(crate) mod aws;
pub(crate) mod azure;
pub(crate) mod gcp;

const MAX_POLICY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OidcProvider {
    Aws,
    Gcp,
    Azure,
}

impl OidcProvider {
    pub(crate) fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aws" => Ok(Self::Aws),
            "gcp" | "google" => Ok(Self::Gcp),
            "azure" | "microsoft" => Ok(Self::Azure),
            other => bail!("Unknown OIDC provider `{other}`: expected aws, gcp, or azure"),
        }
    }
}

impl std::fmt::Display for OidcProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => write!(f, "aws"),
            Self::Gcp => write!(f, "gcp"),
            Self::Azure => write!(f, "azure"),
        }
    }
}

/// A normalized record of "what GitHub OIDC tokens does this trust policy accept".
#[derive(Debug, Clone)]
pub(crate) struct OidcAcceptance {
    pub(crate) provider: OidcProvider,
    pub(crate) file: PathBuf,
    /// Zero or more accepted `sub` patterns. Multi-value because AWS
    /// `StringLike` conditions can take arrays.
    pub(crate) sub_patterns: Vec<SubPattern>,
    /// Accepted audience claims. Empty = no `aud` constraint (dangerous).
    pub(crate) audiences: Vec<String>,
    /// Free-text description of where in the policy this acceptance came from
    /// (statement index, etc.), used in findings.
    pub(crate) location: String,
}

/// A decomposed view of a GitHub OIDC `sub` pattern like
/// `repo:org/repo:ref:refs/heads/main` or `repo:org/*:environment:prod`.
#[derive(Debug, Clone)]
pub(crate) struct SubPattern {
    pub(crate) raw: String,
    /// `org` or `org/repo` with optional `*` wildcards.
    pub(crate) repo: GlobToken,
    /// `ref`, `environment`, `pull_request`, or unqualified.
    pub(crate) kind: SubKind,
    /// `refs/heads/main`, `prod`, etc. — None when the sub has no kind-specific suffix.
    pub(crate) value: Option<GlobToken>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubKind {
    Ref,
    Environment,
    PullRequest,
    /// `repo:org/repo:job_workflow_ref:...`
    JobWorkflowRef,
    /// Any other suffix we don't model precisely.
    Other(String),
    /// No suffix — bare `repo:org/repo:*`.
    Any,
}

/// A glob pattern that's either an exact literal, `*` (any within a segment),
/// or a mix (`my-repo-*`, `*-prod`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobToken {
    pub(crate) raw: String,
}

impl GlobToken {
    pub(crate) fn new(s: impl Into<String>) -> Self {
        Self { raw: s.into() }
    }

    pub(crate) fn is_wildcard(&self) -> bool {
        self.raw == "*"
    }

    pub(crate) fn contains_wildcard(&self) -> bool {
        self.raw.contains('*')
    }
}

impl SubPattern {
    /// Parse a GitHub OIDC sub pattern like `repo:org/repo:ref:refs/heads/main`
    /// or `repo:my-org/*:*`.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        // Strip `repo:` prefix.
        let rest = raw.strip_prefix("repo:")?;

        // Find the first colon after the repo portion. But the repo itself may
        // be `org/repo` with no colon; just split on the first ':' after the
        // initial `repo:` prefix.
        let (repo_str, rest) = rest.find(':').map_or(
            (rest, None),
            |idx| (&rest[..idx], Some(&rest[idx + 1..])),
        );

        let repo = GlobToken::new(repo_str);

        let Some(rest) = rest else {
            return Some(Self {
                raw: raw.to_string(),
                repo,
                kind: SubKind::Any,
                value: None,
            });
        };

        // Case `repo:org/repo:*`
        if rest == "*" {
            return Some(Self {
                raw: raw.to_string(),
                repo,
                kind: SubKind::Any,
                value: Some(GlobToken::new("*")),
            });
        }

        // Split kind/value on first colon.
        let (kind_str, value_str) = rest.find(':').map_or(
            (rest, None),
            |idx| (&rest[..idx], Some(&rest[idx + 1..])),
        );
        let kind = match kind_str {
            "ref" => SubKind::Ref,
            "environment" => SubKind::Environment,
            "pull_request" => SubKind::PullRequest,
            "job_workflow_ref" => SubKind::JobWorkflowRef,
            other => SubKind::Other(other.to_string()),
        };
        let value = value_str.map(GlobToken::new);
        Some(Self {
            raw: raw.to_string(),
            repo,
            kind,
            value,
        })
    }
}

/// Load and parse an OIDC trust policy from disk.
pub(crate) fn load_trust_policy(
    provider: OidcProvider,
    path: &Path,
) -> Result<Vec<OidcAcceptance>> {
    let meta = std::fs::metadata(path)
        .context(format!("Cannot stat OIDC policy {}", path.display()))?;
    if meta.len() > MAX_POLICY_BYTES {
        bail!(
            "OIDC policy file {} is too large ({} bytes, max {} bytes)",
            path.display(),
            meta.len(),
            MAX_POLICY_BYTES
        );
    }
    let text = std::fs::read_to_string(path)
        .context(format!("Cannot read OIDC policy {}", path.display()))?;

    // yaml-rust2 parses JSON as a degenerate YAML 1.2 flow document.
    let docs = YamlLoader::load_from_str(&text)
        .context(format!("Invalid JSON/YAML in {}", path.display()))?;
    let doc = docs.into_iter().next().context(format!(
        "Empty policy document in {}",
        path.display()
    ))?;

    match provider {
        OidcProvider::Aws => aws::parse(&doc, path),
        OidcProvider::Gcp => gcp::parse(&doc, path),
        OidcProvider::Azure => azure::parse(&doc, path),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_sub_pattern_with_ref() {
        let s = SubPattern::parse("repo:my-org/my-repo:ref:refs/heads/main").unwrap();
        assert_eq!(s.repo.raw, "my-org/my-repo");
        assert_eq!(s.kind, SubKind::Ref);
        assert_eq!(s.value.as_ref().map(|g| g.raw.as_str()), Some("refs/heads/main"));
    }

    #[test]
    fn parse_sub_pattern_with_environment() {
        let s = SubPattern::parse("repo:my-org/my-repo:environment:production").unwrap();
        assert_eq!(s.kind, SubKind::Environment);
    }

    #[test]
    fn parse_sub_pattern_wildcard() {
        let s = SubPattern::parse("repo:my-org/*:*").unwrap();
        assert!(s.repo.contains_wildcard());
        assert_eq!(s.kind, SubKind::Any);
    }

    #[test]
    fn parse_provider() {
        assert_eq!(OidcProvider::parse("aws").unwrap(), OidcProvider::Aws);
        assert_eq!(OidcProvider::parse("AWS").unwrap(), OidcProvider::Aws);
        assert_eq!(OidcProvider::parse("gcp").unwrap(), OidcProvider::Gcp);
        assert_eq!(OidcProvider::parse("google").unwrap(), OidcProvider::Gcp);
        assert_eq!(OidcProvider::parse("azure").unwrap(), OidcProvider::Azure);
        OidcProvider::parse("aliyun").expect_err("unknown provider");
    }
}
