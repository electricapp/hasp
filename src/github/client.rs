use crate::error::{Context, Result, bail};
use crate::token::{SecureToken, scrub_string};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
use yaml_rust2::Yaml;

use super::json::{
    api_url, find_tag_in_parsed_list, key_author, key_commit, key_committer, key_date, key_status,
    key_verification, key_verified, parse_compare_response, parse_contents_body,
    parse_git_ref_target, parse_git_tag_info, parse_json_doc, parse_repo_info, spki_hash,
    yaml_field_cached,
};

// ─── Result types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoInfo {
    pub(crate) default_branch: String,
    pub(crate) created_at: Option<String>,
    pub(crate) stargazers_count: Option<u64>,
    pub(crate) forks_count: Option<u64>,
}

impl RepoInfo {
    pub(super) fn fallback() -> Self {
        Self {
            default_branch: "main".to_string(),
            created_at: None,
            stargazers_count: None,
            forks_count: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompareResult {
    pub(crate) owner: String,
    pub(crate) repo: String,
    pub(crate) old_sha: String,
    pub(crate) new_sha: String,
    pub(crate) ahead_by: u32,
    pub(crate) files_changed: u32,
    pub(crate) commit_summaries: Vec<String>,
    pub(crate) html_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReachabilityStatus {
    /// Commit is an ancestor of the default branch
    Reachable,
    /// Commit is ahead of the default branch (e.g. unreleased, PR)
    Ahead,
    /// Commit history has diverged — possible orphaned fork commit
    Diverged,
    /// Commit not reachable at all (404 from compare API)
    Unreachable,
}

pub(crate) trait Api {
    fn verify_commit(&self, owner: &str, repo: &str, sha: &str) -> Result<bool>;
    fn resolve_tag(&self, owner: &str, repo: &str, tag: &str) -> Result<Option<String>>;
    fn find_tag_for_sha(&self, owner: &str, repo: &str, sha: &str) -> Option<String>;
    fn get_repo_info(&self, owner: &str, repo: &str) -> Result<RepoInfo>;
    fn is_commit_reachable(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        default_branch: &str,
    ) -> Result<ReachabilityStatus>;
    fn is_commit_signed(&self, owner: &str, repo: &str, sha: &str) -> Result<bool>;
    fn get_commit_date(&self, owner: &str, repo: &str, sha: &str) -> Result<Option<String>>;
    fn get_tag_creation_date(&self, owner: &str, repo: &str, tag: &str) -> Result<Option<String>>;
    fn get_action_yml(
        &self,
        owner: &str,
        repo: &str,
        path: Option<&str>,
        sha: &str,
    ) -> Result<Option<String>>;
    fn compare_commits(
        &self,
        owner: &str,
        repo: &str,
        base: &str,
        head: &str,
    ) -> Result<CompareResult>;
}

// ─── Internal types ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub(super) struct CommitMetadata {
    pub(super) verified: bool,
    pub(super) authored_date: Option<String>,
}

#[derive(Clone)]
pub(super) struct AnnotatedTagInfo {
    pub(super) object_sha: String,
    pub(super) tagger_date: Option<String>,
}

// ─── TLS pinning ─────────────────────────────────────────────────────────────

pub(super) const PINNED_SPKI_HASHES: &[[u8; 32]] = &[
    [
        0xb6, 0xdf, 0x51, 0x92, 0xc7, 0x52, 0x04, 0x68, 0xa2, 0x79, 0x38, 0xb2, 0x5a, 0x45, 0x3c,
        0x83, 0x73, 0x0e, 0x98, 0x2a, 0xdf, 0x31, 0xcb, 0xd7, 0x0c, 0x60, 0xb8, 0x64, 0x02, 0xec,
        0xf6, 0xb8,
    ],
    [
        0x65, 0x26, 0xa0, 0xbc, 0x3c, 0xe3, 0x96, 0xd2, 0xe4, 0x7b, 0x05, 0xc4, 0x06, 0xe0, 0xf1,
        0x23, 0x3a, 0x56, 0xfd, 0xda, 0x55, 0xc3, 0x52, 0x6e, 0xbe, 0xf9, 0x9d, 0xd2, 0x18, 0x64,
        0xcd, 0xd6,
    ],
    [
        0xb0, 0xb5, 0x63, 0x35, 0x46, 0x85, 0x61, 0xf5, 0xbb, 0x9f, 0xa1, 0x2d, 0x80, 0x17, 0x84,
        0xa6, 0x33, 0xa5, 0x72, 0x70, 0x5d, 0x34, 0xf3, 0x2b, 0x64, 0x34, 0x45, 0xdf, 0xa8, 0xb0,
        0x05, 0xd1,
    ],
];

/// Pre-resolve api.github.com before Landlock denies reads.
pub(crate) fn pre_resolve_api() -> Result<Vec<SocketAddr>> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = "api.github.com:443"
        .to_socket_addrs()
        .context("Failed to resolve api.github.com")?
        .collect();
    if addrs.is_empty() {
        bail!("api.github.com did not resolve to any addresses");
    }
    Ok(addrs)
}

/// Restrict this HTTP client to api.github.com DNS resolution.
/// This reduces accidental egress through `ureq`, but it is not a substitute
/// for syscall-level network confinement.
struct PinnedResolver {
    addrs: Vec<SocketAddr>,
}

#[derive(Debug)]
struct PinnedCertVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        let mut chain = Vec::with_capacity(intermediates.len() + 1);
        chain.push(end_entity);
        chain.extend(intermediates.iter());

        if chain
            .into_iter()
            .filter_map(|cert| spki_hash(cert).ok())
            .any(|hash| PINNED_SPKI_HASHES.contains(&hash))
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "api.github.com certificate chain did not match pinned SPKI set".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

impl ureq::Resolver for PinnedResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        if netloc.starts_with("api.github.com:") {
            Ok(self.addrs.clone())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("DNS denied: only api.github.com is allowed, got {netloc}"),
            ))
        }
    }
}

/// Create a pinned TLS configuration for GitHub API/releases.
/// This applies SPKI pinning and strips proxy environment variables.
pub(crate) fn create_github_pinned_tls_config() -> Result<Arc<rustls::ClientConfig>> {
    // Strip proxy env vars to prevent MITM via environment manipulation.
    for var in &[
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        // SAFETY: called from single-threaded subprocess context (proxy or
        // self-check), before any concurrent work begins.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(var);
        }
    }

    let root_store: rustls::RootCertStore =
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| crate::error::Error::new(format!("Failed to build WebPKI verifier: {e}")))?;
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier { inner: verifier }))
        .with_no_client_auth();

    Ok(Arc::new(tls_config))
}

// ─── Client ──────────────────────────────────────────────────────────────────

pub(crate) struct Client {
    agent: ureq::Agent,
    token: SecureToken,
    call_count: Option<Arc<AtomicU32>>,
    max_calls: u32,
}

#[allow(clippy::same_name_method)]
impl Client {
    pub(crate) fn new_with_call_budget(
        token: SecureToken,
        resolved_addrs: &[SocketAddr],
        call_count: Arc<AtomicU32>,
        max_calls: u32,
    ) -> Result<Self> {
        Self::new_inner(token, resolved_addrs, Some(call_count), max_calls)
    }

    fn new_inner(
        token: SecureToken,
        resolved_addrs: &[SocketAddr],
        call_count: Option<Arc<AtomicU32>>,
        max_calls: u32,
    ) -> Result<Self> {
        if resolved_addrs.is_empty() {
            bail!("Cannot create GitHub client without pre-resolved addresses");
        }

        let tls_config = create_github_pinned_tls_config()?;

        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(30))
            .redirects(5)
            .tls_config(tls_config)
            .resolver(PinnedResolver {
                addrs: resolved_addrs.to_vec(),
            })
            .build();

        Ok(Self {
            agent,
            token,
            call_count,
            max_calls,
        })
    }

    /// Check the token's OAuth scopes by calling the free `/rate_limit` endpoint.
    ///
    /// Returns a list of human-readable warnings for any write scopes that hasp
    /// does not need.  The `/rate_limit` endpoint is free (does not consume a
    /// rate-limit point) so this call is intentionally made outside the call
    /// budget.
    pub(crate) fn check_token_scopes(&self) -> Vec<String> {
        // Scopes that indicate the token has more access than hasp requires.
        // hasp only needs read access to repository contents.  Any *write*
        // scope widens the blast radius if the token leaks during a run.
        const WRITE_SCOPES: &[&str] = &[
            "repo", // full private-repo access (read + write)
            "write:packages",
            "delete:packages",
            "admin:org",
            "write:org",
            "admin:public_key",
            "write:public_key",
            "admin:repo_hook",
            "write:repo_hook",
            "admin:org_hook",
            "gist",
            "delete_repo",
            "write:discussion",
            "admin:enterprise",
            "admin:gpg_key",
            "write:gpg_key",
            "admin:ssh_signing_key",
            "write:ssh_signing_key",
            "workflow",
        ];

        let url = api_url("rate_limit");
        let request = self.token.with_unmasked(|plain| {
            let mut auth_header = format!("Bearer {plain}");
            let req = self
                .agent
                .get(&url)
                .set("Accept", "application/vnd.github+json")
                .set("X-GitHub-Api-Version", "2022-11-28")
                .set("User-Agent", concat!("hasp/", env!("CARGO_PKG_VERSION")))
                .set("Authorization", &auth_header);
            scrub_string(&mut auth_header);
            req
        });

        let Ok(resp) = request.call() else {
            return Vec::new(); // silently skip on any error
        };

        // Save header before consuming the response body.
        let scopes_header = resp.header("X-OAuth-Scopes").map(str::to_string);

        // Consume the response body so the connection can be reused / closed.
        let _ = resp
            .into_reader()
            .take(1024 * 64)
            .read_to_string(&mut String::new());

        let mut warnings = Vec::new();

        // Classic PATs and OAuth tokens expose `X-OAuth-Scopes`.
        // Fine-grained PATs and GITHUB_TOKEN do not set this header at all —
        // their permissions are governed by the token itself, not OAuth scopes,
        // so there is nothing to check here for those token types.
        if let Some(scopes_header) = &scopes_header {
            if scopes_header.is_empty() {
                return warnings;
            }

            let scopes: Vec<&str> = scopes_header
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();

            let excess: Vec<&str> = scopes
                .iter()
                .copied()
                .filter(|scope| WRITE_SCOPES.iter().any(|w| scope == w))
                .collect();

            if !excess.is_empty() {
                warnings.push(format!(
                    "GITHUB_TOKEN has write scope(s) that hasp does not need: {}",
                    excess.join(", "),
                ));
                warnings.push(
                    "hasp only requires read access to repository contents. \
                     Consider using a fine-grained PAT with minimal permissions."
                        .to_string(),
                );
            }
        }

        warnings
    }

    fn consume_call_budget(&self) -> Result<()> {
        let Some(call_count) = &self.call_count else {
            return Ok(());
        };

        let previous = call_count.fetch_add(1, Ordering::Relaxed);
        if previous >= self.max_calls {
            bail!(
                "GitHub API call limit exceeded for this run (limit: {})",
                self.max_calls
            );
        }
        Ok(())
    }

    fn get(&self, url: &str) -> Result<ureq::Request> {
        self.consume_call_budget()?;
        let request = self.token.with_unmasked(|plain| {
            let mut auth_header = format!("Bearer {plain}");
            let req = self
                .agent
                .get(url)
                .set("Accept", "application/vnd.github+json")
                .set("X-GitHub-Api-Version", "2022-11-28")
                .set("User-Agent", concat!("hasp/", env!("CARGO_PKG_VERSION")))
                .set("Authorization", &auth_header);
            scrub_string(&mut auth_header);
            req
        });
        Ok(request)
    }

    /// Read an API response body with a 2 MiB cap to prevent OOM from
    /// oversized or malicious responses.
    fn read_body(resp: ureq::Response) -> Result<String> {
        const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
        let mut buf = String::new();
        resp.into_reader()
            .take(MAX_RESPONSE_BYTES)
            .read_to_string(&mut buf)
            .context("Failed to read GitHub API response body")?;
        Ok(buf)
    }

    pub(crate) fn verify_commit(&self, owner: &str, repo: &str, sha: &str) -> Result<bool> {
        Ok(self.get_commit_metadata(owner, repo, sha)?.is_some())
    }

    /// Resolve a tag to the commit SHA it currently points to.
    pub(crate) fn resolve_tag(&self, owner: &str, repo: &str, tag: &str) -> Result<Option<String>> {
        let url = api_url(&format!("repos/{owner}/{repo}/git/ref/tags/{tag}"));

        let body = match self.get(&url)?.call() {
            Ok(resp) => Self::read_body(resp)?,
            Err(ureq::Error::Status(404, _)) => return Ok(None),
            Err(e) => bail!("GitHub API error resolving tag {tag}: {e}"),
        };

        let (obj_type, sha) = parse_git_ref_target(&body)?;

        // Annotated tags point to a tag object, not directly to a commit
        let commit_sha = if obj_type == "tag" {
            self.deref_annotated_tag(owner, repo, &sha)?
        } else {
            sha
        };

        Ok(Some(commit_sha))
    }

    /// Find which tag (if any) points to a given commit SHA.
    /// Fetches up to 3 pages of tags (300 total) — best-effort, not exhaustive.
    pub(crate) fn find_tag_for_sha(&self, owner: &str, repo: &str, sha: &str) -> Option<String> {
        for page in 1..=3 {
            let url = api_url(&format!(
                "repos/{owner}/{repo}/tags?per_page=100&page={page}"
            ));
            let body = match self.get(&url).ok()?.call() {
                Ok(resp) => Self::read_body(resp).ok()?,
                Err(_) => return None,
            };
            let doc = parse_json_doc(&body).ok()?;
            let arr = doc.as_vec()?;
            let count = arr.len();
            if let Some(tag) = find_tag_in_parsed_list(&doc, sha) {
                return Some(tag);
            }
            // If we got fewer than 100 results, there are no more pages
            if count < 100 {
                break;
            }
        }
        None
    }

    fn get_repo_info(&self, owner: &str, repo: &str) -> Result<RepoInfo> {
        let url = api_url(&format!("repos/{owner}/{repo}"));
        let body = match self.get(&url)?.call() {
            Ok(resp) => Self::read_body(resp)?,
            Err(e) => bail!("GitHub API error fetching repo info: {e}"),
        };
        parse_repo_info(&body)
    }

    /// Check whether a commit is reachable from the default branch.
    /// Uses the compare API: status "behind" or "identical" means reachable.
    fn is_commit_reachable(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        default_branch: &str,
    ) -> Result<ReachabilityStatus> {
        let url = api_url(&format!(
            "repos/{owner}/{repo}/compare/{default_branch}...{sha}"
        ));
        let body = match self.get(&url)?.call() {
            Ok(resp) => Self::read_body(resp)?,
            Err(ureq::Error::Status(404, _)) => return Ok(ReachabilityStatus::Unreachable),
            Err(e) => bail!("GitHub API error checking reachability: {e}"),
        };
        let doc = parse_json_doc(&body)?;
        let status = yaml_field_cached(&doc, key_status())
            .and_then(Yaml::as_str)
            .unwrap_or("unknown");
        match status {
            "behind" | "identical" => Ok(ReachabilityStatus::Reachable),
            "ahead" => Ok(ReachabilityStatus::Ahead),
            "diverged" => Ok(ReachabilityStatus::Diverged),
            _ => Ok(ReachabilityStatus::Unreachable),
        }
    }

    /// Check if a commit has a verified (signed) signature.
    fn is_commit_signed(&self, owner: &str, repo: &str, sha: &str) -> Result<bool> {
        Ok(self
            .get_commit_metadata(owner, repo, sha)?
            .is_some_and(|meta| meta.verified))
    }

    fn get_commit_date(&self, owner: &str, repo: &str, sha: &str) -> Result<Option<String>> {
        Ok(self
            .get_commit_metadata(owner, repo, sha)?
            .and_then(|meta| meta.authored_date))
    }

    fn deref_annotated_tag(&self, owner: &str, repo: &str, tag_sha: &str) -> Result<String> {
        Ok(self
            .get_annotated_tag_info(owner, repo, tag_sha)?
            .object_sha)
    }

    fn get_tag_creation_date(&self, owner: &str, repo: &str, tag: &str) -> Result<Option<String>> {
        let url = api_url(&format!("repos/{owner}/{repo}/git/ref/tags/{tag}"));
        let body = match self.get(&url)?.call() {
            Ok(resp) => Self::read_body(resp)?,
            Err(ureq::Error::Status(404, _)) => return Ok(None),
            Err(e) => bail!("GitHub API error resolving tag {tag}: {e}"),
        };

        let (obj_type, sha) = parse_git_ref_target(&body)?;
        if obj_type != "tag" {
            return Ok(None);
        }

        Ok(self.get_annotated_tag_info(owner, repo, &sha)?.tagger_date)
    }

    fn get_action_yml(
        &self,
        owner: &str,
        repo: &str,
        path: Option<&str>,
        sha: &str,
    ) -> Result<Option<String>> {
        for file_name in ["action.yml", "action.yaml"] {
            let full_path = path.map_or_else(
                || file_name.to_string(),
                |path| format!("{}/{file_name}", path.trim_matches('/')),
            );

            if let Some(contents) = self.fetch_contents_file(owner, repo, &full_path, sha)? {
                return Ok(Some(contents));
            }
        }

        Ok(None)
    }

    fn get_commit_metadata(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> Result<Option<CommitMetadata>> {
        let url = api_url(&format!("repos/{owner}/{repo}/commits/{sha}"));
        let body = match self.get(&url)?.call() {
            Ok(resp) => Self::read_body(resp)?,
            // GitHub returns 404 when the repo exists but the SHA doesn't
            // match any commit, and 422 ("No commit found for SHA") for
            // 40-hex strings that aren't real commits. Treat both as
            // "phantom SHA" so the caller can report it cleanly instead of
            // hard-bailing on 422.
            Err(ureq::Error::Status(404 | 422, _)) => return Ok(None),
            Err(ureq::Error::Status(code @ (401 | 403), resp)) => {
                let remaining = resp.header("x-ratelimit-remaining").map(str::to_string);
                let body = resp.into_string().unwrap_or_default();
                if remaining.as_deref() == Some("0") || body.contains("rate limit") {
                    bail!(
                        "GitHub API rate limit exceeded ({code}) — try again later: {body}"
                    )
                }
                bail!("GitHub API authentication failed ({code}) — check your GITHUB_TOKEN: {body}")
            }
            Err(ureq::Error::Status(429, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                bail!("GitHub API rate limit exceeded (429) — try again later: {body}")
            }
            Err(e) => bail!("GitHub API error for {owner}/{repo}@{sha}: {e}"),
        };

        let doc = parse_json_doc(&body)?;
        Ok(Some(CommitMetadata {
            verified: yaml_field_cached(&doc, key_commit())
                .and_then(|c| yaml_field_cached(c, key_verification()))
                .and_then(|v| yaml_field_cached(v, key_verified()))
                .and_then(Yaml::as_bool)
                .unwrap_or(false),
            authored_date: yaml_field_cached(&doc, key_commit())
                .and_then(|c| yaml_field_cached(c, key_author()))
                .and_then(|a| yaml_field_cached(a, key_date()))
                .and_then(Yaml::as_str)
                .or_else(|| {
                    yaml_field_cached(&doc, key_commit())
                        .and_then(|c| yaml_field_cached(c, key_committer()))
                        .and_then(|c| yaml_field_cached(c, key_date()))
                        .and_then(Yaml::as_str)
                })
                .map(str::to_string),
        }))
    }

    fn get_annotated_tag_info(
        &self,
        owner: &str,
        repo: &str,
        tag_sha: &str,
    ) -> Result<AnnotatedTagInfo> {
        let url = api_url(&format!("repos/{owner}/{repo}/git/tags/{tag_sha}"));

        let body = match self.get(&url)?.call() {
            Ok(resp) => Self::read_body(resp)?,
            Err(e) => bail!("GitHub API error dereferencing tag: {e}"),
        };

        parse_git_tag_info(&body)
    }

    fn fetch_contents_file(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        sha: &str,
    ) -> Result<Option<String>> {
        let url = api_url(&format!("repos/{owner}/{repo}/contents/{path}?ref={sha}"));

        let body = match self.get(&url)?.call() {
            Ok(resp) => Self::read_body(resp)?,
            Err(ureq::Error::Status(404, _)) => return Ok(None),
            Err(e) => bail!("GitHub API error fetching action metadata {path}: {e}"),
        };

        parse_contents_body(&body).map(Some)
    }

    fn compare_commits(
        &self,
        owner: &str,
        repo: &str,
        base: &str,
        head: &str,
    ) -> Result<CompareResult> {
        let url = api_url(&format!("repos/{owner}/{repo}/compare/{base}...{head}"));
        let body = match self.get(&url)?.call() {
            Ok(resp) => Self::read_body(resp)?,
            Err(e) => bail!("GitHub API error comparing {owner}/{repo} {base}..{head}: {e}"),
        };
        let mut result = parse_compare_response(&body)?;
        result.owner = owner.to_string();
        result.repo = repo.to_string();
        result.old_sha = base.to_string();
        result.new_sha = head.to_string();
        Ok(result)
    }
}

fn validate_component(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 100 {
        bail!("Invalid {label}: empty or too long");
    }
    if value.contains("..") {
        bail!("Invalid {label}: contains path traversal");
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        bail!("Invalid {label}: contains disallowed characters");
    }
    Ok(())
}

/// Validate a multi-segment action path (e.g. `"subdir/nested-action"`).
/// Matches the proxy-side `validate_action_path` logic.
fn validate_action_path(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 200 {
        bail!("Invalid action path: expected 1..=200 characters");
    }
    if value.starts_with('/')
        || value.ends_with('/')
        || value.contains("..")
        || value.contains('\\')
    {
        bail!("Invalid action path: unsafe path syntax");
    }
    if !value.split('/').all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }) {
        bail!("Invalid action path: unexpected characters");
    }
    Ok(())
}

fn validate_sha_param(value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("Invalid SHA: expected 40 lowercase hex characters");
    }
    Ok(())
}

impl Api for Client {
    fn verify_commit(&self, owner: &str, repo: &str, sha: &str) -> Result<bool> {
        validate_component(owner, "owner")?;
        validate_component(repo, "repo")?;
        validate_sha_param(sha)?;
        Self::verify_commit(self, owner, repo, sha)
    }

    fn resolve_tag(&self, owner: &str, repo: &str, tag: &str) -> Result<Option<String>> {
        validate_component(owner, "owner")?;
        validate_component(repo, "repo")?;
        validate_component(tag, "tag")?;
        Self::resolve_tag(self, owner, repo, tag)
    }

    fn find_tag_for_sha(&self, owner: &str, repo: &str, sha: &str) -> Option<String> {
        validate_component(owner, "owner").ok()?;
        validate_component(repo, "repo").ok()?;
        validate_sha_param(sha).ok()?;
        Self::find_tag_for_sha(self, owner, repo, sha)
    }

    fn get_repo_info(&self, owner: &str, repo: &str) -> Result<RepoInfo> {
        validate_component(owner, "owner")?;
        validate_component(repo, "repo")?;
        Self::get_repo_info(self, owner, repo)
    }

    fn is_commit_reachable(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        default_branch: &str,
    ) -> Result<ReachabilityStatus> {
        validate_component(owner, "owner")?;
        validate_component(repo, "repo")?;
        validate_sha_param(sha)?;
        validate_component(default_branch, "default_branch")?;
        Self::is_commit_reachable(self, owner, repo, sha, default_branch)
    }

    fn is_commit_signed(&self, owner: &str, repo: &str, sha: &str) -> Result<bool> {
        validate_component(owner, "owner")?;
        validate_component(repo, "repo")?;
        validate_sha_param(sha)?;
        Self::is_commit_signed(self, owner, repo, sha)
    }

    fn get_commit_date(&self, owner: &str, repo: &str, sha: &str) -> Result<Option<String>> {
        validate_component(owner, "owner")?;
        validate_component(repo, "repo")?;
        validate_sha_param(sha)?;
        Self::get_commit_date(self, owner, repo, sha)
    }

    fn get_tag_creation_date(&self, owner: &str, repo: &str, tag: &str) -> Result<Option<String>> {
        validate_component(owner, "owner")?;
        validate_component(repo, "repo")?;
        validate_component(tag, "tag")?;
        Self::get_tag_creation_date(self, owner, repo, tag)
    }

    fn get_action_yml(
        &self,
        owner: &str,
        repo: &str,
        path: Option<&str>,
        sha: &str,
    ) -> Result<Option<String>> {
        validate_component(owner, "owner")?;
        validate_component(repo, "repo")?;
        if let Some(p) = path {
            validate_action_path(p)?;
        }
        validate_sha_param(sha)?;
        Self::get_action_yml(self, owner, repo, path, sha)
    }

    fn compare_commits(
        &self,
        owner: &str,
        repo: &str,
        base: &str,
        head: &str,
    ) -> Result<CompareResult> {
        validate_component(owner, "owner")?;
        validate_component(repo, "repo")?;
        validate_sha_param(base)?;
        validate_sha_param(head)?;
        Self::compare_commits(self, owner, repo, base, head)
    }
}
