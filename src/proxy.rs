use crate::error::{Context, Result, bail};
use crate::github::{self, Api};

use crate::token::SecureToken;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
use std::time::Duration;

pub(crate) const PROXY_ADDR_ENV: &str = "HASP_PROXY_ADDR";
pub(crate) const PROXY_AUTH_ENV: &str = "HASP_PROXY_AUTH";
pub(crate) const GITHUB_ADDRS_ENV: &str = "HASP_GITHUB_ADDRS";
pub(crate) const READY_MAGIC: &str = "HASP_PROXY_READY_V1";

const MAX_MESSAGE_BYTES: usize = 4096;
const MAX_API_CALLS_PER_RUN: u32 = 300;
const MAX_AUTH_FAILURES: u32 = 5;
const MAX_CONNECTIONS: u32 = 1000;

pub(crate) struct Client {
    proxy_addr: SocketAddr,
    auth: SecureToken,
}

impl Client {
    pub(crate) fn from_env() -> Result<Self> {
        let raw = std::env::var(PROXY_ADDR_ENV)
            .context(format!("{PROXY_ADDR_ENV} not set for verifier process"))?;
        let proxy_addr = raw
            .parse::<SocketAddr>()
            .context("Invalid local proxy address")?;
        if !proxy_addr.ip().is_loopback() {
            bail!("Verifier refused non-loopback proxy address {proxy_addr}");
        }
        let auth = SecureToken::from_env(PROXY_AUTH_ENV)?;
        Ok(Self { proxy_addr, auth })
    }

    fn request(&self, tag: &str, fields: &[&str]) -> Result<Vec<String>> {
        let mut stream = TcpStream::connect(self.proxy_addr).context(format!(
            "Failed to connect to local proxy at {}",
            self.proxy_addr
        ))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .context("Failed to set proxy read timeout")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .context("Failed to set proxy write timeout")?;

        self.auth.with_unmasked(|auth_plain| -> Result<()> {
            let mut all_fields = Vec::with_capacity(fields.len() + 1);
            all_fields.push(auth_plain);
            all_fields.extend_from_slice(fields);
            write_record(&mut stream, tag, &all_fields)
        })?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .context("Failed to half-close proxy request stream")?;

        let mut resp = String::new();
        stream
            .take(MAX_MESSAGE_BYTES as u64 + 1)
            .read_to_string(&mut resp)
            .context("Failed to read proxy response")?;
        if resp.len() > MAX_MESSAGE_BYTES {
            bail!("Proxy response exceeded {} bytes", MAX_MESSAGE_BYTES);
        }

        let line = resp
            .lines()
            .next()
            .context("Proxy returned an empty response")?;
        let fields = split_fields(line)?;
        if fields.is_empty() {
            bail!("Proxy returned an empty record");
        }
        if fields[0] == "ERR" {
            let msg = fields
                .get(1)
                .map_or("proxy returned an unspecified error", String::as_str);
            bail!("Proxy error: {msg}");
        }
        Ok(fields)
    }
}

impl Api for Client {
    fn verify_commit(&self, owner: &str, repo: &str, sha: &str) -> Result<bool> {
        let fields = self.request("VERIFY", &[owner, repo, sha])?;
        if fields.len() != 2 || fields[0] != "BOOL" {
            bail!("Malformed VERIFY response from proxy");
        }
        match fields[1].as_str() {
            "1" => Ok(true),
            "0" => Ok(false),
            other => bail!("Malformed proxy boolean response `{other}`"),
        }
    }

    fn resolve_tag(&self, owner: &str, repo: &str, tag: &str) -> Result<Option<String>> {
        let fields = self.request("RESOLVE", &[owner, repo, tag])?;
        if fields.len() != 2 || fields[0] != "OPTION" {
            bail!("Malformed RESOLVE response from proxy");
        }
        if fields[1].is_empty() {
            Ok(None)
        } else {
            Ok(Some(fields[1].clone()))
        }
    }

    fn find_tag_for_sha(&self, owner: &str, repo: &str, sha: &str) -> Option<String> {
        let fields = self.request("FIND_TAG", &[owner, repo, sha]).ok()?;
        if fields.len() != 2 || fields[0] != "OPTION" {
            return None;
        }
        if fields[1].is_empty() {
            None
        } else {
            Some(fields[1].clone())
        }
    }

    fn get_repo_info(&self, owner: &str, repo: &str) -> Result<github::RepoInfo> {
        let fields = self.request("DEFAULT_BRANCH", &[owner, repo])?;
        if fields.len() != 5 || fields[0] != "REPO_INFO" || fields[1].is_empty() {
            bail!("Malformed DEFAULT_BRANCH response from proxy");
        }
        Ok(github::RepoInfo {
            default_branch: fields[1].clone(),
            created_at: optional_field(fields.get(2)),
            stargazers_count: parse_optional_u64(&fields[3])?,
            forks_count: parse_optional_u64(&fields[4])?,
        })
    }

    fn is_commit_reachable(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        default_branch: &str,
    ) -> Result<github::ReachabilityStatus> {
        let fields = self.request("REACHABLE", &[owner, repo, sha, default_branch])?;
        if fields.len() != 2 || fields[0] != "STATUS" {
            bail!("Malformed REACHABLE response from proxy");
        }
        match fields[1].as_str() {
            "reachable" => Ok(github::ReachabilityStatus::Reachable),
            "ahead" => Ok(github::ReachabilityStatus::Ahead),
            "diverged" => Ok(github::ReachabilityStatus::Diverged),
            "unreachable" => Ok(github::ReachabilityStatus::Unreachable),
            other => bail!("Malformed reachability status `{other}`"),
        }
    }

    fn is_commit_signed(&self, owner: &str, repo: &str, sha: &str) -> Result<bool> {
        let fields = self.request("SIGNED", &[owner, repo, sha])?;
        if fields.len() != 2 || fields[0] != "BOOL" {
            bail!("Malformed SIGNED response from proxy");
        }
        match fields[1].as_str() {
            "1" => Ok(true),
            "0" => Ok(false),
            other => bail!("Malformed proxy boolean response `{other}`"),
        }
    }

    fn get_commit_date(&self, owner: &str, repo: &str, sha: &str) -> Result<Option<String>> {
        let fields = self.request("COMMIT_DATE", &[owner, repo, sha])?;
        if fields.len() != 2 || fields[0] != "OPTION" {
            bail!("Malformed COMMIT_DATE response from proxy");
        }
        if fields[1].is_empty() {
            Ok(None)
        } else {
            Ok(Some(fields[1].clone()))
        }
    }

    fn get_tag_creation_date(&self, owner: &str, repo: &str, tag: &str) -> Result<Option<String>> {
        let fields = self.request("TAG_DATE", &[owner, repo, tag])?;
        if fields.len() != 2 || fields[0] != "OPTION" {
            bail!("Malformed TAG_DATE response from proxy");
        }
        if fields[1].is_empty() {
            Ok(None)
        } else {
            Ok(Some(fields[1].clone()))
        }
    }

    fn get_action_yml(
        &self,
        owner: &str,
        repo: &str,
        path: Option<&str>,
        sha: &str,
    ) -> Result<Option<String>> {
        let fields = self.request("GET_ACTION_YML", &[owner, repo, path.unwrap_or(""), sha])?;
        if fields.len() != 2 || fields[0] != "OPTION" {
            bail!("Malformed GET_ACTION_YML response from proxy");
        }
        if fields[1].is_empty() {
            Ok(None)
        } else {
            Ok(Some(fields[1].clone()))
        }
    }

    fn compare_commits(
        &self,
        owner: &str,
        repo: &str,
        base: &str,
        head: &str,
    ) -> Result<github::CompareResult> {
        let fields = self.request("COMPARE", &[owner, repo, base, head])?;
        // Expected: COMPARE_RESULT ahead_by files_changed html_url [up to 10 summaries]
        if fields.len() < 4 || fields[0] != "COMPARE_RESULT" {
            bail!("Malformed COMPARE response from proxy");
        }
        let ahead_by: u32 = fields[1].parse().unwrap_or(0);
        let files_changed: u32 = fields[2].parse().unwrap_or(0);
        let html_url = fields[3].clone();
        // Cap to 10 summaries to match the server-side limit, even if a
        // misbehaving proxy returns more fields.
        let max_summaries = (fields.len() - 4).min(10);
        let commit_summaries: Vec<String> = fields[4..4 + max_summaries].to_vec();
        Ok(github::CompareResult {
            owner: owner.to_string(),
            repo: repo.to_string(),
            old_sha: base.to_string(),
            new_sha: head.to_string(),
            ahead_by,
            files_changed,
            commit_summaries,
            html_url,
        })
    }
}

pub(crate) fn run_server() -> Result<()> {
    let upstream_addrs = parse_upstream_addrs()?;
    let token = SecureToken::from_env("GITHUB_TOKEN")?;
    let auth = SecureToken::from_env(PROXY_AUTH_ENV)?;
    let call_count = Arc::new(AtomicU32::new(0));
    let client = github::Client::new_with_call_budget(
        token,
        &upstream_addrs,
        Arc::clone(&call_count),
        MAX_API_CALLS_PER_RUN,
    )?;

    // Check token scopes before entering the connection loop.  The
    // /rate_limit endpoint is free, so this does not count against the API
    // call budget.  Warnings go to stderr, which the launcher inherits.
    for warning in client.check_token_scopes() {
        eprintln!("hasp: warning: {warning}");
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("Failed to bind local verifier proxy")?;
    let listen_addr = listener
        .local_addr()
        .context("Failed to determine proxy listen address")?;

    {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        writeln!(
            lock,
            "{READY_MAGIC}\t{}",
            encode_field(&listen_addr.to_string())
        )
        .context("Failed to announce proxy readiness")?;
        lock.flush().context("Failed to flush proxy ready line")?;
    }

    let mut auth_failures = 0_u32;
    let mut total_connections = 0_u32;
    for stream in listener.incoming() {
        let mut stream = stream?;
        total_connections += 1;
        if total_connections > MAX_CONNECTIONS {
            write_error(
                &mut stream,
                "Connection limit exceeded; proxy shutting down",
            )?;
            bail!("Proxy shutting down after {MAX_CONNECTIONS} connections");
        }
        if call_count.load(Ordering::Relaxed) >= MAX_API_CALLS_PER_RUN {
            write_error(
                &mut stream,
                "GitHub API call limit exceeded for this run; refusing further proxy requests",
            )?;
            bail!("Proxy shutting down after {MAX_API_CALLS_PER_RUN} API calls");
        }
        if auth_failures >= MAX_AUTH_FAILURES {
            write_error(
                &mut stream,
                "Too many authentication failures; proxy shutting down",
            )?;
            bail!("Proxy shutting down after {MAX_AUTH_FAILURES} authentication failures");
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .context("Failed to set proxy read timeout")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .context("Failed to set proxy write timeout")?;

        let peer = stream
            .peer_addr()
            .context("Failed to determine proxy client address")?;
        if peer.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            write_error(&mut stream, "proxy only accepts loopback clients")?;
            continue;
        }

        match handle_connection(&mut stream, &client, &auth) {
            Ok(()) => {}
            Err(ref err) if err.msg().contains("authentication failed") => {
                auth_failures += 1;
                let msg = err.to_string();
                write_error(&mut stream, &msg)?;
            }
            Err(ref err) => {
                let msg = err.to_string();
                write_error(&mut stream, &msg)?;
            }
        }
    }

    Ok(())
}

pub(crate) fn read_ready_line(reader: impl Read) -> Result<SocketAddr> {
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("Failed to read proxy ready line")?;
    let line = line.trim_end_matches(['\r', '\n']);
    let fields = split_fields(line)?;
    if fields.len() != 2 || fields[0] != READY_MAGIC {
        bail!("Malformed proxy ready line");
    }
    fields[1]
        .parse::<SocketAddr>()
        .context("Invalid proxy ready address")
}

fn parse_upstream_addrs() -> Result<Vec<SocketAddr>> {
    let raw = std::env::var(GITHUB_ADDRS_ENV)
        .context(format!("{GITHUB_ADDRS_ENV} not set for proxy process"))?;
    let mut addrs = Vec::new();
    for part in raw.split(',').filter(|part| !part.is_empty()) {
        addrs.push(
            part.parse::<SocketAddr>()
                .context(format!("Invalid upstream socket address `{part}`"))?,
        );
    }
    if addrs.is_empty() {
        bail!("Proxy received an empty upstream address set");
    }
    Ok(addrs)
}

#[allow(clippy::too_many_lines)]
fn handle_connection(
    stream: &mut TcpStream,
    client: &github::Client,
    auth: &SecureToken,
) -> Result<()> {
    let mut request = String::new();
    stream
        .take(MAX_MESSAGE_BYTES as u64 + 1)
        .read_to_string(&mut request)
        .context("Failed to read proxy request")?;
    if request.len() > MAX_MESSAGE_BYTES {
        bail!("Proxy request exceeded {} bytes", MAX_MESSAGE_BYTES);
    }

    let line = request
        .lines()
        .next()
        .context("Proxy request did not contain a command line")?;
    let fields = split_fields(line)?;
    if fields.len() < 2 {
        bail!("Malformed proxy request");
    }
    let auth_ok = auth
        .with_unmasked(|auth_plain| constant_time_eq(fields[1].as_bytes(), auth_plain.as_bytes()));
    if !auth_ok {
        bail!("Proxy authentication failed");
    }
    match fields[0].as_str() {
        "VERIFY" => {
            if fields.len() != 5 {
                bail!("Malformed VERIFY request");
            }
            validate_github_component(&fields[2], "owner")?;
            validate_github_component(&fields[3], "repo")?;
            validate_sha(&fields[4])?;
            let exists = client.verify_commit(&fields[2], &fields[3], &fields[4])?;
            write_response(stream, "BOOL", &[if exists { "1" } else { "0" }])?;
        }
        "RESOLVE" => {
            if fields.len() != 5 {
                bail!("Malformed RESOLVE request");
            }
            validate_github_component(&fields[2], "owner")?;
            validate_github_component(&fields[3], "repo")?;
            validate_git_ref_name(&fields[4], "tag")?;
            let resolved = client.resolve_tag(&fields[2], &fields[3], &fields[4])?;
            write_response(stream, "OPTION", &[resolved.as_deref().unwrap_or("")])?;
        }
        "FIND_TAG" => {
            if fields.len() != 5 {
                bail!("Malformed FIND_TAG request");
            }
            validate_github_component(&fields[2], "owner")?;
            validate_github_component(&fields[3], "repo")?;
            validate_sha(&fields[4])?;
            let tag = client.find_tag_for_sha(&fields[2], &fields[3], &fields[4]);
            write_response(stream, "OPTION", &[tag.as_deref().unwrap_or("")])?;
        }
        "DEFAULT_BRANCH" => {
            if fields.len() != 4 {
                bail!("Malformed DEFAULT_BRANCH request");
            }
            validate_github_component(&fields[2], "owner")?;
            validate_github_component(&fields[3], "repo")?;
            let repo_info = client.get_repo_info(&fields[2], &fields[3])?;
            let stars = repo_info
                .stargazers_count
                .map(|value| value.to_string())
                .unwrap_or_default();
            let forks = repo_info
                .forks_count
                .map(|value| value.to_string())
                .unwrap_or_default();
            write_response(
                stream,
                "REPO_INFO",
                &[
                    &repo_info.default_branch,
                    repo_info.created_at.as_deref().unwrap_or(""),
                    &stars,
                    &forks,
                ],
            )?;
        }
        "REACHABLE" => {
            if fields.len() != 6 {
                bail!("Malformed REACHABLE request");
            }
            validate_github_component(&fields[2], "owner")?;
            validate_github_component(&fields[3], "repo")?;
            validate_sha(&fields[4])?;
            validate_git_ref_name(&fields[5], "default branch")?;
            let status =
                client.is_commit_reachable(&fields[2], &fields[3], &fields[4], &fields[5])?;
            let status = match status {
                github::ReachabilityStatus::Reachable => "reachable",
                github::ReachabilityStatus::Ahead => "ahead",
                github::ReachabilityStatus::Diverged => "diverged",
                github::ReachabilityStatus::Unreachable => "unreachable",
            };
            write_response(stream, "STATUS", &[status])?;
        }
        "SIGNED" => {
            if fields.len() != 5 {
                bail!("Malformed SIGNED request");
            }
            validate_github_component(&fields[2], "owner")?;
            validate_github_component(&fields[3], "repo")?;
            validate_sha(&fields[4])?;
            let signed = client.is_commit_signed(&fields[2], &fields[3], &fields[4])?;
            write_response(stream, "BOOL", &[if signed { "1" } else { "0" }])?;
        }
        "COMMIT_DATE" => {
            if fields.len() != 5 {
                bail!("Malformed COMMIT_DATE request");
            }
            validate_github_component(&fields[2], "owner")?;
            validate_github_component(&fields[3], "repo")?;
            validate_sha(&fields[4])?;
            let date = client.get_commit_date(&fields[2], &fields[3], &fields[4])?;
            write_response(stream, "OPTION", &[date.as_deref().unwrap_or("")])?;
        }
        "TAG_DATE" => {
            if fields.len() != 5 {
                bail!("Malformed TAG_DATE request");
            }
            validate_github_component(&fields[2], "owner")?;
            validate_github_component(&fields[3], "repo")?;
            validate_git_ref_name(&fields[4], "tag")?;
            let date = client.get_tag_creation_date(&fields[2], &fields[3], &fields[4])?;
            write_response(stream, "OPTION", &[date.as_deref().unwrap_or("")])?;
        }
        "GET_ACTION_YML" => {
            if fields.len() != 6 {
                bail!("Malformed GET_ACTION_YML request");
            }
            validate_github_component(&fields[2], "owner")?;
            validate_github_component(&fields[3], "repo")?;
            let path = if fields[4].is_empty() {
                None
            } else {
                validate_action_path(&fields[4])?;
                Some(fields[4].as_str())
            };
            validate_sha(&fields[5])?;
            let content = client.get_action_yml(&fields[2], &fields[3], path, &fields[5])?;
            write_response(stream, "OPTION", &[content.as_deref().unwrap_or("")])?;
        }
        "COMPARE" => {
            if fields.len() != 6 {
                bail!("Malformed COMPARE request");
            }
            validate_github_component(&fields[2], "owner")?;
            validate_github_component(&fields[3], "repo")?;
            validate_sha(&fields[4])?;
            validate_sha(&fields[5])?;
            let result = client.compare_commits(&fields[2], &fields[3], &fields[4], &fields[5])?;
            let ahead = result.ahead_by.to_string();
            let files = result.files_changed.to_string();
            let mut resp_fields: Vec<&str> = vec![&ahead, &files, &result.html_url];
            // Cap to 10 summaries to stay within proxy message size limits
            for s in result.commit_summaries.iter().take(10) {
                resp_fields.push(s);
            }
            write_response(stream, "COMPARE_RESULT", &resp_fields)?;
        }
        other => {
            let truncated = if other.len() > 32 {
                &other[..32]
            } else {
                other
            };
            bail!("Unknown proxy request `{truncated}`")
        }
    }
    Ok(())
}

fn write_response(stream: &mut TcpStream, tag: &str, fields: &[&str]) -> Result<()> {
    write_record(stream, tag, fields)?;
    stream.flush().context("Failed to flush proxy response")?;
    Ok(())
}

fn write_error(stream: &mut TcpStream, msg: &str) -> Result<()> {
    write_record(stream, "ERR", &[msg])?;
    stream.flush().context("Failed to flush proxy error")?;
    Ok(())
}

fn write_record(writer: &mut impl Write, tag: &str, fields: &[&str]) -> Result<()> {
    writer
        .write_all(tag.as_bytes())
        .context("Failed to write proxy record tag")?;
    for field in fields {
        writer
            .write_all(b"\t")
            .context("Failed to write proxy field separator")?;
        writer
            .write_all(encode_field(field).as_bytes())
            .context("Failed to write proxy field")?;
    }
    writer
        .write_all(b"\n")
        .context("Failed to terminate proxy record")?;
    Ok(())
}

fn split_fields(line: &str) -> Result<Vec<String>> {
    let field_count = line.split('\t').count();
    let mut out = Vec::with_capacity(field_count);
    for (idx, field) in line.split('\t').enumerate() {
        if idx == 0 {
            out.push(field.to_string());
        } else {
            out.push(decode_field(field)?);
        }
    }
    // split('\t') always yields at least one element, but guard against
    // callers passing truly empty input (no tab-separated fields).
    if out.is_empty() || out[0].is_empty() {
        bail!("Malformed proxy record: empty command");
    }
    Ok(out)
}

fn encode_field(value: &str) -> String {
    crate::ipc::percent_encode(value)
}

fn decode_field(field: &str) -> Result<String> {
    crate::ipc::percent_decode(field)
}

fn optional_field(field: Option<&String>) -> Option<String> {
    field.filter(|value| !value.is_empty()).cloned()
}

fn validate_github_component(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 100 {
        bail!("Invalid {label}: expected 1..=100 characters");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("Invalid {label}: unexpected characters");
    }
    Ok(())
}

fn validate_sha(value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("Invalid SHA: expected 40 lowercase hex characters");
    }
    Ok(())
}

fn validate_git_ref_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 100 {
        bail!("Invalid {label}: expected 1..=100 characters");
    }
    if value.starts_with('/')
        || value.ends_with('/')
        || value.contains("..")
        || value.contains('\\')
    {
        bail!("Invalid {label}: unsafe path syntax");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
    {
        bail!("Invalid {label}: unexpected characters");
    }
    Ok(())
}

fn validate_action_path(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 200 {
        bail!("Invalid action path: expected 1..=200 characters");
    }
    if value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains("..")
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

/// Constant-time equality comparison for authentication tokens.
///
/// The length check is *not* constant-time, but that is acceptable here:
/// both sides of the comparison are fixed-length auth tokens whose length
/// is not secret in this protocol.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn parse_optional_u64(field: &str) -> Result<Option<u64>> {
    if field.is_empty() {
        return Ok(None);
    }
    field
        .parse::<u64>()
        .map(Some)
        .context("Malformed numeric proxy field")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ready_line_round_trips() {
        let mut buf = Vec::new();
        writeln!(buf, "{READY_MAGIC}\t{}", encode_field("127.0.0.1:7777")).unwrap();
        let addr = read_ready_line(buf.as_slice()).unwrap();
        assert_eq!(addr, "127.0.0.1:7777".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn field_encoding_round_trips() {
        let value = "api.github.com\tvalue\nnext";
        let encoded = encode_field(value);
        let decoded = decode_field(&encoded).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn rejects_invalid_github_components() {
        validate_github_component("actions", "owner").unwrap();
        validate_github_component("../evil", "owner").unwrap_err();
        validate_github_component("owner with spaces", "owner").unwrap_err();
    }

    #[test]
    fn rejects_invalid_shas_and_refs() {
        validate_sha("0123456789abcdef0123456789abcdef01234567").unwrap();
        validate_sha("0123456789ABCDEF0123456789abcdef01234567").unwrap_err();
        validate_git_ref_name("v4.2.2", "tag").unwrap();
        validate_git_ref_name("../../main", "tag").unwrap_err();
        validate_action_path("subdir/nested-action").unwrap();
        validate_action_path("../escape").unwrap_err();
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn field_encoding_round_trips(s in "\\PC*") {
                let encoded = encode_field(&s);
                let decoded = decode_field(&encoded).expect("decode must succeed for encoded data");
                prop_assert_eq!(decoded, s);
            }

            #[test]
            fn split_fields_never_panics(s in "\\PC{0,512}") {
                let _ = split_fields(&s);
            }

            #[test]
            fn validate_github_component_never_panics(s in "\\PC{0,256}") {
                let _ = validate_github_component(&s, "test");
            }

            #[test]
            fn validate_sha_never_panics(s in "\\PC{0,64}") {
                let _ = validate_sha(&s);
            }

            #[test]
            fn validate_git_ref_never_panics(s in "\\PC{0,128}") {
                let _ = validate_git_ref_name(&s, "test");
            }
        }
    }
}
