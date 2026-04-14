use crate::error::{Context, Result, bail};
use crate::manifest::InjectMode;
use crate::token::SecureToken;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

pub(crate) const FORWARD_PROXY_READY_MAGIC: &str = "HASP_FORWARD_PROXY_READY_V1";
pub(crate) const FORWARD_PROXY_DOMAINS_ENV: &str = "HASP_FWD_DOMAINS";
pub(crate) const FORWARD_PROXY_INJECT_ENV: &str = "HASP_FWD_INJECT";
pub(crate) const FORWARD_PROXY_PREFIX_ENV: &str = "HASP_FWD_PREFIX";
pub(crate) const FORWARD_PROXY_AUTH_ENV: &str = "HASP_FWD_AUTH";
pub(crate) const FORWARD_PROXY_UPSTREAM_ADDRS_ENV: &str = "HASP_FWD_UPSTREAM_ADDRS";

const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024; // 16 KiB
const MAX_REQUEST_HEADERS: usize = 128;
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
const MAX_RESPONSE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB
const MAX_CONNECTIONS: u32 = 10_000;
const MAX_AUTH_FAILURES: u32 = 5;
/// Proxy exits if no connection arrives within this window. Prevents
/// orphaned proxies (e.g. orchestrator OOM-killed) from holding the
/// secret in memory indefinitely.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Run as `hasp --internal-forward-proxy`. Reads configuration from env vars,
/// binds to an ephemeral localhost port, and announces readiness on stdout.
#[allow(clippy::too_many_lines)]
pub(crate) fn run_internal(args: &crate::cli::Args) -> Result<()> {
    crate::sandbox::phase1_deny_writes_and_syscalls(
        args.allow_unsandboxed,
        crate::sandbox::NetworkPolicy::Allow,
        false,
    )?;

    // Read secret from stdin pipe — NOT from environment variables.
    // /proc/PID/environ on Linux exposes the initial exec-time environment
    // forever, even after remove_var(). A same-UID child could read it.
    // The stdin pipe is consumed and closed; no procfs trace remains.
    let secret = SecureToken::from_stdin()?;
    let auth = SecureToken::from_env(FORWARD_PROXY_AUTH_ENV)?;

    let domains_raw = std::env::var(FORWARD_PROXY_DOMAINS_ENV)
        .context(format!("{FORWARD_PROXY_DOMAINS_ENV} not set"))?;
    let allowed_domains: Vec<String> = domains_raw
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if allowed_domains.is_empty() {
        bail!("Forward proxy has no allowed domains");
    }

    // Parse pre-resolved upstream addresses (avoids DNS re-resolution per request)
    let upstream_addrs = parse_upstream_addrs()?;

    let inject_mode = match std::env::var(FORWARD_PROXY_INJECT_ENV)
        .unwrap_or_else(|_| "header".to_string())
        .as_str()
    {
        "header" => InjectMode::Header,
        "basic" => InjectMode::Basic,
        "none" => InjectMode::None,
        other => bail!("Unknown inject mode: {other}"),
    };

    let header_prefix =
        std::env::var(FORWARD_PROXY_PREFIX_ENV).unwrap_or_else(|_| "Bearer ".to_string());

    let tls_config = build_tls_config();

    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("Failed to bind forward proxy")?;
    let listen_addr = listener
        .local_addr()
        .context("Failed to determine forward proxy listen address")?;

    // Announce readiness
    {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        writeln!(lock, "{FORWARD_PROXY_READY_MAGIC}\t{listen_addr}")
            .context("Failed to announce forward proxy readiness")?;
        lock.flush()
            .context("Failed to flush forward proxy ready line")?;
    }

    // Set accept timeout so the proxy exits if the orchestrator dies and
    // no more requests arrive. Without this, an orphaned proxy holds the
    // secret in memory and accepts loopback connections indefinitely.
    listener
        .set_nonblocking(true)
        .context("Failed to set listener non-blocking mode")?;

    let mut total_connections = 0_u32;
    let mut auth_failures = 0_u32;
    let mut last_activity = std::time::Instant::now();
    loop {
        // Use a short accept timeout and check idle deadline between accepts.
        // TcpListener doesn't have set_timeout, so we poll with non-blocking
        // accepts and sleep briefly between checks.
        let stream = match listener.accept() {
            Ok((s, _)) => {
                last_activity = std::time::Instant::now();
                s
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if last_activity.elapsed() > IDLE_TIMEOUT {
                    eprintln!("hasp forward-proxy: idle timeout, shutting down");
                    return Ok(());
                }
                // Brief sleep to avoid busy-wait. The proxy is I/O bound anyway.
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(e) => {
                return Err(crate::error::Error::from(e)).context("Accept failed");
            }
        };
        // Switch accepted stream back to blocking for request handling
        stream
            .set_nonblocking(false)
            .context("Failed to set stream blocking mode")?;
        let mut stream = stream;
        total_connections += 1;
        if total_connections > MAX_CONNECTIONS {
            let _ = write_http_error(&mut stream, 503, "Connection limit exceeded");
            bail!("Forward proxy shutting down after {MAX_CONNECTIONS} connections");
        }
        if auth_failures >= MAX_AUTH_FAILURES {
            let _ = write_http_error(&mut stream, 403, "Too many auth failures");
            bail!("Forward proxy shutting down after {MAX_AUTH_FAILURES} auth failures");
        }
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .context("Failed to set read timeout")?;
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(60)))
            .context("Failed to set write timeout")?;

        // Only accept loopback clients
        let peer = stream.peer_addr().context("Failed to get peer addr")?;
        if !peer.ip().is_loopback() {
            let _ = write_http_error(&mut stream, 403, "Only loopback clients allowed");
            continue;
        }

        match handle_request(
            &mut stream,
            &secret,
            &auth,
            &allowed_domains,
            &upstream_addrs,
            inject_mode,
            &header_prefix,
            &tls_config,
        ) {
            Ok(()) => {}
            Err(ref err) if err.msg().contains("authentication failed") => {
                auth_failures += 1;
                // Truncate error to avoid leaking internals to client
                let _ = write_http_error(&mut stream, 403, "Authentication failed");
            }
            Err(ref err) => {
                eprintln!("hasp forward-proxy: request error: {err}");
                // Send generic error to client — never leak internal error chains
                let _ = write_http_error(&mut stream, 502, "Proxy error");
            }
        }
    }
}

/// Parse readiness line from a forward proxy subprocess.
pub(crate) fn read_ready_line(reader: impl Read) -> Result<SocketAddr> {
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("Failed to read forward proxy ready line")?;
    let line = line.trim_end_matches(['\r', '\n']);
    let parts: Vec<&str> = line.splitn(2, '\t').collect();
    if parts.len() != 2 || parts[0] != FORWARD_PROXY_READY_MAGIC {
        bail!("Malformed forward proxy ready line");
    }
    parts[1]
        .parse::<SocketAddr>()
        .context("Invalid forward proxy ready address")
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn handle_request(
    client: &mut TcpStream,
    secret: &SecureToken,
    auth: &SecureToken,
    allowed_domains: &[String],
    upstream_addrs: &[SocketAddr],
    inject_mode: InjectMode,
    header_prefix: &str,
    tls_config: &Arc<rustls::ClientConfig>,
) -> Result<()> {
    // Parse HTTP request line + headers
    let mut reader = BufReader::new(
        client
            .try_clone()
            .context("Failed to clone client stream")?,
    );
    let req = parse_http_request(&mut reader)?;

    // Auth validation: the child process does not carry auth tokens (they are
    // not exposed in its environment). Access control relies on:
    //   1. BPF cgroup: only the sandboxed child can connect (Linux)
    //   2. Loopback-only: proxy rejects non-127.0.0.1 clients
    //   3. Ephemeral port: proxy binds to a random port
    // If an X-Hasp-Auth header IS present (e.g. from a testing tool), we
    // validate it as defense-in-depth. If absent, we allow the request —
    // the kernel sandbox is the real gate.
    let client_auth = req.headers.iter().find_map(|(k, v): &(String, String)| {
        if k.eq_ignore_ascii_case("x-hasp-auth") {
            Some(v.as_str())
        } else {
            None
        }
    });
    if let Some(provided_auth) = client_auth {
        let auth_ok = auth.with_unmasked(|auth_plain| {
            constant_time_eq(provided_auth.as_bytes(), auth_plain.as_bytes())
        });
        if !auth_ok {
            bail!("Forward proxy authentication failed");
        }
    }

    // Validate Host against domain allowlist (case-insensitive — DNS is case-insensitive)
    let host_domain = req.host.split(':').next().unwrap_or(&req.host);
    if !allowed_domains
        .iter()
        .any(|d| d.eq_ignore_ascii_case(host_domain))
    {
        bail!("Blocked request to disallowed domain: {host_domain}");
    }

    // Read request body if present
    let body = if req.content_length > 0 {
        if req.content_length > MAX_REQUEST_BODY_BYTES {
            bail!("Request body too large: {} bytes", req.content_length);
        }
        let mut buf = vec![0_u8; req.content_length];
        reader
            .read_exact(&mut buf)
            .context("Failed to read request body")?;
        buf
    } else {
        Vec::new()
    };

    // Use pre-resolved upstream address — never re-resolve DNS.
    // Eliminates DNS rebinding attacks between pre-resolution and request time.
    // The BPF cgroup on this proxy already only allows these IPs.
    let upstream_addr = *upstream_addrs
        .first()
        .context("No pre-resolved upstream addresses available")?;

    let server_name = rustls::pki_types::ServerName::try_from(host_domain.to_string())
        .map_err(|e| format!("Invalid server name: {e}"))?;
    let mut tls_conn = rustls::ClientConnection::new(Arc::clone(tls_config), server_name)
        .map_err(|e| format!("TLS connection setup failed: {e}"))?;

    let mut tcp = TcpStream::connect(upstream_addr)
        .context(format!("Failed to connect to upstream {upstream_addr}"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .context("Failed to set upstream read timeout")?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))
        .context("Failed to set upstream write timeout")?;

    let mut tls_stream = rustls::Stream::new(&mut tls_conn, &mut tcp);

    // Write request line
    write!(tls_stream, "{} {} HTTP/1.1\r\n", req.method, req.path)
        .context("Failed to write upstream request line")?;
    write!(tls_stream, "Host: {}\r\n", req.host).context("Failed to write upstream Host header")?;

    // Inject credential
    match inject_mode {
        InjectMode::Header => {
            secret.with_unmasked(|plain| -> Result<()> {
                write!(tls_stream, "Authorization: {header_prefix}{plain}\r\n")
                    .context("Failed to write Authorization header")
            })?;
        }
        InjectMode::Basic => {
            secret.with_unmasked(|plain| -> Result<()> {
                let mut encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    plain.as_bytes(),
                );
                let result = write!(tls_stream, "Authorization: Basic {encoded}\r\n")
                    .context("Failed to write Basic auth header");
                // Scrub the base64-encoded secret from the heap before drop.
                // Without this, the encoded credential persists in freed memory
                // until mimalloc reuses the page.
                crate::token::scrub_string(&mut encoded);
                result
            })?;
        }
        InjectMode::None => {}
    }

    // Forward remaining headers (skip rewritten/injected ones)
    for (name, value) in &req.headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "authorization"
                | "x-hasp-auth"
                | "content-length"
                | "connection"
                | "transfer-encoding"
        ) {
            continue;
        }
        // Reject headers containing CR/LF to prevent header injection
        if name.bytes().any(|b| b == b'\r' || b == b'\n')
            || value.bytes().any(|b| b == b'\r' || b == b'\n')
        {
            continue;
        }
        write!(tls_stream, "{name}: {value}\r\n").context("Failed to write upstream header")?;
    }

    if !body.is_empty() {
        write!(tls_stream, "Content-Length: {}\r\n", body.len())
            .context("Failed to write Content-Length")?;
    }
    write!(tls_stream, "Connection: close\r\n").context("Failed to write Connection header")?;
    write!(tls_stream, "\r\n").context("Failed to end upstream headers")?;

    if !body.is_empty() {
        tls_stream
            .write_all(&body)
            .context("Failed to write upstream body")?;
    }
    tls_stream.flush().context("Failed to flush upstream")?;

    // Stream response back to client through a fixed-size copy buffer.
    // Cap total bytes to prevent OOM from a malicious/broken upstream.
    let mut total_forwarded = 0_u64;
    let mut copy_buf = [0_u8; 16 * 1024]; // 16 KiB streaming buffer
    loop {
        let n = tls_stream
            .read(&mut copy_buf)
            .context("Failed to read upstream response")?;
        if n == 0 {
            break;
        }
        total_forwarded += n as u64;
        if total_forwarded > MAX_RESPONSE_BYTES {
            bail!("Upstream response exceeded {} bytes", MAX_RESPONSE_BYTES);
        }
        client
            .write_all(&copy_buf[..n])
            .context("Failed to forward response to client")?;
    }
    client.flush().context("Failed to flush client response")?;

    Ok(())
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    host: String,
    headers: Vec<(String, String)>,
    content_length: usize,
}

/// Parse HTTP/1.1 request line + headers.
fn parse_http_request(reader: &mut BufReader<TcpStream>) -> Result<HttpRequest> {
    let mut total_read = 0_usize;
    let mut request_line = String::new();
    let n = reader
        .read_line(&mut request_line)
        .context("Failed to read HTTP request line")?;
    total_read += n;
    if total_read > MAX_REQUEST_HEADER_BYTES {
        bail!("HTTP request headers too large");
    }

    let request_line = request_line.trim_end();
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() != 3 {
        bail!(
            "Malformed HTTP request line (truncated: {:?})",
            &request_line[..request_line.len().min(64)]
        );
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();
    if !parts[2].starts_with("HTTP/") {
        bail!("Invalid HTTP version in request line");
    }

    // Reject control characters in method/path — prevents HTTP response
    // splitting and header injection via the request line.
    if method.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        bail!("HTTP method contains invalid characters");
    }
    if path.bytes().any(|b| b.is_ascii_control()) {
        bail!("HTTP path contains control characters");
    }

    // Reject methods that could be used for tunneling or reflection attacks
    if matches!(method.as_str(), "CONNECT" | "TRACE" | "TRACK") {
        bail!("Blocked forbidden HTTP method: {method}");
    }

    // Reject absolute URIs in the request path — a child sending
    // "GET http://evil.com/ HTTP/1.1" with "Host: allowed.com" would
    // pass the Host allowlist but could cause the upstream (or any
    // intermediary) to follow the absolute URI, leaking the injected
    // Authorization header to an attacker-controlled server.
    if path.contains("://") {
        bail!("Absolute URI in request path is forbidden");
    }
    if !path.starts_with('/') {
        bail!("Request path must start with /");
    }

    let mut headers = Vec::with_capacity(32);
    let mut host = String::new();
    let mut content_length = 0_usize;

    loop {
        if headers.len() >= MAX_REQUEST_HEADERS {
            bail!("Too many HTTP headers (max {MAX_REQUEST_HEADERS})");
        }
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .context("Failed to read HTTP header")?;
        total_read += n;
        if total_read > MAX_REQUEST_HEADER_BYTES {
            bail!("HTTP request headers too large");
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("host") {
                host.clone_from(&value);
            }
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }

    if host.is_empty() {
        bail!("HTTP request missing Host header");
    }
    // Reject control characters in Host — prevents header injection
    // when the Host value is written to the upstream request.
    if host.bytes().any(|b| b.is_ascii_control()) {
        bail!("Host header contains control characters");
    }

    Ok(HttpRequest {
        method,
        path,
        host,
        headers,
        content_length,
    })
}

fn parse_upstream_addrs() -> Result<Vec<SocketAddr>> {
    let raw = std::env::var(FORWARD_PROXY_UPSTREAM_ADDRS_ENV)
        .context(format!("{FORWARD_PROXY_UPSTREAM_ADDRS_ENV} not set"))?;
    let mut addrs = Vec::new();
    for part in raw.split(',').filter(|p| !p.is_empty()) {
        addrs.push(
            part.parse::<SocketAddr>()
                .context(format!("Invalid upstream address: `{part}`"))?,
        );
    }
    if addrs.is_empty() {
        bail!("Forward proxy received empty upstream address set");
    }
    Ok(addrs)
}

fn build_tls_config() -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
}

fn write_http_error(stream: &mut TcpStream, code: u16, message: &str) -> Result<()> {
    let reason = match code {
        403 => "Forbidden",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let body = format!("{code} {reason}: {message}\n");
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .context("Failed to write HTTP error response")?;
    stream.flush().context("Failed to flush HTTP error")?;
    Ok(())
}

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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ready_line_round_trips() {
        let mut buf = Vec::new();
        writeln!(buf, "{FORWARD_PROXY_READY_MAGIC}\t127.0.0.1:9999").unwrap();
        let addr = read_ready_line(buf.as_slice()).unwrap();
        assert_eq!(addr, "127.0.0.1:9999".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn rejects_malformed_ready_line() {
        let buf = b"WRONG_MAGIC\t127.0.0.1:9999\n";
        read_ready_line(&buf[..]).unwrap_err();
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    /// Helper: feed raw bytes into `parse_http_request` via a loopback socket pair.
    fn parse_raw_request(raw: &[u8]) -> Result<HttpRequest> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(raw).unwrap();
        drop(client);
        let (server, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(server);
        parse_http_request(&mut reader)
    }

    #[test]
    fn rejects_absolute_uri_in_path() {
        let req = parse_raw_request(b"GET http://evil.com/ HTTP/1.1\r\nHost: allowed.com\r\n\r\n");
        let err = req.unwrap_err();
        assert!(
            err.msg().contains("Absolute URI") || err.msg().contains("must start with /"),
            "expected path rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_path_not_starting_with_slash() {
        let req = parse_raw_request(b"GET evil.com/path HTTP/1.1\r\nHost: allowed.com\r\n\r\n");
        req.unwrap_err();
    }

    #[test]
    fn rejects_connect_method() {
        let req = parse_raw_request(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n");
        let err = req.unwrap_err();
        assert!(
            err.msg().contains("forbidden"),
            "expected method rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_trace_method() {
        let req = parse_raw_request(b"TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        req.unwrap_err();
    }

    #[test]
    fn rejects_method_with_control_chars() {
        let req = parse_raw_request(b"GET\x00DROP / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        req.unwrap_err();
    }

    #[test]
    fn rejects_path_with_control_chars() {
        let req = parse_raw_request(b"GET /\x00evil HTTP/1.1\r\nHost: example.com\r\n\r\n");
        req.unwrap_err();
    }

    #[test]
    fn rejects_host_with_control_chars() {
        let req = parse_raw_request(b"GET / HTTP/1.1\r\nHost: example.com\r\nevil\r\n\r\n");
        // The \r\n in Host causes read_line to split, so Host = "example.com"
        // and "evil" becomes a separate (headerless) line that's ignored.
        // This is safe — but let's verify the parsed Host is clean.
        let parsed = req.unwrap();
        assert_eq!(parsed.host, "example.com");
    }

    #[test]
    fn rejects_oversized_headers() {
        let mut req = b"GET / HTTP/1.1\r\nHost: example.com\r\n".to_vec();
        // Add headers until we exceed MAX_REQUEST_HEADER_BYTES (16 KiB)
        for i in 0..200 {
            req.extend_from_slice(format!("X-Pad-{i}: {}\r\n", "A".repeat(100)).as_bytes());
        }
        req.extend_from_slice(b"\r\n");
        let result = parse_raw_request(&req);
        result.unwrap_err();
    }

    #[test]
    fn accepts_valid_get_request() {
        let req = parse_raw_request(
            b"GET /v2/package HTTP/1.1\r\nHost: registry.npmjs.org\r\nAccept: application/json\r\n\r\n",
        );
        let parsed = req.unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/v2/package");
        assert_eq!(parsed.host, "registry.npmjs.org");
        assert_eq!(parsed.content_length, 0);
    }

    #[test]
    fn parses_content_length() {
        let req = parse_raw_request(
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\n\r\n",
        );
        let parsed = req.unwrap();
        assert_eq!(parsed.content_length, 42);
    }
}
