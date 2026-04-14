use crate::cli::Args;
use crate::error::{Context, Result, bail};
use crate::forward_proxy;
use crate::manifest::StepManifest;
use crate::netguard;
use crate::token;
use std::io::{BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// Environment variables preserved for the child process.
/// Minimal set — no TERM (minor info leak), no SHELL, no EDITOR.
const PRESERVED_ENV_VARS: &[&str] = &["PATH", "HOME", "USER", "LANG"];

/// Hard limits to prevent resource exhaustion from malicious manifests.
const MAX_SECRETS: usize = 32;
const MAX_WRITABLE_DIRS: usize = 64;

struct ProxyInfo {
    env_var: String,
    addr: SocketAddr,
    auth: String,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_exec(args: &Args) -> Result<()> {
    let exec_args = args
        .exec
        .as_ref()
        .context("exec subcommand requires ExecArgs")?;

    crate::sandbox::platform_preflight(args.allow_unsandboxed, true)?;

    // 1. Parse manifest
    let manifest = if let Some(ref manifest_path) = exec_args.manifest {
        let canonical = manifest_path.canonicalize().context(format!(
            "Cannot resolve manifest path {}",
            manifest_path.display()
        ))?;
        eprintln!("hasp exec: loaded manifest from {}", canonical.display());
        StepManifest::load(&canonical)?
    } else {
        eprintln!("hasp exec: no manifest — zero secrets, zero network, read-only fs");
        StepManifest::empty()
    };

    // Enforce resource limits
    if manifest.secrets.len() > MAX_SECRETS {
        bail!(
            "Manifest declares {} secrets (max {MAX_SECRETS})",
            manifest.secrets.len()
        );
    }
    let total_writable = exec_args.writable_dirs.len() + manifest.writable_dirs.len();
    if total_writable > MAX_WRITABLE_DIRS {
        bail!("Too many writable directories: {total_writable} (max {MAX_WRITABLE_DIRS})");
    }

    // 2. Pre-resolve DNS for all allowed domains (before any sandboxing)
    let domain_addrs = pre_resolve_domains(manifest.all_allowed_domains())?;

    // 3. Capture secrets from env → SecureToken, then scrub env
    let mut secret_tokens: Vec<(String, token::SecureToken)> = Vec::new();
    for grant in &manifest.secrets {
        match token::SecureToken::from_env(&grant.env_var) {
            Ok(tok) => {
                secret_tokens.push((grant.env_var.clone(), tok));
            }
            Err(e) => {
                bail!("Secret ${} not found in environment: {e}", grant.env_var);
            }
        }
    }

    // 4. Spawn one forward proxy per secret (with pre-resolved addrs)
    let exe = std::env::current_exe().context("Cannot resolve current executable path")?;
    let mut proxy_children: Vec<Child> = Vec::new();
    let mut proxy_infos: Vec<ProxyInfo> = Vec::new();

    for (idx, grant) in manifest.secrets.iter().enumerate() {
        let (_, ref secret_token) = secret_tokens[idx];

        let proxy_info = match spawn_forward_proxy(&exe, args, grant, secret_token, &domain_addrs) {
            Ok((child, info)) => {
                proxy_children.push(child);
                info
            }
            Err(err) => {
                scrub_proxy_auths(&mut proxy_infos);
                cleanup_children(&mut proxy_children);
                return Err(err);
            }
        };
        proxy_infos.push(proxy_info);
    }

    // 5. Prepare BPF sandbox for child (only proxy localhost ports)
    let child_allowlist: Vec<SocketAddr> = proxy_infos.iter().map(|p| p.addr).collect();
    let child_sandbox = netguard::maybe_prepare(
        netguard::SandboxMode::StepRunner,
        &child_allowlist,
        args.allow_unsandboxed,
    )?;

    // 6. Collect writable dirs: user-specified + manifest + cgroup path
    let mut all_writable: Vec<PathBuf> = exec_args.writable_dirs.clone();
    for dir in &manifest.writable_dirs {
        all_writable.push(PathBuf::from(dir));
    }
    if let Some(ref sandbox) = child_sandbox {
        // Orchestrator needs write access to cgroup.procs to move the child PID
        all_writable.push(sandbox.path().to_path_buf());
    }

    // 7. Apply Landlock + seccomp BEFORE spawning child so child inherits.
    // Landlock is inherited across fork — the child gets the same fs restrictions.
    // seccomp is inherited across fork — the child gets ptrace/process_vm denied.
    // After this point, the orchestrator (and child) can only write to declared dirs.
    crate::sandbox::phase_exec_child(&all_writable, args.allow_unsandboxed)?;

    // 8. Build child command with scrubbed env + proxy vars
    let mut child_cmd = Command::new(&exec_args.command[0]);
    if exec_args.command.len() > 1 {
        child_cmd.args(&exec_args.command[1..]);
    }
    child_cmd.env_clear();
    for var in PRESERVED_ENV_VARS {
        if let Some(val) = std::env::var_os(var) {
            child_cmd.env(var, val);
        }
    }
    // Only proxy URLs are exposed to the child — no auth tokens, no secrets.
    // Access control: BPF cgroup (Linux) + proxy loopback check + ephemeral port.
    for info in &proxy_infos {
        child_cmd.env(
            format!("HASP_PROXY_{}", info.env_var),
            format!("http://{}", info.addr),
        );
    }

    child_cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // 9. Spawn child in BPF cgroup (inherits Landlock + seccomp from step 7)
    let mut child = match netguard::spawn_command(child_cmd, child_sandbox.as_ref()) {
        Ok(child) => child,
        Err(err) => {
            scrub_proxy_auths(&mut proxy_infos);
            cleanup_children(&mut proxy_children);
            return Err(err);
        }
    };
    // Child is spawned — scrub proxy auth tokens from orchestrator memory.
    scrub_proxy_auths(&mut proxy_infos);

    // 10. Wait for child exit
    let status = child.wait().context("Failed to wait for child process")?;

    // 11. Kill proxies
    cleanup_children(&mut proxy_children);

    // Exit with child's exit code
    let code = status.code().unwrap_or(1);
    if code != 0 {
        std::process::exit(code);
    }

    Ok(())
}

fn spawn_forward_proxy(
    exe: &std::path::Path,
    args: &Args,
    grant: &crate::manifest::SecretGrant,
    secret_token: &token::SecureToken,
    domain_addrs: &[(String, Vec<SocketAddr>)],
) -> Result<(Child, ProxyInfo)> {
    let mut proxy_auth = token::generate_ephemeral_secret_hex(32)?;

    // Collect pre-resolved upstream IPs for this secret's domains
    let upstream_addrs: Vec<SocketAddr> = grant
        .domains
        .iter()
        .filter_map(|d| domain_addrs.iter().find(|(domain, _)| domain == d))
        .flat_map(|(_, addrs)| addrs.iter().copied())
        .collect();

    let proxy_sandbox = netguard::maybe_prepare(
        netguard::SandboxMode::SecretProxy,
        &upstream_addrs,
        args.allow_unsandboxed,
    )?;

    let mut proxy_cmd = Command::new(exe);
    if args.allow_unsandboxed {
        proxy_cmd.arg("--allow-unsandboxed");
    }
    proxy_cmd
        .arg("--internal-forward-proxy")
        .stdin(Stdio::piped()) // Secret delivered via pipe, not env var
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let inject_str = match grant.inject {
        crate::manifest::InjectMode::Header => "header",
        crate::manifest::InjectMode::Basic => "basic",
        crate::manifest::InjectMode::None => "none",
    };

    // Pass pre-resolved upstream addresses so the proxy never re-resolves DNS.
    // Eliminates DNS rebinding window and avoids redundant lookups.
    let upstream_addrs_str = upstream_addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    proxy_cmd.env_clear();
    // Secret is NOT passed via env var — /proc/PID/environ on Linux exposes
    // the initial environment forever, even after remove_var(). The secret
    // is written to the proxy's stdin pipe after spawn (see below).
    proxy_cmd.env(forward_proxy::FORWARD_PROXY_AUTH_ENV, proxy_auth.as_str());
    proxy_cmd.env(
        forward_proxy::FORWARD_PROXY_DOMAINS_ENV,
        grant.domains.join(","),
    );
    proxy_cmd.env(forward_proxy::FORWARD_PROXY_INJECT_ENV, inject_str);
    proxy_cmd.env(
        forward_proxy::FORWARD_PROXY_PREFIX_ENV,
        &grant.header_prefix,
    );
    proxy_cmd.env(
        forward_proxy::FORWARD_PROXY_UPSTREAM_ADDRS_ENV,
        &upstream_addrs_str,
    );

    let mut proxy_child = match netguard::spawn_command(proxy_cmd, proxy_sandbox.as_ref()) {
        Ok(child) => child,
        Err(err) => {
            token::scrub_string(&mut proxy_auth);
            return Err(err);
        }
    };

    // Write secret to proxy's stdin pipe, then close it (EOF).
    // The proxy reads from stdin before binding its listener, so this
    // completes before the ready line is emitted. No /proc/PID/environ trace.
    {
        let mut proxy_stdin = proxy_child
            .stdin
            .take()
            .context("Failed to capture forward proxy stdin")?;
        let write_result =
            secret_token.with_unmasked(|plain| proxy_stdin.write_all(plain.as_bytes()));
        // proxy_stdin dropped → EOF sent to proxy
        if let Err(err) = write_result {
            token::scrub_string(&mut proxy_auth);
            let _ = proxy_child.kill();
            let _ = proxy_child.wait();
            return Err(err).context("Failed to write secret to proxy stdin");
        }
    }

    let proxy_stdout = proxy_child
        .stdout
        .take()
        .context("Failed to capture forward proxy stdout")?;
    let proxy_addr = match forward_proxy::read_ready_line(BufReader::new(proxy_stdout)) {
        Ok(addr) => addr,
        Err(err) => {
            token::scrub_string(&mut proxy_auth);
            let _ = proxy_child.kill();
            let _ = proxy_child.wait();
            return Err(err);
        }
    };

    eprintln!(
        "hasp exec: proxy for ${} listening on {} (domains: {})",
        grant.env_var,
        proxy_addr,
        grant.domains.join(", ")
    );

    let info = ProxyInfo {
        env_var: grant.env_var.clone(),
        addr: proxy_addr,
        auth: proxy_auth,
    };

    Ok((proxy_child, info))
}

fn pre_resolve_domains(domains: &[String]) -> Result<Vec<(String, Vec<SocketAddr>)>> {
    use std::net::ToSocketAddrs;
    let mut results = Vec::with_capacity(domains.len());
    for domain in domains {
        let addrs: Vec<SocketAddr> = (domain.as_str(), 443_u16)
            .to_socket_addrs()
            .context(format!("DNS resolution failed for {domain}"))?
            .collect();
        if addrs.is_empty() {
            bail!("No addresses found for domain {domain}");
        }
        eprintln!(
            "hasp exec: resolved {domain} → {}",
            addrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        results.push((domain.clone(), addrs));
    }
    Ok(results)
}

fn scrub_proxy_auths(infos: &mut [ProxyInfo]) {
    for info in infos.iter_mut() {
        token::scrub_string(&mut info.auth);
    }
}

fn cleanup_children(children: &mut [Child]) {
    for child in children.iter_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
}
