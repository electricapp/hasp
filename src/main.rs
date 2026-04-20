mod audit;
mod cli;
mod diff;
mod error;
mod exec;
mod forward_proxy;
mod github;
mod integrity;
mod ipc;
mod manifest;
mod netguard;
mod oidc;
mod policy;
mod proxy;
mod report;
mod sandbox;
mod scanner;
mod selfcheck;
mod token;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use cli::Mode;
use error::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

fn scrubbed_subprocess_vars() -> &'static [&'static str] {
    static DATA: std::sync::OnceLock<Vec<&str>> = std::sync::OnceLock::new();
    DATA.get_or_init(|| {
        include_str!("../data/scrubbed_env_vars.txt")
            .lines()
            .filter(|l| !l.is_empty())
            .collect()
    })
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("rustls CryptoProvider already installed");

    if let Err(e) = run() {
        eprintln!("hasp: error: {e}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let args = cli::parse();

    // ── Self-check (needs full filesystem + network, runs before sandbox) ─────
    if args.self_check {
        return selfcheck::run();
    }

    match args.mode {
        Mode::Launcher => run_launcher(&args),
        Mode::Diff => diff::run(&args),
        Mode::Exec => exec::run_exec(&args),
        Mode::InternalScan => run_internal_scan(&args),
        Mode::InternalVerify => run_internal_verify(&args),
        Mode::InternalProxy => run_internal_proxy(&args),
        Mode::InternalForwardProxy => forward_proxy::run_internal(&args),
        Mode::InternalBpfHelper => netguard::run_bpf_helper(),
    }
}

#[allow(clippy::too_many_lines)]
fn run_launcher(args: &cli::Args) -> Result<()> {
    sandbox::platform_preflight(args.allow_unsandboxed, true)?;
    scrub_parent_environment();

    let canonical_dir = args
        .dir
        .canonicalize()
        .context("Cannot resolve workflow dir")?;
    if !canonical_dir.is_dir() {
        error::bail!("{} is not a directory", canonical_dir.display());
    }

    // ── Load policy ──────────────────────────────────────────────────────
    let policy = load_policy(args, &canonical_dir)?;
    let has_policy_checks = policy.has_any_enabled_check();

    // ── Policy drift detection (--diff-base) ─────────────────────────────
    if let Some(ref base) = args.diff_base {
        check_policy_drift(base, &policy, &canonical_dir);
    }

    // Defense-in-depth: verify workflow files haven't been tampered with after
    // git checkout (e.g. by a prior CI step). Skipped with --allow-unsandboxed
    // since dev workflows may have uncommitted changes.
    if args.allow_unsandboxed {
        eprintln!("hasp: note: workflow integrity check skipped (--allow-unsandboxed)");
    } else {
        integrity::check_workflow_integrity(&canonical_dir)?;
    }

    println!("hasp: scanning {}/", canonical_dir.display());
    let exe = std::env::current_exe().context("Cannot resolve current executable path")?;
    let scan = run_scan_subprocess(&exe, args)?;

    if scan.action_refs.is_empty()
        && scan.container_refs.is_empty()
        && scan.skipped_refs.is_empty()
        && !args.paranoid
        && !has_policy_checks
    {
        println!("hasp: no executable dependency references found.");
        return Ok(());
    }

    if !scan.action_refs.is_empty() {
        println!("hasp: found {} action reference(s)", scan.action_refs.len());
    }
    if !scan.container_refs.is_empty() {
        println!(
            "hasp: found {} container image reference(s)",
            scan.container_refs.len()
        );
    }
    if !scan.skipped_refs.is_empty() {
        println!(
            "hasp: found {} unauditable reference(s)",
            scan.skipped_refs.len()
        );
    }

    // ── Compute diff-base changes (before any env scrubbing) ──────────
    let diff_changes = if let Some(ref base) = args.diff_base {
        let changes = compute_diff_base_changes(base, &scan.action_refs);
        if changes.is_empty() {
            eprintln!("hasp: no SHA changes found since {base}");
        } else {
            eprintln!(
                "hasp: found {} action SHA change(s) since {base}",
                changes.len()
            );
        }
        changes
    } else {
        Vec::new()
    };

    let has_token = std::env::var_os("GITHUB_TOKEN").is_some();
    let (results, mut provenance_findings, compare_results) = if scan.action_refs.is_empty() {
        (Vec::new(), Vec::new(), Vec::new())
    } else if args.no_verify {
        (
            github::skip_verify(&scan.action_refs),
            Vec::new(),
            Vec::new(),
        )
    } else if has_token {
        // run_verify_subprocess scrubs GITHUB_TOKEN from the environment
        // immediately after capturing it for the proxy child.
        let payload = run_verify_subprocess(&exe, args, &scan.action_refs, &diff_changes)?;
        (
            payload.results,
            payload.provenance_findings,
            payload.compare_results,
        )
    } else {
        if args.strict {
            error::bail!(
                "GITHUB_TOKEN not set in --strict mode. \
                 Pass --no-verify to explicitly skip verification."
            );
        }
        eprintln!(
            "hasp: note: GITHUB_TOKEN not set — SHA verification skipped. \
             Pass --no-verify to silence."
        );
        (
            github::skip_verify(&scan.action_refs),
            Vec::new(),
            Vec::new(),
        )
    };

    // ── Phase 3: self-sandbox the launcher ────────────────────────────────
    // All children have exited and their output has been collected. The
    // launcher only needs to format results to stdout/stderr and exit.
    sandbox::phase3_deny_launcher(args.allow_unsandboxed)?;

    let has_unsupported_refs = report::print_skipped_refs(&scan.skipped_refs);
    let has_container_failures = report::print_container_refs(&scan.container_refs, args.strict);
    let has_pin_failures = report::print_results(&results, args.strict, &policy);

    // Policy enables audit even without --paranoid
    let run_audit = args.paranoid || args.has_age_policy() || has_policy_checks;
    let has_audit_failures = if run_audit {
        let mut all_findings = scan.audit_findings;
        all_findings.append(&mut provenance_findings);

        // Apply suppressions from policy
        let suppressed_count = apply_suppressions(&policy, &mut all_findings);
        report::print_audit_findings(&all_findings, suppressed_count)
    } else {
        false
    };

    // Upstream changes section (informational, never causes exit 1)
    if !compare_results.is_empty() {
        report::print_upstream_changes(&compare_results);
    } else if !diff_changes.is_empty() && (args.no_verify || !has_token) {
        report::print_upstream_changes_no_detail(&diff_changes);
    }

    if has_unsupported_refs || has_container_failures || has_pin_failures || has_audit_failures {
        std::process::exit(1);
    }

    Ok(())
}

fn load_policy(args: &cli::Args, canonical_dir: &Path) -> Result<policy::Policy> {
    let pol = if args.no_policy {
        if args.paranoid {
            let mut p = policy::Policy::default();
            p.merge_cli(args);
            p
        } else {
            policy::Policy::default()
        }
    } else if let Some(path) = &args.policy_path {
        let canonical = path
            .canonicalize()
            .context(format!("Cannot resolve policy path {}", path.display()))?;
        let mut p = policy::Policy::load_from(&canonical)?;
        p.merge_cli(args);
        eprintln!("hasp: loaded policy from {}", canonical.display());
        p
    } else {
        // Try to find .hasp.yml by walking up from the workflow dir
        let repo_root = find_repo_root(canonical_dir);
        policy::Policy::load(&repo_root)?.map_or_else(
            || {
                let mut p = policy::Policy::default();
                if args.paranoid {
                    p.merge_cli(args);
                }
                p
            },
            |mut p| {
                p.merge_cli(args);
                eprintln!(
                    "hasp: loaded policy from {}",
                    policy::Policy::policy_path(&repo_root).display()
                );
                p
            },
        )
    };

    if !pol.has_any_enabled_check() {
        eprintln!("hasp: warning: policy disables all security checks");
    }

    if pol.has_broad_suppressions() {
        eprintln!(
            "hasp: warning: policy contains broad suppression patterns (*/*, *) \
             — some findings will be silently hidden"
        );
    }

    Ok(pol)
}

/// Compare the current `.hasp.yml` against the version at `diff_base` and
/// warn loudly if any security checks were weakened.  This catches malicious
/// PRs that weaken the policy file as part of the same change they're scanning.
fn check_policy_drift(diff_base: &str, current: &policy::Policy, workflow_dir: &Path) {
    // Find repo root to locate .hasp.yml
    let repo_root = find_repo_root(workflow_dir);
    let policy_path = policy::Policy::policy_path(&repo_root);
    let relative = policy_path.strip_prefix(&repo_root).unwrap_or(&policy_path);
    let git_path = format!("{diff_base}:{}", relative.display());

    let output = Command::new("git").args(["show", &git_path]).output();

    let Ok(output) = output else { return };
    if !output.status.success() {
        // Policy didn't exist at base — new policy file, nothing to compare.
        return;
    }
    let Ok(old_content) = String::from_utf8(output.stdout) else {
        return;
    };

    let Ok(old_policy) = policy::Policy::parse_text(&old_content) else {
        eprintln!("hasp: warning: could not parse base-branch policy — drift check skipped");
        return;
    };

    let drifts = policy::detect_policy_drift(&old_policy, current);
    if drifts.is_empty() {
        return;
    }

    eprintln!();
    eprintln!(
        "hasp: WARNING: policy file was weakened in this change ({} drift(s) since {diff_base}):",
        drifts.len()
    );
    for drift in &drifts {
        eprintln!("  - {}", drift.description);
    }
    eprintln!("hasp: A malicious PR that weakens the policy file can hide its own findings.");
    eprintln!(
        "hasp: Require CODEOWNERS review for .hasp.yml, or use --paranoid to override the policy."
    );
    eprintln!();
}

fn find_repo_root(start: &Path) -> PathBuf {
    let mut dir = start.to_path_buf();
    let mut depth = 0_u32;
    loop {
        if dir.join(".git").exists() || dir.join(".hasp.yml").exists() {
            return dir;
        }
        depth += 1;
        if depth > 10 || !dir.pop() {
            return start.to_path_buf();
        }
    }
}

/// Collect OIDC acceptances from both CLI `--oidc-policy` flags and
/// `.hasp.yml`'s `oidc:` section, resolved against the repo root. Failures
/// degrade to warnings so a typo in one policy path doesn't block the scan.
fn load_oidc_acceptances(
    args: &cli::Args,
    policy: &policy::Policy,
    workflow_dir: &Path,
) -> Vec<oidc::OidcAcceptance> {
    let repo_root = find_repo_root(workflow_dir);
    let mut entries: Vec<(String, PathBuf)> = args.oidc_policies.clone();
    for p in &policy.oidc_policies {
        entries.push((p.provider.clone(), repo_root.join(&p.path)));
    }
    let mut out = Vec::new();
    for (provider_str, path) in entries {
        let provider = match oidc::OidcProvider::parse(&provider_str) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "hasp: warning: skipping OIDC policy {}: {e}",
                    path.display()
                );
                continue;
            }
        };
        match oidc::load_trust_policy(provider, &path) {
            Ok(acceptances) => out.extend(acceptances),
            Err(e) => {
                eprintln!(
                    "hasp: warning: failed to load OIDC policy {} ({provider}): {e}",
                    path.display()
                );
            }
        }
    }
    out
}

fn apply_suppressions(policy: &policy::Policy, findings: &mut Vec<audit::AuditFinding>) -> usize {
    if !policy.has_suppressions() {
        return 0;
    }

    let mut suppressed = 0_usize;
    findings.retain(|f| {
        let check_name = policy::check_name_for_finding(&f.title);
        // Audit findings don't carry structured owner/repo, so pass None.
        // Suppression patterns of "*" will still match (broad suppression).
        if policy.is_suppressed(check_name, None, &f.file).is_some() {
            suppressed += 1;
            false
        } else {
            true
        }
    });

    suppressed
}

/// Compute action ref changes between `diff_base` and HEAD for all workflow files.
fn compute_diff_base_changes(
    diff_base: &str,
    head_refs: &[scanner::ActionRef],
) -> Vec<scanner::ActionRefChange> {
    // Validate the ref to prevent git option injection and path traversal.
    // Command::args() prevents shell injection, but git itself interprets
    // leading dashes as options.  We also reject control characters and
    // enforce a length limit consistent with git's own ref constraints.
    if diff_base.is_empty()
        || diff_base.len() > 256
        || diff_base.starts_with('-')
        || diff_base.contains('\0')
        || diff_base.contains("..")
        || diff_base.contains('\\')
        || diff_base.bytes().any(|b| b.is_ascii_control())
    {
        eprintln!("hasp: warning: invalid diff-base ref — skipping");
        return Vec::new();
    }

    // Deduplicate file paths
    let files: Vec<&Path> = {
        let mut seen = HashSet::new();
        head_refs
            .iter()
            .filter_map(|r| {
                if seen.insert(&r.file) {
                    Some(r.file.as_path())
                } else {
                    None
                }
            })
            .collect()
    };

    // Get repo root for relative path calculation
    let repo_root = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| PathBuf::from(s.trim()))
            } else {
                None
            }
        });

    let Some(repo_root) = repo_root else {
        eprintln!("hasp: warning: not a git repository — cannot compute diff-base changes");
        return Vec::new();
    };

    // Verify the ref actually resolves; otherwise `git show` will silently
    // miss every file and we'd report "no SHA changes" for what is really a
    // typo in the diff-base ref.
    let resolved = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", diff_base])
        .current_dir(&repo_root)
        .output();
    match resolved {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!(
                "hasp: warning: diff-base ref `{diff_base}` could not be resolved \
                 — skipping diff-base comparison"
            );
            return Vec::new();
        }
    }

    let mut changes = Vec::new();

    for &file in &files {
        let relative = file.strip_prefix(&repo_root).unwrap_or(file);
        let git_path = format!("{diff_base}:{}", relative.display());

        let output = Command::new("git").args(["show", &git_path]).output();

        let Ok(output) = output else {
            continue; // git show failed, skip
        };
        if !output.status.success() {
            continue; // file didn't exist at diff_base
        }
        let Ok(old_content) = String::from_utf8(output.stdout) else {
            continue;
        };

        let Ok(old_refs) = scanner::extract_action_refs_from_content(&old_content, file) else {
            continue;
        };

        // Build old ref map for this file, keyed by (owner, repo, path)
        let mut old_map: HashMap<(&str, &str, Option<&str>), &scanner::ActionRef> = HashMap::new();
        for r in &old_refs {
            old_map.insert((&r.owner, &r.repo, r.path.as_deref()), r);
        }

        // Find pairs where SHA changed
        for r in head_refs {
            if r.file.as_path() != file || r.ref_kind != scanner::RefKind::FullSha {
                continue;
            }
            let key: (&str, &str, Option<&str>) = (&r.owner, &r.repo, r.path.as_deref());
            if let Some(old_ref) = old_map.get(&key)
                && old_ref.ref_str != r.ref_str
            {
                changes.push(scanner::ActionRefChange {
                    file: file.to_path_buf(),
                    owner: r.owner.clone(),
                    repo: r.repo.clone(),
                    path: r.path.clone(),
                    old_sha: old_ref.ref_str.clone(),
                    new_sha: r.ref_str.clone(),
                    old_comment: old_ref.comment_version.clone(),
                    new_comment: r.comment_version.clone(),
                });
            }
        }
    }

    changes
}

/// Run compare API calls for each unique `(owner, repo, old_sha, new_sha)` pair.
fn run_compare_for_changes(
    client: &impl github::Api,
    changes: &[scanner::ActionRefChange],
) -> Vec<github::CompareResult> {
    if changes.is_empty() {
        return Vec::new();
    }

    // Deduplicate by (owner, repo, old_sha, new_sha) using references
    let mut seen: HashSet<(&str, &str, &str, &str)> = HashSet::new();
    let mut results = Vec::new();

    for change in changes {
        let key = (
            change.owner.as_str(),
            change.repo.as_str(),
            change.old_sha.as_str(),
            change.new_sha.as_str(),
        );
        if !seen.insert(key) {
            continue;
        }

        match client.compare_commits(
            &change.owner,
            &change.repo,
            &change.old_sha,
            &change.new_sha,
        ) {
            Ok(result) => results.push(result),
            Err(e) => {
                eprintln!(
                    "hasp: warning: compare API failed for {}/{}: {e}",
                    change.owner, change.repo
                );
            }
        }
    }

    results
}

fn run_internal_scan(args: &cli::Args) -> Result<()> {
    sandbox::phase1_deny_writes_and_syscalls(
        args.allow_unsandboxed,
        sandbox::NetworkPolicy::DenyNewSockets,
        false,
    )?;

    let canonical_dir = args
        .dir
        .canonicalize()
        .context("Cannot resolve workflow dir")?;
    if !canonical_dir.is_dir() {
        error::bail!("{} is not a directory", canonical_dir.display());
    }

    // Load policy before scanning (needs filesystem access)
    let policy = load_policy(args, &canonical_dir)?;

    let scan = scanner::scan_directory(&canonical_dir)?;
    let run_audit = args.paranoid || policy.has_any_enabled_check();
    let audit_findings = if run_audit {
        let effective_owners = policy::Policy::effective_list(
            policy.trust.owners.as_ref(),
            audit::builtin_trusted_owners(),
        );
        let mut findings = audit::run(&scan.workflow_docs, &scan.action_refs, &policy.checks);
        if !policy.checks.untrusted_sources.is_off() {
            audit::check_untrusted_sources(
                &scan.action_refs,
                &mut findings,
                policy.checks.untrusted_sources,
                &effective_owners,
            );
        }
        if !policy.checks.oidc.is_off() && !args.no_oidc {
            let acceptances = load_oidc_acceptances(args, &policy, &canonical_dir);
            audit::oidc::run(
                &scan.workflow_docs,
                &acceptances,
                &mut findings,
                policy.checks.oidc,
            );
        }
        findings
    } else {
        Vec::new()
    };

    sandbox::phase2_deny_reads()?;

    let payload = ipc::ScanPayload {
        action_refs: scan.action_refs,
        skipped_refs: scan.skipped_refs,
        container_refs: scan.container_refs,
        audit_findings,
    };

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    ipc::write_scan_payload(&mut lock, &payload)?;
    lock.flush().context("Failed to flush scan payload")?;
    Ok(())
}

fn run_internal_verify(args: &cli::Args) -> Result<()> {
    sandbox::phase1_deny_writes_and_syscalls(
        args.allow_unsandboxed,
        sandbox::NetworkPolicy::Allow,
        false,
    )?;

    let verifier_input = {
        let stdin = std::io::stdin();
        let lock = stdin.lock();
        ipc::read_verifier_input(lock)?
    };

    if verifier_input.action_refs.is_empty() {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        ipc::write_verification_results(&mut lock, &[], &[], &[])?;
        lock.flush()
            .context("Failed to flush empty verification payload")?;
        return Ok(());
    }

    // Load policy BEFORE phase2_deny_reads (policy loading needs filesystem access)
    let canonical_dir = args
        .dir
        .canonicalize()
        .context("Cannot resolve workflow dir")?;
    let policy = load_policy(args, &canonical_dir)?;

    sandbox::phase2_deny_reads()?;
    let client = proxy::Client::from_env()?;
    let results = github::verify_all_with_api(&client, &verifier_input.action_refs)?;

    let provenance_findings =
        if args.paranoid || args.has_age_policy() || policy.has_any_provenance_check() {
            let mut findings = github::check_provenance_with_api(&client, &results, &policy)?;
            if args.paranoid
                || !policy.checks.provenance.transitive.is_off()
                || !policy.checks.provenance.hidden_execution.is_off()
            {
                findings.extend(github::scan_transitive_with_api(
                    &client,
                    &results,
                    args.max_transitive_depth,
                    policy.checks.provenance.transitive,
                    policy.checks.provenance.hidden_execution,
                ));
            }
            findings
        } else {
            Vec::new()
        };

    // Compare API calls for diff-base changes
    let compare_results = run_compare_for_changes(&client, &verifier_input.diff_changes);

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    ipc::write_verification_results(&mut lock, &results, &provenance_findings, &compare_results)?;
    lock.flush()
        .context("Failed to flush verification payload")?;
    Ok(())
}

fn run_internal_proxy(args: &cli::Args) -> Result<()> {
    sandbox::phase1_deny_writes_and_syscalls(
        args.allow_unsandboxed,
        sandbox::NetworkPolicy::Allow,
        false,
    )?;
    proxy::run_server()
}

fn run_scan_subprocess(exe: &Path, args: &cli::Args) -> Result<ipc::ScanPayload> {
    let mut cmd = build_child_command(exe, args);
    cmd.arg("--internal-scan")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    apply_env_allowlist(&mut cmd, &[]);

    let output = cmd
        .output()
        .context("Failed to launch scanner subprocess")?;

    ensure_child_success("scanner", output.status)?;
    ipc::read_scan_payload(output.stdout.as_slice())
}

#[allow(clippy::too_many_lines)]
fn run_verify_subprocess(
    exe: &Path,
    args: &cli::Args,
    action_refs: &[scanner::ActionRef],
    diff_changes: &[scanner::ActionRefChange],
) -> Result<ipc::VerifyPayload> {
    let github_addrs = github::pre_resolve_api()?;
    let mut proxy_auth = token::generate_ephemeral_secret_hex(32)?;

    let proxy_sandbox = netguard::maybe_prepare(
        netguard::SandboxMode::Proxy,
        &github_addrs,
        args.allow_unsandboxed,
    )?;
    let mut proxy_cmd = build_child_command(exe, args);
    proxy_cmd
        .arg("--internal-proxy")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // Scrub GITHUB_TOKEN from the launcher environment immediately after
    // capturing it for the proxy child. The OsString copy inside the
    // Command env map is freed when spawn_command() consumes the Command;
    // mimalloc "secure" mode zeros freed pages as a residual mitigation.
    let github_token = std::env::var_os("GITHUB_TOKEN");
    // SAFETY: single-threaded at this point — no child processes yet.
    #[allow(unsafe_code)]
    unsafe {
        std::env::remove_var("GITHUB_TOKEN");
    }
    let proxy_env = [
        ("GITHUB_TOKEN", github_token),
        (
            proxy::PROXY_AUTH_ENV,
            Some(OsString::from(proxy_auth.as_str())),
        ),
        (
            proxy::GITHUB_ADDRS_ENV,
            Some(OsString::from(join_socket_addrs(&github_addrs))),
        ),
    ];
    apply_env_allowlist(&mut proxy_cmd, &proxy_env);
    drop(proxy_env);

    let mut proxy_child = match netguard::spawn_command(proxy_cmd, proxy_sandbox.as_ref()) {
        Ok(child) => child,
        Err(err) => {
            token::scrub_string(&mut proxy_auth);
            return Err(err);
        }
    };
    let proxy_addr = {
        let stdout = proxy_child
            .stdout
            .take()
            .context("Failed to capture proxy ready stream")?;
        match proxy::read_ready_line(BufReader::new(stdout)) {
            Ok(addr) => addr,
            Err(err) => {
                token::scrub_string(&mut proxy_auth);
                terminate_child(&mut proxy_child);
                return Err(err);
            }
        }
    };

    let verifier_allowlist = [proxy_addr];
    let verifier_sandbox = netguard::maybe_prepare(
        netguard::SandboxMode::Verifier,
        &verifier_allowlist,
        args.allow_unsandboxed,
    )?;
    let mut verifier_cmd = build_child_command(exe, args);
    verifier_cmd
        .arg("--internal-verify")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let verifier_env = [
        (
            proxy::PROXY_AUTH_ENV,
            Some(OsString::from(proxy_auth.as_str())),
        ),
        (
            proxy::PROXY_ADDR_ENV,
            Some(OsString::from(proxy_addr.to_string())),
        ),
    ];
    apply_env_allowlist(&mut verifier_cmd, &verifier_env);
    drop(verifier_env);
    let mut child = match netguard::spawn_command(verifier_cmd, verifier_sandbox.as_ref()) {
        Ok(child) => {
            token::scrub_string(&mut proxy_auth);
            child
        }
        Err(err) => {
            token::scrub_string(&mut proxy_auth);
            terminate_child(&mut proxy_child);
            return Err(err);
        }
    };

    {
        let mut stdin = child
            .stdin
            .take()
            .context("Failed to open verifier stdin")?;
        ipc::write_action_refs_with_changes(&mut stdin, action_refs, diff_changes)?;
        stdin
            .flush()
            .context("Failed to flush verifier input payload")?;
    }

    let output = child
        .wait_with_output()
        .context("Failed to read verifier subprocess output")?;
    terminate_child(&mut proxy_child);
    ensure_child_success("verifier", output.status)?;
    ipc::read_verification_results(output.stdout.as_slice())
}

fn build_child_command(exe: &Path, args: &cli::Args) -> Command {
    let mut cmd = Command::new(exe);
    if args.allow_unsandboxed {
        cmd.arg("--allow-unsandboxed");
    }
    if args.paranoid {
        cmd.arg("--paranoid");
    }
    if args.strict {
        cmd.arg("--strict");
    }
    if let Some(seconds) = args.min_sha_age_seconds {
        cmd.arg("--min-sha-age").arg(format!("{seconds}s"));
    }
    if let Some(seconds) = args.security_action_min_sha_age_seconds {
        cmd.arg("--security-action-min-sha-age")
            .arg(format!("{seconds}s"));
    }
    if let Some(path) = &args.policy_path {
        cmd.arg("--policy").arg(path);
    }
    if args.no_policy {
        cmd.arg("--no-policy");
    }
    cmd.arg("--dir").arg(&args.dir);
    if args.max_transitive_depth != 3 {
        cmd.arg("--max-transitive-depth")
            .arg(format!("{}", args.max_transitive_depth));
    }
    for (provider, path) in &args.oidc_policies {
        cmd.arg("--oidc-policy")
            .arg(format!("{provider}:{}", path.display()));
    }
    if args.no_oidc {
        cmd.arg("--no-oidc");
    }
    cmd
}

fn scrub_parent_environment() {
    for var in scrubbed_subprocess_vars() {
        // SAFETY: hasp is single-threaded at this point (before any child
        // processes are spawned), so remove_var has no data races.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(var);
        }
    }
}

fn apply_env_allowlist(cmd: &mut Command, allowed: &[(&str, Option<OsString>)]) {
    cmd.env_clear();
    for (key, value) in allowed {
        if let Some(value) = value {
            cmd.env(key, value);
        }
    }
}

fn ensure_child_success(label: &str, status: ExitStatus) -> Result<()> {
    if status.success() {
        return Ok(());
    }

    match status.code() {
        Some(code) => error::bail!("{label} subprocess failed with exit code {code}"),
        None => error::bail!("{label} subprocess terminated by signal"),
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn join_socket_addrs(addrs: &[std::net::SocketAddr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
