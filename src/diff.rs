//! `hasp diff <base>` -- PR-delta mode.
//!
//! Re-runs the static audit against a git worktree checked out at `<base>`,
//! scans HEAD, then emits the finding-level delta: new findings, fixed
//! findings, and unchanged findings. Output is terse-text, markdown (PR
//! comment-friendly), or JSON (CI-consumable).
//!
//! Unlike the primary `hasp --paranoid` scan, delta mode runs the audit
//! inline (no multi-process sandbox). The caller must acknowledge this by
//! passing `--allow-unsandboxed`; otherwise we exit with a usage error and
//! direct them at `hasp --paranoid`. The workflow integrity check still
//! runs on both base and HEAD so a prior CI step can't have mutated the
//! files we're about to compare.

use crate::audit::{self, AuditFinding, Severity};
use crate::error::{Context, Result, bail};
use crate::git_util;
use crate::integrity;
use crate::policy::Policy;
use crate::scanner;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffFormat {
    Terse,
    Markdown,
    Json,
}

impl DiffFormat {
    pub(crate) fn parse(s: &str) -> Result<Self> {
        match s {
            "terse" | "text" => Ok(Self::Terse),
            "markdown" | "md" => Ok(Self::Markdown),
            "json" => Ok(Self::Json),
            other => bail!("Invalid --format `{other}`: expected terse, markdown, or json"),
        }
    }
}

#[derive(Debug)]
struct DeltaReport {
    base: String,
    new: Vec<AuditFinding>,
    fixed: Vec<AuditFinding>,
    unchanged_count: usize,
}

impl DeltaReport {
    fn exit_code(&self) -> i32 {
        i32::from(self.has_blocking_new())
    }

    fn has_blocking_new(&self) -> bool {
        self.new.iter().any(|f| !f.is_warning)
    }
}

pub(crate) fn run(args: &crate::cli::Args) -> Result<()> {
    let base = args
        .diff_base
        .as_ref()
        .context("hasp diff requires a base ref")?
        .clone();
    let format = args.diff_format.unwrap_or(DiffFormat::Terse);

    if !git_util::is_sane_git_ref(&base) {
        bail!("Invalid diff-base ref");
    }

    // Diff mode runs the audit inline; require explicit opt-in so a user
    // doesn't think they're getting the same hardening as `hasp --paranoid`.
    if !args.allow_unsandboxed {
        eprintln!(
            "hasp diff: this runs an unsandboxed inline scan. \
             Pass --allow-unsandboxed to acknowledge, or run `hasp --paranoid` \
             for the sandboxed authoritative scan."
        );
        std::process::exit(2);
    }
    eprintln!("hasp diff: running unsandboxed inline scan");

    // Resolve the workflow dir and repo root.
    let canonical_dir = args
        .dir
        .canonicalize()
        .context("Cannot resolve workflow dir")?;
    let repo_root = git_util::repo_toplevel(&canonical_dir)?;
    let relative_dir = canonical_dir
        .strip_prefix(&repo_root)
        .context("workflow directory is outside the git repo")?
        .to_path_buf();

    // Verify the base ref resolves.
    let base_sha = git_util::resolve_ref_sha(&repo_root, &base)?;

    // Short-circuit when base resolves to the same SHA as HEAD: nothing to
    // diff, and re-running an identical scan against itself is pointless.
    let head_sha = git_util::resolve_ref_sha(&repo_root, "HEAD").ok();
    if head_sha.as_deref() == Some(base_sha.as_str()) {
        let empty = DeltaReport {
            base,
            new: Vec::new(),
            fixed: Vec::new(),
            unchanged_count: 0,
        };
        emit(&empty, format);
        return Ok(());
    }

    // Policy (same policy for both scans).
    let (policy, _) = Policy::resolve(args, &canonical_dir)?;

    // Integrity check on HEAD before we trust its workflow contents.
    integrity::check_workflow_integrity(&canonical_dir)?;
    // Both scans normalize finding `file` paths to be relative to the
    // workflow directory they were scanned from, so identical files in
    // base and head produce identical keys regardless of where the temp
    // worktree happened to land.
    let head_findings = scan_and_audit(&canonical_dir, &canonical_dir, &policy)?;

    // Temp worktree for base. SIGINT/SIGTERM handler installed once.
    install_signal_cleanup_once();
    let worktree = BaseWorktree::create(&repo_root, &base_sha)?;
    register_cleanup_path(worktree.path(), &repo_root);
    let base_scan_root = worktree.path().join(&relative_dir);
    let base_findings = if base_scan_root.is_dir() {
        // Integrity-check the base worktree too: catches files git couldn't
        // restore (e.g. filesystem corruption) before we trust their content.
        integrity::check_workflow_integrity(&base_scan_root)?;
        scan_and_audit(&base_scan_root, &base_scan_root, &policy)?
    } else {
        // Base didn't have the workflow dir at all. All head findings are new.
        Vec::new()
    };

    let delta = compute_delta(&base, &base_findings, &head_findings);
    emit(&delta, format);

    // Drop runs first so the worktree teardown actually happens; clearing the
    // signal target after is safe because `cleanup_worktree` is idempotent
    // (a signal landing between the two only triggers a no-op second pass).
    drop(worktree);
    clear_cleanup_path();

    let code = delta.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn emit(delta: &DeltaReport, format: DiffFormat) {
    match format {
        DiffFormat::Terse => print_terse(delta),
        DiffFormat::Markdown => print_markdown(delta),
        DiffFormat::Json => print_json(delta),
    }
}

/// Scan and audit `scan_dir`, then normalize every finding's `file` field to
/// a path relative to `scan_root`. This is what makes diff-mode work: base
/// and HEAD findings end up keyed on the same logical path even though
/// they were physically scanned from different locations.
fn scan_and_audit(scan_dir: &Path, scan_root: &Path, policy: &Policy) -> Result<Vec<AuditFinding>> {
    let scan = scanner::scan_directory(scan_dir)?;
    let mut findings = audit::run(&scan.workflow_docs, &scan.action_refs, &policy.checks);
    if !policy.checks.untrusted_sources.is_off() {
        let owners = Policy::effective_list(
            policy.trust.owners.as_ref(),
            audit::builtin_trusted_owners(),
        );
        audit::check_untrusted_sources(
            &scan.action_refs,
            &mut findings,
            policy.checks.untrusted_sources,
            &owners,
        );
    }
    if !policy.checks.oidc.is_off() {
        // diff mode reads OIDC acceptances from `.hasp.yml` only — CLI
        // `--oidc-policy` flags aren't exposed by `parse_diff`. Both base and
        // head scans see the same policy file content, so divergence between
        // them is a real OIDC-policy change worth flagging.
        let acceptances =
            crate::oidc::load_policy_acceptances(&[], &policy.oidc_policies, scan_dir);
        audit::oidc::run(
            &scan.workflow_docs,
            &acceptances,
            &mut findings,
            policy.checks.oidc,
        );
    }
    strip_scan_root(&mut findings, scan_root);
    Ok(findings)
}

/// Strip the (canonicalized) scan-root prefix from every place a path can
/// hide in a finding — `file`, plus the user-facing `title` / `detail` strings
/// because some audits (`cross_workflow`, `oidc`) embed `path.display()`
/// directly. Without this rewrite, base and head scans running under different
/// worktree paths produce non-matching `FindingKey` for the same logical issue,
/// and every persistent finding shows up as both `new` and `fixed`.
fn strip_scan_root(findings: &mut [AuditFinding], scan_root: &Path) {
    let canonical_root = scan_root
        .canonicalize()
        .unwrap_or_else(|_| scan_root.to_path_buf());
    let mut prefix = canonical_root.to_string_lossy().into_owned();
    if !prefix.ends_with(std::path::MAIN_SEPARATOR) {
        prefix.push(std::path::MAIN_SEPARATOR);
    }
    // Skip text rewriting when the prefix is empty or just a bare separator —
    // either means canonicalize failed in a way that would replace far too much.
    let strip_text = prefix.len() > 1;
    for f in findings {
        if let Ok(rel) = f.file.strip_prefix(&canonical_root) {
            f.file = rel.to_path_buf();
        }
        if strip_text {
            if f.title.contains(&prefix) {
                f.title = f.title.replace(&prefix, "");
            }
            if f.detail.contains(&prefix) {
                f.detail = f.detail.replace(&prefix, "");
            }
        }
    }
}

fn compute_delta(
    base_ref: &str,
    base_findings: &[AuditFinding],
    head_findings: &[AuditFinding],
) -> DeltaReport {
    let base_keys: HashSet<FindingKey<'_>> = base_findings.iter().map(FindingKey::from).collect();
    let head_keys: HashSet<FindingKey<'_>> = head_findings.iter().map(FindingKey::from).collect();

    let mut new = Vec::new();
    let mut unchanged_count = 0_usize;
    for f in head_findings {
        if base_keys.contains(&FindingKey::from(f)) {
            unchanged_count += 1;
        } else {
            new.push(f.clone());
        }
    }

    let mut fixed = Vec::new();
    for f in base_findings {
        if !head_keys.contains(&FindingKey::from(f)) {
            fixed.push(f.clone());
        }
    }

    new.sort_by_key(|f| f.severity);
    fixed.sort_by_key(|f| f.severity);

    DeltaReport {
        base: base_ref.to_string(),
        new,
        fixed,
        unchanged_count,
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct FindingKey<'a> {
    file: &'a Path,
    severity: Severity,
    title: &'a str,
    detail: &'a str,
    is_warning: bool,
}

impl<'a> From<&'a AuditFinding> for FindingKey<'a> {
    fn from(f: &'a AuditFinding) -> Self {
        Self {
            file: &f.file,
            severity: f.severity,
            title: &f.title,
            detail: &f.detail,
            is_warning: f.is_warning,
        }
    }
}

// ─── Output formatters ──────────────────────────────────────────────────────

fn print_terse(delta: &DeltaReport) {
    println!("hasp diff: base {}", delta.base);
    if delta.new.is_empty() && delta.fixed.is_empty() {
        println!(
            "  no changes in audit findings (unchanged: {})",
            delta.unchanged_count
        );
        return;
    }
    if !delta.new.is_empty() {
        println!("\nNew findings: {}", delta.new.len());
        for f in &delta.new {
            println!(
                "  [{}] {:<4}  {}",
                f.severity,
                status_marker(f.is_warning),
                f.title
            );
        }
    }
    if !delta.fixed.is_empty() {
        println!("\nFixed findings: {}", delta.fixed.len());
        for f in &delta.fixed {
            println!("  [{}] {:<4}  {}", f.severity, "fix", f.title);
        }
    }
    println!("\nUnchanged: {}", delta.unchanged_count);
}

const fn status_marker(is_warning: bool) -> &'static str {
    if is_warning { "warn" } else { "deny" }
}

fn print_markdown(delta: &DeltaReport) {
    // Buffer the whole report and emit in one write so partial reports
    // can't end up interleaved with anything else on stdout.
    let mut out = String::new();
    let _ = writeln!(out, "## hasp audit delta vs `{}`\n", md_inline(&delta.base));

    if delta.new.is_empty() && delta.fixed.is_empty() {
        let _ = writeln!(
            out,
            "_No changes in audit findings ({} unchanged)._\n",
            delta.unchanged_count
        );
        print!("{out}");
        return;
    }

    if !delta.new.is_empty() {
        let _ = writeln!(out, "### New findings ({})\n", delta.new.len());
        out.push_str("| Severity | Check | File | Status |\n");
        out.push_str("|----------|-------|------|--------|\n");
        for f in &delta.new {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                f.severity,
                md_inline(&f.title),
                md_code_cell(&f.file.display().to_string()),
                if f.is_warning { "warn" } else { "**deny**" }
            );
        }
        out.push('\n');
        // Code-fence the detail block instead of raw HTML <details> so
        // attacker-controlled YAML strings can't break out of the wrapper.
        out.push_str("```text\n");
        for f in &delta.new {
            let _ = writeln!(out, "[{}] {}", f.severity, f.title);
            let detail = sanitize_for_codeblock(&f.detail);
            let _ = writeln!(out, "  {detail}");
            out.push('\n');
        }
        out.push_str("```\n\n");
    }

    if !delta.fixed.is_empty() {
        let _ = writeln!(out, "### Fixed findings ({})\n", delta.fixed.len());
        out.push_str("| Severity | Check | File |\n");
        out.push_str("|----------|-------|------|\n");
        for f in &delta.fixed {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                f.severity,
                md_inline(&f.title),
                md_code_cell(&f.file.display().to_string())
            );
        }
        out.push('\n');
    }

    let _ = writeln!(out, "_{} unchanged finding(s)._\n", delta.unchanged_count);
    print!("{out}");
}

/// Escape a string for use inside a markdown table cell (i.e. inline text).
/// Newlines collapse to spaces (tables can't span rows); table separators
/// and the characters that drive markdown/HTML interpretation are
/// backslash-escaped.
fn md_inline(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' | '\r' => out.push(' '),
            '|' => out.push_str(r"\|"),
            '`' => out.push_str(r"\`"),
            '<' => out.push_str(r"\<"),
            '>' => out.push_str(r"\>"),
            '\\' => out.push_str(r"\\"),
            c => out.push(c),
        }
    }
    out
}

/// Render a file path inside a backtick-wrapped markdown cell. Any embedded
/// backticks are doubled in line with `CommonMark`'s code-span rules so the
/// wrapping backticks can't be terminated by user content.
fn md_code_cell(path: &str) -> String {
    let mut sanitized = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '\n' | '\r' => sanitized.push(' '),
            '|' => sanitized.push('_'),
            c => sanitized.push(c),
        }
    }
    if sanitized.contains('`') {
        format!("``{}``", sanitized.replace('`', "` `"))
    } else {
        format!("`{sanitized}`")
    }
}

/// Make `s` safe to drop into a ```text``` fenced block: replace any line
/// that consists of backticks (which could close the fence) with an
/// indented version, and strip carriage returns.
fn sanitize_for_codeblock(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.split('\n') {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.starts_with("```") {
            out.push(' ');
        }
        out.push_str(trimmed);
        out.push('\n');
    }
    // Trim trailing newline we always appended above.
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

fn print_json(delta: &DeltaReport) {
    // Minimal JSON emitter; hasp intentionally has no serde_json dep.
    let mut out = String::from("{");
    let _ = write!(out, r#""base": {},"#, json_string(&delta.base));
    let _ = write!(out, r#""unchanged_count": {},"#, delta.unchanged_count);
    out.push_str(r#""new": "#);
    emit_findings_json(&mut out, &delta.new);
    out.push(',');
    out.push_str(r#""fixed": "#);
    emit_findings_json(&mut out, &delta.fixed);
    out.push('}');
    println!("{out}");
}

fn emit_findings_json(out: &mut String, findings: &[AuditFinding]) {
    out.push('[');
    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        let _ = write!(
            out,
            r#""severity": {},"#,
            json_string(&f.severity.to_string())
        );
        let _ = write!(out, r#""title": {},"#, json_string(&f.title));
        let _ = write!(out, r#""detail": {},"#, json_string(&f.detail));
        let _ = write!(
            out,
            r#""file": {},"#,
            json_string(&f.file.to_string_lossy())
        );
        let _ = write!(out, r#""is_warning": {}"#, f.is_warning);
        out.push('}');
    }
    out.push(']');
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ─── base worktree ──────────────────────────────────────────────────────────

/// Temp worktree that is torn down on Drop so failed runs don't leak
/// git-worktree directories.
struct BaseWorktree {
    repo_root: PathBuf,
    path: PathBuf,
}

impl BaseWorktree {
    fn create(repo_root: &Path, sha: &str) -> Result<Self> {
        let path = unique_worktree_path()?;
        let out = git_util::git_cmd()
            .args([
                "worktree",
                "add",
                "--detach",
                "--no-checkout",
                path.to_string_lossy().as_ref(),
                sha,
            ])
            .current_dir(repo_root)
            .output()
            .context("Failed to run `git worktree add`")?;
        if !out.status.success() {
            bail!(
                "`git worktree add` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        // Construct Self before running checkout so a checkout failure still
        // triggers Drop and tears down the just-registered worktree entry.
        let this = Self {
            repo_root: repo_root.to_path_buf(),
            path,
        };
        // Checkout is a second step so creation stays cheap (--no-checkout)
        // and checkout errors surface distinctly.
        let checkout = git_util::git_cmd()
            .args(["checkout", sha])
            .current_dir(&this.path)
            .output()
            .context("Failed to checkout base worktree")?;
        if !checkout.status.success() {
            bail!(
                "Failed to checkout {sha} in base worktree: {}",
                String::from_utf8_lossy(&checkout.stderr).trim()
            );
        }
        Ok(this)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BaseWorktree {
    fn drop(&mut self) {
        cleanup_worktree(&self.path, &self.repo_root);
    }
}

/// Pick an exclusive path under `temp_dir()`. We seed the suffix with high-
/// resolution time + pid + process-local counter so a local attacker can't
/// reliably pre-create the path to `DoS` the run, and we use `create_dir`
/// (atomic on EEXIST) to confirm exclusivity before removing the dir again
/// so git can populate it.
fn unique_worktree_path() -> Result<PathBuf> {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static C: AtomicU32 = AtomicU32::new(0);
    for _ in 0..64 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let counter = C.fetch_add(1, Ordering::Relaxed);
        // Mix in a coarse hash of pid + nanos + counter to spread the suffix.
        let suffix =
            (u64::from(std::process::id()) << 32) ^ (u64::from(nanos) << 16) ^ u64::from(counter);
        let path = std::env::temp_dir().join(format!("hasp-diff-worktree-{suffix:016x}"));
        #[allow(clippy::create_dir)] // we *want* the EEXIST failure path
        match std::fs::create_dir(&path) {
            Ok(()) => {
                // git worktree add requires the destination to not already
                // exist. Remove the placeholder dir now that we've proven
                // the name is exclusively ours.
                let _ = std::fs::remove_dir(&path);
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => bail!("Could not reserve temp worktree path: {e}"),
        }
    }
    bail!("Exhausted 64 attempts reserving a unique temp worktree path")
}

fn cleanup_worktree(path: &Path, repo_root: &Path) {
    // Best-effort cleanup — don't propagate errors during unwind / signal.
    let _ = git_util::git_cmd()
        .args([
            "worktree",
            "remove",
            "--force",
            path.to_string_lossy().as_ref(),
        ])
        .current_dir(repo_root)
        .output();
    let _ = std::fs::remove_dir_all(path);
    // Belt-and-suspenders: prune any administrative entries git may have
    // left behind in `.git/worktrees/`.
    let _ = git_util::git_cmd()
        .args(["worktree", "prune"])
        .current_dir(repo_root)
        .output();
}

// ─── signal cleanup ─────────────────────────────────────────────────────────

// The atomic flag is the handler's fast path — it can short-circuit without
// acquiring the mutex when no worktree is registered. The mutex protects the
// target itself so repeat registrations (e.g. a future multi-base diff loop)
// can swap targets without losing protection. The handler uses `try_lock`
// to stay async-signal-safe; in the worst case (concurrent register/clear)
// it skips cleanup, which matches the old "leak the temp dir, don't deadlock"
// failure mode.
static CLEANUP_TARGET: std::sync::Mutex<Option<(PathBuf, PathBuf)>> =
    std::sync::Mutex::new(None);
static CLEANUP_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn register_cleanup_path(path: &Path, repo_root: &Path) {
    if let Ok(mut g) = CLEANUP_TARGET.lock() {
        *g = Some((path.to_path_buf(), repo_root.to_path_buf()));
    }
    CLEANUP_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn clear_cleanup_path() {
    CLEANUP_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut g) = CLEANUP_TARGET.lock() {
        *g = None;
    }
}

#[cfg(unix)]
fn install_signal_cleanup_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // The fn-pointer-to-usize cast is the only way to pass an
        // `extern "C" fn` to libc's untyped `sighandler_t`. clippy's
        // fn_to_numeric_cast_any lint targets accidental casts in
        // arithmetic; this is a documented FFI shim.
        #[allow(clippy::fn_to_numeric_cast_any)]
        let handler: libc::sighandler_t = signal_handler as *const () as usize;
        // SAFETY: `signal(2)` only mutates per-process disposition flags.
        // The handler itself is async-signal-safe: it only uses try_lock
        // (never blocks) and `_exit` (async-signal-safe).
        #[allow(unsafe_code)]
        unsafe {
            libc::signal(libc::SIGINT, handler);
            libc::signal(libc::SIGTERM, handler);
        }
    });
}

#[cfg(not(unix))]
const fn install_signal_cleanup_once() {
    // Non-Unix platforms fall back to Drop-on-unwind cleanup only.
}

#[cfg(unix)]
extern "C" fn signal_handler(sig: libc::c_int) {
    if CLEANUP_ACTIVE.load(std::sync::atomic::Ordering::SeqCst)
        && let Ok(guard) = CLEANUP_TARGET.try_lock()
        && let Some((path, repo_root)) = guard.as_ref()
    {
        cleanup_worktree(path, repo_root);
    }
    // SAFETY: `_exit` is async-signal-safe and immediately terminates the
    // process. 128 + signo follows the POSIX shell convention.
    #[allow(unsafe_code)]
    unsafe {
        libc::_exit(128 + sig);
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn finding(title: &str, file: &str, severity: Severity, is_warning: bool) -> AuditFinding {
        AuditFinding {
            file: PathBuf::from(file),
            severity,
            title: title.to_string(),
            detail: format!("{title} detail"),
            is_warning,
        }
    }

    #[test]
    fn delta_splits_new_fixed_unchanged() {
        let base = vec![
            finding("A", "ci.yml", Severity::High, false),
            finding("B", "ci.yml", Severity::Medium, true),
        ];
        let head = vec![
            finding("B", "ci.yml", Severity::Medium, true),
            finding("C", "release.yml", Severity::Critical, false),
        ];
        let delta = compute_delta("main", &base, &head);
        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].title, "C");
        assert_eq!(delta.fixed.len(), 1);
        assert_eq!(delta.fixed[0].title, "A");
        assert_eq!(delta.unchanged_count, 1);
    }

    #[test]
    fn identical_base_and_head_yield_empty_delta_with_unchanged() {
        // Same finding present in both base and head must be unchanged, not
        // simultaneously new and fixed.
        let f = finding("only-finding", "ci.yml", Severity::High, false);
        let one = std::slice::from_ref(&f);
        let delta = compute_delta("main", one, one);
        assert!(
            delta.new.is_empty() && delta.fixed.is_empty(),
            "expected empty new/fixed when base and head are byte-identical, \
             got new={:?} fixed={:?}",
            delta.new,
            delta.fixed
        );
        assert_eq!(delta.unchanged_count, 1);
        assert_eq!(delta.exit_code(), 0);
    }

    #[test]
    fn strip_scan_root_rewrites_file_title_and_detail() {
        // Findings produced by cross_workflow / oidc audits embed absolute
        // paths into title and detail strings via `path.display()`. Base and
        // head scans run under different worktree roots, so the same logical
        // finding would key differently unless we strip the prefix everywhere.
        let temp = std::env::temp_dir().join("hasp-scan-root-test-XXX");
        std::fs::create_dir_all(&temp).unwrap();
        let inside = temp.join(".github/workflows/ci.yml");
        let canonical = temp.canonicalize().unwrap_or_else(|_| temp.clone());
        let canonical_inside = canonical.join(".github/workflows/ci.yml");

        let mut findings = vec![AuditFinding {
            file: canonical_inside.clone(),
            severity: Severity::High,
            title: format!("flow from `{}`", canonical_inside.display()),
            detail: format!(
                "consumer {} downloads artifact produced by {}",
                canonical_inside.display(),
                canonical_inside.display()
            ),
            is_warning: false,
        }];
        strip_scan_root(&mut findings, &temp);

        let f = &findings[0];
        assert_eq!(f.file, Path::new(".github/workflows/ci.yml"));
        assert!(
            !f.title.contains(&*canonical.to_string_lossy()),
            "title still contains scan root: {}",
            f.title
        );
        assert!(
            !f.detail.contains(&*canonical.to_string_lossy()),
            "detail still contains scan root: {}",
            f.detail
        );
        let _ = std::fs::remove_dir_all(inside.parent().unwrap());
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn delta_exit_code_blocks_only_on_new_deny_findings() {
        let delta = DeltaReport {
            base: "main".into(),
            new: vec![finding("X", "ci.yml", Severity::Critical, false)],
            fixed: Vec::new(),
            unchanged_count: 5,
        };
        assert_eq!(delta.exit_code(), 1);

        let delta = DeltaReport {
            base: "main".into(),
            new: vec![finding("X", "ci.yml", Severity::Medium, true)],
            fixed: Vec::new(),
            unchanged_count: 0,
        };
        assert_eq!(delta.exit_code(), 0);
    }

    #[test]
    fn format_parse_accepts_known_values() {
        assert_eq!(DiffFormat::parse("terse").unwrap(), DiffFormat::Terse);
        assert_eq!(DiffFormat::parse("markdown").unwrap(), DiffFormat::Markdown);
        assert_eq!(DiffFormat::parse("json").unwrap(), DiffFormat::Json);
        let err = DiffFormat::parse("yaml").unwrap_err();
        assert!(err.to_string().contains("Invalid"), "got {err}");
    }

    #[test]
    fn json_escapes_control_characters() {
        let s = json_string("hello\n\"world\"");
        assert_eq!(s, r#""hello\n\"world\"""#);
    }

    #[test]
    fn markdown_does_not_expose_attacker_html_tags() {
        // A finding title/detail crafted to break out of a raw `<details>`
        // wrapper must not appear as literal HTML in the rendered output.
        let mut f = finding(
            "step name with </details><img src=x onerror=alert(1)>",
            "ci.yml",
            Severity::High,
            false,
        );
        f.detail = "evil </details> body\n```\nfence-out\n```".into();
        let delta = DeltaReport {
            base: "main".into(),
            new: vec![f],
            fixed: Vec::new(),
            unchanged_count: 0,
        };

        let mut buf = String::new();
        let _ = writeln!(buf, "## hasp audit delta vs `{}`\n", md_inline(&delta.base));
        let _ = writeln!(buf, "### New findings ({})\n", delta.new.len());
        buf.push_str("| Severity | Check | File | Status |\n");
        buf.push_str("|----------|-------|------|--------|\n");
        for ff in &delta.new {
            let _ = writeln!(
                buf,
                "| {} | {} | {} | {} |",
                ff.severity,
                md_inline(&ff.title),
                md_code_cell(&ff.file.display().to_string()),
                if ff.is_warning { "warn" } else { "**deny**" }
            );
        }
        buf.push_str("\n```text\n");
        for ff in &delta.new {
            let _ = writeln!(buf, "[{}] {}", ff.severity, ff.title);
            let detail = sanitize_for_codeblock(&ff.detail);
            let _ = writeln!(buf, "  {detail}");
        }
        buf.push_str("```\n");

        // The title in the table cell must have its `<` / `>` backslash-
        // escaped so GFM doesn't parse it as raw HTML.
        let table_line = buf
            .lines()
            .find(|l| l.starts_with("| HIGH |"))
            .expect("table row not found");
        // Any `<` or `>` in the cell must be preceded by a backslash.
        for (idx, ch) in table_line.char_indices() {
            if ch == '<' || ch == '>' {
                let prev = idx
                    .checked_sub(1)
                    .and_then(|i| table_line.as_bytes().get(i).copied());
                assert_eq!(
                    prev,
                    Some(b'\\'),
                    "unescaped {ch} at byte {idx} in table cell: {table_line}"
                );
            }
        }
        assert!(
            table_line.contains(r"\</details\>") && table_line.contains(r"\<img"),
            "expected backslash-escaped tags in table cell: {table_line}"
        );

        // The detail block must be wrapped in exactly one code fence pair
        // so that ANY raw HTML inside it renders as literal text, not HTML.
        let fence_count = buf.matches("\n```").count();
        assert_eq!(
            fence_count, 2,
            "expected exactly one open and one close code fence, got {fence_count} in:\n{buf}"
        );

        // The body of the fenced block must not contain a literal "```"
        // line that would terminate the fence early (sanitize_for_codeblock
        // is supposed to neutralize those).
        let mut in_fence = false;
        for line in buf.lines() {
            if line == "```text" {
                in_fence = true;
                continue;
            }
            if in_fence && line == "```" {
                in_fence = false;
                continue;
            }
            assert!(
                !in_fence || !line.starts_with("```"),
                "fence-closing line ``` leaked into the body: {line}"
            );
        }
    }

    #[test]
    fn unique_worktree_paths_are_distinct() {
        let a = unique_worktree_path().unwrap();
        let b = unique_worktree_path().unwrap();
        assert_ne!(a, b);
    }
}
