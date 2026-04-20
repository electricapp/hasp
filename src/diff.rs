//! `hasp diff <base>` -- PR-delta mode.
//!
//! Re-runs the static audit against a git worktree checked out at `<base>`,
//! scans HEAD, then emits the finding-level delta: new findings, fixed
//! findings, and unchanged findings. Output is terse-text, markdown (PR
//! comment-friendly), or JSON (CI-consumable).
//!
//! Unlike the primary `hasp --paranoid` scan, delta mode runs inline (no
//! multi-process sandbox) because it is a developer-facing convenience
//! that post-processes two authoritative scans. If you need the hardened
//! sandbox, run `hasp --paranoid` on each branch separately and diff
//! the reports yourself.

use crate::audit::{self, AuditFinding, Severity};
use crate::error::{Context, Result, bail};
use crate::policy::Policy;
use crate::scanner;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    fn exit_code(&self, fail_on_unchanged: bool) -> i32 {
        if self.has_blocking_new() {
            return 1;
        }
        if fail_on_unchanged && self.unchanged_count > 0 {
            return 1;
        }
        0
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

    if !is_sane_git_ref(&base) {
        bail!("Invalid diff-base ref");
    }

    // Resolve the workflow dir and repo root.
    let canonical_dir = args
        .dir
        .canonicalize()
        .context("Cannot resolve workflow dir")?;
    let repo_root = git_repo_root(&canonical_dir)?;
    let relative_dir = canonical_dir
        .strip_prefix(&repo_root)
        .context("workflow directory is outside the git repo")?;

    // Verify the base ref resolves.
    let base_sha = resolve_git_ref(&repo_root, &base)?;

    // Policy (same policy for both scans).
    let policy = load_effective_policy(args, &canonical_dir)?;

    let head_findings = scan_and_audit(&canonical_dir, &policy)?;

    // Temp worktree for base.
    let worktree = BaseWorktree::create(&repo_root, &base_sha)?;
    let base_dir = worktree.path().join(relative_dir);
    let base_findings = if base_dir.is_dir() {
        scan_and_audit(&base_dir, &policy)?
    } else {
        // Base didn't have the workflow dir at all. All head findings are new.
        Vec::new()
    };

    let delta = compute_delta(&base, &base_findings, &head_findings);

    match format {
        DiffFormat::Terse => print_terse(&delta),
        DiffFormat::Markdown => print_markdown(&delta),
        DiffFormat::Json => print_json(&delta),
    }

    drop(worktree); // Explicit for clarity; Drop removes the temp worktree.

    let code = delta.exit_code(false);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// Load policy, respecting --no-policy / --policy / --paranoid as the
/// launcher does. Small duplication of `main::load_policy` avoids leaking that
/// function to the diff path without refactoring main.rs.
fn load_effective_policy(args: &crate::cli::Args, canonical_dir: &Path) -> Result<Policy> {
    if args.no_policy {
        let mut p = Policy::default();
        if args.paranoid {
            p.merge_cli(args);
        }
        return Ok(p);
    }
    if let Some(path) = &args.policy_path {
        let canonical = path
            .canonicalize()
            .context("Cannot resolve --policy path")?;
        let mut p = Policy::load_from(&canonical)?;
        p.merge_cli(args);
        return Ok(p);
    }
    let root = infer_repo_root(canonical_dir);
    Ok(Policy::load(&root)?.map_or_else(
        || {
            let mut p = Policy::default();
            if args.paranoid {
                p.merge_cli(args);
            }
            p
        },
        |mut p| {
            p.merge_cli(args);
            p
        },
    ))
}

fn infer_repo_root(start: &Path) -> PathBuf {
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

fn scan_and_audit(dir: &Path, policy: &Policy) -> Result<Vec<AuditFinding>> {
    let scan = scanner::scan_directory(dir)?;
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
    Ok(findings)
}

fn compute_delta(
    base_ref: &str,
    base_findings: &[AuditFinding],
    head_findings: &[AuditFinding],
) -> DeltaReport {
    let base_keys: HashSet<FindingKey<'_>> =
        base_findings.iter().map(FindingKey::from).collect();
    let head_keys: HashSet<FindingKey<'_>> =
        head_findings.iter().map(FindingKey::from).collect();

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

    new.sort_by(|a, b| a.severity.cmp(&b.severity));
    fixed.sort_by(|a, b| a.severity.cmp(&b.severity));

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
        println!("  no changes in audit findings (unchanged: {})", delta.unchanged_count);
        return;
    }
    if !delta.new.is_empty() {
        println!("\nNew findings: {}", delta.new.len());
        for f in &delta.new {
            println!(
                "  [{}] {}  {}",
                f.severity,
                status_marker(f.is_warning),
                f.title
            );
        }
    }
    if !delta.fixed.is_empty() {
        println!("\nFixed findings: {}", delta.fixed.len());
        for f in &delta.fixed {
            println!("  [{}] fixed  {}", f.severity, f.title);
        }
    }
    println!("\nUnchanged: {}", delta.unchanged_count);
}

const fn status_marker(is_warning: bool) -> &'static str {
    if is_warning { "warn" } else { "deny " }
}

fn print_markdown(delta: &DeltaReport) {
    println!("## hasp audit delta vs `{}`\n", delta.base);
    if delta.new.is_empty() && delta.fixed.is_empty() {
        println!(
            "_No changes in audit findings ({} unchanged)._\n",
            delta.unchanged_count
        );
        return;
    }

    if !delta.new.is_empty() {
        println!("### New findings ({})\n", delta.new.len());
        println!("| Severity | Check | File | Status |");
        println!("|----------|-------|------|--------|");
        for f in &delta.new {
            println!(
                "| {} | {} | `{}` | {} |",
                f.severity,
                md_escape(&f.title),
                f.file.display(),
                if f.is_warning { "warn" } else { "**deny**" }
            );
        }
        println!();
        println!("<details><summary>Details</summary>\n");
        for f in &delta.new {
            println!("**[{}] {}**", f.severity, md_escape(&f.title));
            println!();
            println!("{}\n", md_escape(&f.detail));
        }
        println!("</details>\n");
    }

    if !delta.fixed.is_empty() {
        println!("### Fixed findings ({})\n", delta.fixed.len());
        println!("| Severity | Check | File |");
        println!("|----------|-------|------|");
        for f in &delta.fixed {
            println!(
                "| {} | {} | `{}` |",
                f.severity,
                md_escape(&f.title),
                f.file.display()
            );
        }
        println!();
    }

    println!("_{} unchanged finding(s)._\n", delta.unchanged_count);
}

fn md_escape(s: &str) -> String {
    s.replace('|', r"\|").replace('\n', " ")
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

// ─── git helpers + base worktree ────────────────────────────────────────────

fn is_sane_git_ref(ref_str: &str) -> bool {
    !ref_str.is_empty()
        && ref_str.len() <= 256
        && !ref_str.starts_with('-')
        && !ref_str.contains('\0')
        && !ref_str.contains("..")
        && !ref_str.contains('\\')
        && !ref_str.bytes().any(|b| b.is_ascii_control())
}

fn git_repo_root(start: &Path) -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(start)
        .output()
        .context("Failed to run `git rev-parse --show-toplevel`")?;
    if !out.status.success() {
        bail!(
            "`git rev-parse --show-toplevel` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8(out.stdout)
        .context("git rev-parse output was not UTF-8")?;
    Ok(PathBuf::from(text.trim()))
}

fn resolve_git_ref(repo_root: &Path, ref_str: &str) -> Result<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", ref_str])
        .current_dir(repo_root)
        .output()
        .context("Failed to run `git rev-parse`")?;
    if !out.status.success() {
        bail!("diff-base ref `{ref_str}` could not be resolved");
    }
    let text = String::from_utf8(out.stdout).context("git rev-parse output was not UTF-8")?;
    let sha = text.trim();
    if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("git rev-parse returned unexpected ref `{sha}`");
    }
    Ok(sha.to_string())
}

/// Temp worktree that is torn down on Drop so failed runs don't leak
/// git-worktree directories.
struct BaseWorktree {
    repo_root: PathBuf,
    path: PathBuf,
}

impl BaseWorktree {
    fn create(repo_root: &Path, sha: &str) -> Result<Self> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static C: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "hasp-diff-worktree-{}-{}",
            std::process::id(),
            C.fetch_add(1, Ordering::Relaxed)
        ));
        let out = Command::new("git")
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
        // Do the checkout in a second step so the worktree creation itself
        // stays cheap (--no-checkout) and we can surface checkout errors
        // distinctly.
        let checkout = Command::new("git")
            .args(["checkout", sha])
            .current_dir(&path)
            .output()
            .context("Failed to checkout base worktree")?;
        if !checkout.status.success() {
            bail!(
                "Failed to checkout {sha} in base worktree: {}",
                String::from_utf8_lossy(&checkout.stderr).trim()
            );
        }
        Ok(Self {
            repo_root: repo_root.to_path_buf(),
            path,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BaseWorktree {
    fn drop(&mut self) {
        // Best-effort cleanup — don't propagate errors during unwind.
        let _ = Command::new("git")
            .args([
                "worktree",
                "remove",
                "--force",
                self.path.to_string_lossy().as_ref(),
            ])
            .current_dir(&self.repo_root)
            .output();
        let _ = std::fs::remove_dir_all(&self.path);
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
    fn delta_exit_code_blocks_only_on_new_deny_findings() {
        let delta = DeltaReport {
            base: "main".into(),
            new: vec![finding("X", "ci.yml", Severity::Critical, false)],
            fixed: Vec::new(),
            unchanged_count: 5,
        };
        assert_eq!(delta.exit_code(false), 1);

        let delta = DeltaReport {
            base: "main".into(),
            new: vec![finding("X", "ci.yml", Severity::Medium, true)],
            fixed: Vec::new(),
            unchanged_count: 0,
        };
        assert_eq!(delta.exit_code(false), 0);
    }

    #[test]
    fn format_parse_accepts_known_values() {
        assert_eq!(DiffFormat::parse("terse").unwrap(), DiffFormat::Terse);
        assert_eq!(DiffFormat::parse("markdown").unwrap(), DiffFormat::Markdown);
        assert_eq!(DiffFormat::parse("json").unwrap(), DiffFormat::Json);
        DiffFormat::parse("yaml").expect_err("should reject");
    }

    #[test]
    fn is_sane_git_ref_rejects_path_traversal() {
        assert!(is_sane_git_ref("main"));
        assert!(is_sane_git_ref("HEAD~1"));
        assert!(!is_sane_git_ref(""));
        assert!(!is_sane_git_ref("--upload-pack=evil"));
        assert!(!is_sane_git_ref("../etc/passwd"));
        assert!(!is_sane_git_ref("has\0null"));
    }

    #[test]
    fn json_escapes_control_characters() {
        let s = json_string("hello\n\"world\"");
        assert_eq!(s, r#""hello\n\"world\"""#);
    }
}
