//! `hasp replay --since 30d` -- historical audit replay.
//!
//! Walks git history for workflow file changes over a time window and
//! re-audits each past state with the current rule set. Answers "would
//! today's hasp have caught yesterday's mistake?". Uses `git log` instead
//! of the GitHub API so it runs offline and doesn't burn API quota.

use crate::audit::{self, AuditFinding, Severity};
use crate::error::{Context, Result, bail};
use crate::policy::Policy;
use crate::scanner;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayFormat {
    Terse,
    Markdown,
    Json,
}

impl ReplayFormat {
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
struct HistoricalHit {
    sha: String,
    date: String,
    file: PathBuf,
    findings: Vec<AuditFinding>,
}

pub(crate) fn run(args: &crate::cli::Args) -> Result<()> {
    let since = args
        .replay_since
        .as_deref()
        .unwrap_or("30d")
        .to_string();
    let format = args.replay_format.unwrap_or(ReplayFormat::Terse);

    if !is_sane_since(&since) {
        bail!("Invalid --since `{since}`: expected 30d, 2w, 6h, etc.");
    }

    let canonical_dir = args
        .dir
        .canonicalize()
        .context("Cannot resolve workflow dir")?;
    let repo_root = git_repo_root(&canonical_dir)?;
    let relative_dir = canonical_dir
        .strip_prefix(&repo_root)
        .context("workflow directory is outside the git repo")?
        .to_path_buf();

    let commits = git_log_commits(&repo_root, &since, &relative_dir)?;
    if commits.is_empty() {
        println!("hasp replay: no workflow changes in the last {since}");
        return Ok(());
    }

    let policy = Policy::load(&repo_root)?.unwrap_or_default();

    // Walk each historical commit, audit each changed workflow, accumulate.
    let mut hits: Vec<HistoricalHit> = Vec::new();
    let mut total_audited = 0_usize;
    for commit in &commits {
        let changed = git_show_changed_workflow_files(&repo_root, &commit.sha, &relative_dir)?;
        for rel_path in changed {
            let content = match git_show_file(&repo_root, &commit.sha, &rel_path) {
                Ok(Some(c)) => c,
                Ok(None) => continue, // deleted in this commit
                Err(e) => {
                    eprintln!(
                        "hasp replay: skipping {rel}@{sha}: {e}",
                        rel = rel_path.display(),
                        sha = &commit.sha[..12.min(commit.sha.len())]
                    );
                    continue;
                }
            };
            total_audited += 1;
            let findings = audit_historical_content(&content, &rel_path, &policy);
            if !findings.is_empty() {
                hits.push(HistoricalHit {
                    sha: commit.sha.clone(),
                    date: commit.date.clone(),
                    file: rel_path,
                    findings,
                });
            }
        }
    }

    print_report(format, &since, &hits, total_audited);

    let has_blocking = hits
        .iter()
        .any(|h| h.findings.iter().any(|f| !f.is_warning));
    if has_blocking {
        std::process::exit(1);
    }
    Ok(())
}

fn audit_historical_content(content: &str, file: &Path, policy: &Policy) -> Vec<AuditFinding> {
    // Parse the historical YAML content. We only have a single file at a
    // single revision, so reuse extract_action_refs_from_content + run the
    // static audits against its parsed form.
    let Ok(docs) = yaml_rust2::YamlLoader::load_from_str(content) else {
        return Vec::new();
    };
    let Some(doc) = docs.into_iter().next() else {
        return Vec::new();
    };
    let doc_pair = vec![(file.to_path_buf(), doc)];
    let refs = scanner::extract_action_refs_from_content(content, file).unwrap_or_default();
    let mut findings = audit::run(&doc_pair, &refs, &policy.checks);
    if !policy.checks.untrusted_sources.is_off() {
        let owners = Policy::effective_list(
            policy.trust.owners.as_ref(),
            audit::builtin_trusted_owners(),
        );
        audit::check_untrusted_sources(
            &refs,
            &mut findings,
            policy.checks.untrusted_sources,
            &owners,
        );
    }
    findings
}

// ─── Report formatters ──────────────────────────────────────────────────────

fn print_report(format: ReplayFormat, since: &str, hits: &[HistoricalHit], total_audited: usize) {
    match format {
        ReplayFormat::Terse => print_terse(since, hits, total_audited),
        ReplayFormat::Markdown => print_markdown(since, hits, total_audited),
        ReplayFormat::Json => print_json(since, hits, total_audited),
    }
}

fn print_terse(since: &str, hits: &[HistoricalHit], total_audited: usize) {
    println!("hasp replay: scanned {total_audited} historical workflow state(s) from the last {since}");
    if hits.is_empty() {
        println!("  all past workflow states pass the current audit rules");
        return;
    }
    let (crit, high, medium) = count_by_severity(hits);
    println!(
        "  {} state(s) would have produced findings (CRIT: {crit}, HIGH: {high}, MED: {medium})",
        hits.len()
    );
    for hit in hits {
        let short = &hit.sha[..12.min(hit.sha.len())];
        println!("\n  [{}]  {}  ({short})", hit.date, hit.file.display());
        for f in &hit.findings {
            let marker = if f.is_warning { "warn" } else { "deny" };
            println!("    [{}] [{marker}] {}", f.severity, f.title);
        }
    }
}

fn print_markdown(since: &str, hits: &[HistoricalHit], total_audited: usize) {
    println!("## hasp replay — last {since}\n");
    println!("Scanned **{total_audited}** historical workflow state(s).\n");
    if hits.is_empty() {
        println!("_All past states pass current audit rules._\n");
        return;
    }
    let (crit, high, medium) = count_by_severity(hits);
    println!("**{}** state(s) had findings (CRIT: {crit}, HIGH: {high}, MED: {medium}).\n", hits.len());
    let grouped = group_by_file(hits);
    for (file, file_hits) in grouped {
        println!("### `{}`\n", file.display());
        for hit in file_hits {
            let short = &hit.sha[..12.min(hit.sha.len())];
            println!("- **{}** ({short}):", hit.date);
            for f in &hit.findings {
                let marker = if f.is_warning { "warn" } else { "**deny**" };
                println!("  - [{}] [{marker}] {}", f.severity, md_escape(&f.title));
            }
        }
        println!();
    }
}

fn print_json(since: &str, hits: &[HistoricalHit], total_audited: usize) {
    let mut out = String::from("{");
    let _ = write!(out, r#""since":"{}","#, escape_json(since));
    let _ = write!(out, r#""total_audited":{total_audited},"#);
    out.push_str(r#""hits":["#);
    for (i, hit) in hits.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        let _ = write!(out, r#""sha":"{}","#, escape_json(&hit.sha));
        let _ = write!(out, r#""date":"{}","#, escape_json(&hit.date));
        let _ = write!(
            out,
            r#""file":"{}","#,
            escape_json(&hit.file.to_string_lossy())
        );
        out.push_str(r#""findings":["#);
        for (j, f) in hit.findings.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                r#"{{"severity":"{}","title":"{}","is_warning":{}}}"#,
                f.severity,
                escape_json(&f.title),
                f.is_warning
            );
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    println!("{out}");
}

fn count_by_severity(hits: &[HistoricalHit]) -> (usize, usize, usize) {
    let mut crit = 0;
    let mut high = 0;
    let mut medium = 0;
    for hit in hits {
        for f in &hit.findings {
            match f.severity {
                Severity::Critical => crit += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
            }
        }
    }
    (crit, high, medium)
}

fn group_by_file(hits: &[HistoricalHit]) -> BTreeMap<&Path, Vec<&HistoricalHit>> {
    let mut grouped: BTreeMap<&Path, Vec<&HistoricalHit>> = BTreeMap::new();
    for hit in hits {
        grouped.entry(hit.file.as_path()).or_default().push(hit);
    }
    grouped
}

fn md_escape(s: &str) -> String {
    s.replace('|', r"\|").replace('\n', " ")
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
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
    out
}

// ─── git helpers ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CommitRecord {
    sha: String,
    date: String,
}

fn git_log_commits(
    repo_root: &Path,
    since: &str,
    relative_dir: &Path,
) -> Result<Vec<CommitRecord>> {
    let out = Command::new("git")
        .args([
            "log",
            &format!("--since={since}"),
            "--format=%H\t%aI",
            "--",
            relative_dir.to_string_lossy().as_ref(),
        ])
        .current_dir(repo_root)
        .output()
        .context("Failed to run `git log`")?;
    if !out.status.success() {
        bail!(
            "`git log` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8(out.stdout).context("git log output was not UTF-8")?;
    let mut commits = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(2, '\t');
        let Some(sha) = parts.next() else { continue };
        let Some(date) = parts.next() else { continue };
        if sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
            commits.push(CommitRecord {
                sha: sha.to_string(),
                date: date.to_string(),
            });
        }
    }
    Ok(commits)
}

fn git_show_changed_workflow_files(
    repo_root: &Path,
    sha: &str,
    relative_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .args([
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            sha,
            "--",
            relative_dir.to_string_lossy().as_ref(),
        ])
        .current_dir(repo_root)
        .output()
        .context("Failed to run `git diff-tree --name-only`")?;
    if !out.status.success() {
        bail!(
            "`git diff-tree` failed for {sha}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text =
        String::from_utf8(out.stdout).context("git diff-tree output was not UTF-8")?;
    let mut files = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let p = PathBuf::from(line);
        let ext = p.extension().and_then(|e| e.to_str());
        if matches!(ext, Some("yml" | "yaml")) {
            files.push(p);
        }
    }
    Ok(files)
}

fn git_show_file(repo_root: &Path, sha: &str, rel_path: &Path) -> Result<Option<String>> {
    let git_path = format!("{sha}:{}", rel_path.display());
    let out = Command::new("git")
        .args(["show", &git_path])
        .current_dir(repo_root)
        .output()
        .context("Failed to run `git show <sha>:<path>`")?;
    if !out.status.success() {
        // File didn't exist at this commit.
        return Ok(None);
    }
    let text = String::from_utf8(out.stdout)
        .context(format!("file content was not UTF-8: {}", rel_path.display()))?;
    Ok(Some(text))
}

fn git_repo_root(start: &Path) -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(start)
        .output()
        .context("Failed to run `git rev-parse --show-toplevel`")?;
    if !out.status.success() {
        bail!(
            "`git rev-parse` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8(out.stdout).context("git rev-parse output was not UTF-8")?;
    Ok(PathBuf::from(text.trim()))
}

fn is_sane_since(s: &str) -> bool {
    // Accept values git understands: 30d, 2w, 6h, 1month, "yesterday", etc.
    // Conservative filter: must be short and contain no shell metacharacters.
    !s.is_empty()
        && s.len() <= 64
        && !s.contains('\0')
        && !s.contains('\\')
        && !s.contains('"')
        && !s.contains('\'')
        && !s.contains('`')
        && !s.contains('$')
        && !s.contains('\n')
        && !s.contains('\r')
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_format_accepts_known_values() {
        assert_eq!(ReplayFormat::parse("terse").unwrap(), ReplayFormat::Terse);
        assert_eq!(ReplayFormat::parse("markdown").unwrap(), ReplayFormat::Markdown);
        assert_eq!(ReplayFormat::parse("json").unwrap(), ReplayFormat::Json);
        ReplayFormat::parse("yaml").expect_err("should reject unknown format");
    }

    #[test]
    fn since_filter_rejects_shell_metacharacters() {
        assert!(is_sane_since("30d"));
        assert!(is_sane_since("2w"));
        assert!(is_sane_since("yesterday"));
        assert!(!is_sane_since(""));
        assert!(!is_sane_since("30d$(rm -rf)"));
        assert!(!is_sane_since("30d`echo evil`"));
        assert!(!is_sane_since("30d\nfoo"));
    }

    #[test]
    fn historical_audit_flags_known_pattern() {
        let yaml = "\
name: CI
on: pull_request
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - run: echo ${{ github.event.pull_request.title }}
";
        let policy = Policy::default();
        let findings =
            audit_historical_content(yaml, &PathBuf::from("ci.yml"), &policy);
        assert!(
            findings.iter().any(|f| f.title.contains("injection")),
            "expected injection finding, got: {findings:?}"
        );
    }

    #[test]
    fn historical_audit_on_clean_yaml_emits_nothing() {
        let yaml = "\
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - run: echo hi
";
        let policy = Policy::default();
        let findings =
            audit_historical_content(yaml, &PathBuf::from("ci.yml"), &policy);
        // `ci.yml` as a synthetic path has no pinned uses:, so typosquat/etc
        // shouldn't fire; check that no CRIT/HIGH findings are produced.
        assert!(
            !findings.iter().any(|f| matches!(f.severity, Severity::Critical | Severity::High)),
            "clean YAML should not produce critical/high findings: {findings:?}"
        );
    }

    #[test]
    fn counting_by_severity_tallies_correctly() {
        use crate::audit::{AuditFinding, Severity};
        let hits = vec![
            HistoricalHit {
                sha: "a".repeat(40),
                date: "2025-01-01".into(),
                file: PathBuf::from("ci.yml"),
                findings: vec![
                    AuditFinding {
                        file: PathBuf::from("ci.yml"),
                        severity: Severity::Critical,
                        title: "crit".into(),
                        detail: "x".into(),
                        is_warning: false,
                    },
                    AuditFinding {
                        file: PathBuf::from("ci.yml"),
                        severity: Severity::Medium,
                        title: "med".into(),
                        detail: "x".into(),
                        is_warning: true,
                    },
                ],
            },
            HistoricalHit {
                sha: "b".repeat(40),
                date: "2025-01-02".into(),
                file: PathBuf::from("ci.yml"),
                findings: vec![AuditFinding {
                    file: PathBuf::from("ci.yml"),
                    severity: Severity::High,
                    title: "high".into(),
                    detail: "x".into(),
                    is_warning: false,
                }],
            },
        ];
        let (c, h, m) = count_by_severity(&hits);
        assert_eq!((c, h, m), (1, 1, 1));
    }

}
