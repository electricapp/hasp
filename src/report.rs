use crate::audit::AuditFinding;
use crate::github::{CompareResult, VerificationResult, VerificationStatus};
use crate::policy::{self, Policy};
use crate::scanner::{ActionRefChange, ContainerRef, ContainerRefKind, SkippedRef, SkippedRefKind};
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) fn print_skipped_refs(skipped: &[SkippedRef]) -> bool {
    if skipped.is_empty() {
        return false;
    }

    let mut by_file: BTreeMap<&Path, Vec<&SkippedRef>> = BTreeMap::new();
    for s in skipped {
        by_file.entry(s.file.as_path()).or_default().push(s);
    }

    println!("\n{}", "=".repeat(72));
    println!("Unauditable references: {} finding(s)\n", skipped.len());

    for (file, refs) in &by_file {
        println!("{}", file.display());
        for r in refs {
            let kind = match r.kind {
                SkippedRefKind::RemoteReusableWorkflow => "remote reusable workflow",
                SkippedRefKind::UnresolvedLocalPath | SkippedRefKind::UnsupportedLocalRef => {
                    "local ref"
                }
            };
            println!("  FAIL  {kind} `{}`  ({})", r.uses_str, r.detail,);
        }
    }

    true
}

pub(crate) fn print_container_refs(refs: &[ContainerRef], strict: bool) -> bool {
    if refs.is_empty() {
        return false;
    }

    let mut by_file: BTreeMap<&Path, Vec<&ContainerRef>> = BTreeMap::new();
    for r in refs {
        by_file.entry(r.file.as_path()).or_default().push(r);
    }

    let mut n_pass = 0_usize;
    let mut n_warn = 0_usize;
    let mut n_fail = 0_usize;

    for (file, file_refs) in &by_file {
        println!("\n{}", file.display());

        for r in file_refs {
            let (tag, detail, is_failure) = format_container_ref(r, strict);
            println!("  {:<4}  {}  ({})", tag, r.image, detail);

            if r.is_pinned() {
                n_pass += 1;
            } else if is_failure {
                n_fail += 1;
            } else {
                n_warn += 1;
            }
        }
    }

    println!();
    println!("{}", "=".repeat(72));
    println!("Container check: {n_pass} passed, {n_warn} warned, {n_fail} failed");

    n_fail > 0
}

pub(crate) fn print_results(results: &[VerificationResult], strict: bool, policy: &Policy) -> bool {
    if results.is_empty() {
        return false;
    }

    let mut by_file: BTreeMap<&Path, Vec<&VerificationResult>> = BTreeMap::new();
    for r in results {
        by_file
            .entry(r.action_ref.file.as_path())
            .or_default()
            .push(r);
    }

    let mut n_pass = 0_usize;
    let mut n_warn = 0_usize;
    let mut n_fail = 0_usize;
    let mut n_skip = 0_usize;
    let mut suggestions: Vec<String> = Vec::new();

    for (file, file_results) in &by_file {
        println!("\n{}", file.display());

        for r in file_results {
            // Resolve per-action pin policy
            let resolved = policy.resolve_for_action(
                &r.action_ref.owner,
                &r.action_ref.repo,
                r.action_ref.path.as_deref(),
            );
            let (tag, detail, is_failure) = format_result(r, strict, resolved.pin);
            let target = r.action_ref.target();

            // PinPolicy::Off means skip the mutable ref entirely
            if matches!(&r.status, VerificationStatus::MutableRef { .. })
                && matches!(resolved.pin, policy::PinPolicy::Off)
                && !strict
            {
                n_skip += 1;
                continue;
            }

            println!(
                "  {:<4}  {}@{}  ({})",
                tag,
                target,
                r.action_ref.short_ref(),
                detail
            );

            match &r.status {
                VerificationStatus::Verified => n_pass += 1,
                VerificationStatus::Skipped => n_skip += 1,
                VerificationStatus::NotFound | VerificationStatus::CommentMismatch { .. } => {
                    n_fail += 1;
                }
                VerificationStatus::MutableRef { resolved } => {
                    if is_failure {
                        n_fail += 1;
                    } else {
                        n_warn += 1;
                    }
                    if let Some(sha) = resolved {
                        suggestions.push(format!(
                            "  {target}@{ref_str}  ->  {target}@{sha}",
                            target = r.action_ref.target(),
                            ref_str = r.action_ref.ref_str,
                        ));
                    }
                }
            }
        }
    }

    println!();
    println!("{}", "=".repeat(72));
    println!("Pin check: {n_pass} passed, {n_warn} warned, {n_fail} failed, {n_skip} skipped");

    if !suggestions.is_empty() {
        println!("\nSuggested pins:");
        suggestions.sort();
        suggestions.dedup();
        for s in &suggestions {
            println!("{s}");
        }
    }

    n_fail > 0
}

pub(crate) fn print_audit_findings(findings: &[AuditFinding], suppressed_count: usize) -> bool {
    if findings.is_empty() && suppressed_count == 0 {
        println!("\nParanoid audit: 0 findings");
        return false;
    }

    println!("\n{}", "=".repeat(72));
    println!("Paranoid audit: {} finding(s)\n", findings.len());

    let mut n_deny = 0_usize;
    let mut n_warn = 0_usize;

    for f in findings {
        let tag = if f.is_warning { "WARN" } else { "DENY" };
        if f.is_warning {
            n_warn += 1;
        } else {
            n_deny += 1;
        }
        println!("  [{:<4}]  [{:<4}]  {}", f.severity, tag, f.title);
        println!("                 File: {}", f.file.display());
        for line in textwrap(&f.detail, 57) {
            println!("                 {line}");
        }
        println!();
    }

    if suppressed_count > 0 {
        println!("  ({suppressed_count} finding(s) suppressed by policy)");
        println!();
    }

    println!("Audit totals: {n_deny} denied, {n_warn} warned, {suppressed_count} suppressed");
    // Only denied findings (non-warning) cause exit code 1
    n_deny > 0
}

fn format_result(
    r: &VerificationResult,
    strict: bool,
    pin_policy: policy::PinPolicy,
) -> (&'static str, String, bool) {
    match &r.status {
        VerificationStatus::Verified => ("PASS", "commit verified".into(), false),
        VerificationStatus::NotFound => (
            "FAIL",
            "SHA not found — phantom or typo'd commit".into(),
            true,
        ),
        VerificationStatus::CommentMismatch {
            comment_version,
            tag_resolves_to,
            pinned_version,
        } => {
            let pinned = &r.action_ref.ref_str;
            let short_pin = &pinned[..pinned.len().min(12)];
            let pin_label = pinned_version
                .as_ref()
                .map_or_else(|| short_pin.to_string(), |v| format!("{short_pin} ({v})"));
            let detail = tag_resolves_to.as_ref().map_or_else(
                || format!("comment says {comment_version} but that tag does not exist; pinned to {pin_label}"),
                |sha| format!(
                    "comment says {comment_version} (→ {}) but pinned to {pin_label}",
                    &sha[..sha.len().min(12)]
                ),
            );
            ("FAIL", detail, true)
        }
        VerificationStatus::MutableRef { resolved } => {
            // Global strict flag is a floor: if strict, always FAIL regardless
            // of per-action policy. Otherwise, per-action PinPolicy applies.
            let is_fail = strict || matches!(pin_policy, policy::PinPolicy::Deny);
            let tag = if is_fail { "FAIL" } else { "WARN" };
            let detail = resolved.as_ref().map_or_else(
                || "mutable ref — pin to a SHA instead".into(),
                |sha| {
                    // Safely display first 12 chars of SHA, or full SHA if shorter
                    let short = if sha.len() >= 12 {
                        &sha[..12]
                    } else {
                        sha.as_str()
                    };
                    format!("mutable ref — pin to SHA {short}")
                },
            );
            (tag, detail, is_fail)
        }
        VerificationStatus::Skipped => ("SKIP", "no token — SHA not verified".into(), false),
    }
}

fn format_container_ref(r: &ContainerRef, strict: bool) -> (&'static str, String, bool) {
    let source = match r.kind {
        ContainerRefKind::StepDockerUses => "step docker image",
        ContainerRefKind::JobContainer => "job container image",
        ContainerRefKind::ServiceContainer => "service container image",
    };

    if r.is_pinned() {
        ("PASS", format!("{source} pinned by digest"), false)
    } else {
        let is_failure = strict;
        let tag = if is_failure { "FAIL" } else { "WARN" };
        (
            tag,
            format!("{source} uses a mutable tag; pin with @sha256:<digest>"),
            is_failure,
        )
    }
}

pub(crate) fn print_upstream_changes(results: &[CompareResult]) {
    if results.is_empty() {
        return;
    }

    println!("\n{}", "=".repeat(72));
    println!("Upstream changes: {} action(s) updated\n", results.len());

    for cr in results {
        let old_short = &cr.old_sha[..cr.old_sha.len().min(12)];
        let new_short = &cr.new_sha[..cr.new_sha.len().min(12)];
        println!(
            "  {}/{}  {} \u{2192} {}  ({} commits, {} files)",
            cr.owner, cr.repo, old_short, new_short, cr.ahead_by, cr.files_changed,
        );

        let max_summaries = 5;
        for (i, summary) in cr.commit_summaries.iter().enumerate() {
            if i >= max_summaries {
                let remaining = cr.commit_summaries.len() - max_summaries;
                println!("    ... and {remaining} more");
                break;
            }
            let truncated: std::borrow::Cow<'_, str> = if summary.len() > 72 {
                let end = summary
                    .char_indices()
                    .map(|(i, _)| i)
                    .take_while(|&i| i <= 69)
                    .last()
                    .unwrap_or(0);
                format!("{}...", &summary[..end]).into()
            } else {
                summary.as_str().into()
            };
            println!("    - {truncated}");
        }

        if !cr.html_url.is_empty() {
            println!("    {}", cr.html_url);
        }
        println!();
    }
}

pub(crate) fn print_upstream_changes_no_detail(changes: &[ActionRefChange]) {
    if changes.is_empty() {
        return;
    }

    println!("\n{}", "=".repeat(72));
    println!(
        "Upstream changes: {} action SHA(s) changed (no API detail — no token or --no-verify)\n",
        changes.len()
    );

    for change in changes {
        let old_short = &change.old_sha[..change.old_sha.len().min(12)];
        let new_short = &change.new_sha[..change.new_sha.len().min(12)];
        let target = change.path.as_ref().map_or_else(
            || format!("{}/{}", change.owner, change.repo),
            |path| format!("{}/{}/{}", change.owner, change.repo, path),
        );
        println!("  {target}  {old_short} \u{2192} {new_short}");
    }
    println!();
}

fn textwrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if current.is_empty() {
            current = word.to_string();
        } else if current.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut current));
            current = word.to_string();
        } else {
            current.push(' ');
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
