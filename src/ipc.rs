use crate::audit::{AuditFinding, Severity};
use crate::error::{Context, Result, bail};
use crate::github::{CompareResult, VerificationResult, VerificationStatus};
use crate::scanner::{
    ActionRef, ActionRefChange, ContainerPinKind, ContainerRef, ContainerRefKind, RefKind,
    SkippedRef, SkippedRefKind,
};
use std::io::{Read, Write};
use std::path::PathBuf;

const SCAN_MAGIC: &str = "HASP_SCAN_V1";
const ACTION_REFS_MAGIC: &str = "HASP_ACTION_REFS_V1";
const VERIFY_MAGIC: &str = "HASP_VERIFY_V1";
const MAX_SCAN_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_VERIFY_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanPayload {
    pub(crate) action_refs: Vec<ActionRef>,
    pub(crate) skipped_refs: Vec<SkippedRef>,
    pub(crate) container_refs: Vec<ContainerRef>,
    pub(crate) audit_findings: Vec<AuditFinding>,
}

pub(crate) fn write_scan_payload(mut writer: impl Write, payload: &ScanPayload) -> Result<()> {
    writeln!(writer, "{SCAN_MAGIC}").context("Failed to write scan payload header")?;

    for r in &payload.action_refs {
        let file = r.file.to_string_lossy();
        write_record(
            &mut writer,
            "ACTION",
            &[
                &file,
                &r.owner,
                &r.repo,
                r.path.as_deref().unwrap_or(""),
                &r.ref_str,
                ref_kind_token(r.ref_kind),
                r.comment_version.as_deref().unwrap_or(""),
            ],
        )?;
    }

    for s in &payload.skipped_refs {
        let file = s.file.to_string_lossy();
        write_record(
            &mut writer,
            "SKIPPED",
            &[
                &file,
                &s.uses_str,
                skipped_ref_kind_token(s.kind),
                &s.detail,
            ],
        )?;
    }

    for c in &payload.container_refs {
        let file = c.file.to_string_lossy();
        write_record(
            &mut writer,
            "CONTAINER",
            &[
                &file,
                &c.image,
                container_ref_kind_token(c.kind),
                container_pin_kind_token(c.pin_kind),
            ],
        )?;
    }

    for f in &payload.audit_findings {
        let file = f.file.to_string_lossy();
        write_record(
            &mut writer,
            "AUDIT",
            &[
                &file,
                severity_token(f.severity),
                &f.title,
                &f.detail,
                if f.is_warning { "warn" } else { "deny" },
            ],
        )?;
    }

    Ok(())
}

pub(crate) fn read_scan_payload(mut reader: impl Read) -> Result<ScanPayload> {
    let text = read_protocol_text_limited(&mut reader, "scan payload", MAX_SCAN_PAYLOAD_BYTES)?;
    let mut lines = text.lines();
    expect_magic(lines.next(), SCAN_MAGIC, "scan payload")?;

    let mut payload = ScanPayload {
        action_refs: Vec::new(),
        skipped_refs: Vec::new(),
        container_refs: Vec::new(),
        audit_findings: Vec::new(),
    };

    for (line_no, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields = split_fields(line, line_no + 2)?;
        match fields[0] {
            "ACTION" => {
                ensure_len(&fields, 8, line_no + 2)?;
                payload.action_refs.push(ActionRef {
                    file: decode_path(fields[1])?,
                    owner: decode_string(fields[2])?,
                    repo: decode_string(fields[3])?,
                    path: decode_optional_string(fields[4])?,
                    ref_str: decode_string(fields[5])?,
                    ref_kind: parse_ref_kind(fields[6])?,
                    comment_version: decode_optional_string(fields[7])?,
                });
            }
            "SKIPPED" => {
                ensure_len(&fields, 5, line_no + 2)?;
                payload.skipped_refs.push(SkippedRef {
                    file: decode_path(fields[1])?,
                    uses_str: decode_string(fields[2])?,
                    kind: parse_skipped_ref_kind(fields[3])?,
                    detail: decode_string(fields[4])?,
                });
            }
            "CONTAINER" => {
                ensure_len(&fields, 5, line_no + 2)?;
                payload.container_refs.push(ContainerRef {
                    file: decode_path(fields[1])?,
                    image: decode_string(fields[2])?,
                    kind: parse_container_ref_kind(fields[3])?,
                    pin_kind: parse_container_pin_kind(fields[4])?,
                });
            }
            "AUDIT" => {
                ensure_len(&fields, 6, line_no + 2)?;
                payload.audit_findings.push(AuditFinding {
                    file: decode_path(fields[1])?,
                    severity: parse_severity(fields[2])?,
                    title: decode_string(fields[3])?,
                    detail: decode_string(fields[4])?,
                    is_warning: decode_string(fields[5])? == "warn",
                });
            }
            other => bail!(
                "Unknown scan payload record `{other}` on line {}",
                line_no + 2
            ),
        }
    }

    Ok(payload)
}

#[cfg(test)]
pub(crate) fn write_action_refs(mut writer: impl Write, refs: &[ActionRef]) -> Result<()> {
    writeln!(writer, "{ACTION_REFS_MAGIC}").context("Failed to write action ref payload header")?;
    for r in refs {
        let file = r.file.to_string_lossy();
        write_record(
            &mut writer,
            "ACTION",
            &[
                &file,
                &r.owner,
                &r.repo,
                r.path.as_deref().unwrap_or(""),
                &r.ref_str,
                ref_kind_token(r.ref_kind),
                r.comment_version.as_deref().unwrap_or(""),
            ],
        )?;
    }
    Ok(())
}

pub(crate) fn write_action_refs_with_changes(
    mut writer: impl Write,
    refs: &[ActionRef],
    changes: &[ActionRefChange],
) -> Result<()> {
    writeln!(writer, "{ACTION_REFS_MAGIC}").context("Failed to write action ref payload header")?;
    for r in refs {
        let file = r.file.to_string_lossy();
        write_record(
            &mut writer,
            "ACTION",
            &[
                &file,
                &r.owner,
                &r.repo,
                r.path.as_deref().unwrap_or(""),
                &r.ref_str,
                ref_kind_token(r.ref_kind),
                r.comment_version.as_deref().unwrap_or(""),
            ],
        )?;
    }
    for c in changes {
        let file = c.file.to_string_lossy();
        write_record(
            &mut writer,
            "DIFF",
            &[
                &file,
                &c.owner,
                &c.repo,
                c.path.as_deref().unwrap_or(""),
                &c.old_sha,
                &c.new_sha,
                c.old_comment.as_deref().unwrap_or(""),
                c.new_comment.as_deref().unwrap_or(""),
            ],
        )?;
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct VerifierInput {
    pub(crate) action_refs: Vec<ActionRef>,
    pub(crate) diff_changes: Vec<ActionRefChange>,
}

const MAX_ACTION_REFS_PAYLOAD_BYTES: usize = 1024 * 1024; // 1 MiB

pub(crate) fn read_verifier_input(mut reader: impl Read) -> Result<VerifierInput> {
    let text = read_protocol_text_limited(
        &mut reader,
        "action ref payload",
        MAX_ACTION_REFS_PAYLOAD_BYTES,
    )?;
    let mut lines = text.lines();
    expect_magic(lines.next(), ACTION_REFS_MAGIC, "action ref payload")?;

    let mut action_refs = Vec::new();
    let mut diff_changes = Vec::new();

    for (line_no, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields = split_fields(line, line_no + 2)?;
        match fields[0] {
            "ACTION" => {
                ensure_len(&fields, 8, line_no + 2)?;
                action_refs.push(ActionRef {
                    file: decode_path(fields[1])?,
                    owner: decode_string(fields[2])?,
                    repo: decode_string(fields[3])?,
                    path: decode_optional_string(fields[4])?,
                    ref_str: decode_string(fields[5])?,
                    ref_kind: parse_ref_kind(fields[6])?,
                    comment_version: decode_optional_string(fields[7])?,
                });
            }
            "DIFF" => {
                ensure_len(&fields, 9, line_no + 2)?;
                diff_changes.push(ActionRefChange {
                    file: decode_path(fields[1])?,
                    owner: decode_string(fields[2])?,
                    repo: decode_string(fields[3])?,
                    path: decode_optional_string(fields[4])?,
                    old_sha: decode_string(fields[5])?,
                    new_sha: decode_string(fields[6])?,
                    old_comment: decode_optional_string(fields[7])?,
                    new_comment: decode_optional_string(fields[8])?,
                });
            }
            other => bail!(
                "Unknown action ref payload record `{other}` on line {}",
                line_no + 2
            ),
        }
    }

    Ok(VerifierInput {
        action_refs,
        diff_changes,
    })
}

#[cfg(test)]
pub(crate) fn read_action_refs(mut reader: impl Read) -> Result<Vec<ActionRef>> {
    let text = read_protocol_text_limited(
        &mut reader,
        "action ref payload",
        MAX_ACTION_REFS_PAYLOAD_BYTES,
    )?;
    let mut lines = text.lines();
    expect_magic(lines.next(), ACTION_REFS_MAGIC, "action ref payload")?;

    let mut refs = Vec::new();
    for (line_no, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields = split_fields(line, line_no + 2)?;
        ensure_len(&fields, 8, line_no + 2)?;
        if fields[0] != "ACTION" {
            bail!(
                "Unknown action ref payload record `{}` on line {}",
                fields[0],
                line_no + 2
            );
        }
        refs.push(ActionRef {
            file: decode_path(fields[1])?,
            owner: decode_string(fields[2])?,
            repo: decode_string(fields[3])?,
            path: decode_optional_string(fields[4])?,
            ref_str: decode_string(fields[5])?,
            ref_kind: parse_ref_kind(fields[6])?,
            comment_version: decode_optional_string(fields[7])?,
        });
    }
    Ok(refs)
}

pub(crate) fn write_verification_results(
    mut writer: impl Write,
    results: &[VerificationResult],
    provenance_findings: &[AuditFinding],
    compare_results: &[CompareResult],
) -> Result<()> {
    writeln!(writer, "{VERIFY_MAGIC}").context("Failed to write verification payload header")?;

    for result in results {
        let (status, extra_a, extra_b, extra_c) = match &result.status {
            VerificationStatus::Verified => ("verified", None, None, None),
            VerificationStatus::NotFound => ("not_found", None, None, None),
            VerificationStatus::MutableRef { resolved } => {
                ("mutable_ref", resolved.as_deref(), None, None)
            }
            VerificationStatus::Skipped => ("skipped", None, None, None),
            VerificationStatus::CommentMismatch {
                comment_version,
                tag_resolves_to,
                pinned_version,
            } => (
                "comment_mismatch",
                Some(comment_version.as_str()),
                tag_resolves_to.as_deref(),
                pinned_version.as_deref(),
            ),
        };

        let file = result.action_ref.file.to_string_lossy();
        write_record(
            &mut writer,
            "VERIFY",
            &[
                &file,
                &result.action_ref.owner,
                &result.action_ref.repo,
                result.action_ref.path.as_deref().unwrap_or(""),
                &result.action_ref.ref_str,
                ref_kind_token(result.action_ref.ref_kind),
                result.action_ref.comment_version.as_deref().unwrap_or(""),
                status,
                extra_a.unwrap_or(""),
                extra_b.unwrap_or(""),
                extra_c.unwrap_or(""),
            ],
        )?;
    }

    for f in provenance_findings {
        let file = f.file.to_string_lossy();
        write_record(
            &mut writer,
            "PROVENANCE",
            &[
                &file,
                severity_token(f.severity),
                &f.title,
                &f.detail,
                if f.is_warning { "warn" } else { "deny" },
            ],
        )?;
    }

    for cr in compare_results {
        let ahead = cr.ahead_by.to_string();
        let files = cr.files_changed.to_string();
        // Sanitize \x1f from summaries before using it as delimiter,
        // so a commit message containing literal \x1f can't corrupt the split.
        let sanitized: Vec<String> = cr
            .commit_summaries
            .iter()
            .map(|s| s.replace('\x1f', " "))
            .collect();
        let summaries_joined = sanitized.join("\x1f");
        write_record(
            &mut writer,
            "COMPARE",
            &[
                &cr.owner,
                &cr.repo,
                &cr.old_sha,
                &cr.new_sha,
                &ahead,
                &files,
                &cr.html_url,
                &summaries_joined,
            ],
        )?;
    }

    Ok(())
}

#[derive(Debug)]
pub(crate) struct VerifyPayload {
    pub(crate) results: Vec<VerificationResult>,
    pub(crate) provenance_findings: Vec<AuditFinding>,
    pub(crate) compare_results: Vec<CompareResult>,
}

pub(crate) fn read_verification_results(mut reader: impl Read) -> Result<VerifyPayload> {
    let text = read_protocol_text_limited(
        &mut reader,
        "verification payload",
        MAX_VERIFY_PAYLOAD_BYTES,
    )?;
    let mut lines = text.lines();
    expect_magic(lines.next(), VERIFY_MAGIC, "verification payload")?;

    let mut results = Vec::new();
    let mut provenance_findings = Vec::new();
    let mut compare_results = Vec::new();

    for (line_no, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields = split_fields(line, line_no + 2)?;
        match fields[0] {
            "VERIFY" => {
                ensure_len(&fields, 12, line_no + 2)?;
                let action_ref = ActionRef {
                    file: decode_path(fields[1])?,
                    owner: decode_string(fields[2])?,
                    repo: decode_string(fields[3])?,
                    path: decode_optional_string(fields[4])?,
                    ref_str: decode_string(fields[5])?,
                    ref_kind: parse_ref_kind(fields[6])?,
                    comment_version: decode_optional_string(fields[7])?,
                };
                let status =
                    parse_verification_status(fields[8], fields[9], fields[10], fields[11])?;
                results.push(VerificationResult { action_ref, status });
            }
            "PROVENANCE" => {
                ensure_len(&fields, 6, line_no + 2)?;
                provenance_findings.push(AuditFinding {
                    file: decode_path(fields[1])?,
                    severity: parse_severity(fields[2])?,
                    title: decode_string(fields[3])?,
                    detail: decode_string(fields[4])?,
                    is_warning: decode_string(fields[5])? == "warn",
                });
            }
            "COMPARE" => {
                ensure_len(&fields, 9, line_no + 2)?;
                let summaries_raw = decode_string(fields[8])?;
                let commit_summaries: Vec<String> = if summaries_raw.is_empty() {
                    Vec::new()
                } else {
                    summaries_raw.split('\x1f').map(str::to_string).collect()
                };
                compare_results.push(CompareResult {
                    owner: decode_string(fields[1])?,
                    repo: decode_string(fields[2])?,
                    old_sha: decode_string(fields[3])?,
                    new_sha: decode_string(fields[4])?,
                    ahead_by: decode_string(fields[5])?.parse().unwrap_or(0),
                    files_changed: decode_string(fields[6])?.parse().unwrap_or(0),
                    html_url: decode_string(fields[7])?,
                    commit_summaries,
                });
            }
            other => {
                bail!(
                    "Unknown verification payload record `{other}` on line {}",
                    line_no + 2
                );
            }
        }
    }

    Ok(VerifyPayload {
        results,
        provenance_findings,
        compare_results,
    })
}

fn parse_verification_status(
    kind: &str,
    extra_a: &str,
    extra_b: &str,
    extra_c: &str,
) -> Result<VerificationStatus> {
    match decode_string(kind)?.as_str() {
        "verified" => Ok(VerificationStatus::Verified),
        "not_found" => Ok(VerificationStatus::NotFound),
        "mutable_ref" => Ok(VerificationStatus::MutableRef {
            resolved: decode_optional_string(extra_a)?,
        }),
        "skipped" => Ok(VerificationStatus::Skipped),
        "comment_mismatch" => Ok(VerificationStatus::CommentMismatch {
            comment_version: decode_optional_string(extra_a)?
                .context("Missing comment_mismatch.comment_version")?,
            tag_resolves_to: decode_optional_string(extra_b)?,
            pinned_version: decode_optional_string(extra_c)?,
        }),
        other => bail!("Unknown verification status `{other}`"),
    }
}

// ─── Wire format ──────────────────────────────────────────────────────────────

fn write_record(writer: &mut impl Write, tag: &str, fields: &[&str]) -> Result<()> {
    writer
        .write_all(tag.as_bytes())
        .context("Failed to write protocol record tag")?;
    for field in fields {
        writer
            .write_all(b"\t")
            .context("Failed to write protocol field separator")?;
        write_percent_encoded(writer, field.as_bytes())
            .context("Failed to write protocol field")?;
    }
    writer
        .write_all(b"\n")
        .context("Failed to terminate protocol record")?;
    Ok(())
}

fn read_protocol_text_limited(
    reader: &mut impl Read,
    label: &str,
    max_bytes: usize,
) -> Result<String> {
    let mut buf = String::new();
    reader
        .take(max_bytes as u64 + 1)
        .read_to_string(&mut buf)
        .context(format!("Failed to read {label}"))?;
    if buf.len() > max_bytes {
        bail!("{label} exceeded {} bytes", max_bytes);
    }
    Ok(buf)
}

fn expect_magic(found: Option<&str>, expected: &str, label: &str) -> Result<()> {
    match found {
        Some(line) if line == expected => Ok(()),
        Some(line) => bail!("Unexpected {label} header `{line}`"),
        None => bail!("Missing {label} header"),
    }
}

fn split_fields(line: &str, line_no: usize) -> Result<Vec<&str>> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.is_empty() {
        bail!("Malformed protocol line {line_no}");
    }
    Ok(fields)
}

fn ensure_len(fields: &[&str], expected: usize, line_no: usize) -> Result<()> {
    if fields.len() != expected {
        bail!(
            "Malformed protocol line {line_no}: expected {expected} fields, got {}",
            fields.len()
        );
    }
    Ok(())
}

// ─── Field encoding / decoding ────────────────────────────────────────────────

fn decode_path(field: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(percent_decode(field)?))
}

fn decode_optional_string(field: &str) -> Result<Option<String>> {
    if field.is_empty() {
        Ok(None)
    } else {
        percent_decode(field).map(Some)
    }
}

fn decode_string(field: &str) -> Result<String> {
    percent_decode(field)
}

// ─── Percent-encoding ─────────────────────────────────────────────────────────
//
// Escapes only protocol-sensitive bytes (\t, \n, \r, NUL, %) so that typical
// fields (ASCII owner/repo names, hex SHAs, file paths) pass through unmodified
// — zero intermediate allocation and ~1:1 wire size for the common case.

/// Write `data` to `writer`, percent-encoding only protocol delimiters.
/// For typical fields (no tabs/newlines/percent/NUL), this is a single
/// `write_all` call with no allocation.
fn write_percent_encoded(writer: &mut impl Write, data: &[u8]) -> std::io::Result<()> {
    let mut start = 0;
    for (i, &byte) in data.iter().enumerate() {
        let escape: Option<&[u8; 3]> = match byte {
            0 => Some(b"%00"),
            b'\t' => Some(b"%09"),
            b'\n' => Some(b"%0a"),
            b'\r' => Some(b"%0d"),
            b'%' => Some(b"%25"),
            _ => None,
        };
        if let Some(esc) = escape {
            if start < i {
                writer.write_all(&data[start..i])?;
            }
            writer.write_all(esc)?;
            start = i + 1;
        }
    }
    if start < data.len() {
        writer.write_all(&data[start..])?;
    }
    Ok(())
}

/// Percent-encode a string into a new `String`.  Used by the proxy protocol
/// which needs an owned encoded value.
pub(crate) fn percent_encode(value: &str) -> String {
    let bytes = value.as_bytes();
    if !bytes
        .iter()
        .any(|&b| matches!(b, 0 | b'\t' | b'\n' | b'\r' | b'%'))
    {
        return value.to_string();
    }
    let mut out = Vec::with_capacity(bytes.len() + 8);
    for &byte in bytes {
        match byte {
            0 => out.extend_from_slice(b"%00"),
            b'\t' => out.extend_from_slice(b"%09"),
            b'\n' => out.extend_from_slice(b"%0a"),
            b'\r' => out.extend_from_slice(b"%0d"),
            b'%' => out.extend_from_slice(b"%25"),
            _ => out.push(byte),
        }
    }
    // Input is valid UTF-8 (&str) and the only mutations replace single
    // bytes with ASCII-only %XX sequences — this cannot produce invalid UTF-8.
    String::from_utf8(out).expect("percent-encoding of valid UTF-8 produces valid UTF-8")
}

/// Decode a percent-encoded field.  Fast-paths when no `%` escapes are present.
pub(crate) fn percent_decode(field: &str) -> Result<String> {
    if !field.contains('%') {
        return Ok(field.to_string());
    }
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                bail!("Truncated percent-encoding in protocol field");
            }
            let hi =
                hex_nibble(bytes[i + 1]).context("Invalid percent-encoding in protocol field")?;
            let lo =
                hex_nibble(bytes[i + 2]).context("Invalid percent-encoding in protocol field")?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).context("Protocol field was not valid UTF-8")
}

pub(crate) const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// ─── Token mappings ───────────────────────────────────────────────────────────

const fn ref_kind_token(kind: RefKind) -> &'static str {
    match kind {
        RefKind::FullSha => "full_sha",
        RefKind::Mutable => "mutable",
    }
}

fn parse_ref_kind(field: &str) -> Result<RefKind> {
    match decode_string(field)?.as_str() {
        "full_sha" => Ok(RefKind::FullSha),
        "mutable" => Ok(RefKind::Mutable),
        other => bail!("Unknown ref kind `{other}`"),
    }
}

const fn skipped_ref_kind_token(kind: SkippedRefKind) -> &'static str {
    match kind {
        SkippedRefKind::RemoteReusableWorkflow => "remote_reusable_workflow",
        SkippedRefKind::UnresolvedLocalPath => "unresolved_local_path",
        SkippedRefKind::UnsupportedLocalRef => "unsupported_local_ref",
    }
}

fn parse_skipped_ref_kind(field: &str) -> Result<SkippedRefKind> {
    match decode_string(field)?.as_str() {
        "remote_reusable_workflow" => Ok(SkippedRefKind::RemoteReusableWorkflow),
        "unresolved_local_path" => Ok(SkippedRefKind::UnresolvedLocalPath),
        "unsupported_local_ref" => Ok(SkippedRefKind::UnsupportedLocalRef),
        other => bail!("Unknown skipped ref kind `{other}`"),
    }
}

const fn container_ref_kind_token(kind: ContainerRefKind) -> &'static str {
    match kind {
        ContainerRefKind::StepDockerUses => "step_docker_uses",
        ContainerRefKind::JobContainer => "job_container",
        ContainerRefKind::ServiceContainer => "service_container",
    }
}

fn parse_container_ref_kind(field: &str) -> Result<ContainerRefKind> {
    match decode_string(field)?.as_str() {
        "step_docker_uses" => Ok(ContainerRefKind::StepDockerUses),
        "job_container" => Ok(ContainerRefKind::JobContainer),
        "service_container" => Ok(ContainerRefKind::ServiceContainer),
        other => bail!("Unknown container ref kind `{other}`"),
    }
}

const fn container_pin_kind_token(kind: ContainerPinKind) -> &'static str {
    match kind {
        ContainerPinKind::DigestPinned => "digest_pinned",
        ContainerPinKind::Mutable => "mutable",
    }
}

fn parse_container_pin_kind(field: &str) -> Result<ContainerPinKind> {
    match decode_string(field)?.as_str() {
        "digest_pinned" => Ok(ContainerPinKind::DigestPinned),
        "mutable" => Ok(ContainerPinKind::Mutable),
        other => bail!("Unknown container pin kind `{other}`"),
    }
}

const fn severity_token(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
    }
}

fn parse_severity(field: &str) -> Result<Severity> {
    match decode_string(field)?.as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        other => bail!("Unknown severity `{other}`"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scan_payload_round_trips() {
        let payload = ScanPayload {
            action_refs: vec![ActionRef {
                file: PathBuf::from("/tmp/workflow.yml"),
                owner: "actions".into(),
                repo: "checkout".into(),
                path: Some("subdir".into()),
                ref_str: "v4".into(),
                ref_kind: RefKind::Mutable,
                comment_version: Some("v4.2.2".into()),
            }],
            skipped_refs: vec![SkippedRef {
                file: PathBuf::from("/tmp/workflow.yml"),
                uses_str: "./.github/workflows/reusable.yml".into(),
                kind: SkippedRefKind::RemoteReusableWorkflow,
                detail: "not audited".into(),
            }],
            container_refs: vec![ContainerRef {
                file: PathBuf::from("/tmp/workflow.yml"),
                image: "docker://alpine:latest".into(),
                kind: ContainerRefKind::StepDockerUses,
                pin_kind: ContainerPinKind::Mutable,
            }],
            audit_findings: vec![AuditFinding {
                file: PathBuf::from("/tmp/workflow.yml"),
                severity: Severity::Critical,
                title: "danger".into(),
                detail: "detail".into(),
                is_warning: false,
            }],
        };

        let mut buf = Vec::new();
        write_scan_payload(&mut buf, &payload).unwrap();
        let decoded = read_scan_payload(buf.as_slice()).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn action_refs_round_trip() {
        let refs = vec![ActionRef {
            file: PathBuf::from("/tmp/workflow.yml"),
            owner: "actions".into(),
            repo: "setup-node".into(),
            path: None,
            ref_str: "0123456789012345678901234567890123456789".into(),
            ref_kind: RefKind::FullSha,
            comment_version: None,
        }];

        let mut buf = Vec::new();
        write_action_refs(&mut buf, &refs).unwrap();
        let decoded = read_action_refs(buf.as_slice()).unwrap();
        assert_eq!(decoded, refs);
    }

    #[test]
    fn verification_results_round_trip() {
        let results = vec![
            VerificationResult {
                action_ref: ActionRef {
                    file: PathBuf::from("/tmp/workflow.yml"),
                    owner: "actions".into(),
                    repo: "checkout".into(),
                    path: None,
                    ref_str: "v4".into(),
                    ref_kind: RefKind::Mutable,
                    comment_version: None,
                },
                status: VerificationStatus::MutableRef {
                    resolved: Some("0123456789012345678901234567890123456789".into()),
                },
            },
            VerificationResult {
                action_ref: ActionRef {
                    file: PathBuf::from("/tmp/workflow.yml"),
                    owner: "actions".into(),
                    repo: "checkout".into(),
                    path: Some("nested".into()),
                    ref_str: "0123456789012345678901234567890123456789".into(),
                    ref_kind: RefKind::FullSha,
                    comment_version: Some("v4".into()),
                },
                status: VerificationStatus::CommentMismatch {
                    comment_version: "v4".into(),
                    tag_resolves_to: Some("9999999999999999999999999999999999999999".into()),
                    pinned_version: None,
                },
            },
        ];

        let provenance = vec![
            AuditFinding {
                file: PathBuf::from(".github/workflows/ci.yml"),
                severity: Severity::High,
                title: "test provenance finding".into(),
                detail: "test detail".into(),
                is_warning: false,
            },
            AuditFinding {
                file: PathBuf::from(".github/workflows/ci.yml"),
                severity: Severity::Medium,
                title: "test warning provenance finding".into(),
                detail: "this is a warning".into(),
                is_warning: true,
            },
        ];

        let mut buf = Vec::new();
        write_verification_results(&mut buf, &results, &provenance, &[]).unwrap();
        let decoded = read_verification_results(buf.as_slice()).unwrap();
        assert_eq!(decoded.results, results);
        assert_eq!(decoded.provenance_findings.len(), 2);
        assert_eq!(
            decoded.provenance_findings[0].title,
            "test provenance finding"
        );
        assert!(!decoded.provenance_findings[0].is_warning);
        assert_eq!(
            decoded.provenance_findings[1].title,
            "test warning provenance finding"
        );
        assert!(decoded.provenance_findings[1].is_warning);
    }

    #[test]
    fn percent_encoding_round_trips() {
        let cases = [
            "simple_field",
            "field\twith\ttabs",
            "field\nwith\nnewlines",
            "field%with%percent",
            "mixed\t\n%\r\0all",
            "",
            "actions/checkout",
            "/tmp/workflow.yml",
        ];
        for &original in &cases {
            let encoded = percent_encode(original);
            let decoded = percent_decode(&encoded).unwrap();
            assert_eq!(decoded, original, "round-trip failed for {original:?}");
        }
    }

    #[test]
    fn percent_encoding_no_allocation_for_clean_fields() {
        // Fields without special chars should encode to themselves
        let clean = "actions/checkout@0123456789abcdef0123456789abcdef01234567";
        let encoded = percent_encode(clean);
        assert_eq!(encoded, clean);
    }

    #[test]
    fn rejects_oversized_scan_payloads() {
        let oversized = format!("{SCAN_MAGIC}\n{}\n", "A".repeat(MAX_SCAN_PAYLOAD_BYTES + 1));
        let err = read_scan_payload(oversized.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("scan payload exceeded"));
    }

    #[test]
    fn rejects_oversized_verification_payloads() {
        let oversized = format!(
            "{VERIFY_MAGIC}\n{}\n",
            "A".repeat(MAX_VERIFY_PAYLOAD_BYTES + 1)
        );
        let err = read_verification_results(oversized.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("verification payload exceeded"));
    }

    // ─── Property-based tests ─────────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn percent_encoding_round_trips(s in "\\PC*") {
                let encoded = percent_encode(&s);
                let decoded = percent_decode(&encoded).expect("decode must succeed for encoded data");
                prop_assert_eq!(decoded, s);
            }

            #[test]
            fn encoded_fields_never_contain_delimiters(s in "\\PC*") {
                let encoded = percent_encode(&s);
                prop_assert!(!encoded.contains('\t'), "encoded field contains tab");
                prop_assert!(!encoded.contains('\n'), "encoded field contains newline");
                prop_assert!(!encoded.contains('\r'), "encoded field contains CR");
                prop_assert!(!encoded.contains('\0'), "encoded field contains NUL");
            }

            #[test]
            fn scan_parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let _ = read_scan_payload(data.as_slice());
            }

            #[test]
            fn verify_parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let _ = read_verification_results(data.as_slice());
            }

            #[test]
            fn action_ref_parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let _ = read_verifier_input(data.as_slice());
            }

            #[test]
            fn percent_decode_never_panics(s in "\\PC*") {
                let _ = percent_decode(&s);
            }
        }
    }
}
