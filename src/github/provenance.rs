use crate::audit::{self, AuditFinding, Severity};
use crate::error::{Context, Result, bail};
use crate::scanner::RefKind;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use super::client::{Api, ReachabilityStatus, RepoInfo};
use super::verify::{VerificationResult, VerificationStatus};

pub(super) type CommitKey = String;
pub(super) type RepoKey = String;

#[derive(Clone)]
struct ProvenanceSnapshot {
    reachability: ReachabilityStatus,
    signed: bool,
    commit_date: Option<String>,
}

pub(crate) fn check_provenance_with_api(
    client: &impl Api,
    results: &[VerificationResult],
    policy: &crate::policy::Policy,
) -> Result<Vec<AuditFinding>> {
    Ok(check_provenance_with_api_at(
        client,
        results,
        now_unix_seconds()?,
        policy,
    ))
}

#[allow(clippy::too_many_lines)] // provenance logic is cohesive and reads top-to-bottom
fn check_provenance_with_api_at(
    client: &impl Api,
    results: &[VerificationResult],
    now_seconds: i64,
    policy: &crate::policy::Policy,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let mut checked: HashMap<CommitKey, ProvenanceSnapshot> = HashMap::new();
    let mut repo_infos: HashMap<RepoKey, RepoInfo> = HashMap::new();
    let mut repo_reputation_checked: HashSet<RepoKey> = HashSet::new();
    let mut tag_dates: HashMap<CommitKey, Option<String>> = HashMap::new();

    for result in results {
        // Only check verified full-SHA refs
        if result.action_ref.ref_kind != RefKind::FullSha {
            continue;
        }
        if !matches!(
            result.status,
            VerificationStatus::Verified | VerificationStatus::CommentMismatch { .. }
        ) {
            continue;
        }

        let key = format!(
            "{}/{}/{}",
            result.action_ref.owner, result.action_ref.repo, result.action_ref.ref_str
        );
        let repo_key = format!("{}/{}", result.action_ref.owner, result.action_ref.repo);
        let ri = repo_infos.entry(repo_key.clone()).or_insert_with(|| {
            client
                .get_repo_info(&result.action_ref.owner, &result.action_ref.repo)
                .unwrap_or_else(|_| RepoInfo::fallback())
        });
        let default_branch = &ri.default_branch;
        let created_at = ri.created_at.as_deref();
        let stargazers_count = ri.stargazers_count;
        let forks_count = ri.forks_count;

        if !checked.contains_key(&key) {
            let reachability = client
                .is_commit_reachable(
                    &result.action_ref.owner,
                    &result.action_ref.repo,
                    &result.action_ref.ref_str,
                    default_branch,
                )
                .unwrap_or(ReachabilityStatus::Unreachable);

            let signed = client
                .is_commit_signed(
                    &result.action_ref.owner,
                    &result.action_ref.repo,
                    &result.action_ref.ref_str,
                )
                .unwrap_or(false);
            let commit_date = client
                .get_commit_date(
                    &result.action_ref.owner,
                    &result.action_ref.repo,
                    &result.action_ref.ref_str,
                )
                .unwrap_or(None);

            checked.insert(
                key.clone(),
                ProvenanceSnapshot {
                    reachability,
                    signed,
                    commit_date,
                },
            );
        }
        let snapshot = &checked[&key];

        let target = result.action_ref.target();
        let short_sha = &result.action_ref.ref_str[..result.action_ref.ref_str.len().min(12)];

        // Resolve per-action policy (cascade global -> action override)
        let resolved = policy.resolve_for_action(
            &result.action_ref.owner,
            &result.action_ref.repo,
            result.action_ref.path.as_deref(),
        );
        let provenance_config = &resolved.checks.provenance;

        if repo_reputation_checked.insert(repo_key)
            && !audit::is_trusted_owner(&result.action_ref.owner)
        {
            if !provenance_config.recent_repo.is_off()
                && let Some(created_at_str) = created_at
                && let Some(created_seconds) = parse_iso8601_utc(created_at_str)
            {
                let age_seconds = age_since(now_seconds, created_seconds);
                if (0..=30 * 24 * 60 * 60).contains(&age_seconds) {
                    findings.push(AuditFinding {
                        file: result.action_ref.file.clone(),
                        severity: Severity::High,
                        title: format!("Recently created repository `{target}`"),
                        detail: format!(
                            "Repository `{target}` was created only {} ago. Newly created \
                             action repositories are a common squatting pattern. Verify \
                             the publisher identity and project history carefully before \
                             trusting this dependency.",
                            format_age(age_seconds)
                        ),
                        is_warning: provenance_config.recent_repo.is_warn(),
                    });
                }
            }

            if !provenance_config.repo_reputation.is_off() {
                // Check for very low-signal first (High severity)
                let is_very_low_signal = matches!(
                    (stargazers_count, forks_count),
                    (Some(stars), Some(0)) if stars < 5
                );

                if is_very_low_signal {
                    findings.push(AuditFinding {
                        file: result.action_ref.file.clone(),
                        severity: Severity::High,
                        title: format!("Very low-signal repository `{target}`"),
                        detail: format!(
                            "Repository `{target}` has fewer than 5 stars and zero forks. That \
                             combination is unusually weak social proof for a workflow dependency \
                             and can indicate a newly created squatting repository."
                        ),
                        is_warning: provenance_config.repo_reputation.is_warn(),
                    });
                }

                if let Some(stars) = stargazers_count
                    && stars < 10
                {
                    findings.push(AuditFinding {
                        file: result.action_ref.file.clone(),
                        severity: Severity::Medium,
                        title: format!("Low-reputation repository `{target}`"),
                        detail: format!(
                            "Repository `{target}` has only {stars} star(s). Low-star action \
                             repositories deserve additional scrutiny unless they come from a \
                             trusted publisher."
                        ),
                        is_warning: provenance_config.repo_reputation.is_warn(),
                    });
                }
            }
        }

        if !provenance_config.reachability.is_off() {
            match snapshot.reachability {
                ReachabilityStatus::Diverged | ReachabilityStatus::Unreachable => {
                    let status_word = if snapshot.reachability == ReachabilityStatus::Diverged {
                        "diverged from"
                    } else {
                        "unreachable from"
                    };
                    findings.push(AuditFinding {
                        file: result.action_ref.file.clone(),
                        severity: Severity::High,
                        title: format!(
                            "Commit {short_sha} is {status_word} {target} default branch"
                        ),
                        detail: format!(
                            "The pinned SHA {short_sha} exists in GitHub's object store but is not \
                             reachable from the repository's default branch. This could indicate an \
                             orphaned fork commit — an attacker can push a malicious commit to a fork \
                             and it becomes addressable by SHA from the parent repo. Verify this SHA \
                             belongs to a legitimate release tag."
                        ),
                        is_warning: provenance_config.reachability.is_warn(),
                    });
                }
                ReachabilityStatus::Ahead => {
                    findings.push(AuditFinding {
                        file: result.action_ref.file.clone(),
                        severity: Severity::Medium,
                        title: format!(
                            "Commit {short_sha} is ahead of {target} default branch"
                        ),
                        detail: format!(
                            "The pinned SHA {short_sha} contains commits not yet in the default \
                             branch. This may be from an unmerged PR or pre-release. Consider pinning \
                             to a tagged release commit instead."
                        ),
                        is_warning: provenance_config.reachability.is_warn(),
                    });
                }
                ReachabilityStatus::Reachable => {}
            }
        }

        if !provenance_config.signatures.is_off() && !snapshot.signed {
            findings.push(AuditFinding {
                file: result.action_ref.file.clone(),
                severity: Severity::Medium,
                title: format!("Unsigned commit {short_sha} in {target}"),
                detail: format!(
                    "The pinned commit {short_sha} does not have a verified signature. \
                     Signed commits provide stronger provenance guarantees. Note: not all \
                     legitimate actions use signed commits."
                ),
                is_warning: provenance_config.signatures.is_warn(),
            });
        }

        if let Some(commit_date) = snapshot.commit_date.as_deref() {
            let commit_seconds = parse_iso8601_utc(commit_date);
            let age_policy_finding = if provenance_config.fresh_commit.is_off() {
                None
            } else {
                commit_seconds.and_then(|commit_seconds| {
                    build_commit_age_policy_finding(
                        result,
                        commit_seconds,
                        now_seconds,
                        resolved.min_sha_age_seconds,
                        resolved.security_action_min_sha_age_seconds,
                        provenance_config.fresh_commit,
                    )
                })
            };
            if let Some(finding) = &age_policy_finding {
                findings.push(finding.clone());
            }

            if !provenance_config.fresh_commit.is_off()
                && !audit::is_trusted_owner(&result.action_ref.owner)
                && age_policy_finding.is_none()
                && let Some(commit_seconds) = commit_seconds
            {
                let age_seconds = age_since(now_seconds, commit_seconds);
                if (0..=7 * 24 * 60 * 60).contains(&age_seconds) {
                    findings.push(AuditFinding {
                        file: result.action_ref.file.clone(),
                        severity: Severity::Medium,
                        title: format!("Very fresh commit {short_sha} in {target}"),
                        detail: format!(
                            "The pinned commit {short_sha} is only {} old. For non-trusted \
                             publishers this leaves very little time for community review \
                             and detection of malicious behavior. Prefer older, widely used \
                             release commits when possible.",
                            format_age(age_seconds)
                        ),
                        is_warning: provenance_config.fresh_commit.is_warn(),
                    });
                }
            }

            if !provenance_config.tag_age_gap.is_off()
                && let Some(tag_name) = version_label_for_result(result)
            {
                let tag_key = format!(
                    "{}/{}/{}",
                    result.action_ref.owner, result.action_ref.repo, tag_name
                );
                #[allow(clippy::option_if_let_else)] // borrow conflict prevents map_or_else
                let tag_date = if let Some(existing) = tag_dates.get(&tag_key) {
                    existing.clone()
                } else {
                    let resolved = client
                        .get_tag_creation_date(
                            &result.action_ref.owner,
                            &result.action_ref.repo,
                            tag_name,
                        )
                        .unwrap_or(None);
                    tag_dates.insert(tag_key.clone(), resolved.clone());
                    resolved
                };

                if let (Some(commit_seconds), Some(tag_date)) =
                    (commit_seconds, tag_date.as_deref())
                    && let Some(tag_seconds) = parse_iso8601_utc(tag_date)
                {
                    let lag = age_since(tag_seconds, commit_seconds);
                    if lag > 365 * 24 * 60 * 60 {
                        findings.push(AuditFinding {
                            file: result.action_ref.file.clone(),
                            severity: Severity::Critical,
                            title: format!(
                                "Tag `{tag_name}` may have been retroactively applied to \
                                 an old commit in {target}"
                            ),
                            detail: format!(
                                "Tag `{tag_name}` was created {} after commit \
                                 {short_sha} was authored. A gap this large strongly \
                                 suggests the tag was force-pushed or retroactively \
                                 created on an old commit. This is a common supply-chain \
                                 attack pattern: an attacker pushes a malicious commit, \
                                 then moves an existing tag to point to it.",
                                format_age(lag)
                            ),
                            is_warning: provenance_config.tag_age_gap.is_warn(),
                        });
                    } else if lag > 90 * 24 * 60 * 60 {
                        findings.push(AuditFinding {
                            file: result.action_ref.file.clone(),
                            severity: Severity::High,
                            title: format!(
                                "Tag `{tag_name}` may have been retroactively applied to \
                                 an old commit in {target}"
                            ),
                            detail: format!(
                                "Tag `{tag_name}` was created {} after commit \
                                 {short_sha} was authored. Large retroactive tag gaps \
                                 can indicate moved or newly created tags on old \
                                 commits — a pattern used in supply-chain attacks where \
                                 an attacker force-pushes a tag onto a different commit. \
                                 Verify that this tag history is expected for the \
                                 upstream action.",
                                format_age(lag)
                            ),
                            is_warning: provenance_config.tag_age_gap.is_warn(),
                        });
                    }
                }
            }
        }

        // ── SLSA attestation ───────────────────────────────────────────
        if !provenance_config.slsa_attestation.is_off() {
            match client.get_attestation(
                &result.action_ref.owner,
                &result.action_ref.repo,
                &result.action_ref.ref_str,
            ) {
                Ok(Some(body)) => {
                    match super::slsa::verify_attestation_response(
                        &body,
                        &result.action_ref.ref_str,
                    ) {
                        Ok(verdict) => emit_slsa_finding(
                            &verdict,
                            result,
                            target.as_str(),
                            short_sha,
                            provenance_config.slsa_attestation,
                            &mut findings,
                        ),
                        Err(e) => {
                            // Bad bundle — surface as MED so it's visible but
                            // doesn't block on network-flakiness-shaped errors.
                            findings.push(AuditFinding {
                                file: result.action_ref.file.clone(),
                                severity: Severity::Medium,
                                title: format!(
                                    "SLSA attestation for {target} could not be parsed"
                                ),
                                detail: format!(
                                    "GitHub returned an attestation bundle for \
                                     {short_sha} in {target} but we couldn't parse it: \
                                     {e}. This may indicate an unsupported bundle format."
                                ),
                                is_warning: true,
                            });
                        }
                    }
                }
                Ok(None) => {
                    findings.push(AuditFinding {
                        file: result.action_ref.file.clone(),
                        severity: Severity::Medium,
                        title: format!(
                            "No SLSA attestation published for {target}"
                        ),
                        detail: format!(
                            "GitHub has no build attestation for commit {short_sha} in \
                             {target}. SLSA attestations provide positive evidence that \
                             the pinned SHA was produced by an advertised CI workflow. \
                             Actions that ship SLSA attestations (via \
                             `actions/attest-build-provenance`) give stronger provenance \
                             guarantees than pinning alone."
                        ),
                        is_warning: provenance_config.slsa_attestation.is_warn(),
                    });
                }
                Err(e) => {
                    eprintln!(
                        "hasp: warning: SLSA attestation lookup failed for {target}@{short_sha}: {e}"
                    );
                }
            }
        }
    }

    findings
}

fn emit_slsa_finding(
    verdict: &super::slsa::AttestationVerdict,
    result: &VerificationResult,
    target: &str,
    short_sha: &str,
    level: crate::policy::CheckLevel,
    findings: &mut Vec<AuditFinding>,
) {
    use super::slsa::AttestationVerdict;
    let is_warning = level.is_warn();
    match verdict {
        AttestationVerdict::Verified { .. } | AttestationVerdict::Missing => {}
        AttestationVerdict::UntrustedIssuer {
            issuer_cn,
            subject_uri,
        } => {
            findings.push(AuditFinding {
                file: result.action_ref.file.clone(),
                severity: Severity::High,
                title: format!(
                    "SLSA attestation for {target} issued by non-Fulcio CA"
                ),
                detail: format!(
                    "The attestation bundle's cert was issued by `{issuer_cn}`, which \
                     does not match Sigstore's public Fulcio CA. Workflow identity in \
                     the cert: {}. If this is intentional (private Fulcio instance), \
                     extend hasp's trusted-issuer allowlist. Otherwise treat this as \
                     a tampered or misissued attestation.",
                    subject_uri.as_deref().unwrap_or("<not extracted>")
                ),
                is_warning,
            });
        }
        AttestationVerdict::SubjectMismatch { observed, .. } => {
            findings.push(AuditFinding {
                file: result.action_ref.file.clone(),
                severity: Severity::Critical,
                title: format!(
                    "SLSA attestation for {target} does not bind to pinned SHA"
                ),
                detail: format!(
                    "The SLSA attestation on GitHub for {target} references \
                     subjects {observed:?} but we asked for {short_sha}. This mismatch \
                     could indicate a tampered bundle, an attestation moved from a \
                     different SHA, or a bug in the publisher's release pipeline. \
                     Investigate before trusting the pinned SHA."
                ),
                is_warning,
            });
        }
        AttestationVerdict::UntrustedBuilder { builder_id } => {
            findings.push(AuditFinding {
                file: result.action_ref.file.clone(),
                severity: Severity::High,
                title: format!(
                    "SLSA attestation for {target} signed by untrusted builder"
                ),
                detail: format!(
                    "The SLSA attestation for {short_sha} in {target} was emitted by \
                     `{builder_id}`, which is not a GitHub Actions runner identity. \
                     This is unusual: GitHub-hosted runners produce attestations \
                     rooted at `https://github.com/actions/...`. Verify the builder \
                     matches what the upstream publisher claims."
                ),
                is_warning,
            });
        }
        AttestationVerdict::UnknownPredicate { predicate_type } => {
            findings.push(AuditFinding {
                file: result.action_ref.file.clone(),
                severity: Severity::Medium,
                title: format!(
                    "SLSA attestation for {target} uses unknown predicate type"
                ),
                detail: format!(
                    "The attestation for {short_sha} uses predicateType \
                     `{predicate_type}`, not a recognized SLSA provenance version. \
                     hasp can only verify `https://slsa.dev/provenance/v0.2` and v1 \
                     statements."
                ),
                is_warning,
            });
        }
        AttestationVerdict::MalformedAttestation(msg) => {
            findings.push(AuditFinding {
                file: result.action_ref.file.clone(),
                severity: Severity::Medium,
                title: format!(
                    "SLSA attestation for {target} is malformed"
                ),
                detail: format!(
                    "Attestation bundle for {short_sha} could not be validated: {msg}."
                ),
                is_warning,
            });
        }
    }
}

fn build_commit_age_policy_finding(
    result: &VerificationResult,
    commit_seconds: i64,
    now_seconds: i64,
    min_sha_age_seconds: Option<i64>,
    security_action_min_sha_age_seconds: Option<i64>,
    level: crate::policy::CheckLevel,
) -> Option<AuditFinding> {
    let base_required_age = min_sha_age_seconds.unwrap_or(0);
    let privileged_required_age = if audit::is_privileged_action(
        &result.action_ref.owner,
        &result.action_ref.repo,
        result.action_ref.path.as_deref(),
    ) {
        security_action_min_sha_age_seconds.unwrap_or(0)
    } else {
        0
    };
    let required_age = base_required_age.max(privileged_required_age);
    if required_age <= 0 {
        return None;
    }

    let age_seconds = age_since(now_seconds, commit_seconds);
    if age_seconds >= required_age {
        return None;
    }

    let target = result.action_ref.target();
    let short_sha = &result.action_ref.ref_str[..result.action_ref.ref_str.len().min(12)];
    let privileged_policy_applied = privileged_required_age > 0
        && privileged_required_age >= base_required_age
        && age_seconds < privileged_required_age;
    let severity = if privileged_policy_applied {
        Severity::Critical
    } else {
        Severity::High
    };
    let policy_label = if privileged_policy_applied {
        "privileged action cooling-off policy"
    } else {
        "minimum pinned-commit age policy"
    };

    Some(AuditFinding {
        file: result.action_ref.file.clone(),
        severity,
        title: format!("Pinned commit {short_sha} in {target} is newer than policy"),
        detail: format!(
            "Pinned commit {short_sha} is only {} old, which violates the {policy_label} \
             requiring at least {} before a SHA is trusted in CI. This reduces exposure to \
             hot supply-chain compromises that are often caught shortly after release.",
            format_age(age_seconds),
            format_age(required_age)
        ),
        is_warning: level.is_warn(),
    })
}

const fn age_since(later_seconds: i64, earlier_seconds: i64) -> i64 {
    if later_seconds <= earlier_seconds {
        0
    } else {
        later_seconds - earlier_seconds
    }
}

fn format_age(seconds: i64) -> String {
    let days = seconds / 86_400;
    if days <= 0 {
        "less than a day".to_string()
    } else if days == 1 {
        "1 day".to_string()
    } else {
        format!("{days} days")
    }
}

pub(super) fn version_label_for_result(result: &VerificationResult) -> Option<&str> {
    match &result.status {
        VerificationStatus::Verified => result.action_ref.comment_version.as_deref(),
        VerificationStatus::CommentMismatch { pinned_version, .. } => pinned_version.as_deref(),
        VerificationStatus::NotFound
        | VerificationStatus::MutableRef { .. }
        | VerificationStatus::Skipped => None,
    }
}

// ─── Date/time utilities ─────────────────────────────────────────────────────

pub(super) fn parse_iso8601_utc(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    // Accept both "2024-01-01T00:00:00Z" (20 bytes) and
    // "2024-01-01T00:00:00.000Z" (with fractional seconds, variable length).
    // Minimum length is 20 ("YYYY-MM-DDTHH:MM:SSZ").
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last()? != b'Z'
    {
        return None;
    }

    // Validate the seconds field ends at byte 19 (either 'Z' or '.')
    if bytes[19] != b'Z' && bytes[19] != b'.' {
        return None;
    }

    let year = i32::try_from(parse_digits(bytes, 0, 4)?).ok()?;
    let month = u32::try_from(parse_digits(bytes, 5, 2)?).ok()?;
    let day = u32::try_from(parse_digits(bytes, 8, 2)?).ok()?;
    let hour = parse_digits(bytes, 11, 2)?;
    let minute = parse_digits(bytes, 14, 2)?;
    let second = parse_digits(bytes, 17, 2)?;

    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn parse_digits(bytes: &[u8], start: usize, len: usize) -> Option<i64> {
    let mut value = 0_i64;
    for byte in bytes.get(start..start + len)? {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i64::from(byte - b'0');
    }
    Some(value)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 {
        return None;
    }
    let max_day = match month {
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
            if leap { 29 } else { 28 }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day > max_day {
        return None;
    }

    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    // month is 1..=12 and day is 1..=31, so i32::try_from is infallible here
    let month_i32 = i32::try_from(month).ok()?;
    let day_i32 = i32::try_from(day).ok()?;
    let month_prime = month_i32 + if month > 2 { -3 } else { 9 };
    let doy = (153 * month_prime + 2) / 5 + day_i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(i64::from(era) * 146_097 + i64::from(doe) - 719_468)
}

fn now_unix_seconds() -> Result<i64> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before the UNIX epoch; commit age checks cannot be trusted")?
        .as_secs();
    if secs <= 1_000_000_000 {
        bail!(
            "System clock appears invalid (before ~2001); --min-sha-age would be silently defeated"
        );
    }
    i64::try_from(secs).context("system clock timestamp overflows i64")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::client::CompareResult;
    use super::*;
    use crate::scanner::{ActionRef, RefKind};
    use std::collections::HashMap;
    use std::path::PathBuf;

    struct MockApi {
        reachability: ReachabilityStatus,
        signed: bool,
        repo_info: RepoInfo,
        commit_dates: HashMap<(String, String, String), Option<String>>,
        tag_dates: HashMap<(String, String, String), Option<String>>,
    }

    impl Api for MockApi {
        fn verify_commit(&self, _owner: &str, _repo: &str, _sha: &str) -> Result<bool> {
            Ok(true)
        }

        fn resolve_tag(&self, _owner: &str, _repo: &str, _tag: &str) -> Result<Option<String>> {
            Ok(None)
        }

        fn find_tag_for_sha(&self, _owner: &str, _repo: &str, _sha: &str) -> Option<String> {
            None
        }

        fn get_repo_info(&self, _owner: &str, _repo: &str) -> Result<RepoInfo> {
            Ok(self.repo_info.clone())
        }

        fn is_commit_reachable(
            &self,
            _owner: &str,
            _repo: &str,
            _sha: &str,
            _default_branch: &str,
        ) -> Result<ReachabilityStatus> {
            Ok(self.reachability.clone())
        }

        fn is_commit_signed(&self, _owner: &str, _repo: &str, _sha: &str) -> Result<bool> {
            Ok(self.signed)
        }

        fn get_commit_date(&self, owner: &str, repo: &str, sha: &str) -> Result<Option<String>> {
            Ok(self
                .commit_dates
                .get(&(owner.to_string(), repo.to_string(), sha.to_string()))
                .cloned()
                .unwrap_or(None))
        }

        fn get_tag_creation_date(
            &self,
            owner: &str,
            repo: &str,
            tag: &str,
        ) -> Result<Option<String>> {
            Ok(self
                .tag_dates
                .get(&(owner.to_string(), repo.to_string(), tag.to_string()))
                .cloned()
                .unwrap_or(None))
        }

        fn get_action_yml(
            &self,
            _owner: &str,
            _repo: &str,
            _path: Option<&str>,
            _sha: &str,
        ) -> Result<Option<String>> {
            Ok(None)
        }

        fn compare_commits(
            &self,
            _owner: &str,
            _repo: &str,
            _base: &str,
            _head: &str,
        ) -> Result<CompareResult> {
            Ok(CompareResult {
                owner: String::new(),
                repo: String::new(),
                old_sha: String::new(),
                new_sha: String::new(),
                ahead_by: 0,
                files_changed: 0,
                commit_summaries: Vec::new(),
                html_url: String::new(),
            })
        }
    }

    fn test_policy(
        min_sha_age_seconds: Option<i64>,
        security_action_min_sha_age_seconds: Option<i64>,
    ) -> crate::policy::Policy {
        let mut p = crate::policy::Policy::default();
        p.min_sha_age_seconds = min_sha_age_seconds;
        p.security_action_min_sha_age_seconds = security_action_min_sha_age_seconds;
        p
    }

    fn verified_result(
        owner: &str,
        repo: &str,
        path: Option<&str>,
        sha: &str,
    ) -> VerificationResult {
        VerificationResult {
            action_ref: ActionRef {
                file: PathBuf::from("workflow.yml"),
                owner: owner.to_string(),
                repo: repo.to_string(),
                path: path.map(str::to_string),
                ref_str: sha.to_string(),
                ref_kind: RefKind::FullSha,
                comment_version: None,
            },
            status: VerificationStatus::Verified,
        }
    }

    #[test]
    fn parse_iso8601_utc_to_epoch_seconds() {
        assert_eq!(parse_iso8601_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso8601_utc("1970-01-02T00:00:00Z"), Some(86_400));
    }

    #[test]
    fn parse_iso8601_utc_handles_fractional_seconds() {
        // GitHub API may return fractional seconds like "2024-01-01T00:00:00.000Z"
        assert_eq!(parse_iso8601_utc("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_iso8601_utc("1970-01-02T00:00:00.123456Z"),
            Some(86_400)
        );
    }

    #[test]
    fn flags_fresh_untrusted_commits() {
        let sha = "0123456789012345678901234567890123456789";
        let now = parse_iso8601_utc("2026-03-26T00:00:00Z").unwrap();
        let api = MockApi {
            reachability: ReachabilityStatus::Reachable,
            signed: true,
            repo_info: RepoInfo::fallback(),
            commit_dates: HashMap::from([(
                ("sneaky".into(), "deploy".into(), sha.into()),
                Some("2026-03-24T00:00:00Z".into()),
            )]),
            tag_dates: HashMap::new(),
        };

        let findings = check_provenance_with_api_at(
            &api,
            &[verified_result("sneaky", "deploy", None, sha)],
            now,
            &test_policy(None, None),
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("Very fresh commit"))
        );
    }

    #[test]
    fn flags_retroactive_tags_high_severity() {
        let sha = "0123456789012345678901234567890123456789";
        // Commit 2025-06-01, tag 2025-12-01 => ~183 days lag => HIGH (>90 but <=365)
        let api = MockApi {
            reachability: ReachabilityStatus::Reachable,
            signed: true,
            repo_info: RepoInfo::fallback(),
            commit_dates: HashMap::from([(
                ("actions".into(), "checkout".into(), sha.into()),
                Some("2025-06-01T00:00:00Z".into()),
            )]),
            tag_dates: HashMap::from([(
                ("actions".into(), "checkout".into(), "v4".into()),
                Some("2025-12-01T00:00:00Z".into()),
            )]),
        };
        let mut result = verified_result("actions", "checkout", None, sha);
        result.action_ref.comment_version = Some("v4".into());

        let findings = check_provenance_with_api_at(
            &api,
            &[result],
            parse_iso8601_utc("2026-03-26T00:00:00Z").unwrap(),
            &test_policy(None, None),
        );
        let retroactive = findings
            .iter()
            .find(|f| f.title.contains("retroactively applied"));
        assert!(retroactive.is_some(), "expected a retroactive tag finding");
        assert_eq!(retroactive.unwrap().severity, Severity::High);
    }

    #[test]
    fn flags_retroactive_tags_critical_severity() {
        let sha = "0123456789012345678901234567890123456789";
        // Commit 2024-01-01, tag 2025-06-01 => ~516 days lag => CRITICAL (>365)
        let api = MockApi {
            reachability: ReachabilityStatus::Reachable,
            signed: true,
            repo_info: RepoInfo::fallback(),
            commit_dates: HashMap::from([(
                ("actions".into(), "checkout".into(), sha.into()),
                Some("2024-01-01T00:00:00Z".into()),
            )]),
            tag_dates: HashMap::from([(
                ("actions".into(), "checkout".into(), "v4".into()),
                Some("2025-06-01T00:00:00Z".into()),
            )]),
        };
        let mut result = verified_result("actions", "checkout", None, sha);
        result.action_ref.comment_version = Some("v4".into());

        let findings = check_provenance_with_api_at(
            &api,
            &[result],
            parse_iso8601_utc("2026-03-26T00:00:00Z").unwrap(),
            &test_policy(None, None),
        );
        let retroactive = findings
            .iter()
            .find(|f| f.title.contains("retroactively applied"));
        assert!(retroactive.is_some(), "expected a retroactive tag finding");
        assert_eq!(retroactive.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn flags_recent_low_reputation_repositories() {
        let sha = "0123456789012345678901234567890123456789";
        let now = parse_iso8601_utc("2026-03-26T00:00:00Z").unwrap();
        let api = MockApi {
            reachability: ReachabilityStatus::Reachable,
            signed: true,
            repo_info: RepoInfo {
                default_branch: "main".into(),
                created_at: Some("2026-03-10T00:00:00Z".into()),
                stargazers_count: Some(3),
                forks_count: Some(0),
            },
            commit_dates: HashMap::from([(
                ("sneaky".into(), "deploy".into(), sha.into()),
                Some("2026-03-01T00:00:00Z".into()),
            )]),
            tag_dates: HashMap::new(),
        };

        let findings = check_provenance_with_api_at(
            &api,
            &[verified_result("sneaky", "deploy", None, sha)],
            now,
            &test_policy(None, None),
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("Recently created repository"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("Low-reputation repository"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("Very low-signal repository"))
        );
    }

    #[test]
    fn flags_sha_age_policy_for_privileged_actions() {
        let sha = "0123456789012345678901234567890123456789";
        let now = parse_iso8601_utc("2026-03-26T00:00:00Z").unwrap();
        let api = MockApi {
            reachability: ReachabilityStatus::Reachable,
            signed: true,
            repo_info: RepoInfo::fallback(),
            commit_dates: HashMap::from([(
                ("sneaky".into(), "security-scan".into(), sha.into()),
                Some("2026-03-20T00:00:00Z".into()),
            )]),
            tag_dates: HashMap::new(),
        };

        let findings = check_provenance_with_api_at(
            &api,
            &[verified_result("sneaky", "security-scan", None, sha)],
            now,
            &test_policy(Some(48 * 60 * 60), Some(30 * 24 * 60 * 60)),
        );
        assert!(findings.iter().any(|finding| {
            finding.severity == Severity::Critical && finding.title.contains("newer than policy")
        }));
    }
}
