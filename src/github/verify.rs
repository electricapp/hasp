use crate::error::Result;
use crate::scanner::{ActionRef, RefKind};
use std::collections::HashMap;

use super::client::Api;

// ─── Result types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerificationStatus {
    Verified,
    NotFound,
    MutableRef {
        resolved: Option<String>,
    },
    Skipped,
    /// SHA exists but the inline comment version doesn't match what the tag resolves to
    CommentMismatch {
        comment_version: String,
        tag_resolves_to: Option<String>,
        /// The tag that the pinned SHA actually corresponds to (reverse lookup)
        pinned_version: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerificationResult {
    pub(crate) action_ref: ActionRef,
    pub(crate) status: VerificationStatus,
}

// ─── Verification orchestration ───────────────────────────────────────────────

pub(crate) fn verify_all_with_api(
    client: &impl Api,
    refs: &[ActionRef],
) -> Result<Vec<VerificationResult>> {
    let mut cache: HashMap<String, VerificationStatus> = HashMap::new();
    let mut tag_resolution_cache: HashMap<String, Option<String>> = HashMap::new();
    let mut results = Vec::with_capacity(refs.len());

    for action_ref in refs {
        let key = format!(
            "{}/{}/{}",
            action_ref.owner, action_ref.repo, action_ref.ref_str
        );

        #[allow(clippy::option_if_let_else)] // borrow conflict prevents map_or_else
        let mut status = if let Some(cached) = cache.get(&key) {
            cached.clone()
        } else {
            let s = match action_ref.ref_kind {
                RefKind::FullSha => {
                    let exists = client.verify_commit(
                        &action_ref.owner,
                        &action_ref.repo,
                        &action_ref.ref_str,
                    )?;
                    if exists {
                        VerificationStatus::Verified
                    } else {
                        VerificationStatus::NotFound
                    }
                }
                RefKind::Mutable => {
                    let resolved = client.resolve_tag(
                        &action_ref.owner,
                        &action_ref.repo,
                        &action_ref.ref_str,
                    )?;
                    VerificationStatus::MutableRef { resolved }
                }
            };
            cache.insert(key, s.clone());
            s
        };

        // Check inline comment version against actual tag resolution
        if let (VerificationStatus::Verified, Some(ver)) = (&status, &action_ref.comment_version) {
            // Cache comment-version tag resolutions to avoid duplicate API calls
            // when many refs share the same comment version (e.g. "# v4")
            let comment_key = format!("{}/{}/{}", action_ref.owner, action_ref.repo, ver);
            #[allow(clippy::option_if_let_else)] // borrow conflict prevents map_or_else
            let tag_sha = if let Some(cached) = tag_resolution_cache.get(&comment_key) {
                cached.clone()
            } else {
                let resolved = client.resolve_tag(&action_ref.owner, &action_ref.repo, ver)?;
                tag_resolution_cache.insert(comment_key, resolved.clone());
                resolved
            };

            let sha_matches = tag_sha.as_ref().is_some_and(|s| s == &action_ref.ref_str);

            if !sha_matches {
                let pinned_version = client.find_tag_for_sha(
                    &action_ref.owner,
                    &action_ref.repo,
                    &action_ref.ref_str,
                );
                status = VerificationStatus::CommentMismatch {
                    comment_version: ver.clone(),
                    tag_resolves_to: tag_sha,
                    pinned_version,
                };
            }
        }

        results.push(VerificationResult {
            action_ref: action_ref.clone(),
            status,
        });
    }

    Ok(results)
}

pub(crate) fn skip_verify(refs: &[ActionRef]) -> Vec<VerificationResult> {
    refs.iter()
        .map(|r| VerificationResult {
            action_ref: r.clone(),
            status: match r.ref_kind {
                RefKind::FullSha => VerificationStatus::Skipped,
                RefKind::Mutable => VerificationStatus::MutableRef { resolved: None },
            },
        })
        .collect()
}
