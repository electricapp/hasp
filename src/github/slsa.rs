//! SLSA build-provenance attestation parsing and verification.
//!
//! GitHub's `/repos/{owner}/{repo}/attestations/{sha}` endpoint returns a JSON
//! envelope of the shape:
//!
//! ```json
//! {
//!   "attestations": [{
//!     "bundle": {
//!       "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
//!       "verificationMaterial": { ... },
//!       "dsseEnvelope": {
//!         "payloadType": "application/vnd.in-toto+json",
//!         "payload": "<base64 in-toto statement>",
//!         "signatures": [{"keyid": "", "sig": "<base64>"}]
//!       }
//!     },
//!     "repository_id": 12345
//!   }]
//! }
//! ```
//!
//! The in-toto statement (after base64-decoding `dsseEnvelope.payload`) has
//! shape:
//!
//! ```json
//! {
//!   "_type": "https://in-toto.io/Statement/v1",
//!   "subject": [{"name": "...", "digest": {"sha1": "<40 hex>"}}],
//!   "predicateType": "https://slsa.dev/provenance/v1",
//!   "predicate": {
//!     "buildDefinition": {
//!       "buildType": "...",
//!       "externalParameters": {
//!         "workflow": {"ref": "refs/tags/v1.2.3", "repository": "...", "path": "..."}
//!       }
//!     },
//!     "runDetails": { "builder": { "id": "https://github.com/actions/runner/..." }}
//!   }
//! }
//! ```
//!
//! v1 verifier checks: presence, subject digest binding, builder.id prefix,
//! and predicateType. Sigstore cryptographic signature verification is v2.

use crate::error::{Context, Result};
use yaml_rust2::{Yaml, YamlLoader};

/// Known-good GitHub Actions builder prefixes. SLSA v1 attestations emitted
/// by the default GitHub Actions runner use an identity rooted at
/// `https://github.com/actions/...`.
const TRUSTED_BUILDER_PREFIXES: &[&str] =
    &["https://github.com/actions/", "https://actions.github.io/"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttestationVerdict {
    /// Attestation exists, subject binds to the pinned SHA, builder is trusted.
    Verified {
        workflow_ref: Option<String>,
        builder_id: String,
    },
    /// No attestation was present for this SHA.
    Missing,
    /// Attestation exists but subject's sha1 digest mismatches the pinned SHA.
    SubjectMismatch {
        expected: String,
        observed: Vec<String>,
    },
    /// Attestation exists but the builder identity is not one we trust.
    UntrustedBuilder { builder_id: String },
    /// Attestation exists but the predicateType isn't SLSA v0.2 or v1.
    UnknownPredicate { predicate_type: String },
    /// We couldn't parse the attestation bundle. Carries the parse error.
    MalformedAttestation(String),
}

/// Parse the JSON response body from GitHub's attestations endpoint and verify
/// against an expected SHA.  Returns `Missing` if the envelope has no
/// attestations, `Verified`/`*Mismatch`/`*Builder` on a bundle.
pub(crate) fn verify_attestation_response(body: &str, expected_sha: &str) -> Result<AttestationVerdict> {
    let doc = YamlLoader::load_from_str(body).context("Invalid attestation JSON envelope")?;
    let doc = doc.into_iter().next().unwrap_or(Yaml::Null);
    let map = doc
        .as_hash()
        .context("Attestation envelope was not a JSON object")?;

    let attestations = map
        .get(&Yaml::String("attestations".to_string()))
        .and_then(Yaml::as_vec);

    let Some(attestations) = attestations else {
        return Ok(AttestationVerdict::Missing);
    };
    if attestations.is_empty() {
        return Ok(AttestationVerdict::Missing);
    }

    // Verified always wins. Otherwise we report the strongest negative signal
    // across all attestations: a SubjectMismatch (tampered binding) outranks an
    // UntrustedBuilder, which outranks an UnknownPredicate, which outranks a
    // MalformedAttestation (raw parse failure carries the least signal).
    let mut best_negative: Option<AttestationVerdict> = None;
    for attestation in attestations {
        match verify_single_attestation(attestation, expected_sha) {
            Ok(verdict @ AttestationVerdict::Verified { .. }) => {
                return Ok(verdict);
            }
            Ok(other) => {
                if verdict_rank(&other) > best_negative.as_ref().map_or(0, verdict_rank) {
                    best_negative = Some(other);
                }
            }
            Err(e) => {
                let v = AttestationVerdict::MalformedAttestation(e.to_string());
                if verdict_rank(&v) > best_negative.as_ref().map_or(0, verdict_rank) {
                    best_negative = Some(v);
                }
            }
        }
    }

    Ok(best_negative.unwrap_or(AttestationVerdict::Missing))
}

const fn verdict_rank(v: &AttestationVerdict) -> u8 {
    match v {
        AttestationVerdict::SubjectMismatch { .. } => 4,
        AttestationVerdict::UntrustedBuilder { .. } => 3,
        AttestationVerdict::UnknownPredicate { .. } => 2,
        AttestationVerdict::MalformedAttestation(_) => 1,
        AttestationVerdict::Verified { .. } | AttestationVerdict::Missing => 0,
    }
}

fn verify_single_attestation(attestation: &Yaml, expected_sha: &str) -> Result<AttestationVerdict> {
    let statement = match extract_in_toto_statement(attestation)? {
        Ok(stmt) => stmt,
        Err(verdict) => return Ok(verdict),
    };
    let statement_map = statement
        .as_hash()
        .context("in-toto statement was not a JSON object")?;

    let predicate_type = statement_map
        .get(&Yaml::String("predicateType".to_string()))
        .and_then(Yaml::as_str)
        .unwrap_or("");
    if !is_slsa_provenance_predicate(predicate_type) {
        return Ok(AttestationVerdict::UnknownPredicate {
            predicate_type: predicate_type.to_string(),
        });
    }

    if let Some(mismatch) = check_subject_binding(statement_map, expected_sha) {
        return Ok(mismatch);
    }

    let builder_id = extract_builder_id(statement_map);
    if !is_trusted_builder(&builder_id) {
        return Ok(AttestationVerdict::UntrustedBuilder { builder_id });
    }

    let workflow_ref = extract_workflow_ref(statement_map);
    Ok(AttestationVerdict::Verified {
        workflow_ref,
        builder_id,
    })
}

/// Decode the DSSE payload into an in-toto Statement Yaml. The outer `Result`
/// carries hard errors; the inner `Result` distinguishes a well-formed
/// statement from a malformed-bundle verdict.
fn extract_in_toto_statement(
    attestation: &Yaml,
) -> Result<std::result::Result<Yaml, AttestationVerdict>> {
    let Some(bundle) = attestation
        .as_hash()
        .and_then(|m| m.get(&Yaml::String("bundle".to_string())))
        .and_then(Yaml::as_hash)
    else {
        return Ok(Err(AttestationVerdict::MalformedAttestation(
            "attestation missing `bundle`".to_string(),
        )));
    };
    let Some(envelope) = bundle
        .get(&Yaml::String("dsseEnvelope".to_string()))
        .and_then(Yaml::as_hash)
    else {
        return Ok(Err(AttestationVerdict::MalformedAttestation(
            "bundle missing `dsseEnvelope`".to_string(),
        )));
    };
    let payload_b64 = envelope
        .get(&Yaml::String("payload".to_string()))
        .and_then(Yaml::as_str)
        .context("dsseEnvelope missing `payload`")?;
    let decoded =
        base64_decode(payload_b64).context("dsseEnvelope.payload is not valid base64")?;
    let statement_text = std::str::from_utf8(&decoded)
        .context("dsseEnvelope.payload did not decode to valid UTF-8")?;
    let statement_docs = YamlLoader::load_from_str(statement_text)
        .context("dsseEnvelope.payload was not valid JSON")?;
    Ok(Ok(statement_docs.into_iter().next().unwrap_or(Yaml::Null)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExpectedHash {
    Sha1,
    Sha256,
    Other,
}

/// Return `Some(SubjectMismatch)` if no subject's sha1/gitCommit/sha256 digest
/// matches `expected_sha`. Returns `None` on a successful binding.
fn check_subject_binding(
    statement_map: &yaml_rust2::yaml::Hash,
    expected_sha: &str,
) -> Option<AttestationVerdict> {
    let subjects = statement_map
        .get(&Yaml::String("subject".to_string()))
        .and_then(Yaml::as_vec)
        .cloned()
        .unwrap_or_default();
    let mut observed = Vec::new();
    let mut bound = false;
    // A 40-hex expected_sha is a git commit SHA; accept only digest types that
    // legitimately key git commit hashes (sha1 / gitCommit). A 64-hex value
    // means the caller is binding a SHA-256 (artifact or commit). Cross-type
    // matches (e.g., binding a sha1 expectation against a sha256-keyed digest)
    // would otherwise pass on accidentally-equal hex prefixes.
    let expected_kind = if expected_sha.len() == 40 {
        ExpectedHash::Sha1
    } else if expected_sha.len() == 64 {
        ExpectedHash::Sha256
    } else {
        ExpectedHash::Other
    };
    for subj in &subjects {
        let Some(digest) = subj
            .as_hash()
            .and_then(|m| m.get(&Yaml::String("digest".to_string())))
            .and_then(Yaml::as_hash)
        else {
            continue;
        };
        for key in ["sha1", "gitCommit", "sha256"] {
            if let Some(value) = digest
                .get(&Yaml::String(key.to_string()))
                .and_then(Yaml::as_str)
            {
                observed.push(format!("{key}:{value}"));
                // Reject cross-digest-type matches: a 40-hex (sha1) expected
                // SHA must bind via sha1/gitCommit; a 64-hex (sha256) must
                // bind via sha256. The scanner enforces 40-hex for FullSha
                // refs, so `ExpectedHash::Other` never matches here.
                let key_compatible = matches!(
                    (expected_kind, key),
                    (ExpectedHash::Sha1, "sha1" | "gitCommit")
                        | (ExpectedHash::Sha256, "sha256")
                );
                if key_compatible && value.eq_ignore_ascii_case(expected_sha) {
                    bound = true;
                }
            }
        }
    }
    if bound {
        None
    } else {
        Some(AttestationVerdict::SubjectMismatch {
            expected: expected_sha.to_string(),
            observed,
        })
    }
}

fn extract_builder_id(statement_map: &yaml_rust2::yaml::Hash) -> String {
    statement_map
        .get(&Yaml::String("predicate".to_string()))
        .and_then(Yaml::as_hash)
        .and_then(|m| m.get(&Yaml::String("runDetails".to_string())))
        .and_then(Yaml::as_hash)
        .and_then(|m| m.get(&Yaml::String("builder".to_string())))
        .and_then(Yaml::as_hash)
        .and_then(|m| m.get(&Yaml::String("id".to_string())))
        .and_then(Yaml::as_str)
        .unwrap_or("")
        .to_string()
}

fn extract_workflow_ref(statement_map: &yaml_rust2::yaml::Hash) -> Option<String> {
    statement_map
        .get(&Yaml::String("predicate".to_string()))
        .and_then(Yaml::as_hash)
        .and_then(|m| m.get(&Yaml::String("buildDefinition".to_string())))
        .and_then(Yaml::as_hash)
        .and_then(|m| m.get(&Yaml::String("externalParameters".to_string())))
        .and_then(Yaml::as_hash)
        .and_then(|m| m.get(&Yaml::String("workflow".to_string())))
        .and_then(Yaml::as_hash)
        .and_then(|m| m.get(&Yaml::String("ref".to_string())))
        .and_then(Yaml::as_str)
        .map(str::to_string)
}

fn is_slsa_provenance_predicate(predicate_type: &str) -> bool {
    matches!(
        predicate_type,
        "https://slsa.dev/provenance/v1"
            | "https://slsa.dev/provenance/v0.2"
            | "https://slsa.dev/provenance/v0.1"
    )
}

fn is_trusted_builder(id: &str) -> bool {
    TRUSTED_BUILDER_PREFIXES
        .iter()
        .any(|prefix| id.starts_with(prefix))
}

/// Minimal base64 decoder — we already depend on the `base64` crate elsewhere
/// (Sigstore cert chain in selfcheck), so reuse it.
fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    // DSSE envelopes are canonical base64 but tolerate padding differences.
    STANDARD
        .decode(s.trim())
        .or_else(|_| {
            // Some producers emit URL-safe base64 without padding.
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            URL_SAFE_NO_PAD.decode(s.trim())
        })
        .map_err(|e| crate::error::Error::new(format!("base64 decode failed: {e}")))
}


// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    fn envelope_around(statement_json: &str) -> String {
        let payload = STANDARD.encode(statement_json);
        format!(
            r#"{{
              "attestations": [{{
                "bundle": {{
                  "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
                  "dsseEnvelope": {{
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": "{payload}",
                    "signatures": [{{"keyid": "", "sig": "AAAA"}}]
                  }}
                }},
                "repository_id": 1
              }}]
            }}"#
        )
    }

    #[test]
    fn verifies_valid_slsa_v1_attestation() {
        let stmt = r#"{
          "_type": "https://in-toto.io/Statement/v1",
          "subject": [{"name": "git", "digest": {"sha1": "abcdef0000000000000000000000000000000000"}}],
          "predicateType": "https://slsa.dev/provenance/v1",
          "predicate": {
            "buildDefinition": {
              "buildType": "https://actions.github.io/buildtypes/workflow/v1",
              "externalParameters": {
                "workflow": {"ref": "refs/tags/v4.2.2", "repository": "...", "path": "..."}
              }
            },
            "runDetails": {
              "builder": {"id": "https://github.com/actions/runner/buildx-v4.2.2"}
            }
          }
        }"#;
        let body = envelope_around(stmt);
        let verdict = verify_attestation_response(&body, "abcdef0000000000000000000000000000000000").unwrap();
        if let AttestationVerdict::Verified {
            workflow_ref,
            builder_id,
        } = verdict
        {
            assert!(builder_id.starts_with("https://github.com/actions/runner/"));
            assert_eq!(workflow_ref.as_deref(), Some("refs/tags/v4.2.2"));
        } else {
            panic!("expected Verified, got {verdict:?}");
        }
    }

    #[test]
    fn flags_subject_mismatch() {
        let stmt = r#"{
          "_type": "https://in-toto.io/Statement/v1",
          "subject": [{"name": "git", "digest": {"sha1": "abcdef0000000000000000000000000000000000"}}],
          "predicateType": "https://slsa.dev/provenance/v1",
          "predicate": {"runDetails": {"builder": {"id": "https://github.com/actions/runner/x"}}}
        }"#;
        let body = envelope_around(stmt);
        let verdict = verify_attestation_response(
            &body,
            "1111111111111111111111111111111111111111",
        )
        .unwrap();
        assert!(matches!(verdict, AttestationVerdict::SubjectMismatch { .. }));
    }

    #[test]
    fn flags_untrusted_builder() {
        let stmt = r#"{
          "_type": "https://in-toto.io/Statement/v1",
          "subject": [{"name": "git", "digest": {"sha1": "abcdef0000000000000000000000000000000000"}}],
          "predicateType": "https://slsa.dev/provenance/v1",
          "predicate": {"runDetails": {"builder": {"id": "https://evil.example.com/builder"}}}
        }"#;
        let body = envelope_around(stmt);
        let verdict = verify_attestation_response(&body, "abcdef0000000000000000000000000000000000").unwrap();
        assert!(matches!(verdict, AttestationVerdict::UntrustedBuilder { .. }));
    }

    #[test]
    fn reports_missing_when_envelope_empty() {
        let body = "{\"attestations\": []}";
        let verdict = verify_attestation_response(body, "abcdef0000000000000000000000000000000000").unwrap();
        assert!(matches!(verdict, AttestationVerdict::Missing));
    }

    #[test]
    fn reports_missing_when_no_attestations_key() {
        let body = "{}";
        let verdict = verify_attestation_response(body, "abcdef0000000000000000000000000000000000").unwrap();
        assert!(matches!(verdict, AttestationVerdict::Missing));
    }

    #[test]
    fn rejects_non_slsa_predicate_type() {
        let stmt = r#"{
          "_type": "https://in-toto.io/Statement/v1",
          "subject": [{"name": "x", "digest": {"sha1": "abcdef0000000000000000000000000000000000"}}],
          "predicateType": "https://example.com/other/v1",
          "predicate": {}
        }"#;
        let body = envelope_around(stmt);
        let verdict = verify_attestation_response(&body, "abcdef0000000000000000000000000000000000").unwrap();
        assert!(matches!(verdict, AttestationVerdict::UnknownPredicate { .. }));
    }
}
