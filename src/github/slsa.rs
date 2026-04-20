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
    /// Attestation exists, subject binds to the pinned SHA, builder is trusted,
    /// and (when crypto material is present) the DSSE signature verifies against
    /// the cert's EC public key.
    Verified {
        workflow_ref: Option<String>,
        builder_id: String,
        signer_identity: Option<super::sigstore::SignerIdentity>,
        /// `Some(true)`: DSSE ECDSA signature verified against the cert's
        /// `SubjectPublicKeyInfo`. `Some(false)`: verification was attempted
        /// but failed. `None`: no cert / no signature in the bundle, so
        /// there was nothing to verify.
        signature_verified: Option<bool>,
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
    /// Attestation cert was issued by a CA we don't recognise as Fulcio-shaped.
    /// Carries the best-effort extracted identity so callers can diagnose.
    UntrustedIssuer {
        issuer_cn: String,
        subject_uri: Option<String>,
    },
    /// Attestation's DSSE ECDSA signature does not verify against the
    /// cert's public key. This is the strongest tampering signal.
    SignatureInvalid { reason: String },
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

    // First attestation wins for the verification verdict. If any subsequent
    // attestation verifies successfully, that promotes the overall verdict.
    let mut first_verdict: Option<AttestationVerdict> = None;
    for attestation in attestations {
        match verify_single_attestation(attestation, expected_sha) {
            Ok(verdict @ AttestationVerdict::Verified { .. }) => {
                return Ok(verdict);
            }
            Ok(other) => {
                if first_verdict.is_none() {
                    first_verdict = Some(other);
                }
            }
            Err(e) => {
                if first_verdict.is_none() {
                    first_verdict = Some(AttestationVerdict::MalformedAttestation(e.to_string()));
                }
            }
        }
    }

    Ok(first_verdict.unwrap_or(AttestationVerdict::Missing))
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

    // Evidence layer (v2.1): pull the signer identity from the cert if present.
    let bundle = attestation
        .as_hash()
        .and_then(|m| m.get(&Yaml::String("bundle".to_string())))
        .and_then(Yaml::as_hash);
    let signer_identity = bundle.and_then(super::sigstore::extract_identity_from_bundle);

    // If we have a cert and its issuer clearly isn't Fulcio-shaped, treat
    // that as a distinct verdict rather than lumping it into `Verified`.
    if let Some(identity) = signer_identity.as_ref()
        && identity.issuer_cn.is_some()
        && !identity.looks_like_fulcio()
    {
        return Ok(AttestationVerdict::UntrustedIssuer {
            issuer_cn: identity
                .issuer_cn
                .clone()
                .unwrap_or_default(),
            subject_uri: identity.subject_uri.clone(),
        });
    }

    // DSSE signature verification (v2.2a). Verifies the envelope's signature
    // against the cert's EC public key. Does NOT verify the cert chains to
    // the Fulcio root -- that's the v2.2b layer below.
    let signature_verified = match verify_dsse_signature(bundle) {
        DsseResult::Verified => Some(true),
        DsseResult::NotAttempted => None,
        DsseResult::Invalid(reason) => {
            return Ok(AttestationVerdict::SignatureInvalid { reason });
        }
    };

    let workflow_ref = extract_workflow_ref(statement_map);
    Ok(AttestationVerdict::Verified {
        workflow_ref,
        builder_id,
        signer_identity,
        signature_verified,
    })
}

enum DsseResult {
    Verified,
    /// Bundle lacks crypto material (e.g. legacy shape with no cert) so we
    /// can't attempt verification. Signal to caller that this is a gap, not
    /// a failure.
    NotAttempted,
    /// Signature was present but failed to verify against the cert's key.
    Invalid(String),
}

/// Verify the DSSE envelope's `ECDSA_P256_SHA256` signature against the
/// attestation cert's `SubjectPublicKeyInfo`. DSSE v1 PAE is:
///   `"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload`
/// where SP = 0x20 and LEN is ASCII-decimal byte length.
fn verify_dsse_signature(bundle: Option<&yaml_rust2::yaml::Hash>) -> DsseResult {
    let Some(bundle) = bundle else {
        return DsseResult::NotAttempted;
    };
    let Some(envelope) = bundle
        .get(&Yaml::String("dsseEnvelope".to_string()))
        .and_then(Yaml::as_hash)
    else {
        return DsseResult::NotAttempted;
    };

    let Some(payload_type) = envelope
        .get(&Yaml::String("payloadType".to_string()))
        .and_then(Yaml::as_str)
    else {
        return DsseResult::NotAttempted;
    };
    let Some(payload_b64) = envelope
        .get(&Yaml::String("payload".to_string()))
        .and_then(Yaml::as_str)
    else {
        return DsseResult::NotAttempted;
    };
    let Ok(payload_bytes) = sigstore_base64(payload_b64) else {
        return DsseResult::Invalid("base64 decode failed for DSSE payload".into());
    };

    let Some(first_sig) = envelope
        .get(&Yaml::String("signatures".to_string()))
        .and_then(Yaml::as_vec)
        .and_then(|arr| arr.first())
        .and_then(Yaml::as_hash)
    else {
        return DsseResult::NotAttempted;
    };
    let Some(sig_b64) = first_sig
        .get(&Yaml::String("sig".to_string()))
        .and_then(Yaml::as_str)
    else {
        return DsseResult::NotAttempted;
    };
    let Ok(sig_bytes) = sigstore_base64(sig_b64) else {
        return DsseResult::Invalid("base64 decode failed for DSSE signature".into());
    };

    let Some(pubkey) = super::sigstore::extract_spki_ec_point_from_bundle(bundle) else {
        return DsseResult::NotAttempted;
    };

    // PAE computation.
    let mut pae: Vec<u8> = Vec::with_capacity(32 + payload_type.len() + payload_bytes.len());
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_bytes.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(&payload_bytes);

    let verifier = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        pubkey,
    );
    match verifier.verify(&pae, &sig_bytes) {
        Ok(()) => DsseResult::Verified,
        Err(_) => DsseResult::Invalid(
            "ECDSA_P256_SHA256 verification failed for DSSE envelope".into(),
        ),
    }
}

fn sigstore_base64(s: &str) -> Result<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD
        .decode(s.trim())
        .or_else(|_| {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            URL_SAFE_NO_PAD.decode(s.trim())
        })
        .map_err(|e| crate::error::Error::new(format!("base64 decode failed: {e}")))
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
                if value.eq_ignore_ascii_case(expected_sha) {
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
            signer_identity: _,
            signature_verified,
        } = verdict
        {
            assert!(builder_id.starts_with("https://github.com/actions/runner/"));
            assert_eq!(workflow_ref.as_deref(), Some("refs/tags/v4.2.2"));
            // No cert material in this synthetic bundle -> NotAttempted -> None.
            assert!(signature_verified.is_none());
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
    fn verifies_real_dsse_signature_end_to_end() {
        // Generate a live ECDSA P-256 keypair with ring, sign a real DSSE
        // PAE over the attestation payload, wrap the pubkey in a synthetic
        // x509 cert, and assert the full verifier reports Verified with
        // signature_verified = Some(true).
        use base64::{Engine, engine::general_purpose::STANDARD};
        use ring::rand::SystemRandom;
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let keypair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let pubkey_sec1 = keypair.public_key().as_ref().to_vec();
        assert_eq!(pubkey_sec1.len(), 65, "SEC1 uncompressed P-256 point is 65 bytes");
        assert_eq!(pubkey_sec1[0], 0x04);

        // Build the in-toto statement + compute PAE against its encoded payload.
        let statement = r#"{
          "_type": "https://in-toto.io/Statement/v1",
          "subject": [{"name": "git", "digest": {"sha1": "abcdef0000000000000000000000000000000000"}}],
          "predicateType": "https://slsa.dev/provenance/v1",
          "predicate": {"runDetails": {"builder": {"id": "https://github.com/actions/runner/x"}}}
        }"#;
        let payload_bytes = statement.as_bytes();
        let payload_type = "application/vnd.in-toto+json";
        let mut pae: Vec<u8> = Vec::new();
        pae.extend_from_slice(b"DSSEv1 ");
        pae.extend_from_slice(payload_type.len().to_string().as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(payload_type.as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(payload_bytes.len().to_string().as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(payload_bytes);

        let sig = keypair.sign(&rng, &pae).unwrap();
        let sig_b64 = STANDARD.encode(sig.as_ref());
        let payload_b64 = STANDARD.encode(payload_bytes);

        // Build a synthetic cert wrapping our real pubkey. DER helpers below.
        let cert_der = build_cert_with_pubkey(&pubkey_sec1);
        let cert_b64 = STANDARD.encode(&cert_der);

        let bundle = format!(
            r#"{{
                "attestations": [{{
                    "bundle": {{
                        "dsseEnvelope": {{
                            "payloadType": "{payload_type}",
                            "payload": "{payload_b64}",
                            "signatures": [{{"keyid": "", "sig": "{sig_b64}"}}]
                        }},
                        "verificationMaterial": {{
                            "certificate": {{"rawBytes": "{cert_b64}"}}
                        }}
                    }}
                }}]
            }}"#
        );

        let verdict = verify_attestation_response(
            &bundle,
            "abcdef0000000000000000000000000000000000",
        )
        .unwrap();
        if let AttestationVerdict::Verified {
            signature_verified,
            signer_identity,
            ..
        } = verdict
        {
            assert_eq!(
                signature_verified,
                Some(true),
                "signature should verify against the matching pubkey"
            );
            // Cert has issuer CN `sigstore-intermediate` so it looks like Fulcio.
            assert!(signer_identity.is_some_and(|i| i.looks_like_fulcio()));
        } else {
            panic!("expected Verified, got {verdict:?}");
        }
    }

    #[test]
    fn flags_tampered_payload_as_signature_invalid() {
        // Same keypair, same cert -- but swap the payload after signing. The
        // signature should fail verification.
        use base64::{Engine, engine::general_purpose::STANDARD};
        use ring::rand::SystemRandom;
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let keypair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let pubkey_sec1 = keypair.public_key().as_ref().to_vec();

        let original = br#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x","digest":{"sha1":"abcdef0000000000000000000000000000000000"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"runDetails":{"builder":{"id":"https://github.com/actions/runner/x"}}}}"#;
        let payload_type = "application/vnd.in-toto+json";

        let mut pae: Vec<u8> = Vec::new();
        pae.extend_from_slice(b"DSSEv1 ");
        pae.extend_from_slice(payload_type.len().to_string().as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(payload_type.as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(original.len().to_string().as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(original);
        let sig = keypair.sign(&rng, &pae).unwrap();
        let sig_b64 = STANDARD.encode(sig.as_ref());

        // Tampered payload has the *same SHA binding* (so subject-mismatch
        // doesn't fire) but a different byte somewhere -- flip the builder
        // URL to force a signature mismatch without upsetting the structural
        // checks that run before signature verification.
        let tampered = br#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x","digest":{"sha1":"abcdef0000000000000000000000000000000000"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"runDetails":{"builder":{"id":"https://github.com/actions/runner/y"}}}}"#;
        let tampered_b64 = STANDARD.encode(tampered);
        let cert_b64 = STANDARD.encode(build_cert_with_pubkey(&pubkey_sec1));

        let bundle = format!(
            r#"{{
                "attestations": [{{
                    "bundle": {{
                        "dsseEnvelope": {{
                            "payloadType": "{payload_type}",
                            "payload": "{tampered_b64}",
                            "signatures": [{{"keyid": "", "sig": "{sig_b64}"}}]
                        }},
                        "verificationMaterial": {{
                            "certificate": {{"rawBytes": "{cert_b64}"}}
                        }}
                    }}
                }}]
            }}"#
        );

        let verdict = verify_attestation_response(
            &bundle,
            "abcdef0000000000000000000000000000000000",
        )
        .unwrap();
        assert!(
            matches!(verdict, AttestationVerdict::SignatureInvalid { .. }),
            "expected SignatureInvalid, got {verdict:?}"
        );
    }

    /// Synthetic cert wrapping a caller-supplied EC P-256 SEC1 uncompressed
    /// pubkey (65 bytes). Issuer CN and SAN URI are hardcoded to make the
    /// cert look Fulcio-shaped so the verifier doesn't short-circuit on
    /// `UntrustedIssuer` before reaching signature verification.
    fn build_cert_with_pubkey(pubkey_sec1: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if value.len() < 0x80 {
                out.push(u8::try_from(value.len()).unwrap());
            } else if value.len() < 0x100 {
                out.push(0x81);
                out.push(u8::try_from(value.len()).unwrap());
            } else {
                out.push(0x82);
                out.push(u8::try_from(value.len() >> 8).unwrap());
                out.push(u8::try_from(value.len() & 0xff).unwrap());
            }
            out.extend_from_slice(value);
            out
        }
        fn seq(children: &[&[u8]]) -> Vec<u8> {
            let inner: Vec<u8> = children.iter().flat_map(|c| c.iter().copied()).collect();
            tlv(0x30, &inner)
        }
        fn rdn_cn(cn: &str) -> Vec<u8> {
            let oid = tlv(0x06, &[0x55, 0x04, 0x03]);
            let value = tlv(0x13, cn.as_bytes());
            let attr = seq(&[&oid, &value]);
            let rdn = tlv(0x31, &attr);
            seq(&[&rdn])
        }

        let issuer = rdn_cn("sigstore-intermediate");
        let subject = rdn_cn("placeholder");
        let utc1 = tlv(0x17, b"250101000000Z");
        let utc2 = tlv(0x17, b"260101000000Z");
        let validity = seq(&[&utc1, &utc2]);

        // SPKI with the real pubkey: BIT STRING of the 65-byte point prefixed
        // with unused-bits byte 0x00.
        let alg_oid = tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]); // ecPublicKey
        let alg_params = tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]); // P-256
        let alg = seq(&[&alg_oid, &alg_params]);
        let mut bit_string_bytes = vec![0_u8];
        bit_string_bytes.extend_from_slice(pubkey_sec1);
        let bitstr = tlv(0x03, &bit_string_bytes);
        let spki = seq(&[&alg, &bitstr]);

        let san_uri = "https://github.com/a/b/.github/workflows/x.yml@refs/heads/main";
        let uri_name = tlv(0x86, san_uri.as_bytes());
        let general_names = seq(&[&uri_name]);
        let octet = tlv(0x04, &general_names);
        let san_oid = tlv(0x06, &[0x55, 0x1D, 0x11]);
        let san_ext = seq(&[&san_oid, &octet]);
        let exts = seq(&[&san_ext]);
        let exts_wrapper = tlv(0xA3, &exts);

        let version = tlv(0xA0, &tlv(0x02, &[0x02]));
        let serial = tlv(0x02, &[0x01]);
        let sig_alg = seq(&[&alg_oid, &alg_params]);
        let tbs = seq(&[
            &version, &serial, &sig_alg, &issuer, &validity, &subject, &spki, &exts_wrapper,
        ]);
        let outer_sig_alg = seq(&[&alg_oid, &alg_params]);
        let outer_sig_value = tlv(0x03, &[0x00, 0xAA]);
        seq(&[&tbs, &outer_sig_alg, &outer_sig_value])
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
