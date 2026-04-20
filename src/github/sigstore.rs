//! Minimal Sigstore evidence extraction from GitHub attestation bundles.
//!
//! v2.1 adds *identity* evidence: walks the DER of the attestation's
//! verification-material certificate and surfaces two fields the cert
//! cryptographically binds to (but that we do not ourselves verify against
//! the Fulcio root in this pass):
//!
//!   * **Signer identity** -- the `SubjectAlternativeName` URI Fulcio encodes
//!     in each cert. For GitHub Actions attestations this is a URL like
//!     `https://github.com/owner/repo/.github/workflows/build.yml@refs/tags/v1.2.3`.
//!     It identifies the exact workflow + ref that minted the attestation.
//!   * **Issuer CN** -- identifies the CA that issued the cert. Fulcio CAs
//!     name themselves `sigstore-intermediate` or similar in the Subject CN.
//!
//! ## What this adds over v1's predicate-only check
//!
//! The v1 `AttestationVerdict::Verified` meant: "the attestation's DSSE
//! payload names this SHA, declares a SLSA predicate, and names a GitHub
//! Actions builder." That is *unsigned* evidence from the decoded payload.
//!
//! With v2.1 we also report the cert-embedded identity, so findings can say
//! "this attestation was minted by workflow X at ref Y." When that identity
//! is present and issued by a Fulcio-shaped CA, users have strong evidence
//! of *what* built the artifact -- even though hasp itself doesn't yet
//! cryptographically verify the DSSE signature over the payload.
//!
//! ## v2.2a (landed): DSSE signature verification
//!
//! `verify_dsse_signature` in `slsa.rs` cryptographically verifies the
//! envelope's `ECDSA_P256_SHA256` signature against the cert's
//! `SubjectPublicKeyInfo` via `ring`. A tampered payload or signature
//! produces `AttestationVerdict::SignatureInvalid` (CRIT finding).
//!
//! ## v2.2b (landed): Leaf-to-intermediate chain validation
//!
//! `verify_chain_to_fulcio` verifies the leaf cert's signature against
//! the bundled Sigstore public-good Fulcio intermediate
//! (`data/fulcio/intermediate_v1.pem`). Issuer DN is matched
//! byte-for-byte against the bundled intermediate's Subject DN, and the
//! leaf's `ECDSA_P384_SHA384` signature is verified against the
//! intermediate's public key.
//!
//! ## v2.2c (landed): Intermediate-to-root chain validation
//!
//! `load_verified_intermediate` runs once at first use and refuses to
//! trust the bundled intermediate unless its signature verifies against
//! the bundled Fulcio root (`data/fulcio/root_v1.pem`). A tampered
//! intermediate in the source tree is caught here -- hasp falls back to
//! `ChainVerdict::Malformed` for every attestation rather than trusting
//! it silently. This closes the chain: leaf → intermediate → root, all
//! verified cryptographically via `ring::signature::ECDSA_P384_SHA384`
//! at the root/intermediate tier and `ECDSA_P256_SHA256` at leaves.

use std::sync::OnceLock;
use yaml_rust2::Yaml;

// ─── Bundled Fulcio root + intermediate ─────────────────────────────────────
//
// Sigstore public-good Fulcio v1, fetched from
//   https://github.com/sigstore/root-signing/raw/main/targets/fulcio_v1.crt.pem
//   https://github.com/sigstore/root-signing/raw/main/targets/fulcio_intermediate_v1.crt.pem
// (stored at data/fulcio/{root,intermediate}_v1.pem in the source tree).
//
// Both are P-384 signing certs. The intermediate is cryptographically
// verified against the root at first use; if the check fails, hasp refuses
// to do any chain validation (the intermediate is treated as malformed).
// This closes the v2.2c gap: an attacker who tampers with the bundled
// intermediate but not the root is caught at load time.
//
// Rotation: both certs are valid through 2031-10-05. Rotate by replacing
// the PEM files and shipping a new hasp release.
const FULCIO_ROOT_V1_PEM: &str = include_str!("../../data/fulcio/root_v1.pem");
const FULCIO_INTERMEDIATE_V1_PEM: &str =
    include_str!("../../data/fulcio/intermediate_v1.pem");

fn fulcio_root_der() -> &'static [u8] {
    static DER: OnceLock<Vec<u8>> = OnceLock::new();
    DER.get_or_init(|| pem_to_der(FULCIO_ROOT_V1_PEM).expect("bundled root PEM must decode"))
}

fn fulcio_intermediate_der() -> &'static [u8] {
    static DER: OnceLock<Vec<u8>> = OnceLock::new();
    DER.get_or_init(|| {
        pem_to_der(FULCIO_INTERMEDIATE_V1_PEM).expect("bundled intermediate PEM must decode")
    })
}

/// Returns the bundled intermediate's SPKI + Subject *only if* the
/// intermediate's signature verifies against the bundled root's public key.
/// A mismatch returns `None`, which surfaces as `ChainVerdict::Malformed`
/// to every caller — hasp fails closed rather than trusting a tampered
/// intermediate.
fn fulcio_intermediate_spki() -> Option<&'static FulcioSpki> {
    static SPKI: OnceLock<Option<FulcioSpki>> = OnceLock::new();
    SPKI.get_or_init(load_verified_intermediate).as_ref()
}

fn load_verified_intermediate() -> Option<FulcioSpki> {
    let root_spki = extract_intermediate_spki(fulcio_root_der())?;
    let intermediate_der = fulcio_intermediate_der();
    let (int_tbs, int_sig, int_issuer) = extract_signed_parts(intermediate_der)?;

    // Sigstore's root is self-signed, so the intermediate's issuer DN must
    // match the root's Subject DN byte-for-byte.
    if int_issuer != root_spki.subject {
        eprintln!(
            "hasp: error: bundled Fulcio intermediate issuer DN does not match bundled \
             Fulcio root Subject DN -- intermediate will not be trusted"
        );
        return None;
    }

    let verifier = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P384_SHA384_ASN1,
        &root_spki.point,
    );
    if verifier.verify(&int_tbs, &int_sig).is_err() {
        eprintln!(
            "hasp: error: bundled Fulcio intermediate signature did not verify against \
             bundled Fulcio root -- intermediate will not be trusted"
        );
        return None;
    }

    extract_intermediate_spki(intermediate_der)
}

#[derive(Debug, Clone)]
struct FulcioSpki {
    /// SEC1 uncompressed point, 97 bytes for P-384 (0x04 || X(48) || Y(48))
    point: Vec<u8>,
    /// Signed-name: the cert's Subject DN (for issuer-match on leaf certs).
    subject: Vec<u8>,
}

fn extract_intermediate_spki(der: &[u8]) -> Option<FulcioSpki> {
    let outer = read_tlv(der)?;
    if outer.tag != 0x30 {
        return None;
    }
    let tbs = read_tlv(outer.value)?;
    let items = walk_sequence(tbs.value);
    let version_present = items.first().is_some_and(|t| t.tag == 0xA0);
    let start = usize::from(version_present);
    let subject = items.get(start + 4)?; // issuer, validity, subject
    let spki = items.get(start + 5)?;
    if spki.tag != 0x30 {
        return None;
    }
    let spki_parts = walk_sequence(spki.value);
    let bit = spki_parts.get(1)?;
    if bit.tag != 0x03 || bit.value.len() < 2 || bit.value[0] != 0 {
        return None;
    }
    Some(FulcioSpki {
        point: bit.value[1..].to_vec(),
        subject: subject.value.to_vec(),
    })
}

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut b64 = String::new();
    let mut in_cert = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE") {
            in_cert = true;
        } else if line.starts_with("-----END CERTIFICATE") {
            in_cert = false;
        } else if in_cert {
            b64.push_str(line.trim());
        }
    }
    STANDARD.decode(b64).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignerIdentity {
    pub(crate) subject_uri: Option<String>,
    pub(crate) issuer_cn: Option<String>,
}

impl SignerIdentity {
    /// True when the issuer CN matches one of the strings we expect from
    /// Sigstore's public-good Fulcio CA or a Fulcio-shaped intermediate.
    pub(crate) fn looks_like_fulcio(&self) -> bool {
        self.issuer_cn.as_deref().is_some_and(|cn| {
            let lower = cn.to_ascii_lowercase();
            lower.contains("sigstore") || lower.contains("fulcio")
        })
    }
}

/// Extract signer identity from the first x509 cert of a bundle's
/// verification-material.  Returns `None` if the bundle has no cert chain or
/// parsing fails (malformed DER, unsupported encoding, etc.). Parse errors
/// are swallowed on purpose so the caller can continue to treat presence as
/// a separate signal from verification.
pub(crate) fn extract_identity_from_bundle(bundle: &yaml_rust2::yaml::Hash) -> Option<SignerIdentity> {
    let material = bundle
        .get(&Yaml::String("verificationMaterial".to_string()))?
        .as_hash()?;

    let cert_b64 = first_cert_raw_bytes(material)?;
    let decoded = base64_decode(cert_b64).ok()?;
    parse_cert_identity(&decoded)
}

/// Extract the uncompressed SEC1-encoded ECDSA P-256 public-key point from
/// the first cert's `SubjectPublicKeyInfo`. Returns a 65-byte slice starting
/// with `0x04` (uncompressed marker) followed by X||Y (32+32 bytes).
///
/// Only supports ECDSA P-256 — which is what Fulcio issues for GitHub OIDC
/// certs. Returns `None` for any other curve/algorithm.
pub(crate) fn extract_spki_ec_point_from_bundle(
    bundle: &yaml_rust2::yaml::Hash,
) -> Option<Vec<u8>> {
    let material = bundle
        .get(&Yaml::String("verificationMaterial".to_string()))?
        .as_hash()?;
    let cert_b64 = first_cert_raw_bytes(material)?;
    let decoded = base64_decode(cert_b64).ok()?;
    extract_spki_ec_point(&decoded)
}

/// Chain-verification result for the leaf attestation cert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChainVerdict {
    /// Leaf was signed by the bundled Fulcio intermediate's public key.
    VerifiedAgainstFulcio,
    /// Leaf's issuer doesn't match the bundled intermediate's Subject DN.
    /// This is usually an attestation from a private Fulcio instance.
    IssuerMismatch,
    /// Leaf's issuer matches, but its ECDSA signature didn't verify against
    /// the bundled intermediate's public key. Strongest tampering signal.
    SignatureInvalid,
    /// The bundle carried no cert material, so there's nothing to verify.
    NoMaterial,
    /// Structural failure: we couldn't parse the leaf cert well enough to
    /// extract the tbsCertificate bytes or the signature.
    Malformed(String),
}

/// Verify that the bundle's leaf cert was signed by the bundled Sigstore
/// public-good Fulcio intermediate. This doesn't walk to the root -- it
/// trusts the pinned intermediate directly. An attacker would need
/// Sigstore's intermediate private key to forge a cert that passes.
pub(crate) fn verify_chain_to_fulcio(
    bundle: &yaml_rust2::yaml::Hash,
) -> ChainVerdict {
    let Some(material) = bundle
        .get(&Yaml::String("verificationMaterial".to_string()))
        .and_then(Yaml::as_hash)
    else {
        return ChainVerdict::NoMaterial;
    };
    let Some(cert_b64) = first_cert_raw_bytes(material) else {
        return ChainVerdict::NoMaterial;
    };
    let Ok(leaf_der) = base64_decode(cert_b64) else {
        return ChainVerdict::Malformed("leaf cert base64 decode failed".into());
    };
    let Some(intermediate_spki) = fulcio_intermediate_spki() else {
        return ChainVerdict::Malformed(
            "bundled Fulcio intermediate could not be parsed".into(),
        );
    };

    let Some((tbs_bytes, sig_bytes, leaf_issuer)) = extract_signed_parts(&leaf_der) else {
        return ChainVerdict::Malformed("failed to parse leaf cert".into());
    };

    if leaf_issuer != intermediate_spki.subject {
        return ChainVerdict::IssuerMismatch;
    }

    // Fulcio intermediate uses P-384; leaf certs it issues are signed with
    // ECDSA_P384_SHA384.
    let verifier = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P384_SHA384_ASN1,
        &intermediate_spki.point,
    );
    match verifier.verify(&tbs_bytes, &sig_bytes) {
        Ok(()) => ChainVerdict::VerifiedAgainstFulcio,
        Err(_) => ChainVerdict::SignatureInvalid,
    }
}

/// Extract (tbsCertificate bytes, signatureValue bytes, issuer DN bytes) from a DER cert.
fn extract_signed_parts(cert_der: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let outer = read_tlv(cert_der)?;
    if outer.tag != 0x30 {
        return None;
    }
    // Within the outer SEQUENCE value, walk children: tbsCertificate,
    // signatureAlgorithm, signatureValue. We need the tbsCertificate's full
    // DER bytes (tag + length + value), which is the slice read_tlv
    // consumed.
    let mut cursor = outer.value;
    let tbs = read_tlv(cursor)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let tbs_bytes = cursor[..tbs.consumed].to_vec();
    cursor = &cursor[tbs.consumed..];

    // Skip signatureAlgorithm.
    let sig_alg = read_tlv(cursor)?;
    cursor = &cursor[sig_alg.consumed..];

    // signatureValue: BIT STRING; skip the first byte (unused-bits count).
    let sig_value = read_tlv(cursor)?;
    if sig_value.tag != 0x03 || sig_value.value.is_empty() {
        return None;
    }
    let sig_bytes = sig_value.value[1..].to_vec();

    // Extract issuer DN from tbsCertificate (for matching against bundled
    // intermediate's Subject).
    let tbs_items = walk_sequence(tbs.value);
    let version_present = tbs_items.first().is_some_and(|t| t.tag == 0xA0);
    let issuer_idx = if version_present { 3 } else { 2 };
    let issuer = tbs_items.get(issuer_idx)?;
    Some((tbs_bytes, sig_bytes, issuer.value.to_vec()))
}

/// Pull `SubjectPublicKeyInfo.subjectPublicKey` bytes out of a cert's DER.
/// Expects EC P-256 (ecPublicKey OID 1.2.840.10045.2.1 + prime256v1 OID
/// 1.2.840.10045.3.1.7) and the uncompressed SEC1 form (prefix byte `0x04`).
pub(crate) fn extract_spki_ec_point(der: &[u8]) -> Option<Vec<u8>> {
    let outer = read_tlv(der)?;
    if outer.tag != 0x30 {
        return None;
    }
    let tbs = read_tlv(outer.value)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let items = walk_sequence(tbs.value);
    // After optional [0] version: serial, sigAlg, issuer, validity, subject,
    // SPKI — so SPKI is at index 6 with version present, 5 without.
    let version_present = items.first().is_some_and(|t| t.tag == 0xA0);
    let spki_idx = if version_present { 6 } else { 5 };
    let spki = items.get(spki_idx)?;
    if spki.tag != 0x30 {
        return None;
    }
    let spki_parts = walk_sequence(spki.value);
    let alg = spki_parts.first()?;
    let pubkey_bitstring = spki_parts.get(1)?;
    if pubkey_bitstring.tag != 0x03 {
        return None;
    }
    if !algorithm_is_ecdsa_p256(alg) {
        return None;
    }
    // BIT STRING: first byte is unused-bits count (must be 0 for byte-aligned
    // EC points), remainder is the raw SEC1 uncompressed point.
    let bits = pubkey_bitstring.value;
    if bits.len() < 2 || bits[0] != 0 {
        return None;
    }
    let point = &bits[1..];
    // Uncompressed P-256 point is 65 bytes starting with 0x04.
    if point.len() != 65 || point[0] != 0x04 {
        return None;
    }
    Some(point.to_vec())
}

/// Accepts the two well-formed DER shapes for an EC P-256 `AlgorithmIdentifier`:
///   * `SEQUENCE { OID ecPublicKey, OID prime256v1 }`
///   * `SEQUENCE { OID ecPublicKey }` (parameter elided — rare but valid)
fn algorithm_is_ecdsa_p256(alg: &Tlv<'_>) -> bool {
    if alg.tag != 0x30 {
        return false;
    }
    let parts = walk_sequence(alg.value);
    let Some(oid) = parts.first() else {
        return false;
    };
    // ecPublicKey = 1.2.840.10045.2.1 -> 2A 86 48 CE 3D 02 01
    if oid.tag != 0x06 || oid.value != [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] {
        return false;
    }
    if let Some(params) = parts.get(1) {
        // prime256v1 = 1.2.840.10045.3.1.7 -> 2A 86 48 CE 3D 03 01 07
        if params.tag != 0x06
            || params.value != [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        {
            return false;
        }
    }
    true
}

fn first_cert_raw_bytes(material: &yaml_rust2::yaml::Hash) -> Option<&str> {
    // GitHub's bundle supports two encodings depending on protobuf vs JSON
    // emission: the modern one nests certificates under x509CertificateChain,
    // the older single-cert form uses `certificate`.
    if let Some(chain) = material
        .get(&Yaml::String("x509CertificateChain".to_string()))
        .and_then(Yaml::as_hash)
        && let Some(certs) = chain
            .get(&Yaml::String("certificates".to_string()))
            .and_then(Yaml::as_vec)
        && let Some(first) = certs.first()
        && let Some(first_map) = first.as_hash()
        && let Some(raw) = first_map
            .get(&Yaml::String("rawBytes".to_string()))
            .and_then(Yaml::as_str)
    {
        return Some(raw);
    }
    if let Some(cert) = material
        .get(&Yaml::String("certificate".to_string()))
        .and_then(Yaml::as_hash)
        && let Some(raw) = cert
            .get(&Yaml::String("rawBytes".to_string()))
            .and_then(Yaml::as_str)
    {
        return Some(raw);
    }
    None
}

fn base64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD
        .decode(s.trim())
        .or_else(|_| {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            URL_SAFE_NO_PAD.decode(s.trim())
        })
        .map_err(|_| "base64 decode failed")
}

// ─── Minimal DER walking ────────────────────────────────────────────────────
//
// We walk just enough of the certificate structure to reach the fields we
// care about. No full ASN.1 library -- just length-prefixed TLV traversal.

#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    /// Bytes consumed from the parent buffer (tag + length + value).
    consumed: usize,
}

fn read_tlv(buf: &[u8]) -> Option<Tlv<'_>> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let first_len = buf[1];
    let (len, len_bytes_used) = if first_len & 0x80 == 0 {
        (first_len as usize, 1)
    } else {
        let n = (first_len & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let mut acc: usize = 0;
        for i in 0..n {
            acc = acc.checked_shl(8)?;
            acc = acc.checked_add(buf[2 + i] as usize)?;
        }
        (acc, 1 + n)
    };
    let header = 1 + len_bytes_used;
    if buf.len() < header + len {
        return None;
    }
    Some(Tlv {
        tag,
        value: &buf[header..header + len],
        consumed: header + len,
    })
}

fn walk_sequence(seq_value: &[u8]) -> Vec<Tlv<'_>> {
    let mut items = Vec::new();
    let mut cursor = seq_value;
    while !cursor.is_empty() {
        let Some(tlv) = read_tlv(cursor) else { break };
        items.push(tlv);
        cursor = &cursor[tlv.consumed..];
    }
    items
}

/// Parse an x509 certificate's DER and extract signer identity fields.
fn parse_cert_identity(der: &[u8]) -> Option<SignerIdentity> {
    // Certificate  ::= SEQUENCE {
    //   tbsCertificate       TBSCertificate,
    //   signatureAlgorithm   AlgorithmIdentifier,
    //   signatureValue       BIT STRING
    // }
    let outer = read_tlv(der)?;
    if outer.tag != 0x30 {
        return None;
    }
    let tbs = read_tlv(outer.value)?;
    if tbs.tag != 0x30 {
        return None;
    }

    // TBSCertificate fields, in order:
    //   [0] version (optional, EXPLICIT context-specific 0)
    //   INTEGER serialNumber
    //   AlgorithmIdentifier signature
    //   Name issuer
    //   Validity validity
    //   Name subject
    //   SubjectPublicKeyInfo
    //   [1] issuerUniqueID (optional)
    //   [2] subjectUniqueID (optional)
    //   [3] Extensions (optional, EXPLICIT)
    let items = walk_sequence(tbs.value);
    // Skip optional version tag [0] EXPLICIT.
    let mut idx: usize = usize::from(items.first().is_some_and(|t| t.tag == 0xA0));
    let _serial = items.get(idx)?;
    idx += 1; // serial
    idx += 1; // signature AlgorithmIdentifier
    let issuer_name = items.get(idx)?;
    idx += 1;
    idx += 1; // validity
    let _subject_name = items.get(idx)?;
    idx += 1;
    idx += 1; // SubjectPublicKeyInfo

    // Extensions may appear in [3] EXPLICIT.
    let mut extensions_tlv: Option<Tlv<'_>> = None;
    for tlv in items.iter().skip(idx) {
        if tlv.tag == 0xA3 {
            extensions_tlv = Some(*tlv);
            break;
        }
    }

    let issuer_cn = extract_common_name(issuer_name.value);
    let subject_uri = extensions_tlv
        .and_then(|wrapper| read_tlv(wrapper.value))
        .filter(|inner| inner.tag == 0x30)
        .and_then(|inner| extract_subject_alt_name_uri(inner.value));

    Some(SignerIdentity {
        subject_uri,
        issuer_cn,
    })
}

/// Walk RDNs of a Name to find commonName (OID 2.5.4.3 = 0x55 0x04 0x03).
fn extract_common_name(name_value: &[u8]) -> Option<String> {
    for rdn in walk_sequence(name_value) {
        if rdn.tag != 0x31 {
            continue;
        }
        for attr in walk_sequence(rdn.value) {
            if attr.tag != 0x30 {
                continue;
            }
            let attr_parts = walk_sequence(attr.value);
            let oid = attr_parts.first()?;
            if oid.tag != 0x06 || oid.value != [0x55, 0x04, 0x03] {
                continue;
            }
            let value = attr_parts.get(1)?;
            return der_string_to_utf8(value.tag, value.value);
        }
    }
    None
}

/// Walk Extensions to find `SubjectAlternativeName` (OID 2.5.29.17) and pull
/// the first `GeneralName` of kind URI (tag 0x86).
fn extract_subject_alt_name_uri(extensions_value: &[u8]) -> Option<String> {
    for ext in walk_sequence(extensions_value) {
        if ext.tag != 0x30 {
            continue;
        }
        let parts = walk_sequence(ext.value);
        let oid = parts.first()?;
        if oid.tag != 0x06 {
            continue;
        }
        // 2.5.29.17 encoded: 0x55 0x1D 0x11
        if oid.value != [0x55, 0x1D, 0x11] {
            continue;
        }
        // Extension value is an OCTET STRING whose contents are the SAN SEQUENCE.
        for part in parts.iter().skip(1) {
            if part.tag == 0x04 {
                let inner = read_tlv(part.value)?;
                if inner.tag != 0x30 {
                    return None;
                }
                for name in walk_sequence(inner.value) {
                    // uniformResourceIdentifier = [6] IA5String (implicit) -> tag 0x86.
                    if name.tag == 0x86 {
                        return std::str::from_utf8(name.value)
                            .ok()
                            .map(str::to_string);
                    }
                }
                return None;
            }
            // Extension's `critical TRUE` (BOOLEAN) precedes the OCTET
            // STRING; loop continues past it naturally.
        }
    }
    None
}

fn der_string_to_utf8(tag: u8, value: &[u8]) -> Option<String> {
    // Accept the usual string tags: PrintableString (0x13), UTF8String (0x0C),
    // IA5String (0x16), TeletexString (0x14), BMPString (0x1E) -- simplest
    // cases treat bytes as ASCII/UTF8; BMPString would need UTF-16 decoding
    // but Fulcio CAs don't use it.
    match tag {
        0x0C | 0x13 | 0x14 | 0x16 => String::from_utf8(value.to_vec()).ok(),
        _ => None,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn identity_looks_like_fulcio_matches_sigstore_cn() {
        let id = SignerIdentity {
            subject_uri: Some("https://github.com/a/b/.github/workflows/build.yml@refs/tags/v1".into()),
            issuer_cn: Some("sigstore-intermediate".into()),
        };
        assert!(id.looks_like_fulcio());
    }

    #[test]
    fn identity_does_not_look_like_fulcio_for_other_ca() {
        let id = SignerIdentity {
            subject_uri: None,
            issuer_cn: Some("DigiCert Inc".into()),
        };
        assert!(!id.looks_like_fulcio());
    }

    #[test]
    fn read_tlv_parses_short_length() {
        let buf = [0x30_u8, 0x03, 0x01, 0x02, 0x03];
        let tlv = read_tlv(&buf).unwrap();
        assert_eq!(tlv.tag, 0x30);
        assert_eq!(tlv.value, &[0x01, 0x02, 0x03]);
        assert_eq!(tlv.consumed, 5);
    }

    #[test]
    fn read_tlv_parses_long_length() {
        // Length encoded as 2 bytes: 0x81 0xC8 means "one byte length = 0xC8 = 200"
        let mut buf = vec![0x30, 0x81, 0xC8];
        buf.extend(std::iter::repeat_n(0xFF, 200));
        let tlv = read_tlv(&buf).unwrap();
        assert_eq!(tlv.tag, 0x30);
        assert_eq!(tlv.value.len(), 200);
        assert_eq!(tlv.consumed, 203);
    }

    #[test]
    fn read_tlv_rejects_truncated() {
        assert!(read_tlv(&[0x30, 0x05, 0x01, 0x02]).is_none());
        assert!(read_tlv(&[0x30]).is_none());
    }

    #[test]
    fn extract_common_name_handles_rdn_sequence() {
        // Build a minimal Name with one RDN containing CN=hello
        // Name -> RDNSequence -> SET -> SEQUENCE { OID, PrintableString }
        //   "hello" = 68 65 6c 6c 6f (5 bytes)
        // AttributeTypeAndValue:
        //   OID 2.5.4.3 = 0x55 0x04 0x03 -> TLV: 06 03 55 04 03
        //   value PrintableString "hello" -> TLV: 13 05 68 65 6c 6c 6f
        //   attr SEQUENCE: 30 0C <oid><value>
        //   RDN SET: 31 0E 30 0C <oid><value>
        //   RDNSequence SEQ: 30 10 31 0E 30 0C <oid><value>
        let name_value = vec![
            0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x05, 0x68, 0x65, 0x6c,
            0x6c, 0x6f,
        ];
        assert_eq!(extract_common_name(&name_value).as_deref(), Some("hello"));
    }

    #[test]
    fn extract_common_name_returns_none_when_no_cn() {
        // Empty Name value
        assert!(extract_common_name(&[]).is_none());
    }

    #[test]
    fn first_cert_raw_bytes_prefers_x509_chain_shape() {
        // Build a YAML hash matching the modern GitHub bundle shape.
        let yaml = r#"{
          "x509CertificateChain": {
            "certificates": [
              {"rawBytes": "AAAA"},
              {"rawBytes": "BBBB"}
            ]
          },
          "certificate": {"rawBytes": "CCCC"}
        }"#;
        let doc = yaml_rust2::YamlLoader::load_from_str(yaml).unwrap().remove(0);
        let material = doc.as_hash().unwrap();
        assert_eq!(first_cert_raw_bytes(material), Some("AAAA"));
    }

    #[test]
    fn first_cert_raw_bytes_falls_back_to_single_certificate() {
        let yaml = r#"{"certificate": {"rawBytes": "SINGLE"}}"#;
        let doc = yaml_rust2::YamlLoader::load_from_str(yaml).unwrap().remove(0);
        let material = doc.as_hash().unwrap();
        assert_eq!(first_cert_raw_bytes(material), Some("SINGLE"));
    }

    #[test]
    fn first_cert_raw_bytes_returns_none_for_empty_chain() {
        let yaml = r#"{"x509CertificateChain": {"certificates": []}}"#;
        let doc = yaml_rust2::YamlLoader::load_from_str(yaml).unwrap().remove(0);
        let material = doc.as_hash().unwrap();
        assert!(first_cert_raw_bytes(material).is_none());
    }

    #[test]
    fn extract_identity_from_bundle_returns_none_without_cert() {
        let yaml = r#"{"verificationMaterial": {}}"#;
        let doc = yaml_rust2::YamlLoader::load_from_str(yaml).unwrap().remove(0);
        let map = doc.as_hash().unwrap();
        assert!(extract_identity_from_bundle(map).is_none());
    }

    #[test]
    fn bundled_fulcio_intermediate_parses_and_has_p384_spki() {
        let spki = fulcio_intermediate_spki().expect("bundled PEM should parse");
        // P-384 SEC1 uncompressed: 0x04 || X(48) || Y(48) = 97 bytes
        assert_eq!(spki.point.len(), 97);
        assert_eq!(spki.point[0], 0x04);
        assert!(!spki.subject.is_empty());
    }

    #[test]
    fn bundled_root_is_self_signed_and_p384() {
        let der = fulcio_root_der();
        assert!(!der.is_empty(), "bundled root PEM must decode");
        let spki = extract_intermediate_spki(der).expect("bundled root SPKI must parse");
        assert_eq!(spki.point.len(), 97, "root pubkey is P-384");
        assert_eq!(spki.point[0], 0x04);
        // Self-signed: issuer DN == subject DN + signature verifies against
        // own pubkey (i.e. the root is its own trust anchor).
        let (tbs, sig, issuer) = extract_signed_parts(der).expect("root should parse");
        assert_eq!(issuer, spki.subject, "root issuer DN == subject DN");
        let verifier = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P384_SHA384_ASN1,
            &spki.point,
        );
        verifier
            .verify(&tbs, &sig)
            .expect("root must be self-signed");
    }

    #[test]
    fn intermediate_verifies_against_bundled_root() {
        // This is the v2.2c end-to-end assertion: the bundled intermediate
        // must cryptographically chain to the bundled root. If this fails,
        // `fulcio_intermediate_spki()` returns None and every call to
        // `verify_chain_to_fulcio` surfaces Malformed.
        let loaded = load_verified_intermediate();
        assert!(
            loaded.is_some(),
            "bundled intermediate must verify against bundled root"
        );
    }

    #[test]
    fn chain_verify_returns_no_material_for_empty_bundle() {
        let yaml = "{}";
        let doc = yaml_rust2::YamlLoader::load_from_str(yaml).unwrap().remove(0);
        let map = doc.as_hash().unwrap();
        assert_eq!(verify_chain_to_fulcio(map), ChainVerdict::NoMaterial);
    }

    #[test]
    fn chain_verify_rejects_synthetic_non_fulcio_cert() {
        // Build a synthetic cert (issuer CN "sigstore-intermediate" — a naming
        // spoof) and verify_chain_to_fulcio rejects it because the DN bytes
        // don't match the real bundled intermediate.
        use base64::{Engine, engine::general_purpose::STANDARD};
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
        let issuer = rdn_cn("sigstore-intermediate"); // naming-only spoof
        let subject = rdn_cn("ignored");
        let utc1 = tlv(0x17, b"250101000000Z");
        let utc2 = tlv(0x17, b"260101000000Z");
        let validity = seq(&[&utc1, &utc2]);
        let alg_oid = tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
        let alg_params = tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
        let alg = seq(&[&alg_oid, &alg_params]);
        let bit_string_bytes: Vec<u8> = std::iter::once(0_u8)
            .chain(std::iter::once(0x04))
            .chain(std::iter::repeat_n(0x01_u8, 64))
            .collect();
        let bitstr = tlv(0x03, &bit_string_bytes);
        let spki = seq(&[&alg, &bitstr]);
        let version = tlv(0xA0, &tlv(0x02, &[0x02]));
        let serial = tlv(0x02, &[0x01]);
        let sig_alg = seq(&[&alg_oid, &alg_params]);
        let tbs = seq(&[&version, &serial, &sig_alg, &issuer, &validity, &subject, &spki]);
        let sig_alg_outer = seq(&[&alg_oid, &alg_params]);
        let sig_value = tlv(0x03, &[0x00, 0xAA]);
        let cert = seq(&[&tbs, &sig_alg_outer, &sig_value]);
        let cert_b64 = STANDARD.encode(&cert);

        let yaml = format!(
            r#"{{"verificationMaterial":{{"certificate":{{"rawBytes":"{cert_b64}"}}}}}}"#
        );
        let doc = yaml_rust2::YamlLoader::load_from_str(&yaml).unwrap().remove(0);
        let map = doc.as_hash().unwrap();

        // The synthetic cert's issuer DN is "sigstore-intermediate" but the
        // real bundled Fulcio intermediate's Subject DN is
        // "sigstore.dev / sigstore-intermediate" (two RDNs). Byte comparison
        // fails -> IssuerMismatch.
        assert_eq!(verify_chain_to_fulcio(map), ChainVerdict::IssuerMismatch);
    }

    #[test]
    fn parse_cert_identity_extracts_issuer_and_san_uri() {
        // Build a minimal x509 cert DER with:
        //   issuer CN = "sigstore-intermediate"
        //   subject CN = "placeholder"
        //   SAN URI = "https://github.com/a/b/.github/workflows/x.yml@refs/heads/main"

        // Helper: ASN.1 SEQUENCE with two or more child TLVs.
        fn seq(children: &[&[u8]]) -> Vec<u8> {
            let inner: Vec<u8> = children.iter().flat_map(|c| c.iter().copied()).collect();
            tlv(0x30, &inner)
        }

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

        fn rdn_cn(cn: &str) -> Vec<u8> {
            // AttributeTypeAndValue
            let oid = tlv(0x06, &[0x55, 0x04, 0x03]);
            let value = tlv(0x13, cn.as_bytes()); // PrintableString
            let attr = seq(&[&oid, &value]);
            // RDN is a SET
            let rdn = tlv(0x31, &attr);
            // RDNSequence is a SEQUENCE of RDNs
            seq(&[&rdn])
        }

        let issuer = rdn_cn("sigstore-intermediate");
        let subject = rdn_cn("placeholder");

        // Validity = SEQ{ UTCTime, UTCTime } — minimal placeholder.
        let utc1 = tlv(0x17, b"250101000000Z");
        let utc2 = tlv(0x17, b"260101000000Z");
        let validity = seq(&[&utc1, &utc2]);

        // SPKI = SEQ{ AlgorithmIdentifier, BIT STRING }
        let alg_oid = tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]); // ecPublicKey
        let alg_params = tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
        let alg = seq(&[&alg_oid, &alg_params]);
        let bitstr = tlv(0x03, &[0x00, 0x04, 0x00, 0x00]); // unused-bits byte + point
        let spki = seq(&[&alg, &bitstr]);

        // Extensions: [3] EXPLICIT SEQ OF Extension
        // Extension: SEQ{ OID 2.5.29.17, OCTET STRING containing GeneralNames SEQ{ [6] URI } }
        let san_uri = "https://github.com/a/b/.github/workflows/x.yml@refs/heads/main";
        let uri_name = tlv(0x86, san_uri.as_bytes());
        let general_names = seq(&[&uri_name]);
        let octet = tlv(0x04, &general_names);
        let san_oid = tlv(0x06, &[0x55, 0x1D, 0x11]);
        let san_ext = seq(&[&san_oid, &octet]);
        let exts = seq(&[&san_ext]);
        let exts_wrapper = tlv(0xA3, &exts);

        // version [0] EXPLICIT INTEGER v3
        let version_inner = tlv(0x02, &[0x02]); // v3
        let version = tlv(0xA0, &version_inner);
        // serial INTEGER 1
        let serial = tlv(0x02, &[0x01]);
        // signature AlgorithmIdentifier (same structural shape as SPKI alg)
        let sig_alg = seq(&[&alg_oid, &alg_params]);

        let tbs = seq(&[
            &version, &serial, &sig_alg, &issuer, &validity, &subject, &spki, &exts_wrapper,
        ]);
        // Outer: SEQ{ TBS, sigAlg, sigValue }
        let outer_sig_alg = seq(&[&alg_oid, &alg_params]);
        let outer_sig_value = tlv(0x03, &[0x00, 0xAA]); // bogus signature
        let cert = seq(&[&tbs, &outer_sig_alg, &outer_sig_value]);

        let identity = parse_cert_identity(&cert).expect("cert should parse");
        assert_eq!(identity.issuer_cn.as_deref(), Some("sigstore-intermediate"));
        assert_eq!(identity.subject_uri.as_deref(), Some(san_uri));
        assert!(identity.looks_like_fulcio());
    }
}
