# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | Yes       |

Only the latest release receives security updates.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report vulnerabilities through
[GitHub Security Advisories](https://github.com/electricapp/hasp/security/advisories/new).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity, but critical issues will be
  prioritized

### Scope

The following are in scope:

- Bypass of sandbox confinement (Landlock, seccomp, network egress)
- Token or secret exfiltration from the subprocess architecture
- YAML parsing bugs that could lead to code execution
- TLS/certificate pinning bypass in `--self-check` or API calls
- Supply chain issues in dependencies

The following are out of scope:

- Issues that require `--allow-unsandboxed` (this flag explicitly disables
  protections)
- Denial of service via crafted YAML (hasp processes local files only)

## Verification

See [TRUST.md](TRUST.md) for binary verification, Sigstore signatures, SLSA
provenance, and reproducible build instructions.

## Known limitations

These are shipped gaps -- hasp documents them so users can calibrate trust,
not silently accept less than the surface-level feature name suggests.

### SLSA attestation check (`provenance.slsa-attestation`)

What hasp does today:

- Fetches the GitHub attestation bundle for a pinned SHA
- Decodes the DSSE envelope's base64 payload
- Parses the in-toto Statement and validates `predicateType` is a SLSA
  provenance version (v0.2 or v1)
- Confirms a subject digest binds to the pinned SHA
- Extracts `builder.id` and checks it against a trusted prefix list
  (GitHub-hosted runners)
- Walks the attestation cert's DER (v2.1) to extract the Fulcio-signed
  SubjectAlternativeName URI (workflow identity) and issuer Common Name

What hasp **does** do as of v2.2c:

- **DSSE signature verification** (`ECDSA_P256_SHA256`) against the cert's
  `SubjectPublicKeyInfo` via `ring`. A tampered payload yields
  `AttestationVerdict::SignatureInvalid` and a CRIT finding.
- **Leaf-to-intermediate cert-chain validation.** Each attestation's
  leaf cert is verified by byte-comparing its issuer DN to the bundled
  intermediate's Subject DN, then cryptographically verifying its
  `ECDSA_P384_SHA384` signature against the bundled intermediate's
  public key. A leaf that fails either check yields
  `AttestationVerdict::ChainInvalid` and a CRIT finding.
- **Intermediate-to-root chain validation.** At first use, the bundled
  intermediate (`data/fulcio/intermediate_v1.pem`) is verified against
  the bundled Fulcio root (`data/fulcio/root_v1.pem`). A tampered
  intermediate is caught here: hasp falls back to `Malformed` for every
  attestation check rather than trusting a potentially-substituted
  intermediate. The chain is thus fully validated cryptographically:
  leaf → intermediate → root.

What's still out of scope:

- **Rotation.** Both bundled certs are valid through 2031-10-05.
  Rotation before then requires replacing the PEM files under
  `data/fulcio/` and shipping a new hasp release.
- **Private Fulcio instances.** Organizations running their own Fulcio
  CA will see `ChainInvalid` findings. A trust-list extension for
  private-instance CAs would go in `.hasp.yml` — no current mechanism.
- **TUF root-of-trust rotation.** hasp does not consume Sigstore's TUF
  repository; the bundled root is a point-in-time pin. If Sigstore
  rotates the root CA (unplanned event), hasp needs a release to pick
  up the new root PEM.

### Sandboxed `hasp diff` sandbox assertion

`hasp diff` spawns two `hasp --internal-scan` subprocesses, each of
which applies Landlock / seccomp / BPF on supported kernels. The
integration tests assert the delta output is correct but do **not**
assert the sandbox itself was applied (that would need Linux-specific
procfs introspection or a sandbox-bypass canary).

A sandbox-escape bug could silently revert `hasp diff` to the inline
behavior it had before commit `854e805`. Users relying on `hasp diff`
for hardened scans should run with `--paranoid` + `--no-allow-unsandboxed`
and check `hasp: warning: os-level sandbox unavailable` is absent from
stderr.
