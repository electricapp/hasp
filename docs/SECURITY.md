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

What hasp **does not** do yet:

- **DSSE signature verification.** The envelope's `signatures` array is
  not verified cryptographically against the cert's EC public key. A
  tampered payload + signature pair would not be caught today.
- **Cert-chain validation to Fulcio root.** Issuer identity is a string
  match on the CN (e.g. contains `sigstore` or `fulcio`), not a
  rustls-webpki chain build. A self-signed cert with CN
  `sigstore-intermediate` would pass `looks_like_fulcio`.

Both gaps are tracked with `TODO(v2.2)` comments in
`src/github/sigstore.rs`. Closing them requires adding `ring` and
`rustls-webpki` as direct dependencies (both are already transitive via
`rustls`) plus ~500 lines of cert-chain and DSSE-PAE plumbing.

### Tree online signals (`hasp tree`)

The `collect_online_signals` path in `src/supply_chain_graph.rs`
calls the real GitHub API when `GITHUB_TOKEN` is set. It has unit tests
for the scoring logic but no hermetic test for the API collection
itself — that requires either a live token (non-reproducible in CI) or
a mock `Api` trait fixture.

Tracked with a `TODO(v2.7)` comment; the `MockApi` pattern in
`src/github/provenance.rs` tests is the template for closing this.

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
