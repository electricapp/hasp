# Trust Verification Guide

There is a circular trust problem: you need to trust hasp before running it
in GitHub Actions, but you're using it *because* you don't fully trust GitHub
Actions. This document explains every mechanism available for you to
independently verify the tool — pick your paranoia level.

## Verification Ladder

From least to most effort. Each level builds on the previous.

### Level 1: SHA256 Checksum

**What it proves**: The binary you downloaded matches the binary the maintainers
published.

**What it doesn't prove**: That the published binary was built from the claimed
source code.

```bash
# Download binary + checksum
VERSION="v0.1.0"
curl -fsSL "https://github.com/electricapp/hasp/releases/download/${VERSION}/hasp-linux-amd64" -o hasp
curl -fsSL "https://github.com/electricapp/hasp/releases/download/${VERSION}/hasp-linux-amd64.sha256" -o hasp.sha256

# Verify
sha256sum --check --strict hasp.sha256
```

Or use the built-in self-check (verifies against published hash with TLS
certificate pinning):

```bash
./hasp --self-check
```

### Level 2: Sigstore Cosign Signature

**What it proves**: The binary was produced by a specific GitHub Actions workflow
in the `electricapp/hasp` repository, using GitHub's OIDC identity. No private
keys are involved — the signature is tied to the CI workflow identity.

**What it doesn't prove**: Which source commit was used, or that the workflow
wasn't modified.

```bash
# Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/
cosign verify-blob \
  --signature "https://github.com/electricapp/hasp/releases/download/${VERSION}/hasp-linux-amd64.sig" \
  --certificate "https://github.com/electricapp/hasp/releases/download/${VERSION}/hasp-linux-amd64.pem" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  hasp
```

### Level 3: SLSA Build Provenance

**What it proves**: Which exact commit, which workflow file, which inputs, and
which runner produced the binary. This is a signed, tamper-evident attestation
stored in GitHub's attestation ledger.

**What it doesn't prove**: That the source code is safe (you still need to read
it).

```bash
# Requires gh CLI with attestation extension
gh attestation verify hasp-linux-amd64 --repo electricapp/hasp
```

### Level 4: Reproducible Build

**What it proves**: The published binary is a deterministic product of the
published source code. You build from source in an identical environment and
compare hashes.

```bash
git clone https://github.com/electricapp/hasp.git
cd hasp
git checkout "${VERSION}"

# Build using the reproducible Dockerfile (pinned Rust version, SOURCE_DATE_EPOCH,
# deterministic path remapping)
docker build -f Dockerfile.reproduce \
  --build-arg GITHUB_REPO=electricapp/hasp \
  --output=. .

# Compare with published hash
sha256sum hasp
cat hasp.sha256
```

### Level 5: Source Audit

**What it proves**: You've read the code and understand what it does.

The codebase is ~12k lines of Rust across 25 source files with minimal
dependencies. Start with:

- `src/main.rs` — Entrypoint, subprocess architecture, sandbox orchestration
- `src/scanner.rs` — YAML parsing, `uses:` extraction, container detection
- `src/audit/` — Security audit rules: injection, permissions, triggers, supply chain
- `src/github/` — GitHub API client, SHA verification, provenance checks, transitive scan
- `src/policy/` — `.hasp.yml` policy loading, per-action resolution, suppressions
- `src/sandbox.rs` — Landlock filesystem + seccomp-BPF syscall sandboxing

## What Each Mechanism Proves

| Mechanism    | Integrity | Provenance | Reproducibility | Code Safety |
| ------------ | --------- | ---------- | --------------- | ----------- |
| SHA256       | Yes       | No         | No              | No          |
| Sigstore     | Yes       | Partial    | No              | No          |
| SLSA         | Yes       | Yes        | No              | No          |
| Repro Build  | Yes       | Yes        | Yes             | No          |
| Source Audit | Yes       | Yes        | Yes             | Yes         |

## Dependency Inventory

The hasp binary uses 10 direct crate dependencies by design (8 cross-platform + 2 Linux-only):

| Crate          | Purpose            | Notes                                          |
| -------------- | ------------------ | ---------------------------------------------- |
| `yaml-rust2`   | YAML parsing       | Pure Rust, no serde                            |
| `ureq`         | HTTP client        | Blocking, no async runtime                     |
| `rustls`       | TLS                | Pure Rust, used for certificate pinning        |
| `webpki-roots` | Root CAs           | Compiled-in Mozilla CA bundle                  |
| `sha1`         | SHA-1              | Git blob hashing for workflow integrity checks |
| `sha2`         | SHA-256            | For `--self-check` binary verification         |
| `base64`       | Base64 decode      | For Sigstore certificate parsing               |
| `mimalloc`     | Hardened allocator | Only C dependency (intentional)                |

Linux-only: `landlock` + `libc` for OS-level sandboxing.

Zero proc macros or async runtimes and one intentional C dependency.

## Self-Hosting

hasp's own CI pipeline runs hasp against itself. The `security.yml`
workflow builds from source and scans `.github/workflows/` — if the release
pipeline has issues, hasp catches them. See
`.github/workflows/security.yml` for the self-scan job.

## SBOM

Every release includes an SPDX SBOM (`*.spdx.json`) listing all transitive
dependencies. Download it from the GitHub Release assets:

```bash
curl -fsSL "https://github.com/electricapp/hasp/releases/download/${VERSION}/hasp-linux-amd64.spdx.json" | jq .
```
