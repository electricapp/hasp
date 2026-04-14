# Build, Verify & Reproduce

Step-by-step guide for building hasp from source, verifying a downloaded
binary, reproducing a release, and integrating into CI.

## Prerequisites

| Tool     | Version | Purpose                                    |
| -------- | ------- | ------------------------------------------ |
| Rust     | 1.94.0+ | Build from source                          |
| Docker   | 20+     | Reproducible builds                        |
| `cosign` | 2.x     | Sigstore signature verification (optional) |
| `gh`     | 2.x     | SLSA provenance verification (optional)    |

## 1. Build from Source

```bash
git clone https://github.com/OWNER/hasp.git
cd hasp

# Development build
cargo build

# Release build (optimized, stripped)
cargo build --release

# Run tests
cargo test

# The binary is at target/release/hasp
./target/release/hasp --version
```

### Cross-compile for Linux (from macOS or other hosts)

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl
```

## 2. Verify a Downloaded Binary

Pick your paranoia level. Each level builds on the previous.

### Level 1: SHA256 checksum

Proves the binary matches what was published. Takes 10 seconds.

```bash
VERSION="v0.1.0"
REPO="OWNER/hasp"

curl -fsSL "https://github.com/${REPO}/releases/download/${VERSION}/hasp-linux-amd64" -o hasp
curl -fsSL "https://github.com/${REPO}/releases/download/${VERSION}/hasp-linux-amd64.sha256" -o hasp.sha256

sha256sum --check --strict hasp.sha256
chmod +x hasp
```

Or use the built-in self-check (fetches the hash over TLS with certificate
pinning to GitHub):

```bash
./hasp --self-check
```

### Level 2: Sigstore signature

Proves the binary was produced by a specific GitHub Actions workflow, not
someone's laptop. No private keys involved -- the signature is tied to the
CI workflow's OIDC identity.

```bash
cosign verify-blob \
  --signature "https://github.com/${REPO}/releases/download/${VERSION}/hasp-linux-amd64.sig" \
  --certificate "https://github.com/${REPO}/releases/download/${VERSION}/hasp-linux-amd64.pem" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  hasp
```

### Level 3: SLSA build provenance

Proves which exact commit, workflow file, and runner produced the binary.
Signed attestation stored in GitHub's attestation ledger.

```bash
gh attestation verify hasp --repo "${REPO}"
```

### Level 4: Reproducible build

Proves the published binary is a deterministic product of the published
source. You build it yourself and compare hashes. See section 3 below.

### Level 5: Source audit

Read the code. The codebase is 10-20k lines of Rust across 25 source files
with minimal dependencies. Start with `src/main.rs` (entrypoint and subprocess
architecture), then `src/scanner.rs` (YAML parsing), `src/audit/` (security
rules), `src/github/` (API verification and provenance), `src/sandbox.rs`
(OS confinement).

## 3. Reproduce a Release Binary

The goal: build from source in the same environment as CI and get a
byte-identical binary.

```bash
# Clone at the exact release tag
git clone https://github.com/OWNER/hasp.git
cd hasp
git checkout v0.1.0

# Build using the reproducible Dockerfile
# This pins: Rust version, SOURCE_DATE_EPOCH, path remapping, musl target
docker build -f Dockerfile.reproduce \
  --build-arg GITHUB_REPO=OWNER/hasp \
  --output=. .

# Compare your build against the published hash
sha256sum hasp
curl -fsSL "https://github.com/OWNER/hasp/releases/download/v0.1.0/hasp-linux-amd64.sha256"
```

If the hashes match, the binary is a faithful product of the source code at
that tag. If they don't, something is wrong -- file an issue.

### What makes the build reproducible

| Mechanism                       | Why                                                                                 |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| Pinned Rust version (`1.94.0`)  | Different compiler versions produce different code                                  |
| `SOURCE_DATE_EPOCH=0`           | Zeroes out timestamps embedded by the compiler                                      |
| `RUSTFLAGS --remap-path-prefix` | Normalizes absolute paths so `/home/you/hasp` and `/build` produce identical output |
| musl static linking             | No dynamic linker paths baked into the binary                                       |
| Docker build isolation          | Identical OS packages, no host contamination                                        |

### Build for aarch64

```bash
docker build -f Dockerfile.reproduce \
  --build-arg TARGET=aarch64-unknown-linux-musl \
  --build-arg GITHUB_REPO=OWNER/hasp \
  --output=. .
```

## 4. Integrate into CI

Copy `examples/integration.yml` into your repo's `.github/workflows/`
directory. It downloads hasp, verifies its SHA256, and runs a full scan.

```bash
cp examples/integration.yml .github/workflows/hasp.yml
# Edit the VERSION and EXPECTED_HASH variables
```

The template includes commented-out blocks for Sigstore and SLSA
verification -- uncomment them if you want stronger guarantees.

### Minimal CI integration

If you just want to add hasp to an existing workflow:

```yaml
- name: Install hasp
  run: |
    VERSION="v0.1.0"
    curl -fsSL "https://github.com/OWNER/hasp/releases/download/${VERSION}/hasp-linux-amd64" -o hasp
    chmod +x hasp

- name: Scan workflows
  run: ./hasp --paranoid
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Using a policy file

Commit a `.hasp.yml` at your repo root to configure checks per-action.
When present, hasp enables its configured checks even without `--paranoid`:

```yaml
# .hasp.yml
version: 1
checks:
  expression-injection: deny
  permissions: deny
  persist-credentials: warn
trust:
  owners:
    mode: extend
    list: [my-org]
ignore:
  - check: persist-credentials
    match: "actions/checkout"
    reason: "v4 cleans up credentials in post-step"
```

```yaml
# In your workflow -- no --paranoid needed, policy drives the checks
- run: ./hasp
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## 5. Inspect the SBOM

Every release includes an SPDX SBOM listing all transitive dependencies:

```bash
curl -fsSL "https://github.com/OWNER/hasp/releases/download/v0.1.0/hasp-linux-amd64.spdx.json" | jq .
```

## Troubleshooting

### `hasp: error: Platform sandboxing not available`

You're on macOS or a Linux kernel without Landlock support. Pass
`--allow-unsandboxed` for development use (this weakens the threat model).

### `hasp: error: GITHUB_TOKEN not set`

SHA verification and provenance checks require a GitHub token. Either:
- Set `GITHUB_TOKEN` in your environment (`export GITHUB_TOKEN=$(gh auth token)`)
- Pass `--no-verify` to skip API verification (offline mode)

### Reproducible build hash doesn't match

1. Verify you checked out the exact release tag (`git log --oneline -1`)
2. Verify Docker is using the correct platform (`--platform linux/amd64`)
3. Check that no local `.cargo/config.toml` overrides are leaking into the build
4. File an issue with your `docker version`, `uname -a`, and the mismatched hashes
