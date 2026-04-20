# hasp

> **Alpha — do not use in production.** APIs, CLI flags, policy schema,
> and binary format may change without notice. Pin to a specific commit
> SHA if you experiment with it.

A paranoid security scanner and sandboxed step runner for GitHub Actions.

Verifies that every `uses:` directive is pinned to an immutable commit SHA,
confirms that SHA actually exists in the upstream repository, checks commit
provenance, maps which secrets are visible to which actions, and audits
workflows for injection vulnerabilities, excessive permissions, hidden
execution paths, and supply-chain risks.

**Beyond static scanning**, hasp also:

- **Cross-workflow taint analysis** — catches `workflow_run` / artifact
  chains (tj-actions / Ultralytics pattern)
- **OIDC trust-policy linting** — cross-checks AWS/GCP/Azure trust
  policies against the workflows that mint OIDC tokens
- **SLSA provenance** — full cryptographic verification: DSSE signature +
  leaf→intermediate→root chain against bundled Sigstore public-good Fulcio
- **Cross-repo external artifacts** — flags `curl`/`wget`/`go install`
  pulling unpinned third-party code in `run:` blocks
- **`hasp diff`** — PR-delta mode surfaces new/fixed findings vs a base
  ref, with markdown output for PR comments
- **`hasp tree`** — scored supply-chain DAG with per-node trust signals
- **`hasp replay`** — re-audits historical workflow states, catches
  problems that slipped through before rules existed

`hasp exec` wraps any executable subprocess (e.g. CI step) in a kernel sandbox
where secrets are capabilities — mediated by per-secret localhost proxies with
declarative domain allowlists, so a compromised dependency can never exfiltrate
credentials to unauthorized domains.

## Documentation

- [**docs/AUDITS.md**](docs/AUDITS.md) — every check hasp runs, with severity calibration
- [**docs/POLICY.md**](docs/POLICY.md) — `.hasp.yml` reference, precedence, suppressions
- [**docs/ARCHITECTURE.md**](docs/ARCHITECTURE.md) — multi-process sandbox, threat model, IPC protocol, dependencies
- [**docs/EXEC.md**](docs/EXEC.md) — `hasp exec` step manifest + runtime architecture
- [**docs/COMPARISON.md**](docs/COMPARISON.md) — vs zizmor, vs Harden-Runner / Iron-Proxy / Dagger
- [**docs/GITHUB_ACTION.md**](docs/GITHUB_ACTION.md) — using hasp from a workflow
- [**docs/SECURITY.md**](docs/SECURITY.md) — threat model, known limitations, vulnerability reporting
- [**docs/REPRODUCE.md**](docs/REPRODUCE.md) — reproducible builds, verify workflows
- [**docs/TRUST.md**](docs/TRUST.md) — 5-level binary verification ladder

## Example

```
$ hasp --paranoid
hasp: scanning .github/workflows/
hasp: found 14 action reference(s)

  PASS  actions/checkout@11bd71901bbe  (commit verified)
  FAIL  actions/cache@6849a6489940    (comment says v3.0.0 (-> 6673cd0) but pinned to 6849a64 (v4.1.2))
  WARN  actions/setup-node@v4         (mutable ref -- pin to SHA 49933ea5288c)
  FAIL  my-org/phantom@deadbeef0000   (SHA not found -- phantom or typo'd commit)

  [CRIT]  Script injection via ${{ github.event.pull_request.title }}
  [HIGH]  Commit abc123 is diverged from actions/checkout default branch
  [MED ]  Unsigned commit abc123 in actions/checkout
```

## Usage

```bash
# Basic scan (checks pinning, verifies SHAs with token)
export GITHUB_TOKEN=$(gh auth token)
hasp

# Full paranoid audit (enables all audit categories)
hasp --paranoid

# Enforce cooling-off windows for pinned SHAs
hasp --min-sha-age 48h
hasp --security-action-min-sha-age 30d

# Offline mode (skip GitHub API verification)
hasp --no-verify

# PR-delta mode: show only new/fixed findings vs a base ref
hasp diff main
hasp diff main --format markdown       # ready for `gh pr comment --body-file -`
hasp diff main --format json

# Supply-chain dependency graph with per-node trust scores
hasp tree                              # ASCII, online signals if GITHUB_TOKEN set
hasp tree --format json
hasp tree --min-score 0.6              # CI gate: exit 1 if any root scores below

# Re-audit historical workflow states to catch past-exploit-potential
hasp replay                            # last 30 days
hasp replay --since 2w --format markdown

# OIDC trust-policy linting
hasp --paranoid --oidc-policy aws:./infra/iam/deploy-role-trust.json

# Run a command in a sandboxed environment with proxy-mediated secrets
hasp exec --manifest .hasp/publish.yml -- npm publish
```

### Subcommands

| Command             | What it does                                                                   |
| ------------------- | ------------------------------------------------------------------------------ |
| `hasp`              | Default scan: pin verification + API-backed provenance + `--paranoid` audits   |
| `hasp diff <base>`  | PR-delta — scan base worktree vs HEAD, emit new/fixed/unchanged finding delta  |
| `hasp tree`         | Scored supply-chain DAG of workflows → pinned `uses:` dependencies             |
| `hasp replay`       | Historical re-audit — walk `git log --since=<window>` and replay current rules |
| `hasp exec`         | Sandboxed step runner (kernel-confined, per-secret forward proxies)            |
| `hasp --self-check` | Verify the hasp binary against its own published hashes + Sigstore + SLSA      |

### Exit codes

| Code | Meaning                                               |
| ---- | ----------------------------------------------------- |
| `0`  | All checks pass (or only warnings in non-strict mode) |
| `1`  | One or more failures detected                         |
| `2`  | Usage error or internal failure                       |

## Building

```bash
cargo build --release
```

Reproducible build:

```bash
docker build -f Dockerfile.reproduce --output=. .
# Produces: ./hasp (statically-linked musl binary)
# Compare SHA256 against GitHub release artifacts
```

See [docs/REPRODUCE.md](docs/REPRODUCE.md) for the full reproducible-build
and verification recipe.

## Platform support

| Platform      | Sandbox                                            | Status                         |
| ------------- | -------------------------------------------------- | ------------------------------ |
| Linux x86_64  | Landlock + seccomp-BPF + cgroup-BPF egress sandbox | Full support                   |
| Linux aarch64 | Landlock + seccomp-BPF + cgroup-BPF egress sandbox | Full support                   |
| macOS         | None                                               | Requires `--allow-unsandboxed` |
| Windows       | None                                               | Untested                       |

## Verification & trust

Every release ships with multiple independently-verifiable trust anchors:

- **SHA256 checksums** — integrity check
- **Sigstore cosign signatures** — keyless OIDC proof of which CI workflow built the binary
- **SLSA build provenance** — signed attestation of commit, workflow, and runner
- **SPDX SBOM** — full dependency inventory in machine-readable format
- **Reproducible builds** — `Dockerfile.reproduce` with pinned Rust version, `SOURCE_DATE_EPOCH=0`, and `RUSTFLAGS --remap-path-prefix` for deterministic output

`hasp --self-check` verifies the running binary against published hashes
(TLS-pinned fetch), displays the Sigstore signer identity, and prints
ready-to-run `cosign verify-blob` and `gh attestation verify` commands.
The release CI pipeline runs hasp against itself (`security.yml` self-scan job).

See [docs/TRUST.md](docs/TRUST.md) for the 5-level verification ladder and
[docs/SECURITY.md](docs/SECURITY.md) for vulnerability reporting.

## Known limitations

See [docs/SECURITY.md](docs/SECURITY.md) for the full list. Summary:

- **Sandbox assertion in `hasp diff`** — integration tests verify the
  delta output is correct but don't assert the Landlock / seccomp / BPF
  layers were actually applied.
- **Private Fulcio instances** — attestations signed by a private
  Fulcio will yield `ChainInvalid`. No current mechanism to extend the
  trusted-issuer allowlist via `.hasp.yml`.
- **Fulcio rotation** — bundled root + intermediate are valid through
  2031-10-05. Unplanned Sigstore root rotation before then needs a hasp
  release.
- **Repository identity continuity** — pinning trusted upstreams by
  stable GitHub owner / repository IDs would catch rename-squatting
  attacks. Requires a local cache / baseline file; deferred.

## License

MIT
