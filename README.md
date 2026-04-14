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

`hasp exec` wraps any executable subprocess (e.g. CI step) in a kernel sandbox
where secrets are capabilities — mediated by per-secret localhost proxies with
declarative domain allowlists, so a compromised dependency can never exfiltrate
credentials to unauthorized domains.

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

## Architecture

The hasp binary splits itself into isolated subprocesses, each with the minimum
privileges needed for its job. Before forking, the launcher performs a
pre-scan integrity check (git blob SHA-1) to detect post-checkout tampering.
On Linux, the scanner is confined by Landlock and seccomp-BPF, while the
verifier path gets an additional cgroup-BPF egress allowlist. The `GITHUB_TOKEN`
never touches the process that parses untrusted YAML. A `.hasp.yml` policy file
can extend or replace built-in audit rules on a per-action basis.

```
                            hasp
                     ┌──────────────────────┐
                     │      LAUNCHER        │
                     │                      │
                     │  - git integrity     │
                     │    check (pre-fork)  │
                     │  - load .hasp.yml    │
                     │  - parse CLI flags   │
                     │  - orchestration     │
                     │  - report printing   │
                     │  - exit code logic   │
                     └──┬──────────┬────────┘
                        │          │
          ┌─────────────┘          └──────────────┐
          │ fork+exec                  fork+exec  │
          │ (no GITHUB_TOKEN)          (has token)│
          ▼                                       ▼
  ┌───────────────────┐              ┌──────────────────────┐
  │     SCANNER       │              │    TOKEN PROXY       │
  │                   │              │                      │
  │  Landlock:        │              │  Holds GITHUB_TOKEN  │
  │   - deny writes   │              │  Holds ureq client   │
  │   - deny reads    │              │  PinnedResolver:     │
  │     (after parse) │              │   api.github.com     │
  │  Seccomp:         │              │   only               │
  │   - deny execve   │              │  cgroup-BPF:         │
  │   - deny network  │              │   - GitHub IPs only  │
  │   - deny ptrace   │              │  Loopback TCP server │
  │                   │              │  + per-run auth      │
  │                   │              │                      │
  │  Reads YAML files │              │  Serves:             │
  │  Parses workflows │              │   VERIFY owner/repo  │
  │  Extracts refs    │              │   RESOLVE tag->SHA   │
  │  Static audit     │              │   FIND_TAG SHA->tag  │
  │                   │              │   DEFAULT_BRANCH     │
  │  Outputs:         │              │   REACHABLE (compare)│
  │   ScanPayload     │              │   SIGNED (gpg check) │
  │   via stdout IPC  │              └──────────┬───────────┘
  └───────────────────┘                         │
                                      loopback TCP only
          ┌─────────────────────────────────────┘
          │
          ▼
  ┌────────────────────┐
  │     VERIFIER       │
  │                    │
  │  Landlock:         │
  │   - deny writes    │
  │   - deny reads     │
  │     (after init)   │
  │  Seccomp:          │
  │   - deny execve    │
  │   - deny ptrace    │
  │  cgroup-BPF:       │
  │   - proxy only     │
  │                    │
  │  NO GITHUB_TOKEN   │
  │  NO ureq client    │
  │                    │
  │  Talks to proxy    │
  │  via authenticated │
  │  localhost TCP     │
  │                    │
  │  Runs:             │
  │   SHA verification │
  │   provenance check │
  │                    │
  │  Outputs:          │
  │   VerifyPayload    │
  │   via stdout IPC   │
  └────────────────────┘
```

### Exec Mode Architecture (`hasp exec`)

```
  hasp exec --manifest .hasp/publish.yml -- npm publish
       │
       ├─ parse manifest, pre-resolve DNS, capture secrets
       │
       ├─ [sudo hasp --internal-bpf-helper]     (short-lived, root)
       │     └─ create cgroup + load BPF → chown to caller → exit
       │
       ├─ spawn FORWARD PROXY per secret         (each in own BPF cgroup)
       │   ┌───────────────────────────────────┐
       │   │  FORWARD PROXY (NPM_TOKEN)        │
       │   │  BPF: only registry.npmjs.org IPs │
       │   │  Loopback-only, ephemeral port    │
       │   │  Validates Host header            │
       │   │  Injects Bearer token             │
       │   │  Plain HTTP in → HTTPS out        │
       │   └───────────────────────────────────┘
       │
       ├─ spawn CHILD in BPF cgroup (only proxy ports allowed)
       │   ┌─────────────────────────────┐
       │   │  npm publish                │ 
       │   │  env: scrubbed (no secrets) │
       │   │  HASP_PROXY_NPM_TOKEN=      │
       │   │    http://127.0.0.1:{port}  │
       │   │  Landlock: read-only fs     │
       │   │    (except ./dist)          │
       │   │  Seccomp: deny ptrace       │
       │   │  BPF: only 127.0.0.1:{port} │
       │   └─────────────────────────────┘
       │
       └─ wait for child → kill proxies → exit with child's code
```

### Data Flow

```
  .github/workflows/*.yml        .hasp.yml
          │                       │
          ├─────────────┬─────────┘
          │             │
          │ (git blob check first)
          │             │
          ▼             ▼
  ┌───────────────┐     stdout pipe     ┌──────────────┐
  │    SCANNER    │ ──────────────────► │   LAUNCHER   │
  │               │   ScanPayload:      │              │
  │  parse YAML   │    action_refs[]    │  correlate   │
  │  extract refs │    skipped_refs[]   │  results     │
  │  static audit │    container_refs[] │  print       │
  │               │    audit_findings[] │  report      │
  └───────────────┘                     └──────┬───────┘
                                               │
                     stdin pipe                │   stdout pipe
                  ┌──────────────────┐         │   ┌──────────────────┐
                  │    VERIFIER      │◄────────┘   │    VERIFIER      │
                  │                  │ action_refs │                  │──────►  LAUNCHER
                  │  verify SHAs     │             │  VerifyPayload:  │
                  │  check provenance│             │   results[]      │
                  │                  │             │   provenance[]   │
                  └────────┬─────────┘             └──────────────────┘
                           │
                   loopback TCP
                           │
                  ┌────────▼─────────┐
                  │   TOKEN PROXY    │──────►  api.github.com:443
                  │                  │         (TLS, SPKI-pinned)
                  │  GitHub IP allow │
                  │  list on Linux   │
                  │  GITHUB_TOKEN    │
                  │  ureq + rustls   │
                  └──────────────────┘
```

### Sandbox Phases (Linux)

```
  Process start
       │
       ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  Phase 1: Landlock V5 deny writes + Seccomp BPF              │
  │                                                              │
  │  Filesystem: read-only (no write, mkdir, symlink, truncate)  │
  │  Syscalls:   deny execve, execveat, ptrace, process_vm_*     │
  │  Network:    deny socket/connect/bind/sendmsg (scanner only) │
  │              verifier/proxy egress narrowed by cgroup-BPF    │
  └──────────────────────────────────────────────────────────────┘
       │
       │  ... read YAML, parse, build payloads ...
       │
       ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  Phase 2: Landlock V5 deny reads                             │
  │                                                              │
  │  Filesystem: no read, no readdir, no execute                 │
  │  Process is now fully jailed — can only write to stdout      │
  └──────────────────────────────────────────────────────────────┘
       │
       │  ... serialize results to stdout IPC ...
       │
       ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  Phase 3: Launcher self-sandboxing (after children exit)     │
  │                                                              │
  │  Launcher applies seccomp: deny execve, ptrace, network      │
  │  Final report-printing phase cannot execute code             │
  └──────────────────────────────────────────────────────────────┘
       │
       ▼
  Process exit
```

### Threat Model

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                        ATTACK SURFACE                               │
  ├─────────────────────────────────────────────────────────────────────┤
  │                                                                     │
  │  Malicious YAML ──► SCANNER (sandboxed, no token, no network)       │
  │       │                                                             │
  │       │  Even if yaml-rust2 has a bug and the attacker gets code    │
  │       │  execution in the scanner:                                  │
  │       │   - Cannot write to disk       (Landlock)                   │
  │       │   - Cannot exec malware        (seccomp)                    │
  │       │   - Cannot open sockets        (seccomp)                    │
  │       │   - Cannot read files          (Landlock Phase 2)           │
  │       │   - Cannot access GITHUB_TOKEN (env scrubbed before fork)   │
  │       │   - Cannot ptrace other procs  (seccomp)                    │
  │       │                                                             │
  │  GitHub API ──► TOKEN PROXY (holds token, pinned TLS)               │
  │       │                                                             │
  │       │  The proxy only talks to api.github.com through a pinned    │
  │       │  resolver, SPKI-pinned TLS, and Linux cgroup-BPF IP         │
  │       │  allowlists. The verifier can only reach the loopback       │
  │       │  proxy.                                                     │
  │       │  Proxy env vars (HTTP_PROXY etc.) are stripped on startup.  │
  │       │  Token is XOR-masked at rest, unmasked only during API      │
  │       │  calls (~50ms), then volatile-write scrubbed on drop.       │
  │       │  Token scope verified on startup (warns if overprivileged). │
  │       │  Auth uses constant-time comparison (no timing leak).       │
  │       │  Proxy shuts down after 5 auth failures (rate limited).     │
  │       │  API calls capped at 300/run (token exhaustion prevention). │
  │       │                                                             │
  │  Orphaned fork commits ──► PROVENANCE CHECKER                       │
  │       │                                                             │
  │       │  GitHub's shared object store lets fork commits be          │
  │       │  addressed by SHA from the parent repo. We detect this      │
  │       │  via the compare API (diverged = suspicious).               │
  │       │  Unsigned commits also flagged.                             │
  │                                                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

## What It Checks

### Pre-Scan Integrity
- **Workflow integrity check** (`src/integrity.rs`): Computes git blob SHA-1 of each workflow file; detects post-checkout tampering by prior CI steps

### Pin Verification
- Every `uses:` is pinned to a full 40-char SHA (not a mutable tag/branch)
- The SHA actually exists in the upstream repo (catches phantom commits)
- Inline `# vX.Y.Z` comments match the tag the SHA is actually from
- Mutable refs get suggested pin replacements with resolved SHAs

### Commit Provenance (`--paranoid`)
- Commit is reachable from the repo's default branch (catches orphaned fork commits)
- Commit has a verified signature (catches unsigned/unattributed code)
- Policy-driven cooling-off periods for newly-pushed SHAs (`--min-sha-age 48h`)
- Stricter cooling-off periods for security / auth / deploy / publish actions (`--security-action-min-sha-age 30d`)
- Very fresh pinned commits from non-trusted publishers are flagged
- **Tag mutability detection**: retroactively-created tags on old commits flagged (tagger.date vs commit date)
- Recently-created / low-reputation action repositories are flagged

### Static Audit (`--paranoid`)
- `${{ }}` expression injection in `run:` blocks (CRIT) and `with:` inputs (HIGH)
- `pull_request_target` / `workflow_run` + attacker-controlled checkout detection
- Dangerous `GITHUB_ENV` / `GITHUB_PATH` writes (CRIT with injection, MED otherwise)
- `secrets: inherit` on reusable workflow calls (exposes all secrets)
- Bypassable `contains()` checks on attacker-controlled contexts
- `actions/checkout` without `persist-credentials: false` (token left on disk)
- Secret-to-action visibility mapping for third-party actions
- Excessive `GITHUB_TOKEN` permissions (`contents: write`, `packages: write`, etc.)
- Missing top-level `permissions: {}` block
- Unverified action sources (non-GitHub-official publishers)
- Popular-action typosquatting lookalikes (`action/checkout` vs `actions/checkout`)

### Container Images
- `docker://` step images, job containers, and service containers
- Digest-pinned (`@sha256:...`) vs mutable tag detection

### Unauditable References
- Remote reusable workflows (not transitively scanned)
- Local composite actions (transitively scanned when resolvable)
- Remote composite actions (transitively audited when metadata is fetchable; default depth 3, configurable via `--max-transitive-depth` or `max-transitive-depth` in `.hasp.yml`). When the depth limit is reached, scanning stops silently for that branch — no warning or error is emitted. Increase the limit if you need deeper visibility into nested dependency chains.

### Hidden Execution Audit (`--paranoid`)
- Action metadata `pre` / `post` hooks are flagged
- Composite actions with internal shell `run:` steps are flagged
- Nested execution inside pinned action metadata is surfaced for review

## Usage

```bash
# Basic scan (checks pinning, verifies SHAs with token)
export GITHUB_TOKEN=$(gh auth token)
hasp

# Full paranoid audit
hasp --paranoid

# Enforce a general 48-hour cooling-off window for pinned SHAs
hasp --min-sha-age 48h

# Require security / auth / deploy / publish actions to age for 30 days
hasp --security-action-min-sha-age 30d

# Strict mode (mutable refs = failure, token required)
hasp --strict

# Offline mode (skip GitHub API verification)
hasp --no-verify

# Custom workflow directory
hasp --dir path/to/workflows

# Use a specific policy file
hasp --policy path/to/custom.yml

# Ignore .hasp.yml even if present
hasp --no-policy --paranoid

# Increase transitive dependency scan depth (default: 3, max: 10)
hasp --paranoid --max-transitive-depth 5

# Verify binary integrity against published release
hasp --self-check

# Run a command in a sandboxed environment with proxy-mediated secrets
hasp exec --manifest .hasp/publish.yml -- npm publish

# Run with explicit writable dirs (can be repeated)
hasp exec --manifest .hasp/deploy.yml --writable ./dist --writable /tmp -- deploy.sh
```

### Sandboxed Step Runner (`hasp exec`)

`hasp exec` runs any command in a sandboxed environment where secrets are
capabilities — mediated by per-secret localhost proxies with declarative
domain allowlists. The child process gets zero direct network access and zero
secrets in its environment.

```bash
# Run npm publish with proxy-mediated NPM_TOKEN
export NPM_TOKEN=npm_abc123
hasp exec --manifest .hasp/publish.yml -- npm publish

# Dry run: zero secrets, zero network, read-only fs
hasp exec --allow-unsandboxed -- echo hello
```

A step manifest (YAML) declares per-step secret grants, network allowlist,
and writable directories:

```yaml
# .hasp/publish.yml
secrets:
  NPM_TOKEN:
    domains: [registry.npmjs.org]
    inject: header              # header | basic | none
    header_prefix: "Bearer "    # default

network:
  allow: [registry.npmjs.org]   # union with secret domains

filesystem:
  writable: [./dist]            # Landlock write grants
```

**How it works:**

1. Manifest is parsed and validated
2. DNS for all allowed domains is pre-resolved
3. Secrets are captured from the environment and scrubbed
4. One TLS-terminating forward proxy is spawned per secret (each in its own BPF cgroup)
5. The child's BPF cgroup only allows connections to proxy localhost ports
6. The child's environment is cleared (only `PATH`, `HOME`, `USER`, `LANG`, `TERM` + proxy URLs)
7. Landlock denies writes except to declared writable directories; seccomp denies ptrace
8. The child runs, and hasp exits with the child's exit code

The child uses the proxy by setting tool-specific env vars (e.g.,
`NPM_CONFIG_REGISTRY=http://127.0.0.1:{port}`). The proxy validates the
`Host` header against the domain allowlist, injects the credential as an
HTTP header, and forwards over HTTPS to upstream.

### Policy File (`.hasp.yml`)

Commit a `.hasp.yml` at the repository root to configure checks per-action,
extend or replace built-in trust lists, and suppress known false positives
without disabling entire check categories. When present, the policy enables
its configured checks even without `--paranoid`.

```yaml
version: 1

# ── Global defaults ──────────────────────────────────────────
pin: deny              # deny | warn | off
min-sha-age: 48h
security-action-min-sha-age: 30d
max-transitive-depth: 3  # 1-10, how deep to scan composite action dependencies

# ── Check levels ─────────────────────────────────────────────
# deny = finding is a failure, warn = printed but non-blocking, off = skip
checks:
  expression-injection: deny
  permissions: deny
  secret-exposure: deny
  privileged-triggers: deny
  github-env-writes: deny
  secrets-inherit: deny
  contains-bypass: deny
  persist-credentials: warn
  typosquatting: deny
  untrusted-sources: warn
  provenance:
    reachability: deny
    signatures: warn
    fresh-commit: warn
    tag-age-gap: deny
    repo-reputation: warn
    recent-repo: deny
    transitive: deny
    hidden-execution: deny

# ── Trust lists ──────────────────────────────────────────────
# mode: extend (add to built-in) or replace (use only these)
trust:
  owners:
    mode: extend
    list: [my-org]
  privileged-actions:
    mode: extend
    list: [my-org/deploy-action]
  high-impact-secrets:
    mode: extend
    list: [MY_CUSTOM_TOKEN]

# ── Per-action overrides ─────────────────────────────────────
# First match wins. Glob * matches within a segment.
actions:
  - match: "my-org/*"
    pin: warn
    min-sha-age: 0s
    checks:
      untrusted-sources: off
  - match: "actions/checkout"
    checks:
      persist-credentials: off

# ── Suppressions ─────────────────────────────────────────────
# Escape hatch. Reason is required. Suppressed findings are excluded.
ignore:
  - check: persist-credentials
    match: "actions/checkout"
    reason: "v4 cleans up in post-step"
  - check: expression-injection
    match: "*"
    file: ".github/workflows/label-sync.yml"
    reason: "Schedule-only trigger"
```

**Precedence**: global defaults < per-action overrides (first match wins) < suppressions (post-hoc filter). CLI flags always win on conflict (`--strict` forces `pin: deny`, `--paranoid` forces all checks to `deny`). General rule: most restrictive wins.

**Protecting the policy file**: `.hasp.yml` is itself an attack surface — a malicious PR that modifies it could suppress findings or weaken checks. Protect it with:
- **CODEOWNERS**: require security team review for `.hasp.yml` changes (`/.hasp.yml @your-org/security`)
- **Branch protection**: require PR approval before merging changes to the policy file
- **`--paranoid` in CI**: CLI flags override the policy file, so `--paranoid` in your CI workflow ensures all checks run at `deny` regardless of what `.hasp.yml` says
- hasp warns to stderr when the policy disables all checks or uses broad suppression patterns

### GitHub Action

> **Read before using.** This action downloads and runs a pre-built binary.
> You are trusting this repository's release pipeline and GitHub's hosting.
> For maximum safety, [build from source](docs/REPRODUCE.md) instead.

The action verifies the binary before running it. The `verify` input controls
how many levels of verification are performed (each level includes all below):

| Level | `verify` value | What it checks                                                       |
| ----- | -------------- | -------------------------------------------------------------------- |
| 1     | `sha256`       | SHA256 checksum + cross-check against published `.sha256` file       |
| 2     | `sigstore`     | + Sigstore cosign signature (proves binary came from CI)             |
| 3     | `slsa`         | + SLSA build provenance attestation (proves exact commit + workflow) |

```yaml
permissions: {}

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read   # Required for checkout + hasp
      id-token: write  # Required for SLSA verification (omit if verify: sha256)
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - uses: OWNER/hasp@REPLACE_WITH_FULL_40_CHAR_SHA  # pin to a SHA, never @v1
        with:
          mode: paranoid      # default | paranoid | strict
          verify: slsa        # sha256 | sigstore | slsa
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Safe usage rules:**

1. **Pin to a full SHA.** Never use `@v1` or `@main`. hasp itself will flag you if you do.
2. **Grant only `contents: read`.** hasp needs nothing else. Add `id-token: write` only if you use `verify: slsa`. The action does not write, push, comment, or call any API except GitHub's read-only commit/tag endpoints.
3. **Review `action.yml` at the pinned SHA before first use.** It's a composite action with shell steps -- no Node.js, no build artifacts, fully auditable in one file.
4. **Verify the `expected-hash` input.** The action ships with a default hash for its default version. If you change `version`, update `expected-hash` to match (get it from the release's `.sha256` file).
5. **Full OS-level confinement on hosted runners.** GitHub-hosted Ubuntu runners (22.04+, kernel 6.8+) support Landlock, seccomp-BPF, and cgroup v2. hasp uses a `sudo` BPF helper to load cgroup-BPF programs when unprivileged BPF is unavailable (the default on Ubuntu). No `--allow-unsandboxed` needed.
6. **cosign is also SHA256-verified.** The action downloads cosign for Sigstore verification and verifies its hash before running it. The pinned cosign version and hash are action inputs you can audit and override.

Action inputs:

| Input            | Default             | Description                                         |
| ---------------- | ------------------- | --------------------------------------------------- |
| `version`        | `v0.1.0`            | Release version to download                         |
| `expected-hash`  | *(release hash)*    | SHA256 of the binary; fails if mismatch             |
| `verify`         | `slsa`              | Verification level: `sha256`, `sigstore`, or `slsa` |
| `mode`           | `paranoid`          | `default`, `paranoid`, or `strict`                  |
| `policy`         | *(auto-detect)*     | Path to `.hasp.yml`, or `"none"` to disable         |
| `dir`            | `.github/workflows` | Directory to scan                                   |
| `args`           |                     | Extra CLI flags (e.g. `"--min-sha-age 48h"`)        |
| `cosign-version` | `v2.4.3`            | Cosign version for Sigstore verification            |
| `cosign-hash`    | *(pinned hash)*     | SHA256 of cosign binary                             |

### Version

`hasp --version` prints `hasp 0.1.0 (abc123def456) [rustc 1.94.0]` — the git hash and exact Rust compiler version are embedded at build time for reproducibility tracing.

### Exit Codes

| Code | Meaning                                               |
| ---- | ----------------------------------------------------- |
| `0`  | All checks pass (or only warnings in non-strict mode) |
| `1`  | One or more failures detected                         |
| `2`  | Usage error or internal failure                       |

## Verification & Trust

Every release ships with multiple independently-verifiable trust anchors:

- **SHA256 checksums** — integrity check
- **Sigstore cosign signatures** — keyless OIDC proof of which CI workflow built the binary
- **SLSA build provenance** — signed attestation of commit, workflow, and runner
- **SPDX SBOM** — full dependency inventory in machine-readable format
- **Reproducible builds** — `Dockerfile.reproduce` with pinned Rust version, `SOURCE_DATE_EPOCH=0`, and `RUSTFLAGS --remap-path-prefix` for deterministic output

`--self-check` verifies the running binary against published hashes (TLS-pinned fetch), displays the Sigstore signer identity, and prints ready-to-run `cosign verify-blob` and `gh attestation verify` commands.

The release CI pipeline runs hasp against itself (`security.yml` self-scan job).

See [REPRODUCE.md](docs/REPRODUCE.md) for step-by-step build, verify, and CI integration instructions. See [TRUST.md](docs/TRUST.md) for the full 5-level verification ladder and [SECURITY.md](docs/SECURITY.md) for vulnerability reporting.

## Building

```bash
cargo build --release
```

### Reproducible Builds

```bash
docker build -f Dockerfile.reproduce --output=. .
# Produces: ./hasp (statically-linked musl binary)
# Compare SHA256 against GitHub release artifacts
```

### Dependencies

10 direct crate dependencies (8 cross-platform + 2 Linux-only). One intentional C dependency (`mimalloc` secure mode). Zero proc macros. Zero async runtimes.

| Crate          | Purpose                                                       |
| -------------- | ------------------------------------------------------------- |
| `yaml-rust2`   | YAML parsing (pure Rust)                                      |
| `mimalloc`     | Hardened allocator with guard pages and free-memory scrubbing |
| `rustls`       | Custom TLS verifier for GitHub SPKI pinning                   |
| `webpki-roots` | Mozilla root store bundled for rustls                         |
| `ureq`         | Blocking HTTP client (rustls TLS)                             |
| `sha1`         | Git blob hashing for workflow integrity checks                |
| `sha2`         | SHA-256 for `--self-check`                                    |
| `base64`       | Sigstore certificate parsing in `--self-check`                |
| `landlock`     | Filesystem sandboxing (Linux)                                 |
| `libc`         | Seccomp-BPF + cgroup-BPF syscalls (Linux)                     |

## IPC Protocol

Subprocesses communicate via newline-delimited, tab-separated records over
stdin/stdout pipes with percent-encoded fields. The token proxy uses a separate
authenticated loopback TCP protocol with the same encoding.

```
Scanner -> Launcher:   HASP_SCAN_V1 magic header
                       ACTION, SKIPPED, CONTAINER, AUDIT records

Launcher -> Verifier:  HASP_ACTION_REFS_V1 magic header
                       REF records (action refs to verify)

Verifier -> Launcher:  HASP_VERIFY_V1 magic header
                       VERIFY records (verification results)
                       PROVENANCE records (audit findings)

Verifier <-> Proxy:    Loopback TCP, one request per connection
                       shared-secret authenticated
                       VERIFY, RESOLVE, FIND_TAG, REPO_INFO,
                       REACHABLE, SIGNED, COMMIT_DATE,
                       TAG_DATE, GET_ACTION_YML commands
```

## Platform Support

| Platform      | Sandbox                                            | Status                         |
| ------------- | -------------------------------------------------- | ------------------------------ |
| Linux x86_64  | Landlock + seccomp-BPF + cgroup-BPF egress sandbox | Full support                   |
| Linux aarch64 | Landlock + seccomp-BPF + cgroup-BPF egress sandbox | Full support                   |
| macOS         | None                                               | Requires `--allow-unsandboxed` |
| Windows       | None                                               | Untested                       |

## Comparison

How `hasp exec` compares to other CI/CD security tools:

| Feature                  | hasp exec                      | [Harden-Runner][hr]            | [Iron-Proxy][ip]    | [Dagger][dg]         | GitHub 2026 roadmap |
| ------------------------ | ------------------------------ | ------------------------------ | ------------------- | -------------------- | ------------------- |
| Per-step kernel sandbox  | Landlock + seccomp + BPF       | No                             | No                  | Container            | No                  |
| Per-step network policy  | BPF cgroup per process         | Job-wide                       | DNS/nftables        | Container net        | Runner-wide         |
| Secret never in child env| Yes (proxy injects)            | No                             | Yes (proxy swaps)   | Yes (tmpfs mount)    | No                  |
| Drop-in for existing GHA | `hasp exec -- cmd`             | Step 1 agent                   | Needs rewrite       | Needs rewrite        | Native              |
| Fail-closed              | Refuses without sandbox        | Audit mode default             | Configurable        | Container guarantees | TBD                 |
| Secret scoping           | Per-command, per-domain        | None                           | Per-workload        | Per-module           | Per-environment     |
| Enforcement mechanism    | Kernel (Landlock/BPF/seccomp)  | Userspace agent                | DNS + nftables      | Docker/BuildKit      | Runner-level policy |

[hr]: https://github.com/step-security/harden-runner
[ip]: https://github.com/ironsh/iron-proxy
[dg]: https://github.com/dagger/dagger

**Harden-Runner** is an EDR-like monitoring agent — it observes and optionally
blocks egress at the job level, but does not sandbox individual steps or
mediate secrets.

**Iron-Proxy** is the closest conceptually (proxy-mediated secret swapping +
network enforcement), but targets AI agents and does not use kernel sandboxing
for the workload itself.

**Dagger** achieves genuine per-step secret isolation via containers, but
requires rewriting your build in Dagger's SDK.

**GitHub's 2026 roadmap** plans runner-level egress policies and branch-scoped
secrets, but no per-step kernel sandboxing or proxy-mediated injection.

## Deferred Work

**Repository identity continuity.** The next hardening step is to pin
trusted upstreams by stable GitHub owner / repository IDs and alert if a
familiar `owner/repo` name resolves to a different numeric identity. That
requires a local cache or explicit baseline file, so hasp does not claim to
enforce it yet.

## License

MIT