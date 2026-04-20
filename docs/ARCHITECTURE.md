# Architecture

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

## Data flow

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

## Sandbox phases (Linux)

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

## Threat model

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

## IPC protocol

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
                       TAG_DATE, GET_ACTION_YML, COMPARE,
                       GET_ATTESTATION commands
```

Regular commands cap responses at 4 KiB; `GET_ATTESTATION` opts into a
256 KiB cap on the client side because SLSA bundles are multi-KB.

## Dependencies

12 direct crate dependencies (10 cross-platform + 2 Linux-only). One
intentional C dependency (`mimalloc` secure mode). Zero proc macros. Zero
async runtimes.

| Crate            | Purpose                                                       |
| ---------------- | ------------------------------------------------------------- |
| `yaml-rust2`     | YAML parsing (pure Rust)                                      |
| `mimalloc`       | Hardened allocator with guard pages and free-memory scrubbing |
| `rustls`         | Custom TLS verifier for GitHub SPKI pinning                   |
| `rustls-webpki`  | Staged for future full X.509 chain walks                      |
| `webpki-roots`   | Mozilla root store bundled for rustls                         |
| `ureq`           | Blocking HTTP client (rustls TLS)                             |
| `ring`           | ECDSA P-256/P-384 for SLSA DSSE + Fulcio chain verification   |
| `sha1`           | Git blob hashing for workflow integrity checks                |
| `sha2`           | SHA-256 for `--self-check`                                    |
| `base64`         | Sigstore certificate parsing in `--self-check`                |
| `landlock`       | Filesystem sandboxing (Linux)                                 |
| `libc`           | Seccomp-BPF + cgroup-BPF syscalls (Linux)                     |

## Bundled trust material

| File                                      | Purpose                                                        |
| ----------------------------------------- | -------------------------------------------------------------- |
| `data/fulcio/root_v1.pem`                 | Sigstore public-good Fulcio root (P-384 self-signed)           |
| `data/fulcio/intermediate_v1.pem`         | Fulcio intermediate; verified against root at first use        |

Both expire 2031-10-05. Rotation before then ships as a hasp release.
