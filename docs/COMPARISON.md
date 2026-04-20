# Comparison with other tools

## `hasp` scanner vs [zizmor][zz]

Both are static analyzers for GitHub Actions. zizmor ships a wider offline
audit catalog; hasp goes deeper on commit provenance, cryptographic
attestation verification, and cross-workflow / cross-repo / OIDC boundaries
that zizmor doesn't cross.

| Capability                                                  | hasp                       | zizmor         |
| ----------------------------------------------------------- | -------------------------- | -------------- |
| Unpinned `uses:` / mutable-ref detection                    | ✓                          | ✓              |
| Template-injection in `run:` / `with:`                      | ✓                          | ✓              |
| Excessive / missing permissions                             | ✓                          | ✓              |
| `pull_request_target` + attacker checkout                   | ✓                          | ✓              |
| `secrets: inherit` exposure                                 | ✓                          | ✓              |
| Bypassable `contains()` on attacker contexts                | ✓                          | ✓              |
| `actions/checkout` persist-credentials                      | ✓                          | ✓              |
| Orphaned fork SHA detection                                 | ✓                          | ✓              |
| Hash-comment / tag mismatch                                 | ✓                          | ✓              |
| Docker container image pinning                              | ✓                          | ✓              |
| Typosquatting (`action/checkout`)                           | ✓                          | ✗              |
| Commit signature verification                               | ✓                          | ✗              |
| Commit-age cooling-off periods                              | ✓                          | ✗              |
| Tag-age-gap (retroactive tagging)                           | ✓                          | ✗              |
| Repo reputation / age / newly-created-repo flags            | ✓                          | ✗              |
| **Cross-workflow taint** (artifact / `workflow_run`)        | ✓                          | ✗              |
| **OIDC trust-policy linting** (AWS/GCP/Azure)               | ✓                          | ✗              |
| **Cross-repo external artifacts** (curl/wget in `run:`)     | ✓                          | ✗              |
| **SLSA attestation — cryptographic verification**           | ✓ (DSSE + chain to Fulcio) | ✗              |
| **PR-delta mode** (`hasp diff`)                             | ✓                          | ✗              |
| **Supply-chain graph + scoring** (`hasp tree`)              | ✓                          | ✗              |
| **Historical audit replay** (`hasp replay`)                 | ✓                          | ✗              |
| **Kernel-sandboxed step runner** (`hasp exec`)              | ✓                          | ✗              |
| **Scanner is itself kernel-sandboxed** (Landlock/seccomp)   | ✓                          | ✗              |
| Known-vulnerable actions (CVE DB)                           | ✗                          | ✓              |
| Archived-upstream-repo detection                            | ✗                          | ✓              |
| Cache-poisoning in release workflows                        | ✗                          | ✓              |
| Spoofable `bot` condition checks                            | ✗                          | ✓              |
| Missing concurrency limits                                  | ✗                          | ✓              |
| Dependabot cooldown / execution config                      | ✗                          | ✓              |
| GitHub App token patterns                                   | ✗                          | ✓              |
| `insecure-commands` opt-in detection                        | ✗                          | ✓              |
| Obfuscated-expression detection                             | ✗                          | ✓              |
| `secrets-outside-env` (no environment constraint)           | ✗                          | ✓              |
| Self-hosted runner flagging                                 | ✗                          | ✓              |
| SHA not pointing to a tag (`stale-action-refs`)             | ✗                          | ✓              |
| Superfluous-actions / trusted-publishing advisories         | ✗                          | ✓              |
| Undocumented-permissions comments                           | ✗                          | ✓              |
| Unsound conditions / unredacted secrets                     | ✗                          | ✓              |

Both tools call the GitHub API when they need to — this is not a
"static vs online" split. The real difference is **depth on supply-chain
evidence** (hasp has the trust-signal stack) vs **breadth of CI-config
audits** (zizmor has the larger catalog). Running both is reasonable.

[zz]: https://github.com/zizmorcore/zizmor

## `hasp exec` vs runtime sandboxing tools

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
