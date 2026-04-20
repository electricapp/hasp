# Policy File (`.hasp.yml`)

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
  cross-workflow: deny
  oidc: deny
  external-artifacts: deny
  provenance:
    reachability: deny
    signatures: warn
    fresh-commit: warn
    tag-age-gap: deny
    repo-reputation: warn
    recent-repo: deny
    transitive: deny
    hidden-execution: deny
    slsa-attestation: warn

# ── OIDC trust policies to cross-check against workflows ─────
oidc:
  - provider: aws
    path: infra/iam/deploy-role-trust.json
  - provider: gcp
    path: infra/gcp/wif-provider.json

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

## Precedence

global defaults < per-action overrides (first match wins) < suppressions
(post-hoc filter). CLI flags always win on conflict (`--strict` forces
`pin: deny`, `--paranoid` forces all checks to `deny`). General rule:
most restrictive wins.

## Protecting the policy file

`.hasp.yml` is itself an attack surface — a malicious PR that modifies it
could suppress findings or weaken checks. Protect it with:

- **CODEOWNERS**: require security team review for `.hasp.yml` changes
  (`/.hasp.yml @your-org/security`)
- **Branch protection**: require PR approval before merging changes to the
  policy file
- **`--paranoid` in CI**: CLI flags override the policy file, so
  `--paranoid` in your CI workflow ensures all checks run at `deny`
  regardless of what `.hasp.yml` says
- hasp warns to stderr when the policy disables all checks or uses broad
  suppression patterns
