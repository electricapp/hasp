# What hasp Checks

## Pre-scan integrity
- **Workflow integrity check** (`src/integrity.rs`): Computes git blob SHA-1 of each workflow file; detects post-checkout tampering by prior CI steps

## Pin verification
- Every `uses:` is pinned to a full 40-char SHA (not a mutable tag/branch)
- The SHA actually exists in the upstream repo (catches phantom commits)
- Inline `# vX.Y.Z` comments match the tag the SHA is actually from
- Mutable refs get suggested pin replacements with resolved SHAs

## Commit provenance (`--paranoid`)
- Commit is reachable from the repo's default branch (catches orphaned fork commits)
- Commit has a verified signature (catches unsigned/unattributed code)
- Policy-driven cooling-off periods for newly-pushed SHAs (`--min-sha-age 48h`)
- Stricter cooling-off periods for security / auth / deploy / publish actions (`--security-action-min-sha-age 30d`)
- Very fresh pinned commits from non-trusted publishers are flagged
- **Tag mutability detection**: retroactively-created tags on old commits flagged (tagger.date vs commit date)
- Recently-created / low-reputation action repositories are flagged

## Static audit (`--paranoid`)
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

## Container images
- `docker://` step images, job containers, and service containers
- Digest-pinned (`@sha256:...`) vs mutable tag detection

## Unauditable references
- Remote reusable workflows (not transitively scanned)
- Local composite actions (transitively scanned when resolvable)
- Remote composite actions (transitively audited when metadata is fetchable; default depth 3, configurable via `--max-transitive-depth` or `max-transitive-depth` in `.hasp.yml`). When the depth limit is reached, scanning stops silently for that branch — no warning or error is emitted. Increase the limit if you need deeper visibility into nested dependency chains.

## Hidden execution audit (`--paranoid`)
- Action metadata `pre` / `post` hooks are flagged
- Composite actions with internal shell `run:` steps are flagged
- Nested execution inside pinned action metadata is surfaced for review

## Cross-workflow taint (`--paranoid`)
- `pull_request`-triggered workflow uploads an artifact that a privileged
  `workflow_run`-triggered workflow downloads (tj-actions / Ultralytics
  pattern) — CRIT
- `workflow_run` trigger without an explicit `workflows:` allowlist or
  `types: [completed]` guard in a privileged workflow — HIGH
- Privileged `workflow_run` workflow reads
  `github.event.workflow_run.*` fields that are attacker-controlled when
  the upstream was PR-triggered — HIGH

## OIDC trust-policy linting (`--paranoid`)

Pass trust policies alongside workflows (CLI flag `--oidc-policy aws:./trust.json`
or `.hasp.yml` `oidc:` section) and hasp audits the whole handshake:

- Trust policy accepts a wildcard repository pattern but the workflows
  only mint OIDC tokens from a specific repo — HIGH
- Trust policy accepts PR refs (`refs/pull/*`) but no PR-triggered
  workflow declares `id-token: write` — HIGH (dead entry / latent exploit)
- Trust policy has no `aud` pin — MED
- Trust policy accepts environment wildcards while workflows declare
  specific environments — MED

Supports AWS IAM trust policies, GCP Workload Identity Federation, and
Azure federated credentials.

## Cross-repo external artifacts (`--paranoid`)
- `run:` blocks invoking `curl` / `wget` / `gh release download` /
  `pip install <url>` / `npm install <url>` / `go install` / `cargo
  install --git` against unpinned third-party artifacts
- Severity calibrates to context: CRIT for privileged + PR-triggered,
  HIGH for privileged-or-PR, MED otherwise
- SHA-pinned `raw.githubusercontent.com` URLs are exempt (equivalent
  provenance to `uses:@<sha>`)

## SLSA attestation verification (`--paranoid`)

For every pinned `uses:` SHA that has a GitHub attestation, hasp runs
full cryptographic verification:

```
Leaf cert (P-256 ECDSA_SHA256, fetched from attestation bundle)
  │ DSSE signature verified against leaf's SubjectPublicKeyInfo
  ▼
Intermediate (P-384, bundled at data/fulcio/intermediate_v1.pem)
  │ issuer DN byte-compared; ECDSA_P384_SHA384 signature verified
  ▼
Root (P-384 self-signed, bundled at data/fulcio/root_v1.pem)
    Verified at first use via ECDSA_P384_SHA384
```

Findings (CRIT unless otherwise):
- **SignatureInvalid** — DSSE envelope signature does not verify against
  cert's public key (strongest tampering signal)
- **ChainInvalid** — leaf cert does not chain to Sigstore public-good
  Fulcio
- **SubjectMismatch** — attestation's `subject.digest.sha1` does not
  bind to the pinned SHA
- **UntrustedBuilder** — HIGH; builder.id is not a GitHub Actions runner
- **UnknownPredicate** — MED; predicateType is not SLSA v0.2 or v1
- **Missing** — MED (warn); no attestation exists for this SHA
