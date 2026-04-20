# hasp as a GitHub Action

> **Read before using.** This action downloads and runs a pre-built binary.
> You are trusting this repository's release pipeline and GitHub's hosting.
> For maximum safety, [build from source](REPRODUCE.md) instead.

The action verifies the binary before running it. The `verify` input controls
how many levels of verification are performed (each level includes all below):

| Level | `verify` value | What it checks                                                       |
| ----- | -------------- | -------------------------------------------------------------------- |
| 1     | `sha256`       | SHA256 checksum + cross-check against published `.sha256` file       |
| 2     | `sigstore`     | + Sigstore cosign signature (proves binary came from CI)             |
| 3     | `slsa`         | + SLSA build provenance attestation (proves exact commit + workflow) |

## Usage

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

## Safe usage rules

1. **Pin to a full SHA.** Never use `@v1` or `@main`. hasp itself will flag you if you do.
2. **Grant only `contents: read`.** hasp needs nothing else. Add `id-token: write` only if you use `verify: slsa`. The action does not write, push, comment, or call any API except GitHub's read-only commit/tag endpoints.
3. **Review `action.yml` at the pinned SHA before first use.** It's a composite action with shell steps — no Node.js, no build artifacts, fully auditable in one file.
4. **Verify the `expected-hash` input.** The action ships with a default hash for its default version. If you change `version`, update `expected-hash` to match (get it from the release's `.sha256` file).
5. **Full OS-level confinement on hosted runners.** GitHub-hosted Ubuntu runners (22.04+, kernel 6.8+) support Landlock, seccomp-BPF, and cgroup v2. hasp uses a `sudo` BPF helper to load cgroup-BPF programs when unprivileged BPF is unavailable (the default on Ubuntu). No `--allow-unsandboxed` needed.
6. **cosign is also SHA256-verified.** The action downloads cosign for Sigstore verification and verifies its hash before running it. The pinned cosign version and hash are action inputs you can audit and override.

## Inputs

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
