# Why hasp Exists: The Trivy/LiteLLM March 2026 Crisis

## The Recent Crisis (March 2026)

On **March 19, 2026**, Aqua Security's Trivy—the most widely adopted open-source vulnerability scanner in cloud-native—was compromised in a sophisticated supply chain attack. The attacker (TeamPCP) force-pushed 76 of 77 version tags in `aquasecurity/trivy-action` and all 7 tags in `aquasecurity/setup-trivy`, redirecting existing version references to malicious commits. A credential stealer was injected into `entrypoint.sh` and executed before legitimate scanning—the pipeline appeared to work while secrets were stolen.

Five days later, on **March 24, 2026**, those stolen credentials were weaponized against LiteLLM. TeamPCP published backdoored versions (1.82.7, 1.82.8) of litellm to PyPI—97 million monthly downloads—using the PyPI token stolen from LiteLLM's CI/CD pipeline (which had used the compromised Trivy action). The malicious package was live for ~3 hours before PyPI quarantined it.

**45 repositories** had at least one workflow run using a compromised Trivy version. LiteLLM affected hundreds of downstream projects.

### Root Cause Analysis

Trivy's compromise exploited **incomplete credential revocation from a prior incident**. LiteLLM's compromise exploited the fact that its CI/CD **used a mutable action reference** (`trivy-action@v2` or similar) rather than pinning to a specific commit SHA.

This is precisely what hasp detects and prevents.

---

## What hasp Solves

hasp provides **supply chain defense-in-depth** against CI/CD action compromise by enforcing immutable pinning and verifying that pinned commits actually exist and are legitimate.

### Threat Model It Addresses

**Mutable Reference Attacks**: An attacker with push/tag access to an action repo can force-push tags or branches, retroactively modifying what `actions/something@v2` resolves to. hasp requires all `uses:` to pin to a full 40-character commit SHA, making force-push attacks ineffective. Tag mutability is detected via retroactive tag creation timestamps.

**Phantom/Orphaned Commits**: An attacker might claim a commit SHA exists without it actually being reachable from the default branch. hasp verifies every pinned SHA:
- Exists in the repo
- Is reachable from the default branch (not orphaned in a fork)
- Matches any inline version comments (`# v2.1.0`)

**Transitive Action Vulnerabilities**: If you pin `actions/checkout@abc123`, but that commit contains a `uses:` to an unpinned or phantom action, your supply chain is still vulnerable. hasp recursively scans pinned actions' `action.yml` files (default depth 3, configurable via `--max-transitive-depth` or `max-transitive-depth` in `.hasp.yml`).

**Fresh/Unsigned Commits**: Attackers can create new, unsigned commits in compromised repos. hasp flags:
- Commits created in the past 48 hours (too fresh, likely malicious)
- Unsigned commits (no GPG signature)
- Commits diverged from the default branch (orphaned/fork artifacts)

**Expression Injection**: A compromised action can inject secrets via `${{ github.event.pull_request.title }}` in `run:` blocks. hasp detects 24+ injection contexts and flags unsafe uses.

**Excessive Permissions**: Even if an action is legitimate, if your workflow grants `contents: write` + `pull_request_target`, an attacker with temporary code execution can modify your repo. hasp requires top-level `permissions: {}` and warns on privilege escalation.

---

## What hasp Does NOT Solve

### The Fundamental Problem: Trust in Action Authors

hasp ensures **the commit you pinned is the one you get**. It does **not** validate whether the author of that commit is trustworthy. If you pin `my-malicious-org/evil-action@abc123def456`, hasp will happily verify the SHA—but the code inside is still evil.

**Mitigation**: hasp flags actions from non-trusted owners (`not (actions, github, azure, docker, aws-actions, google-github-actions, hashicorp)`) as Medium severity, prompting manual review. But this is a warning, not a veto.

### Compromised Action Authors

If the **legitimate author** of an action is compromised (as happened with Trivy), and they create a new, properly signed commit, hasp has no way to know it's malicious. The "fresh commit" warning (`< 48h old`) provides some protection, but a sophisticated attacker could publish the malicious commit weeks in advance.

**Mitigation**: hasp flags high-impact actions (`sigstore/cosign-installer`, `docker/build-push-action`, `actions/deploy-to-azure`, etc.) with stricter age policies (`--security-action-min-sha-age 30d`). But this is a policy choice, not detection.

### Compromised CI/CD Infrastructure

hasp runs **inside** the CI/CD pipeline that is being compromised. If an attacker has access to your repo's secrets, they can modify the hasp binary itself (or disable it).

The Trivy attack worked because it stole the PyPI token **from the CI environment where Trivy itself ran**—even a security scanner can't defend against the environment it runs in being compromised.

**Mitigation**: hasp sandboxes itself (Landlock + seccomp on Linux) so that even if the YAML parser is exploited, the attacker can't read the `GITHUB_TOKEN`. It separates the token-holding proxy into a different process. But if the entire CI context is compromised, defense is limited.

### Supply Chain Below CI/CD

hasp focuses on **GitHub Actions**. It does not validate:
- Dependency chain integrity (npm, PyPI, cargo, maven packages)
- Docker image provenance (the base images you use)
- OS-level package security (apt, brew, yum)
- Build toolchain integrity (gcc, rustc, javac)

The Trivy attack was able to steal PyPI credentials *because LiteLLM's build environment didn't validate the credentials it held*. Once Trivy had the token, publishing to PyPI was trivial.

---

## Individual Best Practices

### 1. Always Pin Actions to Commit SHAs

Good:
```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

Bad:
```yaml
- uses: actions/checkout@v4
- uses: actions/checkout@main
```

Use hasp (`--strict`) to enforce this in CI.

### 2. Run hasp Before Deploying

Add hasp to your `pull_request` workflow:
```yaml
- uses: electricapp/hasp@<SHA>
  with:
    paranoid: true
```

This catches unpinned actions, phantom commits, and injection vulnerabilities *before* they reach production.

### 3. Minimize top-level Permissions

```yaml
permissions: {}
jobs:
  build:
    permissions:
      contents: read
      id-token: write
```

Do not grant `contents: write`, `actions: write`, or `packages: write` unless strictly necessary. This limits blast radius if an action is compromised.

### 4. Use Secrets Scoping and Rotation

- Never pass `GITHUB_TOKEN` to untrusted actions.
- Rotate PATs and API tokens monthly.
- Use OIDC federated credentials when possible (no long-lived tokens stored in CI).
- Audit which actions have access to which secrets.

### 5. Validate Downloaded Artifacts

If you use pre-built binaries in CI (like hasp itself), verify the SHA256:
```bash
curl -fsSL https://github.com/electricapp/hasp/releases/download/v1.0/hasp > hasp
echo "abc123...  hasp" | sha256sum --check
chmod +x hasp && ./hasp
```

Do not use mutable URLs. Do not omit the hash check.

### 6. Pin Transitive Dependencies

If `actions/setup-node@sha` runs `npm install` without a `package-lock.json`, it will fetch the latest (potentially compromised) package versions. Always commit lock files:
```bash
npm ci  # use package-lock.json
cargo build --locked  # use Cargo.lock
```

### 7. Assume GitHub Actions Itself May Be Compromised

This is the hardest recommendation: GitHub Actions (the service, not the ecosystem of actions) may eventually have supply chain issues. Options:
- Mirror critical actions to your own org and audit them
- Use self-hosted runners with network egress restrictions
- Consider alternative CI systems (Gitea Actions, GitLab CI, CircleCI) for critical repos
- Assume *any* secrets in CI can be exfiltrated; use short-lived, scoped credentials

---

## Critique of GitHub Actions (and How It Could Be Hardened)

### The Fundamental Design Problem

GitHub Actions' trust model is **reference resolution**. You write:
```yaml
- uses: actions/checkout@v4
```

Behind the scenes, this resolves:
1. `v4` → a git tag in `actions/checkout`
2. That tag → a commit SHA
3. That SHA → the code that runs

**Any of these steps can be manipulated**:
- **Step 1**: An attacker with push/tag access can move the `v4` tag.
- **Step 2**: An attacker can force-push branches, retroactively modifying commits.
- **Step 3**: An attacker can modify the action code before it runs.

The Trivy attack exploited **Step 1 and 2**: force-pushing 76 tags to redirect mutable references.

### How GitHub Could Improve This

#### A. Require Immutable Pinning (Breaking Change)

```yaml
# Only this would be allowed:
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

Mutable refs would be rejected at workflow parse time. This is the nuclear option—backward-incompatible but eliminates a huge class of attacks.

**Why it hasn't happened**: Ecosystem friction. Millions of workflows use `@v1`, `@main`. Forcing pin adoption would break CI/CD globally.

#### B. Signed Action Releases (GitHub Should Provide)

GitHub could offer optional **keyless signing** for action publishers:
```yaml
- uses: actions/checkout@v4
  verify:
    signature: true  # Enforce cosign verification
    issuer: "https://github.com/actions"
```

The runner would automatically `cosign verify` the action against a pinned key before executing. This raises the bar: even if an attacker force-pushes a tag, they'd need to sign it with the *original author's* key.

**Complexity**: Requires key management, revocation procedures, and runner changes.

#### C. Commit Provenance (Require Signed Commits)

GitHub could enforce that action repositories **require signed commits** on the default branch:
- Every commit must have a verified GPG signature from a known maintainer
- Force-pushes are blocked
- Only fast-forward merges allowed

This prevents orphaned commits and force-push attacks.

**Drawback**: Orthogonal to the mutable tag problem. An attacker could still move the `v4` tag to a (legitimately signed) old, vulnerable commit.

#### D. Action Attestations (SLSA Provenance)

GitHub could require that actions include **SLSA build provenance attestations**:
```yaml
- uses: actions/checkout@v4
  verify:
    slsa-provenance: true
```

The runner would verify that the action was built from the correct source commit by the expected GitHub Actions workflow, not by an attacker's local build.

This is closest to a real solution: it ties the action to its origin, making it extremely difficult to inject backdoors without triggering provenance mismatches.

#### E. Runner-Side Sandboxing (Native)

GitHub Actions runners could **natively sandbox actions** using OS-level isolation (seccomp, AppArmor, SELinux on Linux; TCC on macOS; sandboxing on Windows). Currently:
- Actions run with full access to the workflow environment
- An action can read `GITHUB_TOKEN`, all env vars, and all files
- An action can exec arbitrary commands

With native sandboxing:
- Actions would run in a restricted namespace
- Only declared inputs/outputs would be accessible
- Network access would be limited to declared hosts
- The `GITHUB_TOKEN` would only be available to explicitly declared steps

**Benefit**: Even if Trivy's entrypoint was malicious, it couldn't steal the token.

**Drawback**: Massive effort. Requires runtime changes, breaking change to action contract.

#### F. Supply Chain Security Scorecard Integration

GitHub could enforce **OpenSSF Scorecard** requirements on action repos:
- Actions must have branch protection on main
- All commits must be signed
- Repository must have a security policy
- Dependencies must be pinned

This wouldn't be built-in sandbox enforcement, but it would raise the bar for malicious actors to compromise action repos in the first place.

---

## The Hard Truth

**None of these changes are happening soon.**

GitHub Actions is the dominant CI/CD platform, with millions of workflows depending on current behavior. Making it more secure requires:
- Breaking changes to existing workflows
- New tooling (runners, signing, sandboxing)
- Significant technical debt and engineering effort
- Consensus among the ecosystem

Instead, **tools like hasp exist in the gap**. They are imperfect stopgaps that:
- Enforce pinning (hasp's core)
- Verify pins are real (hasp's verifier)
- Sandbox untrusted YAML parsing (hasp's architecture)
- Warn about dangerous patterns (hasp's auditor)

hasp is a **band-aid** on a systemic design problem. But it's a paranoid, well-intentioned band-aid that catches real attacks.

---

The Trivy/LiteLLM attacks show that:

1. **Supply chain attacks on security tools are a top-tier threat.** Trivy is used by millions because it's trusted. That trust made it a high-value target.

2. **Mutable references are exploitable in practice.** This wasn't theoretical. 45 repos were hit. The attack window was 3-12 hours. Repos that detected the change quickly were spared; repos using mutable refs were blind.

3. **Secrets in CI are a liability.** Once Trivy stole the PyPI token, the LiteLLM compromise was inevitable. The token existed, and the stealer had it.

4. **GitHub Actions itself cannot solve this problem.** GitHub didn't, couldn't, and wouldn't have prevented Trivy's compromise. GitHub Actions is the delivery mechanism; the problem is in the repos that use it.

hasp exists because **GitHub Actions is fundamentally a trust-delegation platform**, and that delegation can be exploited. Until GitHub Actions is redesigned (unlikely), the burden is on individual teams to verify their supply chains.

---

## Sources

- [The Hacker News: Trivy Security Scanner GitHub Actions Breached](https://thehackernews.com/2026/03/trivy-security-scanner-github-actions.html)
- [Aqua Security: Trivy Supply Chain Attack](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)
- [StepSecurity: Trivy Compromised a Second Time](https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release)
- [Microsoft Security Blog: Trivy Supply Chain Compromise Guidance](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)
- [CrowdStrike: From Scanner to Stealer](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/)
- [Kaspersky: Trojanization of Trivy, Checkmarx, and LiteLLM](https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/)
- [GitGuardian: Trivy's March Supply Chain Attack](https://blog.gitguardian.com/trivys-march-supply-chain-attack-shows-where-secret-exposure-hurts-most/)
- [LiteLLM Security Update](https://docs.litellm.ai/blog/security-update-march-2026)
- [Snyk: Poisoned Security Scanner Backdooring LiteLLM](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/)
- [The Hacker News: TeamPCP Backdoors LiteLLM](https://thehackernews.com/2026/03/teampcp-backdoors-litellm-versions.html)
- [Wiz: LiteLLM TeamPCP Supply Chain Attack](https://wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)
- [Astral: Open Source Security at Astral](https://astral.sh/blog/open-source-security-at-astral)
