# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | Yes       |

Only the latest release receives security updates.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report vulnerabilities through
[GitHub Security Advisories](https://github.com/OWNER/hasp/security/advisories/new).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity, but critical issues will be
  prioritized

### Scope

The following are in scope:

- Bypass of sandbox confinement (Landlock, seccomp, network egress)
- Token or secret exfiltration from the subprocess architecture
- YAML parsing bugs that could lead to code execution
- TLS/certificate pinning bypass in `--self-check` or API calls
- Supply chain issues in dependencies

The following are out of scope:

- Issues that require `--allow-unsandboxed` (this flag explicitly disables
  protections)
- Denial of service via crafted YAML (hasp processes local files only)

## Verification

See [TRUST.md](TRUST.md) for binary verification, Sigstore signatures, SLSA
provenance, and reproducible build instructions.
