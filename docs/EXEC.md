# `hasp exec`

Runs any command in a sandboxed environment where secrets are capabilities —
mediated by per-secret localhost proxies with declarative domain allowlists.
The child process gets zero direct network access and zero secrets in its
environment.

```bash
# Run npm publish with proxy-mediated NPM_TOKEN
export NPM_TOKEN=npm_abc123
hasp exec --manifest .hasp/publish.yml -- npm publish

# Dry run: zero secrets, zero network, read-only fs
hasp exec --allow-unsandboxed -- echo hello
```

## Step manifest

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

## How it works

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

## Architecture

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
