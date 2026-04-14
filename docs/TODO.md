# TODO: Trust Bootstrap Finalization

## 1. Replace `OWNER/hasp` placeholders

Create the GitHub repo, then search-and-replace `OWNER/hasp` across:
- `.github/workflows/release.yml`
- `.github/workflows/security.yml`
- `Dockerfile.reproduce`
- `Cargo.toml` (repository field)
- `TRUST.md`
- `SECURITY.md`
- `examples/integration.yml`

## 2. Push and tag `v0.1.0`

This triggers the release pipeline, which exercises SBOM generation,
Sigstore signing, and SLSA attestation for the first time.

## 3. Verify the release artifacts

After the pipeline runs:

```bash
# Download the release binary
gh release download v0.1.0 --repo OWNER/hasp -p 'hasp-linux-amd64*'

# L1: checksum
sha256sum --check hasp-linux-amd64.sha256

# L2: Sigstore
cosign verify-blob --signature hasp-linux-amd64.sig \
  --certificate hasp-linux-amd64.pem \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  hasp-linux-amd64

# L3: SLSA provenance
gh attestation verify hasp-linux-amd64 --repo OWNER/hasp

# L4: reproducible build
git checkout v0.1.0
docker build -f Dockerfile.reproduce --build-arg GITHUB_REPO=OWNER/hasp --output=. .
sha256sum hasp  # compare with release hash
```

## 4. Update `examples/integration.yml`

Replace `REPLACE_WITH_ACTUAL_SHA256_AFTER_FIRST_RELEASE` with the real
SHA256 hash from step 3.

## 5. Verify self-scan

Confirm the `self-scan` job in `security.yml` passes on the next push
to `main`.

## 6. SBOM spot-check

Download the `.spdx.json` from the release and verify it lists the
expected dependencies (yaml-rust2, ureq, rustls, webpki-roots, sha2,
base64, mimalloc).
