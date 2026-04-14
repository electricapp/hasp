use crate::error::{Context, Result, bail};
use crate::github;
use sha2::{Digest, Sha256};
use std::fmt::Write;

const GITHUB_REPO: &str = env!("GITHUB_REPO");

/// Verify the running binary against the published SHA256 from GitHub Releases.
pub(crate) fn run() -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let git_hash = env!("GIT_HASH");
    let artifact = artifact_name()?;

    println!("hasp self-check");
    println!("  version:  {version} ({git_hash})");
    println!("  artifact: {artifact}");
    println!("  repo:     {GITHUB_REPO}");

    if GITHUB_REPO == "OWNER/REPO" {
        bail!(
            "GitHub repo not configured. Build from a git clone with a \
             github.com remote, or set GITHUB_REPO at build time."
        );
    }

    // 1. Hash the running binary
    let exe_path = std::env::current_exe().context("Cannot determine own binary path")?;
    let exe_bytes = std::fs::read(&exe_path)
        .context(format!("Cannot read own binary at {}", exe_path.display()))?;

    let mut hasher = Sha256::new();
    hasher.update(&exe_bytes);
    let actual_hex = hasher.finalize().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });

    println!("  local:    {actual_hex}");

    // 2. Fetch expected hash from GitHub release
    let url =
        format!("https://github.com/{GITHUB_REPO}/releases/download/v{version}/{artifact}.sha256");
    println!("  fetching: {url}");

    // Use pinned TLS config to secure the hash fetch against MITM
    let tls_config =
        github::create_github_pinned_tls_config().context("Failed to create pinned TLS config")?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .tls_config(tls_config)
        .build();

    let body = match agent.get(&url).call() {
        Ok(resp) => resp.into_string().context("Failed to read release hash")?,
        Err(ureq::Error::Status(404, _)) => {
            bail!(
                "No release found for v{version}. \
                 This version may not have a published release yet."
            );
        }
        Err(e) => bail!("Failed to fetch release hash: {e}"),
    };

    // .sha256 files are formatted as: "<hash>  <filename>\n"
    let expected_hex = body
        .split_whitespace()
        .next()
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .context("Release .sha256 file has unexpected format")?;

    // 3. Compare
    println!("  expected: {expected_hex}");
    if actual_hex == expected_hex {
        println!("\n  PASS: binary matches published release hash");

        // Display Sigstore certificate identity if available
        print_sigstore_identity(version, artifact);

        // Print verification commands for additional trust levels
        println!("\n  Additional verification commands:");
        println!("  ── Sigstore (proves which CI workflow built this binary) ──");
        println!(
            "  cosign verify-blob \\\n    \
             --signature https://github.com/{GITHUB_REPO}/releases/download/v{version}/{artifact}.sig \\\n    \
             --certificate https://github.com/{GITHUB_REPO}/releases/download/v{version}/{artifact}.pem \\\n    \
             --certificate-oidc-issuer https://token.actions.githubusercontent.com \\\n    \
             {artifact}"
        );
        println!("\n  ── SLSA provenance (proves commit, workflow, inputs) ──");
        println!("  gh attestation verify {artifact} --repo {GITHUB_REPO}",);

        Ok(())
    } else {
        println!("\n  FAIL: hash mismatch!");
        println!("  This binary does NOT match the published release.");
        println!("  If you built from source, use the reproducible build:");
        println!("    docker build -f Dockerfile.reproduce --output=. .");
        bail!("Self-check failed: hash mismatch");
    }
}

/// Fetch the Sigstore .pem certificate from the release and display the OIDC identity.
fn print_sigstore_identity(version: &str, artifact: &str) {
    let pem_url =
        format!("https://github.com/{GITHUB_REPO}/releases/download/v{version}/{artifact}.pem");

    // Use pinned TLS config to protect the Sigstore PEM fetch against MITM
    let Ok(tls_config) = github::create_github_pinned_tls_config() else {
        return;
    };
    let pem_body = match ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .tls_config(tls_config)
        .build()
        .get(&pem_url)
        .call()
    {
        Ok(resp) => match resp.into_string() {
            Ok(body) => body,
            Err(_) => return,
        },
        Err(_) => return,
    };

    // Extract the base64 payload between PEM markers
    let cert_b64: String = pem_body
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();

    if let Ok(cert_der) =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cert_b64)
    {
        // SAN extension OID 2.5.29.17 encoded as DER: 55 1d 11
        // Only search for the GitHub URI after the SAN OID marker to avoid
        // matching URL-like strings in other certificate fields.
        let san_oid: &[u8] = &[0x55, 0x1d, 0x11];
        if let Some(san_offset) = cert_der.windows(san_oid.len()).position(|w| w == san_oid) {
            let san_region = String::from_utf8_lossy(&cert_der[san_offset..]);
            if let Some(start) = san_region.find("https://github.com/")
                && let Some(end) = san_region[start..].find(|c: char| c.is_control())
            {
                let identity = &san_region[start..start + end];
                println!("\n  Sigstore signer: {identity}");
            }
        }
    }
}

#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
fn artifact_name() -> Result<&'static str> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok("hasp-linux-amd64")
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        Ok("hasp-linux-arm64")
    }

    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
    )))]
    {
        bail!("self-check is only supported for published Linux release artifacts");
    }
}
