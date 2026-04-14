use crate::error::{Context, Result, bail};
use std::path::Path;
use yaml_rust2::{Yaml, YamlLoader};

const MAX_MANIFEST_SIZE: u64 = 256 * 1024; // 256 KiB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InjectMode {
    Header,
    Basic,
    None,
}

#[derive(Debug, Clone)]
pub(crate) struct SecretGrant {
    pub(crate) env_var: String,
    pub(crate) domains: Vec<String>,
    pub(crate) inject: InjectMode,
    pub(crate) header_prefix: String,
}

#[derive(Debug, Clone)]
pub(crate) struct StepManifest {
    pub(crate) secrets: Vec<SecretGrant>,
    pub(crate) network_allow: Vec<String>,
    pub(crate) writable_dirs: Vec<String>,
}

impl StepManifest {
    pub(crate) const fn empty() -> Self {
        Self {
            secrets: Vec::new(),
            network_allow: Vec::new(),
            writable_dirs: Vec::new(),
        }
    }

    pub(crate) fn load(path: &Path) -> Result<Self> {
        check_file_size(path)?;
        let content = std::fs::read_to_string(path)
            .context(format!("Failed to read manifest {}", path.display()))?;
        Self::parse_text(&content)
    }

    pub(crate) fn parse_text(text: &str) -> Result<Self> {
        let docs = YamlLoader::load_from_str(text).context("Invalid YAML in manifest")?;
        if docs.is_empty() {
            return Ok(Self::empty());
        }
        let doc = &docs[0];
        if doc.is_null() || doc.is_badvalue() {
            return Ok(Self::empty());
        }

        let secrets = parse_secrets(doc)?;
        let network_allow = parse_network_allow(doc)?;
        let writable_dirs = parse_writable_dirs(doc)?;

        // Union secret domains into network_allow for the complete allowlist
        let mut all_domains = network_allow;
        for grant in &secrets {
            for domain in &grant.domains {
                if !all_domains.contains(domain) {
                    all_domains.push(domain.clone());
                }
            }
        }

        Ok(Self {
            secrets,
            network_allow: all_domains,
            writable_dirs,
        })
    }

    /// All domains that the child process is allowed to reach (union of
    /// explicit network.allow and all secret grant domains).
    pub(crate) fn all_allowed_domains(&self) -> &[String] {
        &self.network_allow
    }
}

fn check_file_size(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path)
        .context(format!("Failed to read metadata for {}", path.display()))?;
    if meta.len() > MAX_MANIFEST_SIZE {
        bail!(
            "Manifest file {} is too large ({} bytes, max {} bytes)",
            path.display(),
            meta.len(),
            MAX_MANIFEST_SIZE
        );
    }
    Ok(())
}

fn parse_secrets(doc: &Yaml) -> Result<Vec<SecretGrant>> {
    let secrets_node = &doc["secrets"];
    if secrets_node.is_badvalue() || secrets_node.is_null() {
        return Ok(Vec::new());
    }
    let map = secrets_node
        .as_hash()
        .context("manifest `secrets` must be a mapping")?;

    let mut grants = Vec::with_capacity(map.len());
    for (key, value) in map {
        let env_var = key
            .as_str()
            .context("secret key must be a string")?
            .to_string();
        validate_env_var_name(&env_var)?;

        let domains = parse_string_list(&value["domains"], "domains")?;
        if domains.is_empty() {
            bail!("secret `{env_var}` must declare at least one domain");
        }
        for domain in &domains {
            validate_domain(domain)?;
        }

        let inject = match value["inject"].as_str() {
            Some("header") | None => InjectMode::Header,
            Some("basic") => InjectMode::Basic,
            Some("none") => InjectMode::None,
            Some(other) => bail!("unknown inject mode `{other}` for secret `{env_var}`"),
        };

        let header_prefix = value["header_prefix"]
            .as_str()
            .unwrap_or("Bearer ")
            .to_string();
        // Reject control characters in header_prefix — YAML double-quoted
        // strings interpret \r\n as literal CR+LF, which would inject
        // arbitrary HTTP headers into upstream requests.
        if header_prefix.bytes().any(|b| b.is_ascii_control()) {
            bail!("header_prefix for secret `{env_var}` contains control characters");
        }

        grants.push(SecretGrant {
            env_var,
            domains,
            inject,
            header_prefix,
        });
    }
    Ok(grants)
}

fn parse_network_allow(doc: &Yaml) -> Result<Vec<String>> {
    let network_node = &doc["network"];
    if network_node.is_badvalue() || network_node.is_null() {
        return Ok(Vec::new());
    }
    let allow_node = &network_node["allow"];
    if allow_node.is_badvalue() || allow_node.is_null() {
        return Ok(Vec::new());
    }
    let domains = parse_string_list(allow_node, "network.allow")?;
    for domain in &domains {
        validate_domain(domain)?;
    }
    Ok(domains)
}

fn parse_writable_dirs(doc: &Yaml) -> Result<Vec<String>> {
    let fs_node = &doc["filesystem"];
    if fs_node.is_badvalue() || fs_node.is_null() {
        return Ok(Vec::new());
    }
    let writable_node = &fs_node["writable"];
    if writable_node.is_badvalue() || writable_node.is_null() {
        return Ok(Vec::new());
    }
    parse_string_list(writable_node, "filesystem.writable")
}

fn parse_string_list(node: &Yaml, label: &str) -> Result<Vec<String>> {
    let arr = node
        .as_vec()
        .context(format!("`{label}` must be a sequence"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .context(format!("`{label}` items must be strings"))?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn validate_env_var_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        bail!("Invalid env var name: expected 1..=128 characters");
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!("Invalid env var name `{name}`: only A-Z, a-z, 0-9, _ allowed");
    }
    if name.as_bytes()[0].is_ascii_digit() {
        bail!("Invalid env var name `{name}`: must not start with a digit");
    }
    Ok(())
}

fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > 253 {
        bail!("Invalid domain: expected 1..=253 characters");
    }
    // Reject obviously unsafe patterns
    if domain.contains('/') || domain.contains('\\') || domain.contains(':') {
        bail!("Invalid domain `{domain}`: must not contain / \\ or :");
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.starts_with('-') {
        bail!("Invalid domain `{domain}`: must not start/end with . or -");
    }
    if domain.contains("..") {
        bail!("Invalid domain `{domain}`: consecutive dots not allowed");
    }
    if !domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        bail!("Invalid domain `{domain}`: unexpected characters");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_manifest() {
        let yaml = r#"
secrets:
  NPM_TOKEN:
    domains: [registry.npmjs.org]
    inject: header
    header_prefix: "Bearer "
  PYPI_TOKEN:
    domains: [upload.pypi.org]
    inject: basic

network:
  allow: [registry.npmjs.org]

filesystem:
  writable: [./dist, ./build]
"#;
        let m = StepManifest::parse_text(yaml).unwrap();
        assert_eq!(m.secrets.len(), 2);
        assert_eq!(m.secrets[0].env_var, "NPM_TOKEN");
        assert_eq!(m.secrets[0].domains, vec!["registry.npmjs.org"]);
        assert_eq!(m.secrets[0].inject, InjectMode::Header);
        assert_eq!(m.secrets[0].header_prefix, "Bearer ");
        assert_eq!(m.secrets[1].env_var, "PYPI_TOKEN");
        assert_eq!(m.secrets[1].inject, InjectMode::Basic);
        // union: network.allow + secret domains (deduped)
        assert!(m.network_allow.contains(&"registry.npmjs.org".to_string()));
        assert!(m.network_allow.contains(&"upload.pypi.org".to_string()));
        assert_eq!(m.writable_dirs, vec!["./dist", "./build"]);
    }

    #[test]
    fn empty_manifest() {
        let m = StepManifest::parse_text("").unwrap();
        assert!(m.secrets.is_empty());
        assert!(m.network_allow.is_empty());
        assert!(m.writable_dirs.is_empty());
    }

    #[test]
    fn defaults_inject_to_header() {
        let yaml = "\
secrets:
  TOKEN:
    domains: [example.com]
";
        let m = StepManifest::parse_text(yaml).unwrap();
        assert_eq!(m.secrets[0].inject, InjectMode::Header);
        assert_eq!(m.secrets[0].header_prefix, "Bearer ");
    }

    #[test]
    fn rejects_invalid_env_var() {
        let yaml = "\
secrets:
  1BAD:
    domains: [example.com]
";
        StepManifest::parse_text(yaml).unwrap_err();
    }

    #[test]
    fn rejects_empty_domains() {
        let yaml = "\
secrets:
  TOKEN:
    domains: []
";
        StepManifest::parse_text(yaml).unwrap_err();
    }

    #[test]
    fn rejects_domain_with_path() {
        let yaml = "\
secrets:
  TOKEN:
    domains: [example.com/path]
";
        StepManifest::parse_text(yaml).unwrap_err();
    }

    #[test]
    fn rejects_unknown_inject_mode() {
        let yaml = "\
secrets:
  TOKEN:
    domains: [example.com]
    inject: cookie
";
        StepManifest::parse_text(yaml).unwrap_err();
    }

    #[test]
    fn validates_domain_characters() {
        validate_domain("registry.npmjs.org").unwrap();
        validate_domain("my-host.example.com").unwrap();
        validate_domain("host:8080").unwrap_err();
        validate_domain("host/path").unwrap_err();
        validate_domain("host with space").unwrap_err();
    }

    #[test]
    fn rejects_domain_leading_trailing_dots() {
        validate_domain(".example.com").unwrap_err();
        validate_domain("example.com.").unwrap_err();
        validate_domain("..").unwrap_err();
        validate_domain(".").unwrap_err();
    }

    #[test]
    fn rejects_domain_consecutive_dots() {
        validate_domain("example..com").unwrap_err();
    }

    #[test]
    fn rejects_domain_leading_hyphen() {
        validate_domain("-example.com").unwrap_err();
    }

    #[test]
    fn rejects_header_prefix_with_crlf() {
        let yaml = "\
secrets:
  TOKEN:
    domains: [example.com]
    inject: header
    header_prefix: \"Bearer \\r\\nEvil: injected\\r\\n\"
";
        StepManifest::parse_text(yaml).unwrap_err();
    }

    #[test]
    fn rejects_header_prefix_with_newline() {
        let yaml = "\
secrets:
  TOKEN:
    domains: [example.com]
    header_prefix: \"line1\\nline2\"
";
        StepManifest::parse_text(yaml).unwrap_err();
    }

    #[test]
    fn validates_env_var_names() {
        validate_env_var_name("NPM_TOKEN").unwrap();
        validate_env_var_name("a").unwrap();
        validate_env_var_name("").unwrap_err();
        validate_env_var_name("1ABC").unwrap_err();
        validate_env_var_name("MY-TOKEN").unwrap_err();
    }
}
