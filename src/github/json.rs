use crate::error::{Context, Result, bail};
use base64::Engine as _;
use rustls::pki_types::CertificateDer;
use sha2::Digest;
use std::sync::OnceLock;
use yaml_rust2::Yaml;

use super::client::{AnnotatedTagInfo, RepoInfo};

// ─── Cached YAML key accessors (avoid repeated heap allocation) ──────────────

macro_rules! yaml_key {
    ($fn_name:ident, $key:expr) => {
        pub(super) fn $fn_name() -> &'static Yaml {
            static K: OnceLock<Yaml> = OnceLock::new();
            K.get_or_init(|| Yaml::String($key.to_string()))
        }
    };
}

yaml_key!(key_sha, "sha");
yaml_key!(key_name, "name");
yaml_key!(key_object, "object");
yaml_key!(key_tagger, "tagger");
yaml_key!(key_date, "date");
yaml_key!(key_content, "content");
yaml_key!(key_encoding, "encoding");
yaml_key!(key_verification, "verification");
yaml_key!(key_verified, "verified");
yaml_key!(key_type, "type");
yaml_key!(key_default_branch, "default_branch");
yaml_key!(key_created_at, "created_at");
yaml_key!(key_stargazers_count, "stargazers_count");
yaml_key!(key_forks_count, "forks_count");
yaml_key!(key_forks, "forks");
yaml_key!(key_commit, "commit");
yaml_key!(key_author, "author");
yaml_key!(key_committer, "committer");
yaml_key!(key_status, "status");
yaml_key!(key_runs, "runs");
yaml_key!(key_pre, "pre");
yaml_key!(key_post, "post");
yaml_key!(key_pre_entrypoint, "pre-entrypoint");
yaml_key!(key_post_entrypoint, "post-entrypoint");
yaml_key!(key_using, "using");
yaml_key!(key_steps, "steps");
yaml_key!(key_run, "run");
yaml_key!(key_uses, "uses");

pub(super) fn yaml_field_cached<'a>(value: &'a Yaml, key: &Yaml) -> Option<&'a Yaml> {
    value.as_hash()?.get(key)
}

// ─── JSON / YAML parsing utilities ───────────────────────────────────────────

pub(super) fn parse_json_doc(body: &str) -> Result<Yaml> {
    let mut docs =
        yaml_rust2::YamlLoader::load_from_str(body).context("Failed to parse GitHub API JSON")?;
    docs.pop()
        .context("GitHub API response did not contain a JSON document")
}

pub(super) fn parse_git_ref_target(body: &str) -> Result<(String, String)> {
    let doc = parse_json_doc(body)?;
    let obj = yaml_field_cached(&doc, key_object());
    let obj_type = obj
        .and_then(|o| yaml_field_cached(o, key_type()))
        .and_then(Yaml::as_str)
        .context("Missing object.type in git/ref response")?
        .to_string();
    let sha = obj
        .and_then(|o| yaml_field_cached(o, key_sha()))
        .and_then(Yaml::as_str)
        .context("Missing object.sha in git/ref response")?
        .to_string();
    Ok((obj_type, sha))
}

#[cfg(test)]
pub(super) fn parse_git_tag_target(body: &str) -> Result<String> {
    Ok(parse_git_tag_info(body)?.object_sha)
}

pub(super) fn parse_git_tag_info(body: &str) -> Result<AnnotatedTagInfo> {
    let doc = parse_json_doc(body)?;
    Ok(AnnotatedTagInfo {
        object_sha: yaml_field_cached(&doc, key_object())
            .and_then(|o| yaml_field_cached(o, key_sha()))
            .and_then(Yaml::as_str)
            .map(str::to_string)
            .context("Missing object.sha in tag response")?,
        tagger_date: yaml_field_cached(&doc, key_tagger())
            .and_then(|t| yaml_field_cached(t, key_date()))
            .and_then(Yaml::as_str)
            .map(str::to_string),
    })
}

pub(super) fn parse_repo_info(body: &str) -> Result<RepoInfo> {
    let doc = parse_json_doc(body)?;
    Ok(RepoInfo {
        default_branch: yaml_field_cached(&doc, key_default_branch())
            .and_then(Yaml::as_str)
            .unwrap_or("main")
            .to_string(),
        created_at: yaml_field_cached(&doc, key_created_at())
            .and_then(Yaml::as_str)
            .map(str::to_string),
        stargazers_count: yaml_field_cached(&doc, key_stargazers_count())
            .and_then(Yaml::as_i64)
            .and_then(|v| u64::try_from(v).ok()),
        forks_count: yaml_field_cached(&doc, key_forks_count())
            .and_then(Yaml::as_i64)
            .and_then(|v| u64::try_from(v).ok())
            .or_else(|| {
                yaml_field_cached(&doc, key_forks())
                    .and_then(Yaml::as_i64)
                    .and_then(|v| u64::try_from(v).ok())
            }),
    })
}

pub(super) fn parse_contents_body(body: &str) -> Result<String> {
    let doc = parse_json_doc(body)?;
    let encoding = yaml_field_cached(&doc, key_encoding())
        .and_then(Yaml::as_str)
        .unwrap_or("");
    if encoding != "base64" {
        bail!("Unsupported GitHub contents encoding `{encoding}`");
    }

    let content = yaml_field_cached(&doc, key_content())
        .and_then(Yaml::as_str)
        .context("Missing content field in contents response")?;
    let cleaned: String = content
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .context("Failed to decode GitHub contents base64")?;
    String::from_utf8(decoded).context("GitHub contents were not valid UTF-8")
}

yaml_key!(key_ahead_by, "ahead_by");
yaml_key!(key_html_url, "html_url");
yaml_key!(key_commits, "commits");
yaml_key!(key_message, "message");
yaml_key!(key_files, "files");
yaml_key!(key_total_commits, "total_commits");

pub(super) fn parse_compare_response(body: &str) -> Result<super::client::CompareResult> {
    let doc = parse_json_doc(body)?;

    let ahead_by = yaml_field_cached(&doc, key_ahead_by())
        .or_else(|| yaml_field_cached(&doc, key_total_commits()))
        .and_then(Yaml::as_i64)
        .unwrap_or(0);

    let html_url = yaml_field_cached(&doc, key_html_url())
        .and_then(Yaml::as_str)
        .unwrap_or("")
        .to_string();

    let files_changed = yaml_field_cached(&doc, key_files())
        .and_then(Yaml::as_vec)
        .map_or(0, Vec::len);

    let mut commit_summaries = Vec::new();
    if let Some(commits) = yaml_field_cached(&doc, key_commits()).and_then(Yaml::as_vec) {
        for (i, commit_entry) in commits.iter().enumerate() {
            if i >= 10 {
                break;
            }
            let msg = yaml_field_cached(commit_entry, key_commit())
                .and_then(|c| yaml_field_cached(c, key_message()))
                .and_then(Yaml::as_str)
                .unwrap_or("");
            // Take only the first line of the commit message
            let first_line = msg.lines().next().unwrap_or("");
            commit_summaries.push(first_line.to_string());
        }
    }

    Ok(super::client::CompareResult {
        owner: String::new(),
        repo: String::new(),
        old_sha: String::new(),
        new_sha: String::new(),
        ahead_by: u32::try_from(ahead_by).unwrap_or(0),
        files_changed: u32::try_from(files_changed).unwrap_or(0),
        commit_summaries,
        html_url,
    })
}

/// Search an already-parsed tags JSON array for a tag pointing to `target_sha`.
pub(super) fn find_tag_in_parsed_list(doc: &Yaml, target_sha: &str) -> Option<String> {
    let arr = doc.as_vec()?;
    for item in arr {
        let sha = yaml_field_cached(item, key_commit())
            .and_then(|c| yaml_field_cached(c, key_sha()))
            .and_then(Yaml::as_str);
        let Some(sha) = sha else {
            continue;
        };
        if sha == target_sha {
            return yaml_field_cached(item, key_name())
                .and_then(Yaml::as_str)
                .map(str::to_string);
        }
    }
    None
}

pub(super) fn api_url(path: &str) -> String {
    debug_assert!(
        !path.starts_with("http"),
        "api_url expects a relative path, not a full URL"
    );
    format!("https://api.github.com/{}", path.trim_start_matches('/'))
}

pub(super) fn spki_hash(cert: &CertificateDer<'_>) -> std::result::Result<[u8; 32], rustls::Error> {
    let parsed = rustls::server::ParsedCertificate::try_from(cert)?;
    let mut hasher = sha2::Sha256::new();
    Digest::update(&mut hasher, parsed.subject_public_key_info().as_ref());
    Ok(hasher.finalize().into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_git_ref_uses_nested_object_fields() {
        let body = r#"{
            "sha": "top-level-ref-sha",
            "type": "not-the-target",
            "object": {
                "type": "tag",
                "sha": "nested-tag-object-sha"
            }
        }"#;

        let (obj_type, sha) = parse_git_ref_target(body).unwrap();
        assert_eq!(obj_type, "tag");
        assert_eq!(sha, "nested-tag-object-sha");
    }

    #[test]
    fn parse_git_tag_ignores_message_text_that_mentions_object_sha() {
        let body = r#"{
            "sha": "annotated-tag-sha",
            "message": "attacker text with \\\"object\\\": {\\\"sha\\\":\\\"evil\\\"}",
            "object": {
                "type": "commit",
                "sha": "real-commit-sha"
            }
        }"#;

        assert_eq!(parse_git_tag_target(body).unwrap(), "real-commit-sha");
        assert_eq!(
            parse_git_tag_info(body).unwrap().object_sha,
            "real-commit-sha"
        );
    }

    #[test]
    fn parse_contents_body_decodes_base64_content() {
        let body = r#"{
            "encoding": "base64",
            "content": "bmFtZTogdGVzdAo=\n"
        }"#;

        assert_eq!(parse_contents_body(body).unwrap(), "name: test\n");
    }
}
