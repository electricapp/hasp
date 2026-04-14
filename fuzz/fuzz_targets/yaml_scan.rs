//! Fuzz target for the YAML workflow parser.
//!
//! Exercises yaml-rust2 on arbitrary input, then walks the parsed tree the
//! same way `scanner::extract_uses` does — extracting `uses:` values,
//! parsing `owner/repo@ref` patterns, and classifying ref kinds.
//!
//! Run: `cargo +nightly fuzz run yaml_scan`

#![no_main]

use libfuzzer_sys::fuzz_target;
use yaml_rust2::{Yaml, YamlLoader};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(docs) = YamlLoader::load_from_str(text) else {
        return;
    };
    let doc = docs.into_iter().next().unwrap_or(Yaml::Null);

    // Walk the tree the same way scanner::extract_uses does.
    walk_yaml(&doc);

    // Also exercise the version-comment extraction path.
    extract_version_comments(text);
});

fn walk_yaml(yaml: &Yaml) {
    match yaml {
        Yaml::Hash(map) => {
            for (k, v) in map {
                if k.as_str() == Some("uses") {
                    if let Some(uses_str) = v.as_str() {
                        parse_uses(uses_str);
                    }
                }
                if k.as_str() == Some("image") {
                    if let Some(image) = v.as_str() {
                        classify_container(image);
                    }
                }
                walk_yaml(v);
            }
        }
        Yaml::Array(arr) => {
            for item in arr {
                walk_yaml(item);
            }
        }
        _ => {}
    }
}

/// Mirrors `scanner::handle_uses_value` — parses `owner/repo@ref` patterns.
fn parse_uses(uses: &str) {
    if uses.starts_with("docker://") {
        classify_container(uses.strip_prefix("docker://").unwrap_or(""));
        return;
    }
    if uses.starts_with("./") || uses.starts_with("../") {
        return;
    }

    let Some(at) = uses.find('@') else { return };
    let (repo_part, ref_str) = (&uses[..at], &uses[at + 1..]);
    if ref_str.is_empty() {
        return;
    }

    let mut segments = repo_part.splitn(3, '/');
    let Some(owner) = segments.next().filter(|s| !s.is_empty()) else {
        return;
    };
    let Some(repo) = segments.next().filter(|s| !s.is_empty()) else {
        return;
    };
    let _path = segments.next();

    // Classify ref kind the same way the scanner does.
    let _is_full_sha =
        ref_str.len() == 40 && ref_str.bytes().all(|b| b.is_ascii_hexdigit());

    // Exercise the validation paths.
    let _ = is_safe_component(owner);
    let _ = is_safe_component(repo);
}

/// Mirrors `scanner::is_safe_github_component`.
fn is_safe_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && !s.contains("..")
        && !s.contains('/')
        && !s.contains('\\')
        && !s.contains('\0')
        && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Mirrors `scanner::is_digest_pinned_image`.
fn classify_container(image: &str) {
    if let Some((_, digest)) = image.rsplit_once("@sha256:") {
        let _pinned = digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit());
    }
}

/// Mirrors `scanner::extract_version_comments`.
fn extract_version_comments(content: &str) {
    for line in content.lines() {
        let trimmed = line.trim();
        let after_uses = if let Some(rest) = trimmed.strip_prefix("uses:") {
            rest.trim()
        } else if let Some(rest) = trimmed.strip_prefix("- uses:") {
            rest.trim()
        } else {
            continue;
        };

        if let Some(hash_pos) = after_uses.find('#') {
            let comment = after_uses[hash_pos + 1..].trim();
            for (i, _) in comment.match_indices('v') {
                let after_v = &comment[i + 1..];
                let _end = after_v
                    .find(|c: char| !c.is_ascii_digit() && c != '.')
                    .unwrap_or(after_v.len());
            }
        }
    }
}
