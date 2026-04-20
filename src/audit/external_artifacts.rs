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

use std::path::{Path, PathBuf};
use yaml_rust2::Yaml;

use super::{AuditFinding, Severity, key_jobs, key_on, key_permissions, key_run, key_steps};

/// Patterns that flag third-party release-artifact downloads. These are
/// deliberately conservative: we only match clearly-external URLs.
const EXTERNAL_DOWNLOAD_PATTERNS: &[(&str, &str)] = &[
    ("curl -", "curl"),
    ("curl ", "curl"),
    ("wget ", "wget"),
    ("gh release download", "gh release download"),
    ("pip install -r https://", "pip install URL"),
    ("pip install https://", "pip install URL"),
    ("pip install git+https://", "pip install git+URL"),
    ("npm install https://", "npm install URL"),
    ("npm install git+https://", "npm install git+URL"),
    ("npm install --registry ", "npm install --registry"),
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

fn check_run_block(
    file: &Path,
    run: &str,
    pr_triggered: bool,
    privileged: bool,
    findings: &mut Vec<AuditFinding>,
    is_warning: bool,
) {
    let lower = run.to_ascii_lowercase();
    let mut hit: Option<&'static str> = None;
    for (needle, label) in EXTERNAL_DOWNLOAD_PATTERNS {
        if lower.contains(needle) {
            hit = Some(label);
            break;
        }
    }
    let Some(label) = hit else { return };

    // Bail if the run: is pulling a GitHub raw URL that's SHA-pinned; the
    // pinning already provides provenance equivalent to `uses:@<sha>`.
    if is_github_sha_pinned(&lower) {
        return;
    }

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
        Yaml::String(s) => matches!(s.as_str(), "pull_request" | "pull_request_target" | "issue_comment"),
        Yaml::Array(arr) => arr.iter().any(|v| {
            v.as_str().is_some_and(|s| {
                matches!(s, "pull_request" | "pull_request_target" | "issue_comment")
            })
        }),
        Yaml::Hash(map) => map.keys().any(|k| {
            k.as_str().is_some_and(|s| {
                matches!(s, "pull_request" | "pull_request_target" | "issue_comment")
            })
        }),
        _ => false,
    }
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
            findings
                .iter()
                .any(|f| f.title.contains("curl")),
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
            findings
                .iter()
                .any(|f| f.title.contains("go install")),
            "expected go-install finding, got: {findings:?}"
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
