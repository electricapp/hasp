use std::path::Path;
use std::sync::OnceLock;
use yaml_rust2::Yaml;

use super::{
    AuditFinding, Severity, find_expressions, key_if, key_jobs, key_on, key_ref, key_repository,
    key_steps, key_uses, key_with, lines,
};

// ─── Privileged trigger + checkout detection ─────────────────────────────

/// Attacker-controlled expressions used in privileged `actions/checkout` inputs.
pub(super) fn attacker_ref_patterns() -> &'static [&'static str] {
    static DATA: OnceLock<Vec<&str>> = OnceLock::new();
    DATA.get_or_init(|| lines(include_str!("../../data/attacker_ref_patterns.txt")))
}

pub(super) fn attacker_repository_patterns() -> &'static [&'static str] {
    static DATA: OnceLock<Vec<&str>> = OnceLock::new();
    DATA.get_or_init(|| lines(include_str!("../../data/attacker_repository_patterns.txt")))
}

pub(super) fn check_privileged_triggers(
    file: &Path,
    doc: &Yaml,
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    let Some(map) = doc.as_hash() else {
        return;
    };

    // Check if on: block contains pull_request_target or workflow_run
    // yaml_rust2 parses unquoted `on` as Yaml::Boolean(true)
    let true_key = Yaml::Boolean(true);
    let Some(on_val) = map.get(key_on()).or_else(|| map.get(&true_key)) else {
        return;
    };

    let has_prt = has_trigger(on_val, "pull_request_target");
    let has_wfr = has_trigger(on_val, "workflow_run");
    if !has_prt && !has_wfr {
        return;
    }

    let trigger_name = if has_prt {
        "pull_request_target"
    } else {
        "workflow_run"
    };

    // Scan all job steps for actions/checkout with attacker-controlled ref:
    let Some(jobs) = map.get(key_jobs()).and_then(|j| j.as_hash()) else {
        return;
    };

    for (_job_name, job_value) in jobs {
        let Some(steps) = job_value
            .as_hash()
            .and_then(|m| m.get(key_steps()))
            .and_then(|s| s.as_vec())
        else {
            continue;
        };

        for step in steps {
            let Some(step_map) = step.as_hash() else {
                continue;
            };

            // Check if this step uses actions/checkout
            let uses_str = match step_map.get(key_uses()).and_then(|u| u.as_str()) {
                Some(s) if s.starts_with("actions/checkout") => s,
                _ => continue,
            };

            let Some(with_map) = step_map.get(key_with()).and_then(|w| w.as_hash()) else {
                continue;
            };

            let inputs: [(&str, Option<&Yaml>, &[&str]); 2] = [
                ("ref", with_map.get(key_ref()), attacker_ref_patterns()),
                (
                    "repository",
                    with_map.get(key_repository()),
                    attacker_repository_patterns(),
                ),
            ];

            let mut flagged = false;
            for (input_name, input_value, patterns) in inputs {
                let Some(input_value) = input_value.and_then(|v| v.as_str()) else {
                    continue;
                };

                for expr in find_expressions(input_value) {
                    let trimmed = expr.trim();
                    if patterns.iter().any(|pattern| trimmed.contains(pattern)) {
                        findings.push(AuditFinding {
                            file: file.to_path_buf(),
                            severity: Severity::Critical,
                            title: format!(
                                "Privileged checkout of attacker code in {trigger_name} workflow"
                            ),
                            detail: format!(
                                "`{uses_str}` uses attacker-controlled `with.{input_name}` \
                                 expression `${{{{ {trimmed} }}}}` in a `{trigger_name}` \
                                 workflow. This can check out attacker code with write access \
                                 to the repo and secrets. Keep untrusted code in a separate \
                                 unprivileged workflow and use only fixed, trusted checkout \
                                 inputs here."
                            ),
                            is_warning: level.is_warn(),
                        });
                        flagged = true;
                        break;
                    }
                }

                if flagged {
                    break;
                }
            }
        }
    }
}

pub(super) fn has_trigger(on_val: &Yaml, trigger: &str) -> bool {
    #[allow(clippy::wildcard_enum_match_arm)] // Yaml has many non-string/array/hash variants
    match on_val {
        Yaml::String(s) => s == trigger,
        Yaml::Array(arr) => arr.iter().any(|v| v.as_str() == Some(trigger)),
        Yaml::Hash(map) => map.contains_key(&Yaml::String(trigger.to_string())),
        _ => false,
    }
}

// ─── Unsound contains() in conditions ────────────────────────────────────────

pub(super) const ATTACKER_CONTROLLED_CONTAINS_CONTEXTS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.label.name",
    "github.head_ref",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
];

pub(super) fn check_unsound_contains(
    file: &Path,
    doc: &Yaml,
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    let Some(jobs) = doc
        .as_hash()
        .and_then(|m| m.get(key_jobs()))
        .and_then(|j| j.as_hash())
    else {
        return;
    };

    for (_job_name, job_value) in jobs {
        let Some(job_map) = job_value.as_hash() else {
            continue;
        };

        // Check job-level if:
        if let Some(cond) = job_map.get(key_if()).and_then(|v| v.as_str()) {
            check_contains_bypass(file, cond, findings, level);
        }

        // Check step-level if:
        let Some(steps) = job_map.get(key_steps()).and_then(|s| s.as_vec()) else {
            continue;
        };
        for step in steps {
            if let Some(cond) = step
                .as_hash()
                .and_then(|m| m.get(key_if()))
                .and_then(|v| v.as_str())
            {
                check_contains_bypass(file, cond, findings, level);
            }
        }
    }
}

pub(super) fn check_contains_bypass(
    file: &Path,
    condition: &str,
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    // Look for contains(<attacker-context>, 'literal') patterns
    let lower = condition.to_lowercase();
    if !lower.contains("contains(") {
        return;
    }

    for ctx in ATTACKER_CONTROLLED_CONTAINS_CONTEXTS {
        if lower.contains(ctx) && lower.contains("contains(") {
            findings.push(AuditFinding {
                file: file.to_path_buf(),
                severity: Severity::High,
                title: "Bypassable `contains()` check on attacker-controlled input".to_string(),
                detail: format!(
                    "Condition uses `contains()` with attacker-controlled context `{ctx}`. \
                     `contains()` matches substrings, so an attacker can craft input that \
                     includes the expected value as a substring to bypass the check. Use \
                     exact equality (`==`) instead."
                ),
                is_warning: level.is_warn(),
            });
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Severity;
    use super::super::tests_common::run_audit;

    #[test]
    fn flags_attacker_controlled_checkout_repository() {
        let findings = run_audit(
            "
on: pull_request_target
permissions: {}
jobs:
  test:
    permissions: {}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
",
        );

        assert!(findings.iter().any(|finding| {
            finding.severity == Severity::Critical
                && finding
                    .title
                    .contains("Privileged checkout of attacker code")
        }));
    }

    #[test]
    fn flags_unsound_contains() {
        let findings = run_audit(
            "
on: pull_request
permissions: {}
jobs:
  test:
    permissions: {}
    runs-on: ubuntu-latest
    if: contains(github.event.label.name, 'deploy')
    steps:
      - run: echo deploy
",
        );
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.title.contains("contains()"))
        );
    }

    #[test]
    fn no_finding_for_safe_contains() {
        let findings = run_audit(
            "
on: push
permissions: {}
jobs:
  test:
    permissions: {}
    runs-on: ubuntu-latest
    if: contains(github.ref, 'refs/tags/')
    steps:
      - run: echo tag
",
        );
        assert!(!findings.iter().any(|f| f.title.contains("contains()")));
    }
}
