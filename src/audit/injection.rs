use std::path::Path;
use yaml_rust2::Yaml;

use super::{
    AuditFinding, Severity, find_expressions, injectable_contexts, key_jobs, key_name, key_run,
    key_steps, key_with,
};

// ─── Expression injection ────────────────────────────────────────────────────

pub(super) fn check_expression_injection(
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

            let step_name = step_map
                .get(key_name())
                .and_then(|n| n.as_str())
                .unwrap_or("<unnamed step>");

            // Check run: scripts
            if let Some(script) = step_map.get(key_run()).and_then(|r| r.as_str()) {
                check_script_injection(
                    file,
                    step_name,
                    script,
                    Severity::Critical,
                    findings,
                    level,
                );
            }

            // Check with: values
            if let Some(with_map) = step_map.get(key_with()).and_then(|w| w.as_hash()) {
                for (_key, val) in with_map {
                    if let Some(val_str) = val.as_str() {
                        check_script_injection(
                            file,
                            step_name,
                            val_str,
                            Severity::High,
                            findings,
                            level,
                        );
                    }
                }
            }
        }
    }
}

pub(super) fn check_script_injection(
    file: &Path,
    step_name: &str,
    text: &str,
    severity: Severity,
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    for expr in find_expressions(text) {
        let trimmed = expr.trim();
        for ctx in injectable_contexts() {
            // Check both direct use (starts_with) and wrapped use via
            // format(), join(), fromJSON() etc. (contains).
            if trimmed.contains(ctx) {
                let kind = if severity == Severity::Critical {
                    "Script injection"
                } else {
                    "Potential injection in action input"
                };
                findings.push(AuditFinding {
                    file: file.to_path_buf(),
                    severity,
                    title: format!("{kind} via ${{{{ {trimmed} }}}}"),
                    detail: format!(
                        "Step \"{step_name}\" uses user-controlled input \
                         `${{{{ {trimmed} }}}}`. Fix: assign to an env var and \
                         reference as $ENV_VAR instead of ${{{{ }}}} interpolation."
                    ),
                    is_warning: level.is_warn(),
                });
                break;
            }
        }
    }
}

// ─── GITHUB_ENV / GITHUB_PATH write detection ────────────────────────────────

pub(super) fn check_github_env_writes(
    file: &Path,
    doc: &Yaml,
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    const DANGEROUS_TARGETS: [&str; 2] = ["$GITHUB_ENV", "$GITHUB_PATH"];

    let Some(jobs) = doc
        .as_hash()
        .and_then(|m| m.get(key_jobs()))
        .and_then(|j| j.as_hash())
    else {
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
            let Some(script) = step_map.get(key_run()).and_then(|r| r.as_str()) else {
                continue;
            };

            let step_name = step_map
                .get(key_name())
                .and_then(|n| n.as_str())
                .unwrap_or("<unnamed step>");

            for target in &DANGEROUS_TARGETS {
                if script.contains(target) {
                    // Check if the write includes attacker-controlled expressions
                    let has_injection = find_expressions(script)
                        .iter()
                        .any(|expr| injectable_contexts().iter().any(|ctx| expr.contains(ctx)));

                    let (severity, detail) = if has_injection {
                        (
                            Severity::Critical,
                            format!(
                                "Step \"{step_name}\" writes to `{target}` using attacker-controlled \
                                 input. An attacker can inject arbitrary environment variables or PATH \
                                 entries, leading to code execution in subsequent steps."
                            ),
                        )
                    } else {
                        (
                            Severity::Medium,
                            format!(
                                "Step \"{step_name}\" writes to `{target}`. Writes to GITHUB_ENV \
                                 and GITHUB_PATH modify the environment for all subsequent steps in \
                                 the job. Ensure no untrusted data flows into these writes."
                            ),
                        )
                    };

                    findings.push(AuditFinding {
                        file: file.to_path_buf(),
                        severity,
                        title: format!("Dangerous write to {target}"),
                        detail,
                        is_warning: level.is_warn(),
                    });
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Severity;
    use super::super::tests_common::run_audit;

    #[test]
    fn flags_github_env_write_with_injection() {
        let findings = run_audit(
            "
on: pull_request
permissions: {}
jobs:
  test:
    permissions: {}
    runs-on: ubuntu-latest
    steps:
      - run: echo \"FOO=${{ github.event.pull_request.title }}\" >> $GITHUB_ENV
",
        );
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("GITHUB_ENV"))
        );
    }

    #[test]
    fn flags_github_env_write_without_injection_as_medium() {
        let findings = run_audit(
            "
on: push
permissions: {}
jobs:
  test:
    permissions: {}
    runs-on: ubuntu-latest
    steps:
      - run: echo \"FOO=bar\" >> $GITHUB_ENV
",
        );
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium && f.title.contains("GITHUB_ENV"))
        );
    }
}
