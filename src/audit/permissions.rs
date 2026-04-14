use std::path::Path;
use yaml_rust2::Yaml;

use super::{
    AuditFinding, Severity, key_jobs, key_permissions, key_persist_credentials, key_secrets,
    key_steps, key_uses, key_with,
};

// ─── Permissions audit ───────────────────────────────────────────────────────

pub(super) fn check_permissions(
    file: &Path,
    doc: &Yaml,
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) {
    let Some(map) = doc.as_hash() else {
        return;
    };

    let has_top = check_permissions_value(
        file,
        map.get(key_permissions()),
        "top-level",
        findings,
        level,
    );

    let mut saw_job = false;
    let mut missing_job_permissions = false;
    if let Some(Yaml::Hash(jobs)) = map.get(key_jobs()) {
        for (job_name, job_value) in jobs {
            if let Some(job_map) = job_value.as_hash() {
                saw_job = true;
                let label = job_name.as_str().unwrap_or("unknown");
                let has_job_permissions = check_permissions_value(
                    file,
                    job_map.get(key_permissions()),
                    &format!("jobs.{label}"),
                    findings,
                    level,
                );
                if !has_job_permissions {
                    missing_job_permissions = true;
                }
            }
        }
    }

    if !has_top && (!saw_job || missing_job_permissions) {
        findings.push(AuditFinding {
            file: file.to_path_buf(),
            severity: Severity::Medium,
            title: "Missing top-level permissions block".to_string(),
            detail: "No explicit top-level permissions block found, and one or more jobs \
                     also rely on inherited defaults. Depending on org/repo policy and \
                     trigger type, those jobs may receive broader GITHUB_TOKEN access \
                     than intended. Add `permissions: {}` at the workflow root or set \
                     explicit job-level permissions everywhere."
                .to_string(),
            is_warning: level.is_warn(),
        });
    }
}

pub(super) fn check_permissions_value(
    file: &Path,
    value: Option<&Yaml>,
    context: &str,
    findings: &mut Vec<AuditFinding>,
    level: crate::policy::CheckLevel,
) -> bool {
    let Some(val) = value else {
        return false;
    };

    if let Some(s) = val.as_str()
        && s == "write-all"
    {
        findings.push(AuditFinding {
            file: file.to_path_buf(),
            severity: Severity::Critical,
            title: format!("write-all permissions at {context}"),
            detail: format!(
                "{context} has `permissions: write-all`. Grants the GITHUB_TOKEN \
                 write access to ALL scopes. Restrict to only needed scopes."
            ),
            is_warning: level.is_warn(),
        });
    }

    if let Some(perm_map) = val.as_hash() {
        let dangerous = [
            (
                "contents",
                "write",
                "push code, create releases, and modify repo contents",
            ),
            ("actions", "write", "approve/cancel other workflow runs"),
            (
                "packages",
                "write",
                "publish packages under your org's name",
            ),
        ];
        for (scope, bad_level, desc) in &dangerous {
            let key = Yaml::String(scope.to_string());
            if let Some(perm_val) = perm_map.get(&key)
                && perm_val.as_str() == Some(bad_level)
            {
                findings.push(AuditFinding {
                    file: file.to_path_buf(),
                    severity: Severity::High,
                    title: format!("{context}: {scope}: {bad_level}"),
                    detail: format!(
                        "`{scope}: write` at {context} allows the GITHUB_TOKEN to {desc}. \
                         Only grant if genuinely needed."
                    ),
                    is_warning: level.is_warn(),
                });
            }
        }
    }

    true
}

// ─── secrets: inherit detection ──────────────────────────────────────────────

pub(super) fn check_secrets_inherit(
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

    for (job_name, job_value) in jobs {
        let Some(job_map) = job_value.as_hash() else {
            continue;
        };
        let Some(secrets_val) = job_map.get(key_secrets()) else {
            continue;
        };

        if secrets_val.as_str() == Some("inherit") {
            let job_label = job_name.as_str().unwrap_or("<unnamed job>");
            findings.push(AuditFinding {
                file: file.to_path_buf(),
                severity: Severity::High,
                title: format!(
                    "Reusable workflow call uses `secrets: inherit` in job `{job_label}`"
                ),
                detail: format!(
                    "Job `{job_label}` passes all secrets to a reusable workflow via \
                     `secrets: inherit`. This exposes every repository secret to the called \
                     workflow. Pass only the specific secrets needed instead."
                ),
                is_warning: level.is_warn(),
            });
        }
    }
}

// ─── Checkout persist-credentials detection ──────────────────────────────────

pub(super) fn check_checkout_persist_credentials(
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
            let Some(uses_str) = step_map.get(key_uses()).and_then(|u| u.as_str()) else {
                continue;
            };

            // Only check actions/checkout
            if !uses_str.starts_with("actions/checkout") {
                continue;
            }

            let persist = step_map
                .get(key_with())
                .and_then(|w| w.as_hash())
                .and_then(|m| m.get(key_persist_credentials()));

            let is_disabled =
                persist.is_some_and(|v| v.as_bool() == Some(false) || v.as_str() == Some("false"));

            if !is_disabled {
                findings.push(AuditFinding {
                    file: file.to_path_buf(),
                    severity: Severity::Medium,
                    title: "actions/checkout persists credentials on disk".to_string(),
                    detail: format!(
                        "`{uses_str}` does not set `persist-credentials: false`. The \
                         GITHUB_TOKEN is written to `.git/config` and remains accessible to \
                         all subsequent steps. Set `persist-credentials: false` to remove it \
                         after checkout."
                    ),
                    is_warning: level.is_warn(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Severity;
    use super::super::tests_common::run_audit;

    #[test]
    fn does_not_flag_missing_top_level_permissions_when_all_jobs_are_explicit() {
        let findings = run_audit(
            "
on: push
jobs:
  build:
    permissions: {}
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
  test:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
",
        );

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Missing top-level permissions block")
        );
    }

    #[test]
    fn flags_missing_top_level_permissions_when_jobs_inherit_defaults() {
        let findings = run_audit(
            "
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
",
        );

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Missing top-level permissions block")
        );
    }

    #[test]
    fn flags_secrets_inherit() {
        let findings = run_audit(
            "
on: push
permissions: {}
jobs:
  deploy:
    uses: org/repo/.github/workflows/deploy.yml@main
    secrets: inherit
",
        );
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.title.contains("secrets: inherit"))
        );
    }

    #[test]
    fn no_finding_for_explicit_secrets() {
        let findings = run_audit(
            "
on: push
permissions: {}
jobs:
  deploy:
    uses: org/repo/.github/workflows/deploy.yml@main
    secrets:
      TOKEN: ${{ secrets.DEPLOY_TOKEN }}
",
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("secrets: inherit"))
        );
    }

    #[test]
    fn flags_checkout_without_persist_credentials_false() {
        let findings = run_audit(
            "
on: push
permissions: {}
jobs:
  test:
    permissions: {}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
",
        );
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium && f.title.contains("persist"))
        );
    }

    #[test]
    fn no_finding_for_checkout_with_persist_false() {
        let findings = run_audit(
            "
on: push
permissions: {}
jobs:
  test:
    permissions: {}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
",
        );
        assert!(!findings.iter().any(|f| f.title.contains("persist")));
    }
}
