#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! Paranoid audit: injection, permissions, typosquatting, transitive
//! composite-action injection.

mod common;
use common::*;

#[test]
fn paranoid_finds_multiple_audit_categories() {
    let dir = fixture("paranoid_audit");
    let o = run(
        &dir,
        &[
            "--dir", ".", "--allow-unsandboxed", "--no-verify", "--no-policy", "--paranoid",
        ],
    );
    let out = combined(&o).to_lowercase();
    let expected_any = [
        "expression-injection",
        "pull_request_target",
        "github_env",
        "typosquat",
        "permissions",
    ];
    let hits = expected_any
        .iter()
        .filter(|s| out.contains(&s.to_lowercase()))
        .count();
    assert!(hits >= 3, "expected ≥3 audit categories to fire, got {hits}: {out}");
}

#[test]
fn composite_transitive_injection_is_flagged() {
    let repo = make_git_repo("transitive_injection");
    let composite_dir = repo.join(".github/actions/bad");
    std::fs::create_dir_all(&composite_dir).unwrap();
    std::fs::write(
        composite_dir.join("action.yml"),
        "name: bad\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo \"${{ github.event.pull_request.title }}\"\n",
    )
    .unwrap();
    write_workflow(
        &repo,
        "caller.yml",
        "name: Caller\non:\n  pull_request_target:\n    types: [opened]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n      - uses: ./.github/actions/bad\n",
    );
    commit_all(&repo, "transitive injection");

    let o = run(
        &repo,
        &[
            "--dir",
            ".github/workflows",
            "--allow-unsandboxed",
            "--no-verify",
            "--no-policy",
            "--paranoid",
        ],
    );
    let out = combined(&o).to_lowercase();
    assert!(
        out.contains("injection") || out.contains("expression"),
        "expected transitive expression-injection finding: {out}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
