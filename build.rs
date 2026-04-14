use std::process::Command;

fn run_git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
}

fn main() {
    // Embed git commit hash at compile time for --version output
    let git_hash =
        run_git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=GIT_HASH={git_hash}");

    // Allow GITHUB_REPO env override (for CI where remote != canonical)
    let repo_slug = std::env::var("GITHUB_REPO")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            run_git(&["remote", "get-url", "origin"])
                .and_then(|url| parse_github_slug(&url))
                .unwrap_or_else(|| "OWNER/REPO".to_owned())
        });

    println!("cargo:rustc-env=GITHUB_REPO={repo_slug}");

    // Embed Rust version for --version and reproducibility
    let rust_version = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "unknown".to_owned(), |s| s.trim().to_owned());

    println!("cargo:rustc-env=RUST_VERSION={rust_version}");

    // Propagate SOURCE_DATE_EPOCH if set (reproducible builds)
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        println!("cargo:rustc-env=SOURCE_DATE_EPOCH={epoch}");
    }

    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/");
    println!("cargo:rerun-if-env-changed=GITHUB_REPO");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

/// Extract `owner/repo` from a GitHub remote URL.
///
/// Handles `https://github.com/owner/repo.git` and `git@github.com:owner/repo.git`.
fn parse_github_slug(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let path = if let Some(rest) = trimmed.strip_prefix("https://github.com/") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        rest
    } else {
        return None;
    };
    let cleaned = path.strip_suffix(".git").unwrap_or(path);
    let parts: Vec<&str> = cleaned.splitn(3, '/').collect();
    match (parts.first(), parts.get(1)) {
        (Some(owner), Some(repo)) if !owner.is_empty() && !repo.is_empty() => {
            Some(format!("{owner}/{repo}"))
        }
        _ => None,
    }
}
