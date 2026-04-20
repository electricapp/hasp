use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Launcher,
    Diff,
    Exec,
    InternalScan,
    InternalVerify,
    InternalProxy,
    InternalForwardProxy,
    InternalBpfHelper,
}

pub(crate) struct ExecArgs {
    pub(crate) manifest: Option<PathBuf>,
    pub(crate) writable_dirs: Vec<PathBuf>,
    pub(crate) command: Vec<String>,
}

#[allow(clippy::struct_excessive_bools)] // CLI flags are inherently boolean
pub(crate) struct Args {
    pub(crate) dir: PathBuf,
    pub(crate) strict: bool,
    pub(crate) paranoid: bool,
    pub(crate) no_verify: bool,
    pub(crate) min_sha_age_seconds: Option<i64>,
    pub(crate) security_action_min_sha_age_seconds: Option<i64>,
    pub(crate) self_check: bool,
    pub(crate) allow_unsandboxed: bool,
    pub(crate) policy_path: Option<PathBuf>,
    pub(crate) no_policy: bool,
    pub(crate) max_transitive_depth: u8,
    pub(crate) diff_base: Option<String>,
    pub(crate) oidc_policies: Vec<(String, PathBuf)>,
    pub(crate) no_oidc: bool,
    pub(crate) diff_format: Option<crate::diff::DiffFormat>,
    pub(crate) mode: Mode,
    pub(crate) exec: Option<ExecArgs>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            dir: PathBuf::from(".github/workflows"),
            strict: false,
            paranoid: false,
            no_verify: false,
            min_sha_age_seconds: None,
            security_action_min_sha_age_seconds: None,
            self_check: false,
            allow_unsandboxed: false,
            policy_path: None,
            no_policy: false,
            max_transitive_depth: 3,
            diff_base: None,
            oidc_policies: Vec::new(),
            no_oidc: false,
            diff_format: None,
            mode: Mode::Launcher,
            exec: None,
        }
    }
}

impl Args {
    pub(crate) const fn has_age_policy(&self) -> bool {
        self.min_sha_age_seconds.is_some() || self.security_action_min_sha_age_seconds.is_some()
    }
}

pub(crate) fn parse() -> Args {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1);

    // Peek at the first argument to detect subcommands
    let first = iter.next();
    if let Some(ref first_arg) = first {
        if first_arg == "exec" {
            return parse_exec(args, iter);
        }
        if first_arg == "diff" {
            return parse_diff(args, iter);
        }
    }
    // If not a subcommand, re-process the first argument in the normal loop
    let replay = first.into_iter().chain(iter);
    parse_scanner_args(&mut args, replay);
    args
}

fn parse_diff(mut args: Args, mut iter: std::iter::Skip<std::env::Args>) -> Args {
    args.mode = Mode::Diff;
    let mut positional: Vec<String> = Vec::new();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--format" => {
                let raw = iter.next().unwrap_or_else(|| {
                    eprintln!("hasp diff: --format requires a value (terse|markdown|json)");
                    std::process::exit(2);
                });
                args.diff_format = Some(crate::diff::DiffFormat::parse(&raw).unwrap_or_else(|e| {
                    eprintln!("hasp diff: {e}");
                    std::process::exit(2);
                }));
            }
            "-d" | "--dir" => {
                args.dir = PathBuf::from(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp diff: --dir requires a value");
                    std::process::exit(2);
                }));
            }
            "--policy" => {
                args.policy_path = Some(PathBuf::from(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp diff: --policy requires a value");
                    std::process::exit(2);
                })));
            }
            "--no-policy" => args.no_policy = true,
            "--paranoid" => args.paranoid = true,
            "--allow-unsandboxed" => args.allow_unsandboxed = true,
            "-h" | "--help" => {
                print_diff_help();
                std::process::exit(0);
            }
            other => {
                // First non-flag positional is the base ref.
                if other.starts_with('-') {
                    eprintln!("hasp diff: unknown option: {other}");
                    eprintln!("Try 'hasp diff --help' for usage.");
                    std::process::exit(2);
                }
                positional.push(other.to_string());
            }
        }
    }
    if positional.is_empty() {
        eprintln!("hasp diff: missing <base> argument (e.g. main, HEAD~1)");
        eprintln!("Usage: hasp diff <base> [--format terse|markdown|json]");
        std::process::exit(2);
    }
    if positional.len() > 1 {
        eprintln!(
            "hasp diff: expected 1 base ref, got {} ({:?})",
            positional.len(),
            positional
        );
        std::process::exit(2);
    }
    args.diff_base = Some(positional.remove(0));
    args
}

fn parse_exec(mut args: Args, mut iter: std::iter::Skip<std::env::Args>) -> Args {
    args.mode = Mode::Exec;
    let mut manifest: Option<PathBuf> = None;
    let mut writable_dirs: Vec<PathBuf> = Vec::new();
    let mut command: Vec<String> = Vec::new();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                command.extend(iter.by_ref());
                break;
            }
            "--manifest" | "-m" => {
                manifest = Some(PathBuf::from(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp exec: --manifest requires a file path");
                    std::process::exit(2);
                })));
            }
            "--writable" | "-w" => {
                writable_dirs.push(PathBuf::from(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp exec: --writable requires a directory path");
                    std::process::exit(2);
                })));
            }
            "--allow-unsandboxed" => args.allow_unsandboxed = true,
            "-h" | "--help" => {
                print_exec_help();
                std::process::exit(0);
            }
            other => {
                eprintln!("hasp exec: unknown option: {other}");
                eprintln!("Try 'hasp exec --help' for usage.");
                std::process::exit(2);
            }
        }
    }

    if command.is_empty() {
        eprintln!("hasp exec: no command specified after '--'");
        eprintln!("Usage: hasp exec [OPTIONS] -- command [args...]");
        std::process::exit(2);
    }

    args.exec = Some(ExecArgs {
        manifest,
        writable_dirs,
        command,
    });
    args
}

#[allow(clippy::too_many_lines)]
fn parse_scanner_args(args: &mut Args, mut iter: impl Iterator<Item = String>) {
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-d" | "--dir" => {
                args.dir = PathBuf::from(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp: --dir requires a value");
                    std::process::exit(2);
                }));
            }
            "--strict" => args.strict = true,
            "--paranoid" => args.paranoid = true,
            "--no-verify" => args.no_verify = true,
            "--min-sha-age" => {
                let value = iter.next().unwrap_or_else(|| {
                    eprintln!("hasp: --min-sha-age requires a value like 48h or 7d");
                    std::process::exit(2);
                });
                args.min_sha_age_seconds = Some(parse_duration_or_exit("--min-sha-age", &value));
            }
            "--security-action-min-sha-age" => {
                let value = iter.next().unwrap_or_else(|| {
                    eprintln!("hasp: --security-action-min-sha-age requires a value like 30d");
                    std::process::exit(2);
                });
                args.security_action_min_sha_age_seconds = Some(parse_duration_or_exit(
                    "--security-action-min-sha-age",
                    &value,
                ));
            }
            "--policy" => {
                args.policy_path = Some(PathBuf::from(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp: --policy requires a file path");
                    std::process::exit(2);
                })));
            }
            "--no-policy" => args.no_policy = true,
            "--max-transitive-depth" => {
                let value = iter.next().unwrap_or_else(|| {
                    eprintln!("hasp: --max-transitive-depth requires a value (1-10)");
                    std::process::exit(2);
                });
                let depth: u8 = value.parse().unwrap_or_else(|_| {
                    eprintln!("hasp: --max-transitive-depth must be a number (1-10)");
                    std::process::exit(2);
                });
                if depth == 0 || depth > 10 {
                    eprintln!("hasp: --max-transitive-depth must be between 1 and 10");
                    std::process::exit(2);
                }
                args.max_transitive_depth = depth;
            }
            "--diff-base" => {
                args.diff_base = Some(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp: --diff-base requires a git ref (e.g. HEAD~1, main)");
                    std::process::exit(2);
                }));
            }
            "--oidc-policy" => {
                let raw = iter.next().unwrap_or_else(|| {
                    eprintln!("hasp: --oidc-policy requires a value like aws:./trust.json");
                    std::process::exit(2);
                });
                let Some((provider, path)) = raw.split_once(':') else {
                    eprintln!(
                        "hasp: --oidc-policy expects <provider>:<path>, got {raw:?}"
                    );
                    std::process::exit(2);
                };
                if provider.is_empty() || path.is_empty() {
                    eprintln!(
                        "hasp: --oidc-policy expects <provider>:<path>, got {raw:?}"
                    );
                    std::process::exit(2);
                }
                args.oidc_policies
                    .push((provider.to_string(), PathBuf::from(path)));
            }
            "--no-oidc" => args.no_oidc = true,
            "--self-check" => args.self_check = true,
            "--allow-unsandboxed" => args.allow_unsandboxed = true,
            "--internal-scan" => args.mode = Mode::InternalScan,
            "--internal-verify" => args.mode = Mode::InternalVerify,
            "--internal-proxy" => args.mode = Mode::InternalProxy,
            "--internal-forward-proxy" => args.mode = Mode::InternalForwardProxy,
            "--internal-bpf-helper" => args.mode = Mode::InternalBpfHelper,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!(
                    "hasp {} ({}) [{}]",
                    env!("CARGO_PKG_VERSION"),
                    env!("GIT_HASH"),
                    env!("RUST_VERSION"),
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("hasp: unknown argument: {other}");
                eprintln!("Try 'hasp --help' for usage.");
                std::process::exit(2);
            }
        }
    }

    if args.paranoid {
        args.min_sha_age_seconds.get_or_insert(48 * 60 * 60);
        args.security_action_min_sha_age_seconds
            .get_or_insert(30 * 24 * 60 * 60);
    }

    if args.no_policy && args.policy_path.is_some() {
        eprintln!("hasp: --policy and --no-policy are mutually exclusive");
        std::process::exit(2);
    }
}

fn parse_duration_or_exit(flag: &str, raw: &str) -> i64 {
    parse_duration(raw).unwrap_or_else(|| {
        eprintln!("hasp: {flag} expects a duration like 48h, 30d, 15m, or 3600s");
        std::process::exit(2);
    })
}

fn parse_duration(raw: &str) -> Option<i64> {
    if raw.len() < 2 || !raw.is_ascii() {
        return None;
    }
    let (number, unit) = raw.split_at(raw.len() - 1);
    let value = number.parse::<i64>().ok()?;
    if value < 0 {
        return None;
    }

    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => return None,
    };
    value.checked_mul(multiplier)
}

fn print_diff_help() {
    println!(
        "\
hasp diff {}
Show the audit-finding delta between a base git ref and HEAD.

USAGE:
    hasp diff <base> [OPTIONS]

ARGS:
    <base>      Base git ref (e.g. main, HEAD~1, v1.2.3)

OPTIONS:
    --format terse|markdown|json   Output format [default: terse]
        markdown: PR-comment-friendly GitHub-flavored markdown
        json:     machine-readable for CI consumption
    -d, --dir <DIR>                Workflow directory [default: .github/workflows]
        --policy <PATH>            Path to .hasp.yml policy file
        --no-policy                Ignore .hasp.yml
        --paranoid                 Enable all checks during the compare
        --allow-unsandboxed        Skip sandbox preflight (dev mode)
    -h, --help                     Print this help

EXIT CODES:
    0   No new blocking findings introduced
    1   At least one new deny-level finding in the head branch

EXAMPLE:
    hasp diff main --format markdown | gh pr comment --body-file -",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_exec_help() {
    println!(
        "\
hasp exec {}
Run a command in a sandboxed environment with proxy-mediated secrets.

USAGE:
    hasp exec [OPTIONS] -- command [args...]

OPTIONS:
    -m, --manifest <PATH>   Step manifest YAML declaring secrets, network
                            allowlist, and writable directories. Without this,
                            defaults to zero secrets, zero network, read-only fs.
    -w, --writable <DIR>    Additional writable directory (may be repeated)
        --allow-unsandboxed
                            Permit running without the full OS sandbox.
                            Development-only; weakens the threat model.
    -h, --help              Print this help

EXAMPLE:
    hasp exec --manifest .hasp/publish.yml -- npm publish

The child process runs with:
  - No direct network access (only proxy localhost ports)
  - No secrets in its environment (scrubbed before spawn)
  - Read-only filesystem (except --writable dirs)
  - Secrets injected as HTTP headers by per-secret forward proxies",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_help() {
    println!(
        "\
hasp {}
Scans GitHub Actions workflows for unpinned or phantom action references.

Verifies every 'uses:' directive is pinned to an immutable 40-char commit SHA,
then confirms that SHA actually exists via the GitHub API. Also validates that
any # version comment matches the SHA's actual tagged release.

USAGE:
    hasp [OPTIONS]

OPTIONS:
    -d, --dir <DIR>   Workflow directory [default: .github/workflows]
        --strict      Treat mutable tag/branch refs as failures (not warnings)
        --paranoid    Enable all security audits (injection, permissions, sources)
        --no-verify   Skip GitHub API verification (offline mode)
        --max-transitive-depth <N>
                      Maximum recursion depth for transitive dependency
                      scanning [default: 3, range: 1-10]
        --min-sha-age <AGE>
                      Require pinned commits to be at least this old. Supports
                      s/m/h/d/w suffixes. Default in --paranoid: 48h
        --security-action-min-sha-age <AGE>
                      Require security / auth / deploy / publish actions to be
                      older than this age. Supports s/m/h/d/w suffixes.
                      Default in --paranoid: 30d
        --policy <PATH>
                      Path to a .hasp.yml policy file [default: .hasp.yml at
                      repo root]. Policy enables checks per-action and extends
                      trust lists.
        --no-policy   Ignore .hasp.yml policy file
        --diff-base <REF>
                      Show upstream changelog for actions whose pinned SHA
                      changed since <REF> (e.g. HEAD~1, main). Compares
                      old and new SHAs via the GitHub Compare API.
        --self-check  Verify this binary against the published release hash
        --allow-unsandboxed
                      Permit running without the full OS sandbox / Linux
                      egress confinement. Development-only; weakens the
                      threat model.
    -h, --help        Print this help
    -V, --version     Print version

EXIT CODES:
    0   All checks pass (or only warnings in non-strict mode)
    1   One or more failures detected
    2   Usage error

ENVIRONMENT:
    GITHUB_TOKEN      Required for SHA verification and tag resolution",
        env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::parse_duration;

    #[test]
    fn parses_supported_durations() {
        assert_eq!(parse_duration("3600s"), Some(3600));
        assert_eq!(parse_duration("15m"), Some(900));
        assert_eq!(parse_duration("48h"), Some(172_800));
        assert_eq!(parse_duration("30d"), Some(2_592_000));
        assert_eq!(parse_duration("2w"), Some(1_209_600));
    }

    #[test]
    fn rejects_invalid_durations() {
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("48"), None);
        assert_eq!(parse_duration("-1h"), None);
        assert_eq!(parse_duration("tenh"), None);
        assert_eq!(parse_duration("48y"), None);
    }
}
