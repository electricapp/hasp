use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Launcher,
    Diff,
    Tree,
    Replay,
    Exec,
    Doctor,
    Docs,
    Completion,
    InternalScan,
    InternalVerify,
    InternalProxy,
    InternalForwardProxy,
    InternalBpfHelper,
}

/// Subcommands recognized as the first positional argument. Used both for
/// dispatch and for "did you mean" suggestions on typos.
const SUBCOMMANDS: &[&str] = &[
    "diff",
    "tree",
    "replay",
    "exec",
    "doctor",
    "docs",
    "completion",
    "help",
];

/// Top-level scan-mode flags, for "did you mean" suggestions on unknown flags.
const SCANNER_FLAGS: &[&str] = &[
    "--dir",
    "--strict",
    "--paranoid",
    "--no-verify",
    "--max-transitive-depth",
    "--min-sha-age",
    "--security-action-min-sha-age",
    "--policy",
    "--no-policy",
    "--oidc-policy",
    "--no-oidc",
    "--diff-base",
    "--self-check",
    "--allow-unsandboxed",
    "--token-file",
    "--timeout",
    "--json",
    "--quiet",
    "--verbose",
    "--help",
    "--version",
];

#[derive(Clone)]
pub(crate) struct ExecArgs {
    pub(crate) manifest: Option<PathBuf>,
    pub(crate) writable_dirs: Vec<PathBuf>,
    pub(crate) command: Vec<String>,
}

#[allow(clippy::struct_excessive_bools)] // CLI flags are inherently boolean
#[derive(Clone)]
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
    /// Launcher-mode `--diff-base <ref>` (policy drift + SHA-change check).
    pub(crate) diff_base: Option<String>,
    /// `hasp diff <base>` positional argument.
    pub(crate) diff_subcommand_base: Option<String>,
    pub(crate) oidc_policies: Vec<(String, PathBuf)>,
    pub(crate) no_oidc: bool,
    pub(crate) diff_format: Option<crate::diff::DiffFormat>,
    pub(crate) tree_format: Option<crate::supply_chain_graph::TreeFormat>,
    pub(crate) tree_min_score: Option<f32>,
    pub(crate) replay_since: Option<String>,
    pub(crate) replay_format: Option<crate::replay::ReplayFormat>,
    /// Global `--json` switch: machine-readable output for the scan mode and
    /// `doctor`. Subcommands with richer formats keep their own `--format`.
    pub(crate) json: bool,
    /// `-q`/`--quiet`: suppress non-essential `note:`/status lines on stderr.
    pub(crate) quiet: bool,
    /// `-v`/`--verbose`: emit extra diagnostic detail.
    pub(crate) verbose: bool,
    /// `--timeout <secs>`: per-request network timeout (default 30s).
    pub(crate) timeout_seconds: Option<u64>,
    /// `--token-file <path>`: read the GitHub token from a file instead of
    /// the `GITHUB_TOKEN` environment variable.
    pub(crate) token_file: Option<PathBuf>,
    /// `hasp docs [topic]` positional.
    pub(crate) docs_topic: Option<String>,
    /// `hasp completion <shell>` positional.
    pub(crate) completion_shell: Option<String>,
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
            diff_subcommand_base: None,
            oidc_policies: Vec::new(),
            no_oidc: false,
            diff_format: None,
            tree_format: None,
            tree_min_score: None,
            replay_since: None,
            replay_format: None,
            json: false,
            quiet: false,
            verbose: false,
            timeout_seconds: None,
            token_file: None,
            docs_topic: None,
            completion_shell: None,
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
    let args = Args::default();
    let mut iter = std::env::args().skip(1);

    // Peek at the first argument to detect subcommands. Dispatch is exact-match
    // only: no prefix abbreviations (so adding a subcommand can never change
    // what an existing abbreviation means) and no implicit catch-all.
    let first = iter.next();
    if let Some(ref first_arg) = first {
        match first_arg.as_str() {
            "exec" => return parse_exec(args, iter),
            "diff" => return parse_diff(args, iter),
            "tree" => return parse_tree(args, iter),
            "replay" => return parse_replay(args, iter),
            "doctor" => return parse_doctor(args, iter),
            "docs" => return parse_docs(args, iter),
            "completion" => return parse_completion(args, iter),
            "help" => print_help_for(iter.next().as_deref()),
            _ => {}
        }
    }
    // If not a subcommand, re-process the first argument in the normal loop.
    let mut args = args;
    let replay = first.into_iter().chain(iter);
    parse_scanner_args(&mut args, replay);
    args
}

/// Levenshtein edit distance between two strings (hand-rolled, no deps).
/// Used only for short CLI tokens, so the quadratic cost is irrelevant.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr: Vec<usize> = vec![0_usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// The closest candidate to `input` within edit distance 2, if any.
fn suggest<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (levenshtein(input, c), *c))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|&(d, _)| d)
        .map(|(_, c)| c)
}

/// Print "Did you mean '<prefix><suggestion>'?" on stderr when a near match
/// exists for `token` among `candidates`.
fn print_suggestion(token: &str, candidates: &[&str], prefix: &str) {
    if let Some(s) = suggest(token, candidates) {
        eprintln!("Did you mean '{prefix}{s}'?");
    }
}

/// Dispatch `hasp help [command]`. Diverges (prints and exits).
fn print_help_for(name: Option<&str>) -> ! {
    match name {
        None => print_help(),
        Some("diff") => print_diff_help(),
        Some("tree") => print_tree_help(),
        Some("replay") => print_replay_help(),
        Some("exec") => print_exec_help(),
        Some("doctor") => print_doctor_help(),
        Some("docs") => print_docs_help(),
        Some("completion") => print_completion_help(),
        Some(other) => {
            eprintln!("hasp help: unknown command: {other}");
            print_suggestion(other, SUBCOMMANDS, "hasp help ");
            eprintln!("Run 'hasp help' for the list of commands.");
            std::process::exit(2);
        }
    }
    std::process::exit(0);
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
                    print_suggestion(
                        other,
                        &[
                            "--format",
                            "--dir",
                            "--policy",
                            "--no-policy",
                            "--paranoid",
                            "--allow-unsandboxed",
                        ],
                        "",
                    );
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
    args.diff_subcommand_base = Some(positional.remove(0));
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
                print_suggestion(
                    other,
                    &["--manifest", "--writable", "--allow-unsandboxed"],
                    "",
                );
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
                    eprintln!("hasp: --oidc-policy expects <provider>:<path>, got {raw:?}");
                    std::process::exit(2);
                };
                if provider.is_empty() || path.is_empty() {
                    eprintln!("hasp: --oidc-policy expects <provider>:<path>, got {raw:?}");
                    std::process::exit(2);
                }
                args.oidc_policies
                    .push((provider.to_string(), PathBuf::from(path)));
            }
            "--no-oidc" => args.no_oidc = true,
            "--self-check" => args.self_check = true,
            "--allow-unsandboxed" => args.allow_unsandboxed = true,
            "--token-file" => {
                args.token_file = Some(PathBuf::from(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp: --token-file requires a file path");
                    std::process::exit(2);
                })));
            }
            "--timeout" => {
                let value = iter.next().unwrap_or_else(|| {
                    eprintln!("hasp: --timeout requires a value in seconds");
                    std::process::exit(2);
                });
                args.timeout_seconds = Some(parse_timeout_or_exit(&value));
            }
            "--json" => args.json = true,
            "-q" | "--quiet" => args.quiet = true,
            "-v" | "--verbose" => args.verbose = true,
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
                    "hasp {} ({}, {}) [{}]",
                    env!("CARGO_PKG_VERSION"),
                    env!("GIT_HASH"),
                    env!("COMMIT_DATE"),
                    env!("RUST_VERSION"),
                );
                std::process::exit(0);
            }
            other => {
                if other.starts_with('-') {
                    eprintln!("hasp: unknown option: {other}");
                    print_suggestion(other, SCANNER_FLAGS, "");
                } else {
                    eprintln!("hasp: unknown argument: {other}");
                    print_suggestion(other, SUBCOMMANDS, "hasp ");
                }
                eprintln!("Try 'hasp --help' for usage.");
                std::process::exit(2);
            }
        }
    }

    if args.quiet && args.verbose {
        eprintln!("hasp: --quiet and --verbose are mutually exclusive");
        std::process::exit(2);
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

/// Parse `--timeout` as whole seconds in the range 1..=3600.
fn parse_timeout_or_exit(raw: &str) -> u64 {
    match raw.parse::<u64>() {
        Ok(secs) if (1..=3600).contains(&secs) => secs,
        _ => {
            eprintln!("hasp: --timeout must be a whole number of seconds between 1 and 3600");
            std::process::exit(2);
        }
    }
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

fn parse_tree(mut args: Args, mut iter: std::iter::Skip<std::env::Args>) -> Args {
    args.mode = Mode::Tree;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--format" => {
                let raw = iter.next().unwrap_or_else(|| {
                    eprintln!("hasp tree: --format requires a value (ascii|json)");
                    std::process::exit(2);
                });
                let format = crate::supply_chain_graph::TreeFormat::parse(&raw)
                    .unwrap_or_else(|e| {
                        eprintln!("hasp tree: {e}");
                        std::process::exit(2);
                    });
                args.tree_format = Some(format);
            }
            "--min-score" => {
                let raw = iter.next().unwrap_or_else(|| {
                    eprintln!("hasp tree: --min-score requires a value (0.0-1.0)");
                    std::process::exit(2);
                });
                let parsed: f32 = raw.parse().unwrap_or_else(|_| {
                    eprintln!("hasp tree: --min-score must be a number between 0.0 and 1.0");
                    std::process::exit(2);
                });
                if !(0.0..=1.0).contains(&parsed) {
                    eprintln!("hasp tree: --min-score must be between 0.0 and 1.0");
                    std::process::exit(2);
                }
                args.tree_min_score = Some(parsed);
            }
            "-d" | "--dir" => {
                args.dir = PathBuf::from(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp tree: --dir requires a value");
                    std::process::exit(2);
                }));
            }
            "--allow-unsandboxed" => args.allow_unsandboxed = true,
            "--no-verify" => args.no_verify = true,
            "-h" | "--help" => {
                print_tree_help();
                std::process::exit(0);
            }
            other => {
                eprintln!("hasp tree: unknown option: {other}");
                print_suggestion(
                    other,
                    &[
                        "--format",
                        "--min-score",
                        "--dir",
                        "--no-verify",
                        "--allow-unsandboxed",
                    ],
                    "",
                );
                eprintln!("Try 'hasp tree --help' for usage.");
                std::process::exit(2);
            }
        }
    }
    args
}

fn parse_replay(mut args: Args, mut iter: std::iter::Skip<std::env::Args>) -> Args {
    args.mode = Mode::Replay;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--since" => {
                args.replay_since = Some(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp replay: --since requires a value (e.g. 30d, 2w)");
                    std::process::exit(2);
                }));
            }
            "--format" => {
                let raw = iter.next().unwrap_or_else(|| {
                    eprintln!("hasp replay: --format requires a value (terse|markdown|json)");
                    std::process::exit(2);
                });
                args.replay_format = Some(crate::replay::ReplayFormat::parse(&raw).unwrap_or_else(
                    |e| {
                        eprintln!("hasp replay: {e}");
                        std::process::exit(2);
                    },
                ));
            }
            "-d" | "--dir" => {
                args.dir = PathBuf::from(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp replay: --dir requires a value");
                    std::process::exit(2);
                }));
            }
            "-h" | "--help" => {
                print_replay_help();
                std::process::exit(0);
            }
            other => {
                eprintln!("hasp replay: unknown option: {other}");
                print_suggestion(other, &["--since", "--format", "--dir"], "");
                eprintln!("Try 'hasp replay --help' for usage.");
                std::process::exit(2);
            }
        }
    }
    args
}

fn parse_doctor(mut args: Args, mut iter: std::iter::Skip<std::env::Args>) -> Args {
    args.mode = Mode::Doctor;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => args.json = true,
            "--no-verify" => args.no_verify = true,
            "--allow-unsandboxed" => args.allow_unsandboxed = true,
            "-q" | "--quiet" => args.quiet = true,
            "-v" | "--verbose" => args.verbose = true,
            "--token-file" => {
                args.token_file = Some(PathBuf::from(iter.next().unwrap_or_else(|| {
                    eprintln!("hasp doctor: --token-file requires a file path");
                    std::process::exit(2);
                })));
            }
            "--timeout" => {
                let value = iter.next().unwrap_or_else(|| {
                    eprintln!("hasp doctor: --timeout requires a value in seconds");
                    std::process::exit(2);
                });
                args.timeout_seconds = Some(parse_timeout_or_exit(&value));
            }
            "-h" | "--help" => {
                print_doctor_help();
                std::process::exit(0);
            }
            other => {
                eprintln!("hasp doctor: unknown option: {other}");
                eprintln!("Try 'hasp doctor --help' for usage.");
                std::process::exit(2);
            }
        }
    }
    args
}

fn parse_docs(mut args: Args, iter: std::iter::Skip<std::env::Args>) -> Args {
    args.mode = Mode::Docs;
    let mut positional: Vec<String> = Vec::new();
    for arg in iter {
        match arg.as_str() {
            "-h" | "--help" => {
                print_docs_help();
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                eprintln!("hasp docs: unknown option: {other}");
                eprintln!("Try 'hasp docs --help' for usage.");
                std::process::exit(2);
            }
            other => positional.push(other.to_string()),
        }
    }
    if positional.len() > 1 {
        eprintln!("hasp docs: expected at most one topic, got {positional:?}");
        std::process::exit(2);
    }
    args.docs_topic = positional.into_iter().next();
    args
}

fn parse_completion(mut args: Args, iter: std::iter::Skip<std::env::Args>) -> Args {
    args.mode = Mode::Completion;
    let mut positional: Vec<String> = Vec::new();
    for arg in iter {
        match arg.as_str() {
            "-h" | "--help" => {
                print_completion_help();
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                eprintln!("hasp completion: unknown option: {other}");
                eprintln!("Try 'hasp completion --help' for usage.");
                std::process::exit(2);
            }
            other => positional.push(other.to_string()),
        }
    }
    match positional.len() {
        0 => {
            eprintln!("hasp completion: missing <shell> (bash, zsh, or fish)");
            eprintln!("Usage: hasp completion <bash|zsh|fish>");
            std::process::exit(2);
        }
        1 => args.completion_shell = Some(positional.remove(0)),
        _ => {
            eprintln!("hasp completion: expected one shell name, got {positional:?}");
            std::process::exit(2);
        }
    }
    args
}

fn print_replay_help() {
    println!(
        "\
hasp replay {}
Re-audit the historical states of workflow files over a time window.

USAGE:
    hasp replay [OPTIONS]

OPTIONS:
    --since <WINDOW>               How far back to walk [default: 30d]
                                   Anything `git log --since=` accepts
                                   (e.g. 30d, 2w, 6h, yesterday)
    --format terse|markdown|json   Output format [default: terse]
    -d, --dir <DIR>                Workflow directory [default: .github/workflows]
    -h, --help                     Print this help

EXIT CODES:
    0   No past state would have produced a deny-level finding
    1   At least one past state would have failed today's audit
    2   Usage error

EXAMPLES:
    hasp replay --since 90d
    hasp replay --since 6h --format markdown

Uses `git log` to enumerate historical revisions of workflow files and
re-runs the current audit rules against each past state. Answers:
\"would today's rules have caught yesterday's problem?\".",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_tree_help() {
    println!(
        "\
hasp tree {}
Emit a scored supply-chain dependency graph for the repo's workflows.

USAGE:
    hasp tree [OPTIONS]

OPTIONS:
    --format ascii|json            Output format [default: ascii]
    --min-score <SCORE>            Fail with exit 1 if any node score
                                   (workflow or pinned action) is below
                                   this threshold (0.0-1.0). Workflows
                                   with no pinned `uses:` score 1.0 and
                                   therefore always pass.
    --no-verify                    Skip all online (GitHub API) signals;
                                   render the graph from offline data only
    -d, --dir <DIR>                Workflow directory [default: .github/workflows]
        --allow-unsandboxed        Skip sandbox preflight (dev mode)
    -h, --help                     Print this help

NOTE:
    `hasp tree` always runs the static audit at the policy-configured
    levels to populate `findings_here`. `--paranoid` and `--no-oidc`
    are honored by `hasp` / `hasp diff` but do not affect tree output.

EXIT CODES:
    0   Every node scores at or above --min-score (or no threshold set)
    1   At least one node scored below --min-score
    2   Usage error

EXAMPLES:
    hasp tree
    hasp tree --format json | jq '.nodes[] | select(.score < 0.5)'
    hasp tree --min-score 0.6",
        env!("CARGO_PKG_VERSION")
    );
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
    2   Usage error

EXAMPLES:
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

EXIT CODES:
    The child command's own exit status is propagated. hasp itself uses
    exit 2 for usage errors and refuses to run (exit 2) without a sandbox
    unless --allow-unsandboxed is passed.

EXAMPLES:
    hasp exec --manifest .hasp/publish.yml -- npm publish

The child process runs with:
  - No direct network access (only proxy localhost ports)
  - No secrets in its environment (scrubbed before spawn)
  - Read-only filesystem (except --writable dirs)
  - Secrets injected as HTTP headers by per-secret forward proxies",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_doctor_help() {
    println!(
        "\
hasp doctor {}
Run environment health checks and report what works and what doesn't.

USAGE:
    hasp doctor [OPTIONS]

OPTIONS:
        --no-verify         Skip checks that require the GitHub API (offline)
        --token-file <PATH> Read the GitHub token from a file
        --timeout <SECS>    Per-request network timeout [default: 30]
        --allow-unsandboxed Report sandbox status without refusing to run
        --json              Machine-readable JSON output
    -q, --quiet             Print only failures
    -h, --help              Print this help

CHECKS:
    * GitHub token present (env or --token-file)
    * api.github.com reachable and token accepted
    * Clock skew vs the GitHub server
    * OS sandbox availability (Landlock / seccomp on this platform)
    * Policy file (.hasp.yml) discovery and parse

EXIT CODES:
    0   All checks passed (warnings allowed)
    1   At least one check failed
    2   Usage error

EXAMPLES:
    hasp doctor
    hasp doctor --json | jq '.checks[] | select(.status != \"ok\")'",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_docs_help() {
    println!(
        "\
hasp docs {}
Print in-binary documentation topics. Works fully offline; the text is
embedded in this exact build.

USAGE:
    hasp docs [TOPIC]

ARGS:
    [TOPIC]   A topic name. With no topic, lists the available topics.

EXIT CODES:
    0   Topic printed, or topic list shown
    2   Unknown topic

EXAMPLES:
    hasp docs                # list topics
    hasp docs policy         # print the .hasp.yml policy reference
    hasp docs security | less",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_completion_help() {
    println!(
        "\
hasp completion {}
Generate a shell completion script. Print it to stdout and source it.

USAGE:
    hasp completion <SHELL>

ARGS:
    <SHELL>   One of: bash, zsh, fish

EXIT CODES:
    0   Script written to stdout
    2   Missing or unsupported shell

EXAMPLES:
    hasp completion bash > /etc/bash_completion.d/hasp
    hasp completion zsh  > \"${{fpath[1]}}/_hasp\"
    hasp completion fish > ~/.config/fish/completions/hasp.fish",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_help() {
    println!(
        "\
hasp {} ({}, {})
Paranoid security scanner and sandboxed step runner for GitHub Actions.

Verifies every 'uses:' directive is pinned to an immutable 40-char commit SHA,
confirms that SHA actually exists via the GitHub API, and validates that any
# version comment matches the SHA's tagged release. With --paranoid it also
audits workflows for injection, excessive permissions, hidden execution paths,
and supply-chain risks.

USAGE:
    hasp [OPTIONS]             Scan .github/workflows (default command)
    hasp <COMMAND> [ARGS]      Run a subcommand (see COMMANDS)

COMMANDS:
    diff <base>     Show the audit-finding delta between a base ref and HEAD
    tree            Emit a scored supply-chain dependency graph for the repo
    replay          Re-audit historical workflow states over a time window
    exec -- <cmd>   Run a command in a sandbox with proxy-mediated secrets
    doctor          Run environment health checks
    docs [topic]    Print in-binary documentation topics
    completion      Generate shell completion scripts
    help [command]  Print help for hasp or a specific command

    The command must be the first argument. Run `hasp help <command>`
    or `hasp <command> --help` for command-specific options.

SCAN OPTIONS:
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
        --oidc-policy <PROVIDER>:<PATH>
                      Audit a cloud OIDC trust policy against the workflows
                      that mint GitHub OIDC tokens. PROVIDER is one of
                      aws, gcp, or azure. Repeatable. Also configurable via
                      the .hasp.yml `oidc:` section.
        --no-oidc     Skip OIDC trust-policy auditing entirely
        --diff-base <REF>
                      Show upstream changelog for actions whose pinned SHA
                      changed since <REF> (e.g. HEAD~1, main). Compares
                      old and new SHAs via the GitHub Compare API.
        --self-check  Verify this binary against the published release hash
        --allow-unsandboxed
                      Permit running without the full OS sandbox / Linux
                      egress confinement. Development-only; weakens the
                      threat model.
        --token-file <PATH>
                      Read the GitHub token from a file instead of the
                      GITHUB_TOKEN environment variable.
        --timeout <SECS>
                      Per-request network timeout [default: 30, range: 1-3600]
        --json        Machine-readable JSON output instead of the text report
    -q, --quiet       Suppress non-essential status/notes on stderr
    -v, --verbose     Show extra diagnostic detail
    -h, --help        Print this help
    -V, --version     Print version

EXIT CODES:
    0   All checks pass (or only warnings in non-strict mode)
    1   One or more failures detected
    2   Usage error, or the run could not proceed (bad input, sandbox
        unavailable without --allow-unsandboxed, network/setup failure)

ENVIRONMENT:
    GITHUB_TOKEN      GitHub API token for SHA verification and tag
                      resolution. Read once, then scrubbed from the
                      environment. Overridden by --token-file.
    NO_COLOR          Honored implicitly: hasp emits no ANSI color.
    SOURCE_DATE_EPOCH Build-time only: pins timestamps for reproducible builds.

    Proxy variables (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY) are deliberately
    IGNORED and stripped: hasp pins its only outbound host (api.github.com)
    to prevent MITM via an attacker-controlled proxy.

EXAMPLES:
    $ hasp                                # scan with default checks
    $ hasp --paranoid                     # enable all security audits
    $ hasp --strict                       # treat mutable refs as failures
    $ hasp diff main --format markdown    # PR-delta as a PR comment
    $ hasp tree --min-score 0.6           # fail on low-trust dependencies
    $ hasp exec --manifest publish.yml -- npm publish

LEARN MORE:
    Use `hasp <command> --help` for details on any subcommand.
    Docs:    https://github.com/{}/tree/main/docs
    Issues:  https://github.com/{}/issues",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH"),
        env!("COMMIT_DATE"),
        env!("GITHUB_REPO"),
        env!("GITHUB_REPO"),
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
