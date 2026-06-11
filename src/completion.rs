//! `hasp completion <shell>` — emit a static shell-completion script to stdout.
//!
//! The scripts are hand-written and embedded (no codegen crate, consistent
//! with hasp's minimal-dependency stance). They are printed verbatim, so the
//! format string is always the literal `"{SCRIPT}"` — the script's own braces
//! are never reparsed.

use crate::error::Result;

#[allow(clippy::unnecessary_wraps)] // signature matches the run() dispatch table
pub(crate) fn run(shell: &str) -> Result<()> {
    match shell {
        "bash" => print!("{BASH}"),
        "zsh" => print!("{ZSH}"),
        "fish" => print!("{FISH}"),
        other => {
            eprintln!("hasp completion: unsupported shell: {other}");
            eprintln!("Supported shells: bash, zsh, fish");
            std::process::exit(2);
        }
    }
    Ok(())
}

const BASH: &str = r#"# bash completion for hasp
_hasp() {
    local cur cmd
    cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="diff tree replay exec doctor docs completion help"
    local global="--dir --strict --paranoid --no-verify --policy --no-policy --oidc-policy --no-oidc --diff-base --max-transitive-depth --min-sha-age --security-action-min-sha-age --self-check --allow-unsandboxed --token-file --timeout --json --quiet --verbose --help --version"
    if [ "${COMP_CWORD}" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "${commands} ${global}" -- "${cur}") )
        return 0
    fi
    cmd="${COMP_WORDS[1]}"
    case "${cmd}" in
        completion) COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") ) ;;
        docs) COMPREPLY=( $(compgen -W "architecture audits comparison exec github-action policy reproduce security trust" -- "${cur}") ) ;;
        help) COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") ) ;;
        diff) COMPREPLY=( $(compgen -W "--format --dir --policy --no-policy --paranoid --allow-unsandboxed --help" -- "${cur}") ) ;;
        tree) COMPREPLY=( $(compgen -W "--format --min-score --dir --no-verify --allow-unsandboxed --help" -- "${cur}") ) ;;
        replay) COMPREPLY=( $(compgen -W "--since --format --dir --help" -- "${cur}") ) ;;
        exec) COMPREPLY=( $(compgen -W "--manifest --writable --allow-unsandboxed --help" -- "${cur}") ) ;;
        doctor) COMPREPLY=( $(compgen -W "--no-verify --token-file --timeout --allow-unsandboxed --json --quiet --help" -- "${cur}") ) ;;
        *) COMPREPLY=( $(compgen -W "${global}" -- "${cur}") ) ;;
    esac
    return 0
}
complete -F _hasp hasp
"#;

const ZSH: &str = r#"#compdef hasp
_hasp() {
    local -a commands
    commands=(
        'diff:Audit-finding delta vs a base ref'
        'tree:Scored supply-chain dependency graph'
        'replay:Re-audit historical workflow states'
        'exec:Run a command in a sandbox'
        'doctor:Environment health checks'
        'docs:Print in-binary documentation'
        'completion:Generate shell completions'
        'help:Print help'
    )
    if (( CURRENT == 2 )); then
        _describe -t commands 'hasp command' commands
        return
    fi
    case ${words[2]} in
        completion) compadd bash zsh fish ;;
        docs) compadd architecture audits comparison exec github-action policy reproduce security trust ;;
        help) compadd diff tree replay exec doctor docs completion ;;
        *) _files ;;
    esac
}
_hasp "$@"
"#;

const FISH: &str = "# fish completion for hasp
complete -c hasp -f

# subcommands (only valid as the first argument)
complete -c hasp -n __fish_use_subcommand -a diff -d 'Audit-finding delta vs a base ref'
complete -c hasp -n __fish_use_subcommand -a tree -d 'Scored supply-chain dependency graph'
complete -c hasp -n __fish_use_subcommand -a replay -d 'Re-audit historical workflow states'
complete -c hasp -n __fish_use_subcommand -a exec -d 'Run a command in a sandbox'
complete -c hasp -n __fish_use_subcommand -a doctor -d 'Environment health checks'
complete -c hasp -n __fish_use_subcommand -a docs -d 'Print in-binary documentation'
complete -c hasp -n __fish_use_subcommand -a completion -d 'Generate shell completions'
complete -c hasp -n __fish_use_subcommand -a help -d 'Print help'

complete -c hasp -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c hasp -n '__fish_seen_subcommand_from docs' -a 'architecture audits comparison exec github-action policy reproduce security trust'

complete -c hasp -l paranoid -d 'Enable all security audits'
complete -c hasp -l strict -d 'Treat mutable refs as failures'
complete -c hasp -l no-verify -d 'Skip GitHub API verification'
complete -c hasp -s d -l dir -d 'Workflow directory' -r
complete -c hasp -l json -d 'JSON output'
complete -c hasp -s q -l quiet -d 'Suppress non-essential output'
complete -c hasp -s v -l verbose -d 'Extra detail'
complete -c hasp -s h -l help -d 'Print help'
complete -c hasp -s V -l version -d 'Print version'
";
