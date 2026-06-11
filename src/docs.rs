//! `hasp docs [topic]` — in-binary documentation.
//!
//! The markdown under `docs/` is embedded into this exact build via
//! `include_str!`, so the text always matches the installed binary and works
//! with no network access. `hasp docs` with no topic lists what's available.

use crate::error::Result;

/// (topic name, embedded markdown). The topic names are stable CLI surface;
/// keep them lowercase and hyphenated. Internal notes (`docs/NOTES.md`) are
/// intentionally not exposed.
const TOPICS: &[(&str, &str)] = &[
    ("architecture", include_str!("../docs/ARCHITECTURE.md")),
    ("audits", include_str!("../docs/AUDITS.md")),
    ("comparison", include_str!("../docs/COMPARISON.md")),
    ("exec", include_str!("../docs/EXEC.md")),
    ("github-action", include_str!("../docs/GITHUB_ACTION.md")),
    ("policy", include_str!("../docs/POLICY.md")),
    ("reproduce", include_str!("../docs/REPRODUCE.md")),
    ("security", include_str!("../docs/SECURITY.md")),
    ("trust", include_str!("../docs/TRUST.md")),
];

#[allow(clippy::unnecessary_wraps)] // signature matches the run() dispatch table
pub(crate) fn run(topic: Option<&str>) -> Result<()> {
    let Some(name) = topic else {
        list_topics();
        return Ok(());
    };
    for (t, body) in TOPICS {
        if *t == name {
            print!("{body}");
            return Ok(());
        }
    }
    eprintln!("hasp docs: unknown topic: {name}");
    eprintln!("Run 'hasp docs' to list available topics.");
    std::process::exit(2);
}

fn list_topics() {
    println!("Available documentation topics:\n");
    for (name, _) in TOPICS {
        println!("    {name}");
    }
    println!("\nPrint one with:  hasp docs <topic>");
    println!(
        "Full docs:       https://github.com/{}/tree/main/docs",
        env!("GITHUB_REPO")
    );
}
