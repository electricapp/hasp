//! `hasp doctor` — environment health checks.
//!
//! Reports whether the things hasp needs at runtime are actually present:
//! a GitHub token, network reachability to api.github.com, a sane clock,
//! an enforceable OS sandbox, and a parseable policy file. It is purely
//! diagnostic — it never modifies anything and never self-sandboxes.

use crate::cli::Args;
use crate::error::Result;
use crate::jsonout;
use crate::token::SecureToken;
use std::fmt::Write as _;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    const fn tag(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Ok => "[ ok ]",
            Self::Warn => "[warn]",
            Self::Fail => "[fail]",
        }
    }
}

struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

impl Check {
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
        }
    }
}

#[allow(clippy::unnecessary_wraps)] // signature matches the run() dispatch table
pub(crate) fn run(args: &Args) -> Result<()> {
    let checks = collect(args);

    if args.json {
        print_json(&checks);
    } else {
        print_text(&checks, args.quiet);
    }

    if checks.iter().any(|c| c.status == Status::Fail) {
        std::process::exit(1);
    }
    Ok(())
}

fn collect(args: &Args) -> Vec<Check> {
    let mut checks: Vec<Check> = Vec::new();

    // ── 1. GitHub token ──────────────────────────────────────────────────
    let token = load_token(args);
    match &token {
        Ok(Some((src, _))) => {
            checks.push(Check::new(
                "GitHub token",
                Status::Ok,
                format!("present (via {src})"),
            ));
        }
        Ok(None) => checks.push(Check::new(
            "GitHub token",
            Status::Warn,
            "not set — set GITHUB_TOKEN or pass --token-file (verification will be skipped)",
        )),
        Err(e) => checks.push(Check::new("GitHub token", Status::Fail, format!("{e}"))),
    }

    // ── 2. API connectivity + clock skew ─────────────────────────────────
    if args.no_verify {
        checks.push(Check::new(
            "API connectivity",
            Status::Warn,
            "skipped (--no-verify)",
        ));
    } else {
        let timeout = args
            .timeout_seconds
            .unwrap_or(crate::github::DEFAULT_HTTP_TIMEOUT_SECS);
        match token {
            Ok(Some((_, tok))) => probe_network(&mut checks, tok, timeout),
            Ok(None) => checks.push(Check::new(
                "API connectivity",
                Status::Warn,
                "skipped (no token)",
            )),
            Err(_) => checks.push(Check::new(
                "API connectivity",
                Status::Warn,
                "skipped (token unavailable)",
            )),
        }
    }

    // ── 3. OS sandbox availability ───────────────────────────────────────
    let sb = crate::sandbox::doctor_status();
    checks.push(Check::new(
        "OS sandbox",
        if sb.available {
            Status::Ok
        } else {
            Status::Warn
        },
        sb.detail,
    ));

    // ── 4. Policy file ───────────────────────────────────────────────────
    let dir = args
        .dir
        .canonicalize()
        .or_else(|_| std::env::current_dir())
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    match crate::policy::Policy::resolve(args, &dir) {
        Ok((_, Some(path))) => checks.push(Check::new(
            "Policy file",
            Status::Ok,
            format!("{} parsed OK", path.display()),
        )),
        Ok((_, None)) => checks.push(Check::new(
            "Policy file",
            Status::Ok,
            "no .hasp.yml found (using built-in defaults)",
        )),
        Err(e) => checks.push(Check::new("Policy file", Status::Fail, format!("{e}"))),
    }

    checks
}

fn load_token(args: &Args) -> Result<Option<(&'static str, SecureToken)>> {
    if let Some(path) = &args.token_file {
        return Ok(Some(("--token-file", SecureToken::from_file(path)?)));
    }
    if std::env::var_os("GITHUB_TOKEN").is_some() {
        return Ok(Some((
            "GITHUB_TOKEN",
            SecureToken::from_env("GITHUB_TOKEN")?,
        )));
    }
    Ok(None)
}

fn probe_network(checks: &mut Vec<Check>, token: SecureToken, timeout_secs: u64) {
    let addrs = match crate::github::pre_resolve_api() {
        Ok(a) => a,
        Err(e) => {
            checks.push(Check::new(
                "API connectivity",
                Status::Fail,
                format!("cannot resolve api.github.com: {e}"),
            ));
            return;
        }
    };

    let client = match crate::github::Client::new_with_call_budget(
        token,
        &addrs,
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        5,
        timeout_secs,
    ) {
        Ok(c) => c,
        Err(e) => {
            checks.push(Check::new("API connectivity", Status::Fail, format!("{e}")));
            return;
        }
    };

    match client.probe() {
        Ok(p) => {
            if (200..300).contains(&p.status) {
                let mut detail = format!("api.github.com reachable (HTTP {})", p.status);
                if let Some(remaining) = &p.rate_remaining {
                    let _ = write!(detail, ", {remaining} API calls remaining this hour");
                }
                checks.push(Check::new("API connectivity", Status::Ok, detail));
            } else if p.status == 401 {
                checks.push(Check::new(
                    "API connectivity",
                    Status::Fail,
                    "token rejected (HTTP 401) — check the token value and scopes",
                ));
            } else {
                checks.push(Check::new(
                    "API connectivity",
                    Status::Warn,
                    format!("reachable but unexpected HTTP {}", p.status),
                ));
            }
            check_clock_skew(checks, p.server_date.as_deref());
        }
        Err(e) => checks.push(Check::new("API connectivity", Status::Fail, format!("{e}"))),
    }
}

fn check_clock_skew(checks: &mut Vec<Check>, server_date: Option<&str>) {
    let Some(date) = server_date else {
        checks.push(Check::new(
            "Clock skew",
            Status::Warn,
            "no Date header returned by the server",
        ));
        return;
    };
    let Some(server_secs) = parse_http_date(date) else {
        checks.push(Check::new(
            "Clock skew",
            Status::Warn,
            format!("could not parse server date: {date}"),
        ));
        return;
    };
    let Ok(elapsed) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        checks.push(Check::new(
            "Clock skew",
            Status::Fail,
            "local clock is before the Unix epoch",
        ));
        return;
    };
    let now = elapsed.as_secs();
    let skew = (i64::try_from(now).unwrap_or(i64::MAX) - server_secs).abs();
    if skew <= 5 {
        checks.push(Check::new(
            "Clock skew",
            Status::Ok,
            format!("within {skew}s of the GitHub server"),
        ));
    } else if skew <= 300 {
        checks.push(Check::new(
            "Clock skew",
            Status::Warn,
            format!("{skew}s off the GitHub server clock"),
        ));
    } else {
        checks.push(Check::new(
            "Clock skew",
            Status::Fail,
            format!("{skew}s off GitHub — provenance/age checks may be unreliable"),
        ));
    }
}

/// Parse an RFC 1123 HTTP date ("Wed, 21 Oct 2026 07:28:00 GMT") to seconds
/// since the Unix epoch. Returns `None` on any unexpected shape.
fn parse_http_date(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let day: i64 = parts[1].parse().ok()?;
    let month: i64 = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[3].parse().ok()?;
    let hms: Vec<&str> = parts[4].split(':').collect();
    if hms.len() != 3 {
        return None;
    }
    let h: i64 = hms[0].parse().ok()?;
    let m: i64 = hms[1].parse().ok()?;
    let sec: i64 = hms[2].parse().ok()?;
    if !(0..24).contains(&h) || !(0..60).contains(&m) || !(0..61).contains(&sec) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86400 + h * 3600 + m * 60 + sec)
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
/// algorithm). Pure integer math, no date crate.
const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn print_text(checks: &[Check], quiet: bool) {
    if !quiet {
        println!("hasp doctor\n");
    }
    for c in checks {
        if quiet && c.status == Status::Ok {
            continue;
        }
        println!("  {}  {:<18}{}", c.status.label(), c.name, c.detail);
    }
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    if !quiet {
        println!("\ndoctor: {warns} warning(s), {fails} failure(s)");
    }
}

fn print_json(checks: &[Check]) {
    let any_fail = checks.iter().any(|c| c.status == Status::Fail);
    let mut out = String::new();
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"checks\": [");
    for (i, c) in checks.iter().enumerate() {
        let comma = if i + 1 < checks.len() { "," } else { "" };
        let _ = writeln!(
            out,
            "    {{\"name\": {}, \"status\": {}, \"detail\": {}}}{comma}",
            jsonout::quote(c.name),
            jsonout::quote(c.status.tag()),
            jsonout::quote(&c.detail),
        );
    }
    let _ = writeln!(out, "  ],");
    let _ = writeln!(out, "  \"ok\": {}", !any_fail);
    let _ = writeln!(out, "}}");
    print!("{out}");
}

#[cfg(test)]
mod tests {
    use super::{days_from_civil, parse_http_date};

    #[test]
    fn civil_epoch_is_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), 0, "epoch day");
        assert_eq!(days_from_civil(1970, 1, 2), 1, "day after epoch");
        assert_eq!(days_from_civil(2000, 1, 1), 10_957, "Y2K days");
    }

    #[test]
    fn parses_http_date() {
        // 2021-10-21T07:28:00Z = 1634801280
        assert_eq!(
            parse_http_date("Thu, 21 Oct 2021 07:28:00 GMT"),
            Some(1_634_801_280),
            "rfc1123 to epoch"
        );
    }

    #[test]
    fn rejects_malformed_http_date() {
        assert_eq!(parse_http_date("not a date"), None);
        assert_eq!(parse_http_date("Thu, 21 Foo 2021 07:28:00 GMT"), None);
        assert_eq!(parse_http_date("Thu, 21 Oct 2021 7:28 GMT"), None);
    }
}
