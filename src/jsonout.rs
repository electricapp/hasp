//! Minimal hand-rolled JSON output helpers.
//!
//! hasp carries no serde dependency by design (see `Cargo.toml`), so the
//! handful of commands that emit `--json` build their documents through these
//! escaping primitives. Output only — there is no JSON *parser* here.

use std::fmt::Write as _;

/// Escape a string for inclusion inside a JSON double-quoted string, without
/// the surrounding quotes.
pub(crate) fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Control characters must be \u-escaped. write! to a String is
                // infallible; the Result is discarded deliberately.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// A complete JSON string literal (with surrounding quotes) for `s`.
pub(crate) fn quote(s: &str) -> String {
    format!("\"{}\"", esc(s))
}
