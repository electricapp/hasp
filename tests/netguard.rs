//! Integration tests for the netguard sandbox-stop protocol.
//!
//! These tests exercise Linux-only behavior and only assert facts that
//! hold on any platform with a recent enough kernel. They are NOT
//! `#[ignore]`-gated because they don't hit the network or any external
//! resource — they just spawn the locally built `hasp` binary.

#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]

mod common;
use common::*;

/// `HASP_AWAIT_SANDBOX=1 hasp --version` must NOT hang. The child
/// inspects its parent's `/proc/<ppid>/exe` against `/proc/self/exe`
/// before honoring the env var; from `cargo test`, the parent is the
/// test harness binary, not `hasp`, so the child should ignore the env
/// var and exit normally.
///
/// Skipped on non-Linux because the `/proc/<ppid>/exe` check is Linux-only;
/// the env var has no effect on other platforms.
#[test]
#[cfg(target_os = "linux")]
fn await_sandbox_env_from_untrusted_parent_does_not_hang() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let mut child = Command::new(hasp_bin())
        .arg("--version")
        .env("HASP_AWAIT_SANDBOX", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hasp --version");

    // Poll for exit with a generous bound. Without the parent-exe check,
    // the child would raise(SIGSTOP) on itself and never exit.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait().expect("try_wait failed") {
            Some(status) => {
                assert!(
                    status.success(),
                    "hasp --version exited non-zero with HASP_AWAIT_SANDBOX=1 \
                     from untrusted parent: {status:?}"
                );
                return;
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "hasp --version hung when HASP_AWAIT_SANDBOX=1 was set by \
                     an untrusted (non-hasp) parent — the parent-exe check is \
                     not engaged"
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// On platforms where the env-var protocol is not implemented (anything
/// other than Linux), the var must still be a no-op rather than affecting
/// startup. Mirrors the Linux test above but without the polling — these
/// platforms cannot self-SIGSTOP at all, so the binary just exits.
#[test]
#[cfg(not(target_os = "linux"))]
fn await_sandbox_env_is_inert_off_linux() {
    let output = std::process::Command::new(hasp_bin())
        .arg("--version")
        .env("HASP_AWAIT_SANDBOX", "1")
        .output()
        .expect("failed to spawn hasp --version");
    assert!(
        output.status.success(),
        "hasp --version exited non-zero off-Linux with HASP_AWAIT_SANDBOX=1: {:?}",
        output.status
    );
}
