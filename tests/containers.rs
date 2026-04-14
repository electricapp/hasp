#![allow(clippy::tests_outside_test_module, clippy::unwrap_used)]
//! Container image pinning: job/service containers, `docker://` prefix,
//! digest vs mutable tag.

mod common;
use common::*;

#[test]
fn mutable_container_tags_warn() {
    let dir = fixture("containers");
    let o = run(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--no-verify", "--no-policy"],
    );
    let out = stdout(&o);
    assert!(out.contains("node:20") && out.contains("WARN"), "{out}");
    assert!(out.contains("alpine:3.20") && out.contains("WARN"), "{out}");
}

#[test]
fn digest_pinned_container_passes() {
    let dir = fixture("containers");
    let o = run(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--no-verify", "--no-policy"],
    );
    let out = stdout(&o);
    assert!(out.contains("postgres@sha256") && out.contains("PASS"), "{out}");
}

#[test]
fn strict_turns_mutable_container_into_fail() {
    let dir = fixture("containers");
    let o = run(
        &dir,
        &[
            "--dir", ".", "--allow-unsandboxed", "--no-verify", "--no-policy", "--strict",
        ],
    );
    let out = stdout(&o);
    assert!(out.contains("node:20") && out.contains("FAIL"), "{out}");
    assert!(out.contains("alpine:3.20") && out.contains("FAIL"), "{out}");
}

#[test]
fn docker_prefix_detects_both_mutable_and_digest() {
    let dir = fixture("docker_images");
    let o = run(
        &dir,
        &["--dir", ".", "--allow-unsandboxed", "--no-verify", "--no-policy"],
    );
    let out = stdout(&o);
    assert!(out.contains("alpine:3.20") && out.contains("WARN"), "{out}");
    assert!(
        out.contains("ghcr.io/owner/image") && out.contains("PASS"),
        "{out}"
    );
}
