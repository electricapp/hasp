//! Fuzz the launcher → verifier IPC `VerifierInput` reader.
//!
//! This surface is fed by an arbitrary input pipe, so it must never panic
//! on malformed bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hasp::fuzz_api::read_verifier_input(data);
});
