//! Fuzz the scanner → launcher IPC `ScanPayload` reader with arbitrary bytes.
//!
//! The scanner subprocess sends this payload to the launcher over a pipe.
//! A panic here would be a binary-edge parser crash: fail the fuzzer.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hasp::fuzz_api::read_scan_payload(data);
});
