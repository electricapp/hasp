//! Fuzz the IPC percent-decoder. Inputs are the raw field text as seen on
//! the wire after `split_fields` has produced the per-field slice.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = hasp::fuzz_api::percent_decode(s);
});
