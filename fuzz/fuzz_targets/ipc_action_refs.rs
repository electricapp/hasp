//! Fuzz the action-refs IPC reader — raw bytes → parsed `ActionRef` list.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hasp::fuzz_api::read_action_refs(data);
});
