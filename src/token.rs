use crate::error::{Context, Result};
use std::io::Read;

/// Holds a secret token XOR-masked with a random pad, reducing the window
/// during which plaintext sits in memory.  Immediately removes the value
/// from the process environment on construction.
///
/// The plaintext is only recovered inside [`with_unmasked`], which unmasks
/// into a temporary buffer, calls the supplied closure, then scrubs the
/// buffer before returning.
pub(crate) struct SecureToken {
    masked: Vec<u8>,
    pad: Vec<u8>,
    /// Pre-allocated plaintext buffer — reused across `with_unmasked` calls
    /// to avoid per-call heap allocation.  Always scrubbed after use.
    plain_buf: std::cell::UnsafeCell<Vec<u8>>,
}

/// Maximum secret size when reading from a pipe (64 KiB).
const MAX_PIPE_SECRET_BYTES: u64 = 64 * 1024;

impl SecureToken {
    pub(crate) fn from_env(var: &str) -> Result<Self> {
        let value = std::env::var(var).context(format!(
            "${var} not set — GitHub API verification requires a token"
        ))?;
        // SAFETY: hasp is single-threaded at token construction time (before
        // any child processes are spawned), so remove_var has no data races.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(var);
        }
        Self::from_string(value)
    }

    /// Read a secret from stdin (pipe from parent process).
    ///
    /// This avoids passing secrets via environment variables, which leak
    /// through `/proc/PID/environ` on Linux even after `remove_var()`.
    /// The parent writes the secret and closes the pipe; we read to EOF.
    pub(crate) fn from_stdin() -> Result<Self> {
        let mut value = String::with_capacity(256);
        {
            let stdin = std::io::stdin();
            let lock = stdin.lock();
            lock.take(MAX_PIPE_SECRET_BYTES + 1)
                .read_to_string(&mut value)
                .context("Failed to read secret from stdin pipe")?;
        }
        if value.len() as u64 > MAX_PIPE_SECRET_BYTES {
            scrub_string(&mut value);
            crate::error::bail!("Secret from stdin exceeds {MAX_PIPE_SECRET_BYTES} bytes");
        }
        if value.is_empty() {
            crate::error::bail!("Secret from stdin is empty (pipe closed before write?)");
        }
        Self::from_string(value)
    }

    fn from_string(mut value: String) -> Result<Self> {
        let len = value.len();
        let pad = generate_random_pad(len)?;
        let masked = xor_bytes(value.as_bytes(), &pad);
        scrub_string(&mut value);
        Ok(Self {
            masked,
            pad,
            plain_buf: std::cell::UnsafeCell::new(vec![0_u8; len]),
        })
    }

    /// Temporarily unmask the token, pass it to `f`, then scrub the plaintext.
    ///
    /// # Panics
    ///
    /// Panics (after scrubbing the plaintext) if the unmasked bytes are not
    /// valid UTF-8.  This indicates memory corruption of the masked/pad
    /// buffers and is an unrecoverable state.
    pub(crate) fn with_unmasked<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R,
    {
        // SAFETY: SecureToken is not Sync (UnsafeCell prevents it), so only
        // one thread can access plain_buf at a time. We unmask into the
        // pre-allocated buffer, use it, then scrub — no aliasing possible.
        #[allow(unsafe_code)]
        let buf = unsafe { &mut *self.plain_buf.get() };
        xor_into(&self.masked, &self.pad, buf.as_mut_slice());
        let Ok(text) = std::str::from_utf8(buf) else {
            scrub_bytes(buf);
            panic!(
                "BUG: XOR unmask produced invalid UTF-8 — possible memory corruption. \
                 Aborting to prevent use of corrupted credentials."
            );
        };
        let result = f(text);
        scrub_bytes(buf);
        result
    }
}

impl Drop for SecureToken {
    fn drop(&mut self) {
        scrub_bytes(&mut self.masked);
        scrub_bytes(&mut self.pad);
        // SAFETY: We have &mut self, so exclusive access is guaranteed.
        #[allow(unsafe_code)]
        scrub_bytes(unsafe { &mut *self.plain_buf.get() });
    }
}

pub(crate) fn scrub_string(secret: &mut String) {
    // Overwrite with zeros using volatile writes so the compiler cannot
    // optimise the dead store away. This prevents the optimized-away pattern
    // but does NOT protect against:
    // - Copies made by prior operations (e.g., String::from, format!(), .clone())
    // - Stack spills of this variable during its lifetime
    // - Registers holding copies in other functions (e.g., ureq internally)
    // - OsString copies inside std::process::Command env maps
    //
    // Residual mitigations:
    // - mimalloc "secure" mode zeros freed pages, catching most freed-buffer copies
    // - seccomp denies ptrace/process_vm_readv on Linux, blocking /proc/PID/mem reads
    // - Subprocess env_clear() prevents token propagation to children
    //
    // This is a best-effort mitigation for memory on the heap; it is not a
    // cryptographic guarantee.

    // SAFETY: We are writing zeros to our own String's allocation within bounds.
    // The String owns the buffer, and we hold &mut, so no aliasing.
    // write_volatile prevents the compiler from eliding the dead store.
    #[allow(unsafe_code)]
    unsafe {
        let ptr = secret.as_mut_vec().as_mut_ptr();
        let len = secret.len();
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0_u8);
        }
    }
    secret.clear();
}

/// Volatile-zero a byte buffer in-place so the compiler cannot elide the
/// scrub. Length is preserved so reusable buffers (e.g. `plain_buf`) can be
/// scrubbed between uses without resizing.
pub(crate) fn scrub_bytes(buf: &mut [u8]) {
    // SAFETY: We are writing zeros to a mutable borrow of a caller-owned
    // byte slice within bounds. write_volatile prevents the compiler from
    // eliding the dead store.
    #[allow(unsafe_code)]
    unsafe {
        let ptr = buf.as_mut_ptr();
        let len = buf.len();
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0_u8);
        }
    }
}

fn xor_bytes(data: &[u8], pad: &[u8]) -> Vec<u8> {
    debug_assert_eq!(
        data.len(),
        pad.len(),
        "xor_bytes: input slices must be equal length"
    );
    data.iter().zip(pad.iter()).map(|(a, b)| a ^ b).collect()
}

/// XOR `data` with `pad` into an existing pre-allocated buffer in-place.
fn xor_into(data: &[u8], pad: &[u8], out: &mut [u8]) {
    debug_assert_eq!(
        data.len(),
        pad.len(),
        "xor_into: slices must be equal length"
    );
    debug_assert_eq!(
        data.len(),
        out.len(),
        "xor_into: output buffer must match input length"
    );
    for ((o, d), p) in out.iter_mut().zip(data.iter()).zip(pad.iter()) {
        *o = d ^ p;
    }
}

/// Fill `buf` with cryptographically secure random bytes using the
/// `getrandom(2)` syscall. This avoids opening `/dev/urandom`, which the
/// verifier's Landlock sandbox blocks.
#[cfg(target_os = "linux")]
fn fill_random(buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        // SAFETY: getrandom(2) writes at most `buf.len() - filled` bytes into
        // a valid mutable slice we own; the kernel touches no other memory.
        #[allow(unsafe_code)]
        let n = unsafe {
            libc::getrandom(
                buf[filled..].as_mut_ptr().cast::<libc::c_void>(),
                buf.len() - filled,
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err).context("getrandom(2) syscall failed");
        }
        filled += usize::try_from(n).expect("getrandom returned non-negative count");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn fill_random(buf: &mut [u8]) -> Result<()> {
    use std::fs::File;
    File::open("/dev/urandom")
        .context("Failed to open /dev/urandom")?
        .read_exact(buf)
        .context("Failed to read from /dev/urandom")?;
    Ok(())
}

fn generate_random_pad(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0_u8; len];
    fill_random(&mut buf).context("Failed to generate token XOR pad")?;
    Ok(buf)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn generate_ephemeral_secret_hex(bytes: usize) -> Result<String> {
    let mut raw = vec![0_u8; bytes];
    fill_random(&mut raw).context("Failed to generate proxy auth secret")?;

    let mut out = String::with_capacity(bytes * 2);
    for byte in raw {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn xor_round_trips() {
        let data = b"ghp_abcdef123456";
        let pad = generate_random_pad(data.len()).unwrap();
        let masked = xor_bytes(data, &pad);
        // masked should differ from original (overwhelmingly likely)
        assert_ne!(&masked, data);
        let recovered = xor_bytes(&masked, &pad);
        assert_eq!(&recovered, data);
    }

    #[test]
    fn with_unmasked_provides_original() {
        // Manually construct a SecureToken to test round-trip without env
        let original = "test_token_value";
        let pad = generate_random_pad(original.len()).unwrap();
        let masked = xor_bytes(original.as_bytes(), &pad);
        let len = original.len();
        let token = SecureToken {
            masked,
            pad,
            plain_buf: std::cell::UnsafeCell::new(vec![0_u8; len]),
        };
        token.with_unmasked(|plain| {
            assert_eq!(plain, original);
        });
    }

    #[test]
    fn scrub_bytes_zeroes_buffer_in_place() {
        let mut buf = vec![0xAA_u8; 16];
        scrub_bytes(&mut buf);
        assert_eq!(buf.len(), 16, "length must be preserved for reuse");
        assert!(
            buf.iter().all(|&b| b == 0),
            "all bytes must be zeroed: {buf:?}"
        );
    }
}
