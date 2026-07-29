/// Two-phase OS-level sandboxing.
///
/// FAIL-CLOSED DESIGN: If any sandbox layer cannot be enforced, the process
/// ABORTS rather than continuing unsandboxed. On non-Linux, the binary refuses
/// to run unless --allow-unsandboxed is passed.
use crate::error::Result;
use crate::error::bail;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkPolicy {
    Allow,
    DenyNewSockets,
}

// On Linux this is a no-op; the Result return and runtime work exist for the
// non-Linux build where the function refuses to run without --allow-unsandboxed.
#[cfg_attr(
    target_os = "linux",
    allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)
)]
pub(crate) fn platform_preflight(allow_unsandboxed: bool, emit_warning: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = allow_unsandboxed;
        let _ = emit_warning;
    }

    #[cfg(not(target_os = "linux"))]
    {
        if allow_unsandboxed {
            if emit_warning {
                eprintln!(
                    "hasp: WARNING: OS-level sandbox unavailable on this platform. \
                     Proceeding because --allow-unsandboxed was supplied."
                );
            }
        } else {
            bail!(
                "OS-level sandbox unavailable on this platform. \
                 Refusing to run without Landlock/seccomp; rerun with \
                 --allow-unsandboxed only for development."
            );
        }
    }

    Ok(())
}

/// Make the current process non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`).
///
/// A same-uid child can otherwise read `/proc/<pid>/{environ,mem,maps}` of a
/// parent or sibling. The `hasp exec` orchestrator captures each secret from
/// its own environment (`SecureToken::from_env`), and `env::remove_var` does
/// NOT scrub `/proc/self/environ` — the kernel keeps serving the original
/// stack block — so without this a sandboxed step could recover the plaintext
/// secret straight out of `/proc/<ppid>/environ`, defeating the proxy-mediated
/// isolation entirely. dumpable=0 reparents those proc files to root and denies
/// same-uid access (`PTRACE_MODE_READ_FSCREDS` fails). Applied to the
/// orchestrator and to every secret-holding forward proxy before any child is
/// spawned. On non-Linux this is a no-op (the exec path refuses to run
/// unsandboxed there anyway).
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
pub(crate) fn harden_process_dumpable() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) sets a boolean process attribute;
        // it takes no pointer arguments and cannot corrupt memory.
        #[allow(unsafe_code)]
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if ret != 0 {
            bail!(
                "prctl(PR_SET_DUMPABLE, 0) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

/// Human-facing summary of OS sandbox availability, for `hasp doctor`.
pub(crate) struct SandboxReport {
    /// Whether the OS sandbox can be enforced on this platform/kernel.
    pub(crate) available: bool,
    /// One-line detail (platform note, kernel requirement, or error).
    pub(crate) detail: String,
}

/// Detect — without self-restricting — whether the OS sandbox is available.
/// Used only by `hasp doctor`; never alters the calling process. On Linux it
/// creates (but does NOT enforce) a Landlock ruleset to confirm kernel support.
pub(crate) fn doctor_status() -> SandboxReport {
    #[cfg(target_os = "linux")]
    {
        use landlock::{AccessFs, Ruleset, RulesetAttr};

        let write_rights = AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::RemoveFile;
        match Ruleset::default()
            .handle_access(write_rights)
            .map_err(|e| format!("{e}"))
            .and_then(|r| r.create().map_err(|e| format!("{e}")))
        {
            Ok(_ruleset) => SandboxReport {
                available: true,
                detail: "Landlock + seccomp available (Linux)".to_string(),
            },
            Err(e) => SandboxReport {
                available: false,
                detail: format!("Landlock unavailable (kernel >= 5.13 required): {e}"),
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        SandboxReport {
            available: false,
            detail: "OS sandbox is Linux-only; use --allow-unsandboxed for development".to_string(),
        }
    }
}

pub(crate) fn phase1_deny_writes_and_syscalls(
    allow_unsandboxed: bool,
    network_policy: NetworkPolicy,
    emit_unsandboxed_warning: bool,
) -> Result<()> {
    platform_preflight(allow_unsandboxed, emit_unsandboxed_warning)?;
    let _ = network_policy;

    #[cfg(target_os = "linux")]
    {
        apply_landlock_deny_writes()?;
        apply_seccomp(network_policy)?;
    }

    Ok(())
}

#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
pub(crate) fn phase2_deny_reads() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        apply_landlock_deny_reads()?;
    }
    Ok(())
}

/// Phase 3: lock down the launcher process after all children have been
/// spawned. At this point the launcher only needs to read from pipes,
/// write to stdout/stderr, wait on children, and exit.
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
pub(crate) fn phase3_deny_launcher(allow_unsandboxed: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = apply_seccomp_launcher() {
            if allow_unsandboxed {
                eprintln!(
                    "hasp: WARNING: launcher self-sandbox failed: {e}. \
                     Continuing because --allow-unsandboxed was supplied."
                );
                return Ok(());
            }
            return Err(e);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = allow_unsandboxed;
    }

    Ok(())
}

// ─── Landlock Phase 1: deny writes ──────────────────────────────────────────

#[cfg(target_os = "linux")]
fn apply_landlock_deny_writes() -> Result<()> {
    use landlock::{AccessFs, Ruleset, RulesetAttr};

    let write_rights = AccessFs::WriteFile
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSym
        | AccessFs::MakeFifo
        | AccessFs::MakeSock
        | AccessFs::RemoveDir
        | AccessFs::RemoveFile;

    let status = Ruleset::default()
        .handle_access(write_rights)
        .map_err(|e| format!("Landlock ruleset error: {e}"))?
        .create()
        .map_err(|e| format!("Landlock create error: {e}"))?
        .restrict_self()
        .map_err(|e| format!("Landlock restrict error: {e}"))?;

    // FAIL CLOSED: if Landlock isn't enforced at all, abort.
    // PartiallyEnforced is acceptable — it means the kernel supports V1+ write
    // restrictions but not the newer V2-V5 rights (Refer, Truncate, etc.).
    // We still get the core write-deny protections.
    match status.ruleset {
        landlock::RulesetStatus::NotEnforced => {
            bail!(
                "Landlock not enforced (kernel >= 5.13 required). \
                 Refusing to run without filesystem sandbox."
            );
        }
        landlock::RulesetStatus::PartiallyEnforced | landlock::RulesetStatus::FullyEnforced => {}
    }

    Ok(())
}

// ─── Landlock Phase 2: deny reads ───────────────────────────────────────────

#[cfg(target_os = "linux")]
fn apply_landlock_deny_reads() -> Result<()> {
    use landlock::{AccessFs, Ruleset, RulesetAttr};

    let read_rights = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;

    let status = Ruleset::default()
        .handle_access(read_rights)
        .map_err(|e| format!("Landlock read-deny error: {e}"))?
        .create()
        .map_err(|e| format!("Landlock create error: {e}"))?
        .restrict_self()
        .map_err(|e| format!("Landlock restrict error: {e}"))?;

    // FAIL CLOSED on total failure; PartiallyEnforced is acceptable (core read
    // deny works, newer kernel rights may not be available).
    match status.ruleset {
        landlock::RulesetStatus::NotEnforced => {
            bail!(
                "Landlock read-deny not enforced (kernel >= 5.13 required). \
                 Refusing to run without filesystem sandbox."
            );
        }
        landlock::RulesetStatus::PartiallyEnforced | landlock::RulesetStatus::FullyEnforced => {}
    }

    Ok(())
}

// ─── Exec child sandbox: Landlock write-whitelist + seccomp ─────────────────

/// Sandbox for `hasp exec` child processes. Denies all writes except to
/// explicitly listed directories, and denies `ptrace`/`process_vm`. Network
/// is handled by BPF cgroup, not seccomp, so we allow network syscalls.
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
/// Apply the exec-child filesystem/syscall sandbox to the current process so
/// the about-to-be-spawned child inherits it.
///
/// `writable_dirs` get full write rights (create/write/remove beneath them).
/// `remove_only_dirs` get *only* `RemoveDir`/`RemoveFile` — used to grant the
/// orchestrator the ability to `rmdir` the per-sandbox cgroup directories (which
/// live directly under these parents) during teardown, without otherwise
/// widening write access. Landlock checks `RemoveDir` against the *parent* of
/// the removed entry, so the parent, not the cgroup dir itself, carries the right.
pub(crate) fn phase_exec_child(
    writable_dirs: &[std::path::PathBuf],
    remove_only_dirs: &[std::path::PathBuf],
    allow_unsandboxed: bool,
) -> Result<()> {
    platform_preflight(allow_unsandboxed, true)?;

    #[cfg(target_os = "linux")]
    {
        apply_landlock_exec_child(writable_dirs, remove_only_dirs)?;
        apply_seccomp_exec_child()?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = writable_dirs;
        let _ = remove_only_dirs;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_landlock_exec_child(
    writable_dirs: &[std::path::PathBuf],
    remove_only_dirs: &[std::path::PathBuf],
) -> Result<()> {
    use landlock::{AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr};

    let write_rights = AccessFs::WriteFile
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSym
        | AccessFs::MakeFifo
        | AccessFs::MakeSock
        | AccessFs::RemoveDir
        | AccessFs::RemoveFile;

    let mut ruleset = Ruleset::default()
        .handle_access(write_rights)
        .map_err(|e| format!("Landlock ruleset error: {e}"))?
        .create()
        .map_err(|e| format!("Landlock create error: {e}"))?;

    for dir in writable_dirs {
        // canonicalize() resolves ALL symlinks, preventing a symlink at
        // ./dist → / from granting write to the root filesystem. It also
        // resolves relative paths to absolute ones.
        let Ok(path) = dir.canonicalize() else {
            eprintln!(
                "hasp exec: warning: writable dir {} does not exist or is not resolvable, skipping",
                dir.display()
            );
            continue;
        };
        if !path.is_dir() {
            eprintln!(
                "hasp exec: warning: writable path {} is not a directory, skipping",
                path.display()
            );
            continue;
        }
        let fd = PathFd::new(&path)
            .map_err(|e| format!("Landlock PathFd error for {}: {e}", path.display()))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, write_rights))
            .map_err(|e| format!("Landlock add_rule error for {}: {e}", path.display()))?;
    }

    // Remove-only parents: grant just the rights needed to delete an empty
    // subdirectory (the per-sandbox cgroup dirs), not to create or write under
    // them. Skips paths that don't resolve rather than failing the whole run.
    let remove_rights = AccessFs::RemoveDir | AccessFs::RemoveFile;
    for dir in remove_only_dirs {
        let Ok(path) = dir.canonicalize() else {
            continue;
        };
        if !path.is_dir() {
            continue;
        }
        let fd = PathFd::new(&path)
            .map_err(|e| format!("Landlock PathFd error for {}: {e}", path.display()))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, remove_rights))
            .map_err(|e| format!("Landlock add_rule error for {}: {e}", path.display()))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| format!("Landlock restrict error: {e}"))?;

    match status.ruleset {
        landlock::RulesetStatus::NotEnforced => {
            bail!(
                "Landlock not enforced (kernel >= 5.13 required). \
                 Refusing to run exec child without filesystem sandbox."
            );
        }
        landlock::RulesetStatus::PartiallyEnforced | landlock::RulesetStatus::FullyEnforced => {}
    }

    Ok(())
}

/// Seccomp for exec child: deny `ptrace`/`process_vm` and keyring access.
/// Allows execve (the child IS an arbitrary command) and network (BPF cgroup
/// handles network policy).
///
/// Note: this does NOT deny namespace syscalls (`unshare`/`clone`/`setns`).
/// A user namespace can't relax the sandbox — `NO_NEW_PRIVS` is set and the
/// Landlock, seccomp, and cgroup-egress restrictions are all inherited across
/// `unshare`/`clone` and can't be dropped — and blocking them outright would
/// break legitimate rootless-container build steps.
#[cfg(target_os = "linux")]
fn apply_seccomp_exec_child() -> Result<()> {
    let denied: Vec<u32> = [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        // Prevent reading inherited kernel keyring entries (SSH keys, etc.)
        libc::SYS_keyctl,
        libc::SYS_request_key,
        libc::SYS_add_key,
    ]
    .iter()
    .map(|&s| u32::try_from(s).expect("libc::SYS_* constants are positive and fit in u32"))
    .collect();
    install_seccomp_filter(&denied, "exec-child")
}

// ─── Seccomp-BPF ─────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
const NETWORK_SYSCALLS: &[i64] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    // Block fd-passing via SCM_RIGHTS to prevent exfiltration over
    // any hypothetically inherited socket fds.
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_sendmmsg,
    libc::SYS_recvmmsg,
];

#[cfg(target_os = "linux")]
const PROCESS_SYSCALLS: &[i64] = &[
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
];

/// Install a seccomp-BPF filter that kills the process on any denied syscall.
#[cfg(target_os = "linux")]
fn install_seccomp_filter(denied: &[u32], label: &str) -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xC000_00B7;

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    const fn stmt(code: u16, k: u32) -> SockFilter {
        SockFilter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    const LD_ABS_W: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RET_K: u16 = 0x06; // BPF_RET | BPF_K
    const RET_ALLOW: u32 = 0x7FFF_0000;
    const RET_KILL: u32 = 0x8000_0000; // SECCOMP_RET_KILL_PROCESS

    // On x86_64, syscalls issued through the x32 ABI report AUDIT_ARCH_X86_64
    // but carry __X32_SYSCALL_BIT (0x4000_0000) in the syscall number. Without
    // an explicit guard, a denied syscall (socket, connect, execve, ptrace, …)
    // invoked as `nr | 0x4000_0000` matches no JEQ entry and falls through to
    // RET_ALLOW, defeating the filter. We insert one extra instruction that
    // kills any syscall with that bit set. aarch64 has no x32 ABI.
    #[cfg(target_arch = "x86_64")]
    const X32_GUARD: usize = 1;
    #[cfg(not(target_arch = "x86_64"))]
    const X32_GUARD: usize = 0;

    let n = denied.len();
    let kill_idx = 3 + X32_GUARD + n + 1;

    if n > 250 {
        bail!("Too many denied syscalls for BPF filter: {} (max 250)", n);
    }

    let mut filter = Vec::with_capacity(kill_idx + 1);

    filter.push(stmt(LD_ABS_W, 4)); // load arch
    filter.push(jump(
        JEQ_K,
        AUDIT_ARCH,
        0,
        u8::try_from(kill_idx - 2).expect("offset bounded by n ≤ 250 check"),
    )); // wrong arch → kill
    filter.push(stmt(LD_ABS_W, 0)); // load syscall nr

    #[cfg(target_arch = "x86_64")]
    {
        const JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K (unsigned >=)
        const X32_SYSCALL_BIT: u32 = 0x4000_0000;
        filter.push(jump(
            JGE_K,
            X32_SYSCALL_BIT,
            u8::try_from(kill_idx - 4).expect("offset bounded by n ≤ 250 check"),
            0,
        )); // x32 syscall (high bit set) → kill
    }

    for (i, &sc) in denied.iter().enumerate() {
        filter.push(jump(
            JEQ_K,
            sc,
            u8::try_from(kill_idx - 3 - X32_GUARD - i - 1)
                .expect("offset bounded by n ≤ 250 check"),
            0,
        ));
    }

    filter.push(stmt(RET_K, RET_ALLOW));
    filter.push(stmt(RET_K, RET_KILL));

    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS) is a well-defined Linux syscall that
    // sets a process attribute. No pointer aliasing or memory safety concerns.
    #[allow(unsafe_code)]
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        bail!(
            "prctl(NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let prog = SockFprog {
        len: u16::try_from(filter.len()).expect("filter length bounded by n ≤ 250 check"),
        filter: filter.as_ptr(),
    };
    // SAFETY: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) installs a
    // BPF filter. `prog` and `filter` are valid for the duration of this call;
    // the kernel copies the program, so no lifetime concern after prctl returns.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
            std::ptr::from_ref(&prog) as libc::c_ulong,
            0,
            0,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        bail!("{label} seccomp-bpf failed: {err}. Refusing to run without syscall filter.");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_seccomp(network_policy: NetworkPolicy) -> Result<()> {
    let mut denied: Vec<u32> = PROCESS_SYSCALLS
        .iter()
        .map(|&s| u32::try_from(s).expect("syscall id fits in u32"))
        .collect();
    if matches!(network_policy, NetworkPolicy::DenyNewSockets) {
        denied.extend(
            NETWORK_SYSCALLS
                .iter()
                .map(|&s| u32::try_from(s).expect("syscall id fits in u32")),
        );
    }
    install_seccomp_filter(&denied, "scanner")
}

/// Applies a seccomp-BPF filter to the launcher process itself after all
/// children have been spawned.  Denies exec, ptrace, and all network syscalls.
/// The launcher only needs: read from pipes, write to stdout/stderr, wait on
/// children, and exit.
#[cfg(target_os = "linux")]
fn apply_seccomp_launcher() -> Result<()> {
    let mut denied: Vec<u32> = PROCESS_SYSCALLS
        .iter()
        .map(|&s| u32::try_from(s).expect("syscall id fits in u32"))
        .collect();
    denied.extend(
        NETWORK_SYSCALLS
            .iter()
            .map(|&s| u32::try_from(s).expect("syscall id fits in u32")),
    );
    install_seccomp_filter(&denied, "launcher")
}
