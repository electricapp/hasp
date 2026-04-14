use crate::error::{Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

#[cfg(target_os = "linux")]
use crate::error::bail;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::net::{SocketAddrV4, SocketAddrV6};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::process::Stdio;

// ─── BPF syscall constants ───────────────────────────────────────────────────
// These were removed from the `libc` crate in 0.2.185. Values are from
// `<linux/bpf.h>` and are part of the stable Linux syscall ABI.

#[cfg(target_os = "linux")]
#[allow(non_camel_case_types)]
mod bpf {
    pub(super) const BPF_MAP_CREATE: libc::c_long = 0;
    pub(super) const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
    pub(super) const BPF_PROG_LOAD: libc::c_long = 5;
    pub(super) const BPF_PROG_ATTACH: libc::c_long = 8;

    pub(super) const BPF_MAP_TYPE_HASH: u32 = 1;

    pub(super) const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;

    pub(super) const BPF_CGROUP_INET4_CONNECT: u32 = 10;
    pub(super) const BPF_CGROUP_INET6_CONNECT: u32 = 11;
    pub(super) const BPF_CGROUP_UDP4_SENDMSG: u32 = 14;
    pub(super) const BPF_CGROUP_UDP6_SENDMSG: u32 = 15;

    pub(super) const BPF_ANY: u64 = 0;
}

// ─── BPF helper IPC ──────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
const BPF_READY_MAGIC: &str = "HASP_BPF_READY_V1";
#[cfg(target_os = "linux")]
const BPF_HELPER_ALLOWLIST_ENV: &str = "HASP_BPF_ALLOWLIST";
#[cfg(target_os = "linux")]
const BPF_HELPER_MODE_ENV: &str = "HASP_BPF_MODE";
#[cfg(target_os = "linux")]
const BPF_HELPER_OWNER_UID_ENV: &str = "HASP_BPF_OWNER_UID";
#[cfg(target_os = "linux")]
const BPF_HELPER_OWNER_GID_ENV: &str = "HASP_BPF_OWNER_GID";

#[derive(Clone, Copy)]
pub(crate) enum SandboxMode {
    Proxy,
    Verifier,
    StepRunner,
    SecretProxy,
}

impl SandboxMode {
    /// All sandboxed processes try `sudo` when unprivileged BPF/cgroup
    /// setup fails. On GitHub-hosted runners and many CI envs, sudo is
    /// passwordless and the helper can engage the egress sandbox even
    /// for the scanner path. Without sudo, callers may still opt to
    /// continue via `--allow-unsandboxed`.
    #[cfg(target_os = "linux")]
    const fn use_sudo_fallback(self) -> bool {
        matches!(
            self,
            Self::Proxy | Self::Verifier | Self::StepRunner | Self::SecretProxy
        )
    }

    #[cfg(target_os = "linux")]
    const fn label(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Verifier => "verifier",
            Self::StepRunner => "step",
            Self::SecretProxy => "secret-proxy",
        }
    }

    #[cfg(target_os = "linux")]
    const fn detail(self) -> &'static str {
        match self {
            Self::Proxy => "proxy process constrained to GitHub API IPs",
            Self::Verifier => "verifier process constrained to the local proxy",
            Self::StepRunner => "step runner constrained to proxy localhost ports",
            Self::SecretProxy => "secret proxy constrained to upstream domain IPs",
        }
    }
}

pub(crate) struct SandboxHandle {
    path: PathBuf,
}

impl SandboxHandle {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(target_os = "linux")]
    fn move_pid(&self, pid: u32) -> Result<()> {
        std::fs::write(self.path.join("cgroup.procs"), format!("{pid}\n"))
            .context("Failed to move process into sandbox cgroup")
    }
}

impl Drop for SandboxHandle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
pub(crate) fn maybe_prepare(
    mode: SandboxMode,
    allowlist: &[SocketAddr],
    allow_unsandboxed: bool,
) -> Result<Option<SandboxHandle>> {
    #[cfg(target_os = "linux")]
    {
        match prepare_linux(mode, allowlist) {
            Ok(handle) => {
                eprintln!(
                    "hasp: note: kernel egress sandbox active ({})",
                    mode.detail()
                );
                Ok(Some(handle))
            }
            Err(err) => {
                // If BPF failed (EPERM) and this mode supports sudo, try elevated helper
                if mode.use_sudo_fallback()
                    && (err.msg().contains("BPF")
                        || err.msg().contains("Failed to create cgroup"))
                {
                    eprintln!("hasp: note: unprivileged BPF unavailable, trying sudo helper...");
                    match prepare_linux_via_sudo(mode, allowlist) {
                        Ok(handle) => {
                            eprintln!(
                                "hasp: note: kernel egress sandbox active via sudo ({})",
                                mode.detail()
                            );
                            return Ok(Some(handle));
                        }
                        Err(sudo_err) => {
                            if allow_unsandboxed {
                                eprintln!(
                                    "hasp: WARNING: kernel egress sandbox unavailable \
                                     (sudo fallback failed: {sudo_err}). \
                                     Continuing because --allow-unsandboxed was supplied."
                                );
                                return Ok(None);
                            }
                            return Err(crate::error::Error::new(format!(
                                "kernel egress sandbox unavailable: {err}; \
                                 sudo fallback also failed: {sudo_err}. \
                                 Rerun with --allow-unsandboxed only for development."
                            )));
                        }
                    }
                }
                if allow_unsandboxed {
                    eprintln!(
                        "hasp: WARNING: kernel egress sandbox unavailable: {err}. \
                         Continuing because --allow-unsandboxed was supplied."
                    );
                    return Ok(None);
                }
                Err(crate::error::Error::new(format!(
                    "kernel egress sandbox unavailable: {err}. \
                     Refusing to run without cgroup/BPF; \
                     rerun with --allow-unsandboxed only for development."
                )))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = mode;
        let _ = allowlist;
        let _ = allow_unsandboxed;
        Ok(None)
    }
}

pub(crate) fn spawn_command(mut cmd: Command, sandbox: Option<&SandboxHandle>) -> Result<Child> {
    #[cfg(not(target_os = "linux"))]
    let _ = sandbox;

    #[cfg(target_os = "linux")]
    if sandbox.is_some() {
        // SAFETY: pre_exec runs in the forked child between fork and exec.
        // We only call async-signal-safe libc functions (kill, getpid).
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(|| {
                if libc::kill(libc::getpid(), libc::SIGSTOP) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let child = cmd.spawn().context("Failed to spawn child process")?;

    #[cfg(target_os = "linux")]
    if let Some(sandbox) = sandbox {
        wait_for_stop(child.id())?;
        sandbox.move_pid(child.id())?;
        resume_process(child.id())?;
    }

    Ok(child)
}

#[cfg(target_os = "linux")]
fn wait_for_stop(pid: u32) -> Result<()> {
    let pid_t = libc::pid_t::try_from(pid)
        .map_err(|_| crate::error::Error::new(format!("PID {pid} exceeds pid_t range")))?;
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid is a well-defined Linux syscall. `status` is a valid
    // mutable pointer to a stack-allocated c_int.
    #[allow(unsafe_code)]
    let ret = unsafe { libc::waitpid(pid_t, &raw mut status, libc::WUNTRACED) };
    if ret < 0 {
        bail!(
            "waitpid() failed while preparing sandboxed child: {}",
            std::io::Error::last_os_error()
        );
    }
    let stopped = libc::WIFSTOPPED(status);
    if ret == 0 || !stopped {
        bail!("Sandboxed child did not stop before exec");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resume_process(pid: u32) -> Result<()> {
    let pid_t = libc::pid_t::try_from(pid)
        .map_err(|_| crate::error::Error::new(format!("PID {pid} exceeds pid_t range")))?;
    // SAFETY: kill is a well-defined Linux syscall taking a pid and signal.
    #[allow(unsafe_code)]
    let ret = unsafe { libc::kill(pid_t, libc::SIGCONT) };
    if ret != 0 {
        bail!(
            "Failed to resume sandboxed child: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

// BPF_CGROUP_UNIX_CONNECT was added in Linux 6.7. The libc crate may not
// define it yet, so we use the raw constant from the kernel UAPI header.
#[cfg(target_os = "linux")]
const BPF_CGROUP_UNIX_CONNECT: u32 = 46;

/// Attach a BPF program that unconditionally denies all `AF_UNIX` `connect()`
/// calls on the given cgroup. Prevents access to Docker socket, D-Bus, etc.
#[cfg(target_os = "linux")]
fn attach_unix_deny_prog(cgroup_fd: libc::c_int) -> Result<()> {
    let prog_fd = load_deny_all_prog(BPF_CGROUP_UNIX_CONNECT)?;
    let result = attach_prog(cgroup_fd, prog_fd, BPF_CGROUP_UNIX_CONNECT);
    // SAFETY: closing a BPF program fd we just created via bpf() syscall.
    #[allow(unsafe_code)]
    unsafe {
        libc::close(prog_fd);
    }
    result
}

/// Load a minimal BPF program: `mov r0, 0; exit` — unconditional deny.
#[cfg(target_os = "linux")]
fn load_deny_all_prog(attach_type: u32) -> Result<libc::c_int> {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Insn {
        code: u8,
        regs: u8,
        off: i16,
        imm: i32,
    }

    #[repr(C)]
    struct Attr {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
    }

    // r0 = 0 (deny); exit
    let program = [
        Insn {
            code: 0x07 | 0xb0, // BPF_ALU64 | BPF_MOV | BPF_K (BPF_K == 0)
            regs: 0,
            off: 0,
            imm: 0,
        },
        Insn {
            code: 0x05 | 0x90, // BPF_JMP | BPF_EXIT
            regs: 0,
            off: 0,
            imm: 0,
        },
    ];
    let license = b"GPL\0";
    let insn_cnt = u32::try_from(program.len()).expect("program length fits in u32");
    let attr = Attr {
        prog_type: bpf::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        insn_cnt,
        insns: program.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
        kern_version: 0,
        prog_flags: 0,
        prog_name: [0; 16],
        prog_ifindex: 0,
        expected_attach_type: attach_type,
    };

    // SAFETY: bpf(BPF_PROG_LOAD) is a well-defined Linux syscall. The Attr
    // struct and program array are valid for the duration of this call.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf::BPF_PROG_LOAD,
            std::ptr::from_ref(&attr),
            size_of::<Attr>(),
        )
    };
    if ret < 0 {
        bail!(
            "BPF_PROG_LOAD (deny-all) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    libc::c_int::try_from(ret).context("BPF_PROG_LOAD returned fd out of c_int range")
}

/// Set the maximum number of PIDs in a cgroup (fork bomb prevention).
/// Best-effort: silently returns Ok if the write fails (e.g. non-root).
#[cfg(target_os = "linux")]
fn set_pids_max(cgroup_path: &Path, max: u32) -> Result<()> {
    let pids_max_path = cgroup_path.join("pids.max");
    std::fs::write(&pids_max_path, format!("{max}\n")).context(format!(
        "Failed to write pids.max for {}",
        cgroup_path.display()
    ))
}

#[cfg(target_os = "linux")]
fn prepare_linux(mode: SandboxMode, allowlist: &[SocketAddr]) -> Result<SandboxHandle> {
    let cgroup_path = create_cgroup(mode)?;
    let cgroup_fd = open_dir_fd(&cgroup_path)?;

    let v4_targets: Vec<SocketAddrV4> = allowlist
        .iter()
        .filter_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(*v4),
            SocketAddr::V6(_) => None,
        })
        .collect();
    let v6_targets: Vec<SocketAddrV6> = allowlist
        .iter()
        .filter_map(|addr| match addr {
            SocketAddr::V4(_) => None,
            SocketAddr::V6(v6) => Some(*v6),
        })
        .collect();

    let v4_entries = u32::try_from(std::cmp::max(v4_targets.len(), 1))
        .context("too many v4 allowlist entries")?;
    let v6_entries = u32::try_from(std::cmp::max(v6_targets.len(), 1))
        .context("too many v6 allowlist entries")?;
    let v4_map = create_hash_map(8, v4_entries)?;
    let v6_map = create_hash_map(20, v6_entries)?;

    for target in &v4_targets {
        update_v4_allowlist(v4_map, *target)?;
    }
    for target in &v6_targets {
        update_v6_allowlist(v6_map, *target)?;
    }

    attach_sock_addr_prog(
        cgroup_fd,
        v4_map,
        bpf::BPF_CGROUP_INET4_CONNECT,
        IpVersion::V4,
    )?;
    attach_sock_addr_prog(
        cgroup_fd,
        v6_map,
        bpf::BPF_CGROUP_INET6_CONNECT,
        IpVersion::V6,
    )?;
    attach_sock_addr_prog(
        cgroup_fd,
        v4_map,
        bpf::BPF_CGROUP_UDP4_SENDMSG,
        IpVersion::V4,
    )?;
    attach_sock_addr_prog(
        cgroup_fd,
        v6_map,
        bpf::BPF_CGROUP_UDP6_SENDMSG,
        IpVersion::V6,
    )?;

    // Best-effort: deny AF_UNIX connections to prevent Docker socket, D-Bus,
    // and SSH agent access. Requires kernel 6.7+ (BPF_CGROUP_UNIX_CONNECT).
    // Silently skipped on older kernels — INET confinement still active.
    if let Err(e) = attach_unix_deny_prog(cgroup_fd) {
        eprintln!("hasp: note: AF_UNIX deny unavailable ({e}), INET-only confinement");
    }

    // Best-effort: cap child process count to prevent fork bombs.
    // Succeeds as root (sudo helper path); silently ignored if unprivileged.
    let _ = set_pids_max(&cgroup_path, 4096);

    // SAFETY: closing file descriptors we opened earlier in this function.
    // These are plain ints returned by kernel syscalls (BPF map create, dup).
    #[allow(unsafe_code)]
    unsafe {
        libc::close(v4_map);
        libc::close(v6_map);
        libc::close(cgroup_fd);
    }

    Ok(SandboxHandle { path: cgroup_path })
}

#[cfg(target_os = "linux")]
fn create_cgroup(mode: SandboxMode) -> Result<PathBuf> {
    let base = current_cgroup_dir()?;
    let path = base.join(format!(
        "hasp-{}-{}-{}",
        std::process::id(),
        mode.label(),
        unique_suffix()
    ));
    std::fs::create_dir_all(&path)
        .context(format!("Failed to create cgroup {}", path.display()))?;
    Ok(path)
}

#[cfg(target_os = "linux")]
fn current_cgroup_dir() -> Result<PathBuf> {
    let text =
        std::fs::read_to_string("/proc/self/cgroup").context("Failed to read /proc/self/cgroup")?;
    let rel = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .context("Current process is not running in a cgroup v2 hierarchy")?;
    let mut path = PathBuf::from("/sys/fs/cgroup");
    path.push(rel.trim_start_matches('/'));
    if !path.is_dir() {
        bail!("Resolved cgroup path {} is not a directory", path.display());
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn unique_suffix() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(target_os = "linux")]
fn open_dir_fd(path: &Path) -> Result<libc::c_int> {
    let file = File::open(path).context(format!("Failed to open {}", path.display()))?;
    let fd = file.as_raw_fd();
    // SAFETY: dup() is a well-defined Linux syscall taking a valid fd.
    #[allow(unsafe_code)]
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        bail!(
            "dup() failed for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(dup_fd)
}

#[cfg(target_os = "linux")]
fn create_hash_map(key_size: u32, max_entries: u32) -> Result<libc::c_int> {
    #[repr(C)]
    struct Attr {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    }

    let attr = Attr {
        map_type: bpf::BPF_MAP_TYPE_HASH,
        key_size,
        value_size: 1,
        max_entries,
        map_flags: 0,
    };
    // SAFETY: bpf(BPF_MAP_CREATE) is a well-defined Linux syscall.
    // `attr` is a valid stack-allocated struct for the duration of the call.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf::BPF_MAP_CREATE,
            std::ptr::from_ref(&attr),
            size_of::<Attr>(),
        )
    };
    if ret < 0 {
        bail!("BPF_MAP_CREATE failed: {}", std::io::Error::last_os_error());
    }
    libc::c_int::try_from(ret).context("BPF_MAP_CREATE returned fd out of c_int range")
}

#[cfg(target_os = "linux")]
fn update_v4_allowlist(map_fd: libc::c_int, target: SocketAddrV4) -> Result<()> {
    #[repr(C)]
    struct Key {
        ip: u32,
        port: u32,
    }

    // IPv4 octets are in network byte order (big-endian).
    // The kernel's bpf_sock_addr.user_ip4 field is also in network byte order.
    // Use from_be_bytes to convert correctly on all architectures.
    let key = Key {
        ip: u32::from_be_bytes(target.ip().octets()),
        port: u32::from(target.port().to_be()),
    };
    update_map(map_fd, &key, &1_u8)
}

#[cfg(target_os = "linux")]
fn update_v6_allowlist(map_fd: libc::c_int, target: SocketAddrV6) -> Result<()> {
    #[repr(C)]
    struct Key {
        ip: [u32; 4],
        port: u32,
    }

    // IPv6 octets are in network byte order. The kernel's bpf_sock_addr.user_ip6 is also
    // in network byte order. Use from_be_bytes on each 4-byte chunk.
    let octets = target.ip().octets();
    let key = Key {
        ip: [
            u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
            u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
            u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
            u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
        ],
        port: u32::from(target.port().to_be()),
    };
    update_map(map_fd, &key, &1_u8)
}

#[cfg(target_os = "linux")]
fn update_map<K, V>(map_fd: libc::c_int, key: &K, value: &V) -> Result<()> {
    #[repr(C)]
    struct Attr {
        map_fd: u32,
        pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let attr = Attr {
        map_fd: u32::try_from(map_fd).context("map_fd must be non-negative")?,
        pad: 0,
        key: std::ptr::from_ref(key) as u64,
        value: std::ptr::from_ref(value) as u64,
        flags: bpf::BPF_ANY,
    };
    // SAFETY: bpf(BPF_MAP_UPDATE_ELEM) is a well-defined Linux syscall.
    // `attr` is valid for the duration of the call; the kernel reads `key`
    // and `value` via the embedded pointers, both of which outlive the call.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf::BPF_MAP_UPDATE_ELEM,
            std::ptr::from_ref(&attr),
            size_of::<Attr>(),
        )
    };
    if ret != 0 {
        bail!(
            "BPF_MAP_UPDATE_ELEM failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum IpVersion {
    V4,
    V6,
}

#[cfg(target_os = "linux")]
fn attach_sock_addr_prog(
    cgroup_fd: libc::c_int,
    map_fd: libc::c_int,
    attach_type: u32,
    version: IpVersion,
) -> Result<()> {
    let prog_fd = load_sock_addr_prog(map_fd, attach_type, version)?;
    attach_prog(cgroup_fd, prog_fd, attach_type)?;
    // SAFETY: closing a file descriptor we received from load_sock_addr_prog.
    #[allow(unsafe_code)]
    unsafe {
        libc::close(prog_fd);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn attach_prog(cgroup_fd: libc::c_int, prog_fd: libc::c_int, attach_type: u32) -> Result<()> {
    #[repr(C)]
    struct Attr {
        target_fd: u32,
        attach_bpf_fd: u32,
        attach_type: u32,
        attach_flags: u32,
        replace_bpf_fd: u32,
    }

    let attr = Attr {
        target_fd: u32::try_from(cgroup_fd).context("cgroup_fd must be non-negative")?,
        attach_bpf_fd: u32::try_from(prog_fd).context("prog_fd must be non-negative")?,
        attach_type,
        attach_flags: 0,
        replace_bpf_fd: 0,
    };
    // SAFETY: bpf(BPF_PROG_ATTACH) is a well-defined Linux syscall; `attr`
    // is valid for the duration of the call.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf::BPF_PROG_ATTACH,
            std::ptr::from_ref(&attr),
            size_of::<Attr>(),
        )
    };
    if ret != 0 {
        bail!(
            "BPF_PROG_ATTACH failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

#[cfg(target_os = "linux")]
const fn bpf_insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> BpfInsn {
    BpfInsn {
        code,
        regs: (src << 4) | dst,
        off,
        imm,
    }
}

#[cfg(target_os = "linux")]
fn build_sock_addr_program(map_fd: libc::c_int, version: IpVersion) -> Vec<BpfInsn> {
    const BPF_LD: u8 = 0x00;
    const BPF_LDX: u8 = 0x01;
    const BPF_STX: u8 = 0x03;
    const BPF_JMP: u8 = 0x05;
    const BPF_ALU64: u8 = 0x07;
    const BPF_W: u8 = 0x00;
    const BPF_DW: u8 = 0x18;
    const BPF_MEM: u8 = 0x60;
    const BPF_IMM: u8 = 0x00;
    const BPF_K: u8 = 0x00;
    const BPF_X: u8 = 0x08;
    const BPF_ADD: u8 = 0x00;
    const BPF_JNE: u8 = 0x50;
    const BPF_CALL: u8 = 0x80;
    const BPF_EXIT: u8 = 0x90;
    const BPF_MOV: u8 = 0xb0;
    const BPF_PSEUDO_MAP_FD: u8 = 1;
    const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;

    const R0: u8 = 0;
    const R1: u8 = 1;
    const R2: u8 = 2;
    const R3: u8 = 3;
    const R6: u8 = 6;
    const R10: u8 = 10;

    const fn mov64_reg(dst: u8, src: u8) -> BpfInsn {
        bpf_insn(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
    }
    const fn mov64_imm(dst: u8, imm: i32) -> BpfInsn {
        bpf_insn(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
    }
    const fn add64_imm(dst: u8, imm: i32) -> BpfInsn {
        bpf_insn(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm)
    }
    const fn ldx_mem_w(dst: u8, src: u8, off: i16) -> BpfInsn {
        bpf_insn(BPF_LDX | BPF_W | BPF_MEM, dst, src, off, 0)
    }
    const fn stx_mem_w(dst: u8, off: i16, src: u8) -> BpfInsn {
        bpf_insn(BPF_STX | BPF_W | BPF_MEM, dst, src, off, 0)
    }
    const fn call(helper: i32) -> BpfInsn {
        bpf_insn(BPF_JMP | BPF_CALL, 0, 0, 0, helper)
    }
    const fn jne_imm(dst: u8, imm: i32, off: i16) -> BpfInsn {
        bpf_insn(BPF_JMP | BPF_JNE | BPF_K, dst, 0, off, imm)
    }
    const fn exit() -> BpfInsn {
        bpf_insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
    }
    const fn ld_map_fd(dst: u8, fd: i32) -> [BpfInsn; 2] {
        [
            bpf_insn(BPF_LD | BPF_DW | BPF_IMM, dst, BPF_PSEUDO_MAP_FD, 0, fd),
            bpf_insn(0, 0, 0, 0, 0),
        ]
    }

    match version {
        IpVersion::V4 => {
            let mut p = Vec::with_capacity(14);
            p.push(mov64_reg(R6, R1));
            p.push(mov64_reg(R2, R10));
            p.push(add64_imm(R2, -8));
            p.push(ldx_mem_w(R3, R6, 4));
            p.push(stx_mem_w(R2, 0, R3));
            p.push(ldx_mem_w(R3, R6, 24));
            p.push(stx_mem_w(R2, 4, R3));
            p.extend_from_slice(&ld_map_fd(R1, map_fd));
            p.push(call(BPF_FUNC_MAP_LOOKUP_ELEM));
            p.push(jne_imm(R0, 0, 2));
            p.push(mov64_imm(R0, 0));
            p.push(exit());
            p.push(mov64_imm(R0, 1));
            p.push(exit());
            p
        }
        IpVersion::V6 => {
            let mut p = Vec::with_capacity(20);
            p.push(mov64_reg(R6, R1));
            p.push(mov64_reg(R2, R10));
            p.push(add64_imm(R2, -24));
            p.push(ldx_mem_w(R3, R6, 8));
            p.push(stx_mem_w(R2, 0, R3));
            p.push(ldx_mem_w(R3, R6, 12));
            p.push(stx_mem_w(R2, 4, R3));
            p.push(ldx_mem_w(R3, R6, 16));
            p.push(stx_mem_w(R2, 8, R3));
            p.push(ldx_mem_w(R3, R6, 20));
            p.push(stx_mem_w(R2, 12, R3));
            p.push(ldx_mem_w(R3, R6, 24));
            p.push(stx_mem_w(R2, 16, R3));
            p.extend_from_slice(&ld_map_fd(R1, map_fd));
            p.push(call(BPF_FUNC_MAP_LOOKUP_ELEM));
            p.push(jne_imm(R0, 0, 2));
            p.push(mov64_imm(R0, 0));
            p.push(exit());
            p.push(mov64_imm(R0, 1));
            p.push(exit());
            p
        }
    }
}

#[cfg(target_os = "linux")]
fn load_sock_addr_prog(
    map_fd: libc::c_int,
    attach_type: u32,
    version: IpVersion,
) -> Result<libc::c_int> {
    #[repr(C)]
    struct Attr {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
    }

    let program = build_sock_addr_program(map_fd, version);
    let license = b"GPL\0";
    let mut log_buf = vec![0_u8; 64 * 1024];
    let insn_cnt = u32::try_from(program.len()).expect("program length fits in u32");
    let log_size = u32::try_from(log_buf.len()).expect("log buffer size fits in u32");
    let attr = Attr {
        prog_type: bpf::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        insn_cnt,
        insns: program.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size,
        log_buf: log_buf.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name: [0; 16],
        prog_ifindex: 0,
        expected_attach_type: attach_type,
    };

    // SAFETY: bpf(BPF_PROG_LOAD) is a well-defined Linux syscall; `attr`,
    // the program slice, license, and log buffer all outlive the call.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf::BPF_PROG_LOAD,
            std::ptr::from_ref(&attr),
            size_of::<Attr>(),
        )
    };
    if ret < 0 {
        let log = String::from_utf8_lossy(&log_buf)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        if log.is_empty() {
            bail!("BPF_PROG_LOAD failed: {}", std::io::Error::last_os_error());
        }
        bail!(
            "BPF_PROG_LOAD failed: {} ({log})",
            std::io::Error::last_os_error()
        );
    }
    libc::c_int::try_from(ret).context("BPF_PROG_LOAD returned fd out of c_int range")
}

// ─── Privileged BPF helper ──────────────────────────────────────────────────
//
// When unprivileged BPF is disabled (the default on Ubuntu), `hasp exec` spawns
// a short-lived `sudo hasp --internal-bpf-helper` process that creates the
// cgroup, loads BPF programs, delegates the cgroup to the original user, and
// exits. The BPF programs persist on the cgroup after the helper exits.
// The unprivileged parent then moves the child process into the cgroup.
//

/// Entry point for `hasp --internal-bpf-helper`. Runs as root via sudo.
#[cfg(target_os = "linux")]
pub(crate) fn run_bpf_helper() -> Result<()> {
    let allowlist = parse_helper_allowlist()?;
    let mode = parse_helper_mode()?;
    let user_id = parse_helper_u32(BPF_HELPER_OWNER_UID_ENV)?;
    let group_id = parse_helper_u32(BPF_HELPER_OWNER_GID_ENV)?;

    let handle = prepare_linux(mode, &allowlist)?;
    delegate_cgroup(&handle.path, user_id, group_id)?;

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    writeln!(lock, "{BPF_READY_MAGIC}\t{}", handle.path.display())
        .context("Failed to announce BPF helper readiness")?;
    lock.flush().context("Failed to flush BPF helper output")?;

    // Parent takes ownership of the cgroup — suppress cleanup on drop.
    let _keep = std::mem::ManuallyDrop::new(handle);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn run_bpf_helper() -> Result<()> {
    crate::error::bail!("BPF helper is only available on Linux")
}

/// Spawn `sudo hasp --internal-bpf-helper` and parse the cgroup path it creates.
#[cfg(target_os = "linux")]
fn prepare_linux_via_sudo(mode: SandboxMode, allowlist: &[SocketAddr]) -> Result<SandboxHandle> {
    let exe = std::env::current_exe().context("Cannot resolve executable for sudo BPF helper")?;

    // SAFETY: getuid is a trivial POSIX syscall with no pointer arguments.
    #[allow(unsafe_code)]
    let uid = unsafe { libc::getuid() };
    // SAFETY: getgid is a trivial POSIX syscall with no pointer arguments.
    #[allow(unsafe_code)]
    let gid = unsafe { libc::getgid() };

    let addrs_str = allowlist
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    // Use `sudo env KEY=VALUE ... hasp --internal-bpf-helper` so that env
    // vars survive regardless of the system's sudoers env_reset policy.
    let output = Command::new("sudo")
        .args(["--non-interactive", "env"])
        .arg(format!("{BPF_HELPER_ALLOWLIST_ENV}={addrs_str}"))
        .arg(format!("{BPF_HELPER_MODE_ENV}={}", mode.label()))
        .arg(format!("{BPF_HELPER_OWNER_UID_ENV}={uid}"))
        .arg(format!("{BPF_HELPER_OWNER_GID_ENV}={gid}"))
        .arg(&exe)
        .arg("--internal-bpf-helper")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .context("Failed to spawn sudo BPF helper")?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        bail!("sudo BPF helper exited with code {code}");
    }

    let stdout_str = String::from_utf8(output.stdout)
        .map_err(|_| crate::error::Error::new("BPF helper produced non-UTF8 output".to_string()))?;
    let line = stdout_str
        .lines()
        .next()
        .context("BPF helper produced no output")?;
    let parts: Vec<&str> = line.splitn(2, '\t').collect();
    if parts.len() != 2 || parts[0] != BPF_READY_MAGIC {
        bail!("Malformed BPF helper ready line");
    }

    let path = PathBuf::from(parts[1]);
    if !path.is_dir() {
        bail!(
            "BPF helper returned non-existent cgroup path: {}",
            path.display()
        );
    }

    Ok(SandboxHandle { path })
}

/// `chown` the cgroup directory and `cgroup.procs` so the unprivileged parent
/// can move processes into the cgroup and clean it up on exit.
#[cfg(target_os = "linux")]
fn delegate_cgroup(path: &Path, uid: u32, gid: u32) -> Result<()> {
    chown_path(path, uid, gid)?;
    chown_path(&path.join("cgroup.procs"), uid, gid)
}

#[cfg(target_os = "linux")]
fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| crate::error::Error::new("Path contains null byte".to_string()))?;
    // SAFETY: chown is a standard POSIX syscall. c_path is a valid
    // null-terminated string for the duration of this call.
    #[allow(unsafe_code)]
    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        bail!(
            "Failed to chown {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_helper_allowlist() -> Result<Vec<SocketAddr>> {
    let raw = std::env::var(BPF_HELPER_ALLOWLIST_ENV)
        .context(format!("{BPF_HELPER_ALLOWLIST_ENV} not set"))?;
    let mut addrs = Vec::new();
    for part in raw.split(',').filter(|p| !p.is_empty()) {
        addrs.push(
            part.parse::<SocketAddr>()
                .context(format!("Invalid address in BPF helper allowlist: `{part}`"))?,
        );
    }
    if addrs.is_empty() {
        bail!("BPF helper received empty allowlist");
    }
    Ok(addrs)
}

#[cfg(target_os = "linux")]
fn parse_helper_mode() -> Result<SandboxMode> {
    let raw =
        std::env::var(BPF_HELPER_MODE_ENV).context(format!("{BPF_HELPER_MODE_ENV} not set"))?;
    match raw.as_str() {
        "proxy" => Ok(SandboxMode::Proxy),
        "verifier" => Ok(SandboxMode::Verifier),
        "step" => Ok(SandboxMode::StepRunner),
        "secret-proxy" => Ok(SandboxMode::SecretProxy),
        other => bail!("Unknown BPF helper mode: {other}"),
    }
}

#[cfg(target_os = "linux")]
fn parse_helper_u32(var: &str) -> Result<u32> {
    std::env::var(var)
        .context(format!("{var} not set"))?
        .parse::<u32>()
        .context(format!("{var} is not a valid u32"))
}
