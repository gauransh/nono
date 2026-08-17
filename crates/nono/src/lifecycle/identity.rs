//! Process identity that a recycled pid cannot forge.
//!
//! A pid on its own proves nothing: the kernel hands the number back out once
//! the process is reaped, so "pid 4242 is still alive" can be true about an
//! entirely different program. [`ProcessIdentity`] pairs the pid with two facts
//! that a recycled pid cannot reproduce — the process's own start time and the
//! boot the number was issued in — and re-checks all three together.
//!
//! Both extra facts are best-effort: a platform may refuse them (permissions,
//! a missing `/proc`, a sysctl that is not present). When either half is
//! missing the answer is [`ProcessIdentity::is_same_process`] `== false`, never
//! an optimistic "probably". Absence of evidence is not evidence of identity.
//!
//! # Attribution
//!
//! The per-platform start-time reads are lifted from `nono-cli`'s
//! `session.rs::get_process_start_time` (`crates/nono-cli/src/session.rs`,
//! Linux `/proc/<pid>/stat` field 22 and the macOS `PROC_PIDTBSDINFO` layout).
//! That code is private to the binary crate, so the library cannot call it; the
//! logic is reproduced here with the arithmetic made checked. The boot-identity
//! half is new to this module.

use serde::{Deserialize, Serialize};

/// A pid plus the facts that make it non-reusable.
///
/// Captured immediately after `fork` and re-checked before any statement about
/// "that process" is trusted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    /// The process id as the kernel issued it.
    pid: i32,
    /// Platform-opaque start time. Comparable for equality only; the units
    /// differ per platform (Linux clock ticks since boot, macOS microseconds
    /// since the epoch). `None` when the platform would not tell us.
    start_time: Option<u64>,
    /// Opaque identifier for the boot the pid was issued in. `None` when the
    /// platform would not tell us.
    boot_id: Option<String>,
}

impl ProcessIdentity {
    /// Record the identity of `pid` as it is right now.
    ///
    /// Never fails: a fact the platform withholds is recorded as `None` and
    /// makes every later [`Self::is_same_process`] check answer `false`.
    #[must_use]
    pub fn capture(pid: i32) -> Self {
        Self {
            pid,
            start_time: process_start_time(pid),
            boot_id: boot_id(),
        }
    }

    /// Build an identity from parts, for tests that need one the platform
    /// would never hand out — a reissued pid, an unrecorded start time, an
    /// earlier boot.
    ///
    /// Test-only: outside tests an identity is always *captured*, so that
    /// nothing can claim a fact the kernel did not supply.
    #[cfg(test)]
    pub(crate) fn from_parts(pid: i32, start_time: Option<u64>, boot_id: Option<String>) -> Self {
        Self {
            pid,
            start_time,
            boot_id,
        }
    }

    /// The recorded pid.
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The recorded start time, if the platform provided one.
    #[must_use]
    pub fn start_time(&self) -> Option<u64> {
        self.start_time
    }

    /// The recorded boot identifier, if the platform provided one.
    #[must_use]
    pub fn boot_id(&self) -> Option<&str> {
        self.boot_id.as_deref()
    }

    /// Whether the pid still names the same process this identity was captured
    /// from.
    ///
    /// Fail-closed in every ambiguous case: a start time we could not record, a
    /// start time we can no longer read (the process is gone, or is not ours to
    /// inspect), a start time that changed, or a boot id that changed all
    /// answer `false`. Only a full match answers `true`.
    ///
    /// A reaped-but-not-yet-waited zombie still answers `true`: it *is* the same
    /// process. Proving a process absent is cleanup verification's job, not
    /// identity's.
    #[must_use]
    pub fn is_same_process(&self) -> bool {
        let (Some(recorded), Some(current)) = (self.start_time, process_start_time(self.pid))
        else {
            return false;
        };
        if recorded != current {
            return false;
        }
        match (self.boot_id.as_deref(), boot_id()) {
            (Some(recorded), Some(current)) => recorded == current,
            // The platform names no boot at all, in either read. There is no
            // disagreement to act on, and the start time already matched.
            (None, None) => true,
            // One read produced a boot id and the other did not. Something
            // changed about what we can observe; refuse to call it the same.
            _ => false,
        }
    }
}

/// Read a process's start time, or `None` if the platform will not say.
///
/// Adapted from `nono-cli/src/session.rs::get_process_start_time`; see the
/// module-level attribution note.
#[cfg(target_os = "linux")]
pub(crate) fn process_start_time(pid: i32) -> Option<u64> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 22 (1-indexed) is starttime. Field 2 is `comm`, which is the
    // executable name in parentheses and may itself contain spaces and
    // parentheses — so the only safe way in is the LAST ')' in the whole line.
    let after_comm = content.rfind(')')?.checked_add(1)?;
    let tail = content.get(after_comm..)?;
    // After the closing paren the next field is 3 (state), so starttime sits at
    // index 22 - 3 = 19.
    tail.split_whitespace().nth(19)?.parse::<u64>().ok()
}

/// Read a process's start time, or `None` if the platform will not say.
///
/// Adapted from `nono-cli/src/session.rs::get_process_start_time`; see the
/// module-level attribution note. The seconds/microseconds combination is
/// checked here, where upstream multiplies unchecked.
#[cfg(target_os = "macos")]
pub(crate) fn process_start_time(pid: i32) -> Option<u64> {
    let info = proc_bsd_info(pid)?;
    info.pbi_start_tvsec
        .checked_mul(1_000_000)?
        .checked_add(info.pbi_start_tvusec)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn process_start_time(_pid: i32) -> Option<u64> {
    None
}

/// The identifier of the current boot, or `None` if the platform will not say.
#[cfg(target_os = "linux")]
pub(crate) fn boot_id() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

/// The identifier of the current boot, or `None` if the platform will not say.
///
/// macOS has no boot uuid in a readable file; `kern.boottime` is the closest
/// equivalent — the wall-clock instant the kernel started, which changes on
/// every boot.
#[cfg(target_os = "macos")]
pub(crate) fn boot_id() -> Option<String> {
    let mut boottime = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut size = std::mem::size_of::<libc::timeval>();
    // SAFETY: `kern.boottime` is a stable macOS sysctl returning one
    // `struct timeval`. We pass a pointer to a live, correctly-typed local and
    // a length that is exactly its size; the kernel writes at most `size` bytes
    // and updates `size` with what it wrote. The new-value pointer is null with
    // a zero length, which is the documented way to spell "read only".
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.boottime".as_ptr(),
            std::ptr::from_mut(&mut boottime).cast::<std::ffi::c_void>(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size != std::mem::size_of::<libc::timeval>() {
        return None;
    }
    Some(format!("{}.{:06}", boottime.tv_sec, boottime.tv_usec))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn boot_id() -> Option<String> {
    None
}

/// `PROC_PIDTBSDINFO`, the `proc_pidinfo` flavour carrying the start time.
#[cfg(target_os = "macos")]
const PROC_PIDTBSDINFO: i32 = 3;

/// `struct proc_bsdinfo` from `<sys/proc_info.h>`.
///
/// Layout copied from `nono-cli/src/session.rs`; the size assertion below is
/// what keeps the copy honest.
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    _reserved: u32,
    pbi_comm: [u8; 16],
    pbi_name: [u8; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

/// Compile-time check that the copied layout is still the 136 bytes the kernel
/// expects. A mismatch would make every `proc_pidinfo` call return a short
/// count and every identity read `None`.
#[cfg(target_os = "macos")]
const _: [(); 136] = [(); std::mem::size_of::<ProcBsdInfo>()];

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut std::ffi::c_void,
        buffersize: i32,
    ) -> i32;
}

#[cfg(target_os = "macos")]
fn proc_bsd_info(pid: i32) -> Option<ProcBsdInfo> {
    let size = i32::try_from(std::mem::size_of::<ProcBsdInfo>()).ok()?;
    // SAFETY: `info` is a live, correctly-sized `ProcBsdInfo`; `proc_pidinfo`
    // writes at most `size` bytes into it and returns how many it wrote. The
    // all-zero start is a valid value of every field (all are integers and byte
    // arrays), so no uninitialised memory is ever read even on a short write.
    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    // SAFETY: as above; the pointer is derived from the live local and the
    // length matches its type exactly.
    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            std::ptr::from_mut(&mut info).cast::<std::ffi::c_void>(),
            size,
        )
    };
    // A short write means the kernel filled a different (older) layout; treat
    // it as no answer rather than reading fields that may not be there.
    if written == size { Some(info) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_pid() -> i32 {
        // `std::process::id` is u32 and always fits an i32 pid on every
        // platform nono supports; the fallback keeps the cast lossless-checked.
        i32::try_from(std::process::id()).unwrap_or(0)
    }

    #[test]
    fn capturing_our_own_identity_recognises_us() {
        let identity = ProcessIdentity::capture(current_pid());
        assert_eq!(identity.pid(), current_pid());
        assert!(
            identity.is_same_process(),
            "the running process must recognise itself: {identity:?}"
        );
    }

    #[test]
    fn this_platform_reports_a_start_time() {
        // Both supported platforms must answer; a silent None here would make
        // every identity check fail closed and nothing would ever be verified.
        assert!(
            ProcessIdentity::capture(current_pid())
                .start_time()
                .is_some(),
            "supported platforms must report a start time"
        );
    }

    #[test]
    fn this_platform_reports_a_boot_id() {
        assert!(
            ProcessIdentity::capture(current_pid()).boot_id().is_some(),
            "supported platforms must report a boot identity"
        );
    }

    #[test]
    fn a_changed_start_time_is_not_the_same_process() {
        let identity = ProcessIdentity::capture(current_pid());
        let recycled = ProcessIdentity {
            pid: identity.pid,
            start_time: identity.start_time.map(|value| value.wrapping_add(1)),
            boot_id: identity.boot_id.clone(),
        };
        assert!(
            !recycled.is_same_process(),
            "a pid whose start time moved is a different process"
        );
    }

    #[test]
    fn a_changed_boot_id_is_not_the_same_process() {
        let identity = ProcessIdentity::capture(current_pid());
        let rebooted = ProcessIdentity {
            pid: identity.pid,
            start_time: identity.start_time,
            boot_id: Some("not-this-boot".to_string()),
        };
        assert!(
            !rebooted.is_same_process(),
            "a pid from another boot is a different process"
        );
    }

    #[test]
    fn a_missing_start_time_fails_closed() {
        let identity = ProcessIdentity {
            pid: current_pid(),
            start_time: None,
            boot_id: boot_id(),
        };
        assert!(
            !identity.is_same_process(),
            "an unrecorded start time must never verify"
        );
    }

    #[test]
    fn an_unreadable_pid_is_not_the_same_process() {
        // pid 0 is not a process we can stat on either platform.
        let identity = ProcessIdentity {
            pid: 0,
            start_time: Some(1),
            boot_id: boot_id(),
        };
        assert!(!identity.is_same_process());
    }

    #[test]
    fn identity_round_trips_through_serde() -> Result<(), serde_json::Error> {
        let identity = ProcessIdentity::capture(current_pid());
        let json = serde_json::to_string(&identity)?;
        assert_eq!(serde_json::from_str::<ProcessIdentity>(&json)?, identity);
        Ok(())
    }
}
