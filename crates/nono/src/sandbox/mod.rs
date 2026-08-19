//! OS-level sandbox implementation
//!
//! This module provides the core sandboxing functionality using platform-specific
//! mechanisms:
//! - Linux: Landlock LSM
//! - macOS: Seatbelt sandbox

use crate::capability::CapabilitySet;
use crate::error::Result;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

// Re-export macOS extension functions for supervisor use
#[cfg(target_os = "macos")]
pub use macos::{extension_consume, extension_issue_file, extension_release};

// Seatbelt pieces the lifecycle module needs to split "build the profile" from
// "install it": the build happens in the parent, the install in the forked
// child. Crate-internal — the public API stays `Sandbox::apply_auto`.
#[cfg(target_os = "macos")]
pub(crate) use macos::{generate_seatbelt_profile, sandbox_init_raw};

// Re-export Linux Landlock ABI detection and scope policy reporting
#[cfg(target_os = "linux")]
pub use linux::{
    DetectedAbi, LandlockScopePolicy, detect_abi, landlock_scope_policy, restrict_execute,
};

// Re-export Linux WSL2 detection
#[cfg(target_os = "linux")]
pub use linux::is_wsl2;

// The one place a `landlock::ABI` becomes the plain version number the
// mode mapping (and the support report's per-mode table) is driven by.
// Crate-internal: `DetectedAbi` stays the public shape.
#[cfg(target_os = "linux")]
pub(crate) use linux::abi_version_number;

// The Linux pieces the lifecycle needs to install the block-all network
// filter in a forked pre-exec child: the decision is made in the parent from
// the capability set, the install happens in the child with raw syscalls.
// Crate-internal — the public API stays `Sandbox::apply_auto`.
#[cfg(target_os = "linux")]
pub(crate) use linux::{
    StaticNetworkFilter, install_seccomp_block_network_raw, install_seccomp_tcp_only_network_raw,
    required_static_network_filter, seccomp_network_fallback_mode,
};

// Re-export Linux seccomp-notify primitives for supervisor use
#[cfg(target_os = "linux")]
pub use linux::{
    OpenHow, PreparedLandlockSandbox, PreparedSeccompNotifyFilter, RawSandboxError,
    RawSandboxStage, SYS_BIND, SYS_CONNECT, SYS_OPENAT, SYS_OPENAT2, SYS_SENDMMSG, SYS_SENDMSG,
    SYS_SENDTO, SeccompData, SeccompNetFallback, SeccompNotif, SeccompOpts, SockaddrInfo,
    UnixSocketKind, classify_access_from_flags, classify_af_unix, continue_notif, deny_notif,
    inject_fd, install_seccomp_af_unix_filter, install_seccomp_notify,
    install_seccomp_proxy_filter, notif_id_valid, prepare_seccomp_af_unix_filter,
    prepare_seccomp_proxy_filter, prepare_seccomp_with_abi, probe_seccomp_block_network_support,
    read_mmsghdr_dests, read_msghdr_dest, read_notif_path, read_notif_sockaddr, read_open_how,
    recv_notif, resolve_notif_path, respond_notif_errno, validate_openat2_size,
};

/// Information about sandbox support on this platform
#[derive(Debug, Clone)]
pub struct SupportInfo {
    /// Whether sandboxing is supported
    pub is_supported: bool,
    /// Platform name
    pub platform: &'static str,
    /// Detailed support information
    pub details: String,
}

/// Main sandbox API
///
/// This struct provides static methods for applying sandboxing restrictions.
/// Once applied, restrictions cannot be removed or expanded.
///
/// # Example
///
/// ```no_run
/// use nono::{CapabilitySet, AccessMode, Sandbox};
///
/// let caps = CapabilitySet::new()
///     .allow_path("/usr", AccessMode::Read)?
///     .allow_path("/project", AccessMode::ReadWrite)?
///     .block_network();
///
/// // Check if sandbox is supported
/// if Sandbox::is_supported() {
///     Sandbox::apply_auto(&caps)?;
/// }
/// # Ok::<(), nono::NonoError>(())
/// ```
pub struct Sandbox;

impl Sandbox {
    /// Detect the Landlock ABI version supported by the running kernel.
    ///
    /// This is only available on Linux. Returns a `DetectedAbi` that can
    /// be passed to `apply_with_abi()` to avoid re-probing.
    ///
    /// # Errors
    ///
    /// Returns an error if Landlock is not available.
    #[cfg(target_os = "linux")]
    #[must_use = "ABI detection result should be checked"]
    pub fn detect_abi() -> Result<DetectedAbi> {
        linux::detect_abi()
    }

    /// Apply sandboxing with automatic Landlock → seccomp fallback (Linux).
    ///
    /// Uses Landlock where possible; falls back to seccomp when the kernel
    /// ABI lacks network support (< V4). This preserves the compatibility
    /// behaviour for library consumers; the CLI selects
    /// [`SeccompOpts::network_baseline`] for its stronger default.
    /// `BlockAll` is installed inline; `ProxyOnly` must be installed
    /// post-fork via `install_seccomp_proxy_filter()`.
    #[cfg(target_os = "linux")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_auto(caps: &CapabilitySet) -> Result<linux::SeccompNetFallback> {
        linux::apply_auto(caps)
    }

    /// Apply sandboxing with automatic fallback and a pre-detected ABI (Linux).
    #[cfg(target_os = "linux")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_auto_with_abi(
        caps: &CapabilitySet,
        abi: &DetectedAbi,
    ) -> Result<linux::SeccompNetFallback> {
        linux::apply_auto_with_abi(caps, abi)
    }

    /// Apply Landlock-only sandboxing (Linux).
    ///
    /// Returns an error if network restrictions cannot be satisfied via
    /// Landlock alone (kernel ABI < V4). Use `apply_auto` for fallback.
    #[cfg(target_os = "linux")]
    pub fn apply_landlock(caps: &CapabilitySet) -> Result<()> {
        linux::apply_landlock(caps)
    }

    /// Apply Landlock-only sandboxing with a pre-detected ABI (Linux).
    #[cfg(target_os = "linux")]
    pub fn apply_landlock_with_abi(caps: &CapabilitySet, abi: &DetectedAbi) -> Result<()> {
        linux::apply_landlock_with_abi(caps, abi)
    }

    /// Apply Landlock filesystem/process sandboxing and seccomp TCP fallback (Linux).
    ///
    /// Filesystem/process sandboxing is always Landlock-enforced. `opts`
    /// controls only nono-managed TCP network fallback/delegation.
    #[cfg(target_os = "linux")]
    pub fn apply_seccomp(
        caps: &CapabilitySet,
        opts: linux::SeccompOpts,
    ) -> Result<linux::SeccompNetFallback> {
        linux::apply_seccomp(caps, opts)
    }

    /// Apply Landlock filesystem/process sandboxing and seccomp TCP fallback
    /// with a pre-detected ABI (Linux).
    #[cfg(target_os = "linux")]
    pub fn apply_seccomp_with_abi(
        caps: &CapabilitySet,
        abi: &DetectedAbi,
        opts: linux::SeccompOpts,
    ) -> Result<linux::SeccompNetFallback> {
        linux::apply_seccomp_with_abi(caps, abi, opts)
    }

    /// Prepare an allocation-free Linux sandbox apply for a raw-cloned child.
    #[cfg(target_os = "linux")]
    pub fn prepare_seccomp_with_abi(
        caps: &CapabilitySet,
        abi: &DetectedAbi,
        opts: linux::SeccompOpts,
    ) -> Result<linux::PreparedLandlockSandbox> {
        linux::prepare_seccomp_with_abi(caps, abi, opts)
    }

    /// Declare that TCP network enforcement is handled externally (Linux).
    ///
    /// This is intentionally a no-op marker. It must not be used as the whole
    /// `nono run` sandbox; filesystem/process sandboxing is applied separately.
    #[cfg(target_os = "linux")]
    pub fn apply_external() -> Result<()> {
        linux::apply_external()
    }

    /// Apply the sandbox with the given capabilities (macOS).
    #[cfg(target_os = "macos")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_auto(caps: &CapabilitySet) -> Result<()> {
        macos::apply(caps)
    }

    /// Stack a second Landlock layer that restricts execute to the given paths (Linux only).
    ///
    /// Must be called after `apply()`. See [`linux::restrict_execute`] for semantics.
    ///
    /// # Errors
    ///
    /// Returns an error if the restriction cannot be applied.
    #[cfg(target_os = "linux")]
    pub fn restrict_execute(paths: &[impl AsRef<std::path::Path>]) -> Result<()> {
        linux::restrict_execute(paths)
    }

    /// What this platform will do with the mode-aware grants in `caps`.
    ///
    /// One [`CompiledModes`] per
    /// [`allow_path_modes`][CapabilitySet::allow_path_modes] grant, in grant
    /// order. This is the same compilation the profile or ruleset is built
    /// from, so a caller that reads the disclosures and a caller that applies
    /// the policy cannot be looking at two different answers.
    ///
    /// Read it before applying: `bundled` names every mode the grant confers
    /// beyond what was asked for, `always_allowed` names every mode this
    /// platform cannot restrict at all, and `delegated` names the modes another
    /// capability enforces.
    ///
    /// # Errors
    ///
    /// [`NonoError::ModeUnsupported`][crate::NonoError::ModeUnsupported] if a
    /// granted mode is one this platform will not express — the same refusal
    /// that fails the apply, surfaced before anything is applied. On Linux this
    /// probes the Landlock ABI, so it can also fail if Landlock is unavailable.
    pub fn compile_fs_modes(caps: &CapabilitySet) -> Result<Vec<crate::CompiledModes>> {
        #[cfg(target_os = "linux")]
        {
            linux::compile_fs_modes(caps)
        }

        #[cfg(target_os = "macos")]
        {
            macos::compile_fs_modes(caps)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            if caps.fs_mode_capabilities().is_empty() {
                return Ok(Vec::new());
            }
            Err(crate::NonoError::UnsupportedPlatform(format!(
                "no sandbox mechanism on {}, so no filesystem mode can be enforced",
                std::env::consts::OS
            )))
        }
    }

    /// Check if sandboxing is supported on this platform
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(target_os = "linux")]
        {
            linux::is_supported()
        }

        #[cfg(target_os = "macos")]
        {
            macos::is_supported()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    /// Get detailed information about sandbox support on this platform
    #[must_use]
    pub fn support_info() -> SupportInfo {
        #[cfg(target_os = "linux")]
        {
            linux::support_info()
        }

        #[cfg(target_os = "macos")]
        {
            macos::support_info()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            SupportInfo {
                is_supported: false,
                platform: std::env::consts::OS,
                details: format!("Platform '{}' is not supported", std::env::consts::OS),
            }
        }
    }
}
