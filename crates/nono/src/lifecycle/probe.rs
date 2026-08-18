//! Asking the kernel what the installed enforcement actually does.
//!
//! Everything else in this module reports what the library *did*: a plan was
//! turned into a policy, the policy was applied, the child said so. None of
//! that is an observation of the enforcement itself. A policy that was built
//! from the right capabilities and applied without an error can still be a
//! policy the kernel implements differently from the way the mapping tables
//! believe it does, and no amount of parent-side bookkeeping can notice.
//!
//! A probe is the observation that can. It sends one operation to the *already
//! confined* child, the child attempts it with a single real syscall, and the
//! kernel's own `errno` comes back. The answer is never derived from a
//! [`CapabilitySet`][crate::CapabilitySet], from a
//! [`QueryContext`][crate::query::QueryContext], or from anything else in
//! [`crate::query`] — that module's own documentation says it answers "without
//! actually applying the sandbox", which is exactly the self-report a probe
//! exists to distrust.
//!
//! # A probe is not a simulation
//!
//! The operation really happens. A [`FsMode::Create`] probe that comes back
//! [`ProbeOutcome::Permitted`] has created a file; a [`FsMode::RemoveFile`]
//! probe that comes back permitted has removed one. That is the point: the only
//! way to find out whether an operation is refused is to attempt it, and an
//! attempt that was not refused is an attempt that succeeded. A caller plants
//! an operation it expects to be *refused*, on a path it is content to have
//! touched if it is not.
//!
//! # Three answers, and why there is no fourth
//!
//! | Kernel said | Reported as |
//! |---|---|
//! | the syscall succeeded | [`ProbeOutcome::Permitted`] |
//! | `EPERM` or `EACCES` | [`ProbeOutcome::Refused`] with that number |
//! | any other `errno` | [`ProbeIndeterminate::ProbeCouldNotRun`] with that number |
//!
//! The third row is the one that is easy to get wrong. `ENOENT` says the object
//! is not there; it does not say the mechanism would have let the child reach
//! it had it been. Folding that into `Permitted` would hand a caller an answer
//! the kernel never gave, so it is reported as what it is — the probe ran and
//! established nothing about enforcement — with the kernel's own number
//! attached.
//!
//! `EPERM`/`EACCES` is also what an ordinary Unix permission denial looks like.
//! The kernel does not say which layer produced it and this module does not
//! guess: [`ProbeOutcome::Refused`] means the kernel refused, not that a
//! particular mechanism did. That distinction is why
//! [`ProbeObservation::denial_observed`] is a separate field and why it is
//! always `false` here — see below.
//!
//! # Scope: this child, right now
//!
//! Every observation this slice produces is [`ProbeScope::InstalledChild`]: the
//! probe ran inside the very process whose confinement is in question, in the
//! window between its sandbox apply and its `execve`. That is the strongest
//! scope there is, and it is only reachable while the child is held.
//!
//! A future post-activation probe cannot reach that process — the customer's
//! program owns it, and the gate descriptor is dropped at release
//! ([`super::prepare`]). It would have to fork a fresh sibling, re-apply
//! [`ValidatedPlan::capabilities`][super::ValidatedPlan::capabilities], and
//! probe that; such an observation is [`ProbeScope::RederivedSibling`] and it
//! proves something strictly weaker. **It proves the mechanism is still
//! installable, not that this child is still confined.** A kernel that lost the
//! original child's ruleset would still install a fresh one perfectly. Keeping
//! the two labelled apart is the whole reason the enum has two variants.
//!
//! # Reaching a held child that is in another process
//!
//! A detached run's child is held by the supervisor, not by the caller, so the
//! [`PreparedSandbox`][super::PreparedSandbox] that can ask it is unreachable
//! from the caller's side. [`ControlRequest::ProbeEnforcement`][req] is the
//! only way across, and it carries the request rather than an answer: the
//! supervisor hands it to the same method the in-process path calls, and passes
//! what comes back over the wire **unchanged**. It has no opinion to add. An
//! [`ProbeOutcome::Indeterminate`] never becomes a refusal or a permission in
//! transit, and [`ProbeObservation::denial_observed`] is never upgraded,
//! because the supervisor observed nothing — the child did.
//!
//! Every type below is therefore serializable. That is a transport fact and not
//! a licence to build an observation from parts: nothing outside this module
//! constructs a [`ProbeObservation`], and the one constructor is
//! [`observation`], which is where [`ProbeScope::InstalledChild`] is written
//! down exactly once.
//!
//! [req]: super::ControlRequest::ProbeEnforcement

use super::exit::STATUS_RECORD_LEN;
use super::state::LifecycleState;
use crate::capability_modes::FsMode;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use thiserror::Error;

// ---------------------------------------------------------------------------
// The vocabulary a caller speaks.

/// A caller-supplied tag that comes back on the observation.
///
/// Opaque to this library: nothing here parses it, matches on it, or gives it
/// meaning. It exists so a caller that plants several probes can tell the
/// answers apart without relying on ordering.
///
/// Unbounded, like every other caller-chosen string this library carries. On
/// the detached path that is not a hole: a request whose encoded form would not
/// fit [`MAX_CONTROL_FRAME_BYTES`][limit] is refused by the framing before a
/// byte is written, so a long tag costs the caller its own request and nothing
/// else — see [`DetachedSession::probe_enforcement`][probe].
///
/// [limit]: super::MAX_CONTROL_FRAME_BYTES
/// [probe]: super::DetachedSession::probe_enforcement
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProbeId(String);

impl ProbeId {
    /// Tag a probe with a caller-chosen string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The tag, as the caller supplied it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProbeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which transport a network probe asks about.
///
/// Defined here rather than reused because this repository has no
/// transport-protocol vocabulary: [`NetworkMode`][crate::capability::NetworkMode]
/// describes a *policy* ("blocked", "allow all", "proxy only"), not the socket
/// type an individual operation uses. Two values, because those are the two
/// this library's network capabilities can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    /// A `SOCK_STREAM` socket.
    Tcp,
    /// A `SOCK_DGRAM` socket.
    Udp,
}

impl TransportProtocol {
    /// Every value, in a fixed order.
    pub const ALL: [TransportProtocol; 2] = [TransportProtocol::Tcp, TransportProtocol::Udp];

    /// The stable snake_case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One operation a probe attempts.
///
/// Filesystem operations are named in this library's existing per-operation
/// vocabulary ([`FsMode`]) rather than in a second one invented here, so a
/// caller that granted `allow_path_modes(path, [FsMode::Write])` can probe the
/// same word it granted.
///
/// A path that is not UTF-8 cannot be encoded for the control socket, and is
/// refused there rather than mangled into a different path: the same rule the
/// child's own channel applies to an interior NUL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "probe_op", rename_all = "snake_case")]
pub enum ProbeOp {
    /// Attempt one filesystem operation against a path.
    OpenPath {
        /// The path the operation names.
        path: PathBuf,
        /// Which operation.
        mode: FsMode,
    },
    /// Attempt to execute a program.
    ///
    /// Has no in-scope probe while the child is held — see
    /// [`ProbeIndeterminate::PlatformHasNoInScopeProbe`].
    Execute {
        /// The program the operation names.
        program: PathBuf,
    },
    /// Attempt to connect a socket to an address.
    Connect {
        /// The socket type.
        protocol: TransportProtocol,
        /// The address to reach for.
        addr: SocketAddr,
    },
    /// Attempt to bind a socket to an address.
    Bind {
        /// The socket type.
        protocol: TransportProtocol,
        /// The address to claim.
        addr: SocketAddr,
    },
}

/// One probe: what to attempt, and what to call the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRequest {
    /// The caller's tag, returned on the observation.
    pub id: ProbeId,
    /// The operation to attempt.
    pub op: ProbeOp,
}

/// What the kernel said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// The syscall succeeded. The operation really happened.
    Permitted,
    /// The kernel refused, with the number it refused with.
    ///
    /// `EPERM` and `EACCES` are the only two numbers that reach here, because
    /// they are the only two either mechanism uses to refuse. Which *layer*
    /// refused — the enforcement mechanism or ordinary Unix permissions — is
    /// not something the kernel reports, and this is not a claim about it.
    Refused {
        /// The kernel's own number.
        errno: i32,
    },
    /// Nothing about enforcement was established, and why.
    Indeterminate {
        /// Which kind of nothing.
        reason: ProbeIndeterminate,
    },
}

/// Why a probe established nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "indeterminate", rename_all = "snake_case")]
pub enum ProbeIndeterminate {
    /// The mechanism has no check for this operation at all, so an answer from
    /// it would be meaningless rather than merely uncertain.
    ///
    /// The one case this slice produces is `stat(2)` under Landlock: Landlock
    /// has no right covering it (see
    /// [`FsMode::ReadMetadata`][crate::capability_modes::FsMode::ReadMetadata]),
    /// so a metadata probe on Linux would come back `Permitted` for every
    /// policy — including one that intended to forbid it.
    MechanismCannotExpress {
        /// The mechanism that cannot express it.
        mechanism: EnforcementMechanism,
    },
    /// The syscall was attempted and failed for a reason that is not a refusal,
    /// or could not be attempted because its setup failed.
    ///
    /// Carries the kernel's own number. `ENOENT` on a path that is not there,
    /// `ECONNREFUSED` from a port nothing is listening on, `EACCES` from the
    /// `socket(2)` that a network probe needs before it can `connect(2)` — none
    /// of them say what the enforcement would have done.
    ProbeCouldNotRun {
        /// The kernel's own number.
        errno: i32,
    },
    /// There is no probe for this operation that is in scope for a held child.
    ///
    /// Exec is the case that matters. A held child cannot `execve` anything:
    /// doing so would destroy the very process whose confinement is under
    /// question, and it would run a program. Forking a helper that execs
    /// instead would run that program too. Neither is a probe of *this* child,
    /// so the honest answer is that this scope has none.
    ///
    /// [`FsMode::AtomicWrite`] lands here for a different reason: it is a named
    /// bundle over four leaves, and one syscall cannot ask a four-part
    /// question. Probe the leaves.
    PlatformHasNoInScopeProbe,
}

impl ProbeIndeterminate {
    /// The stable snake_case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MechanismCannotExpress { .. } => "mechanism_cannot_express",
            Self::ProbeCouldNotRun { .. } => "probe_could_not_run",
            Self::PlatformHasNoInScopeProbe => "platform_has_no_in_scope_probe",
        }
    }
}

impl std::fmt::Display for ProbeIndeterminate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which kernel facility the answer came from.
///
/// One value per platform on this path, because the lifecycle installs exactly
/// one policy per platform: [`Self::Seatbelt`] on macOS, where
/// `sandbox_init` is the only call made; [`Self::Landlock`] on Linux, where the
/// ruleset is what expresses the plan's filesystem, exec, and — on ABI V4 and
/// above — TCP port rights.
///
/// [`Self::Seccomp`] and [`Self::SeccompUserNotify`] exist in this vocabulary
/// but are never reported by a pre-activation probe, and the reason is worth
/// stating rather than leaving to inference. The lifecycle's seccomp layer is a
/// baseline that refuses to *create* socket families the policy excludes; a
/// probe whose `socket(2)` is refused never reaches its `connect(2)`, so it is
/// reported as [`ProbeIndeterminate::ProbeCouldNotRun`] and not as a refusal.
/// Proxy-only mediation — the one arrangement that would install a
/// user-notification listener — is refused outright at prepare time by
/// `refuse_unsupported_fallback` in [`super::prepare`], so no held child on
/// this path has one. This label therefore names the mechanism that expresses
/// the operation in the installed ruleset; the kernel offers no per-syscall
/// attribution and none is invented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMechanism {
    /// The Linux Landlock LSM.
    Landlock,
    /// A static seccomp-bpf filter.
    Seccomp,
    /// A seccomp filter whose decisions are delegated to a user-space listener.
    SeccompUserNotify,
    /// The macOS Seatbelt sandbox.
    Seatbelt,
}

impl EnforcementMechanism {
    /// Every mechanism this vocabulary names, in a fixed order.
    pub const ALL: [EnforcementMechanism; 4] = [
        EnforcementMechanism::Landlock,
        EnforcementMechanism::Seccomp,
        EnforcementMechanism::SeccompUserNotify,
        EnforcementMechanism::Seatbelt,
    ];

    /// The stable snake_case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Landlock => "landlock",
            Self::Seccomp => "seccomp",
            Self::SeccompUserNotify => "seccomp_user_notify",
            Self::Seatbelt => "seatbelt",
        }
    }
}

impl std::fmt::Display for EnforcementMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which process the answer is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeScope {
    /// The probe ran inside the confined child itself.
    ///
    /// The only scope this slice produces, and the only one that says anything
    /// about *this* run: the operation was attempted by the same process whose
    /// confinement is in question, under the enforcement that process is
    /// actually carrying.
    InstalledChild,
    /// The probe ran in a fresh process the policy was re-applied to.
    ///
    /// Strictly weaker, and never conflated with the above. It proves the
    /// mechanism is still *installable* on this host — not that the process
    /// under question is still confined. Not produced by this slice.
    RederivedSibling,
}

impl ProbeScope {
    /// Every scope, in a fixed order.
    pub const ALL: [ProbeScope; 2] = [ProbeScope::InstalledChild, ProbeScope::RederivedSibling];

    /// The stable snake_case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstalledChild => "installed_child",
            Self::RederivedSibling => "rederived_sibling",
        }
    }
}

impl std::fmt::Display for ProbeScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one probe established.
///
/// Serializable because a detached run's held child is in the supervisor and
/// the answer has to reach the caller, and for no other reason: the supervisor
/// forwards what [`super::PreparedSandbox::probe_enforcement`] returned and
/// changes nothing about it. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeObservation {
    /// The caller's tag, returned unchanged.
    pub id: ProbeId,
    /// What the kernel said.
    pub outcome: ProbeOutcome,
    /// Which facility expressed the operation in the installed policy.
    pub mechanism: EnforcementMechanism,
    /// Which process the answer is about.
    pub scope: ProbeScope,
    /// Whether a **denial record** was captured for this operation.
    ///
    /// Always `false` on this fork, and that is the honest answer rather than a
    /// missing feature. A refused syscall is an `errno` returned to the caller;
    /// a *denial record* is the enforcement layer's own account of having
    /// refused, and this library observes none. `super::support` records
    /// [`EventFamily::KernelDenial`][super::EventFamily::KernelDenial] with
    /// [`EventFidelity::NotObserved`][super::EventFidelity::NotObserved] and
    /// [`super::events`] states in its first paragraph that "there is no
    /// `KernelDenial` variant in this vocabulary because this library does not
    /// observe kernel denials". Setting this field from
    /// [`ProbeOutcome::Refused`] would manufacture exactly the event those two
    /// places refuse to manufacture — the `errno` says the syscall failed, not
    /// that a particular layer recorded a denial.
    pub denial_observed: bool,
    /// When the answer arrived here.
    pub observed_at: SystemTime,
}

/// Everything a probe can refuse to do.
///
/// Deliberately short. A probe that reached the child and got an answer always
/// returns an observation, however unhelpful the answer; these two are the
/// cases where there was no answer at all.
///
/// Serializable for the same reason [`ActivationError`][err] is: a probe asked
/// for over a detached supervisor's control socket must be refused with the
/// typed answer the in-process call would have given, not a string.
///
/// [err]: super::ActivationError
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(tag = "probe_error", rename_all = "snake_case")]
pub enum ProbeError {
    /// The run is not being held, so there is no confined pre-exec child to ask.
    #[error("a probe is only legal while the child is held at the gate; run is {state}")]
    NotLegalInState {
        /// Where the run actually is.
        state: LifecycleState,
    },

    /// The child could not be reached, or stopped answering.
    #[error("the held child could not be reached: errno {errno}")]
    ChildUnreachable {
        /// Platform error number, or 0 where the failure was not an OS error —
        /// an end-of-file on the status descriptor, which is what a child that
        /// died mid-probe leaves behind.
        errno: i32,
    },
}

// ---------------------------------------------------------------------------
// The wire between the supervisor and the held child.
//
// One fixed-size request on the gate descriptor, one fixed-size reply on the
// status descriptor. Both shapes match what this module already does across
// that fork boundary: a tag byte plus a little-endian i32, and buffers the
// child can hold on its stack without an allocator.

/// Reply tag: the syscall succeeded.
pub(super) const TAG_PROBE_PERMITTED: u8 = 0x02;
/// Reply tag: the kernel refused, with its number in the record.
pub(super) const TAG_PROBE_REFUSED: u8 = 0x03;
/// Reply tag: the syscall failed for a reason that is not a refusal.
pub(super) const TAG_PROBE_COULD_NOT_RUN: u8 = 0x04;

/// How much room the path region has, including its terminating NUL.
///
/// `PATH_MAX` is 4096 on Linux and 1024 on macOS; the larger is used on both so
/// the record has one shape. A path that does not fit is refused before
/// anything is written, with the number the kernel would have given it anyway.
///
/// Visible to [`super::protocol`], which asserts at compile time that a path
/// this long still fits a control frame even fully JSON-escaped: a path the
/// child's own channel would accept must not be a path the supervisor cannot be
/// asked about.
pub(super) const PROBE_PATH_BYTES: usize = 4096;

/// Offset of the operation tag.
const OFFSET_OP: usize = 0;
/// Offset of the per-operation detail tag: an [`FsMode`] for a path operation,
/// a [`TransportProtocol`] for a socket one.
const OFFSET_DETAIL: usize = 1;
/// Offset of the port, little-endian.
const OFFSET_PORT: usize = 2;
/// Offset of the address family tag.
const OFFSET_FAMILY: usize = 4;
/// Offset of the address bytes, in network order, IPv4 in the first four.
const OFFSET_ADDR: usize = 5;
/// How many address bytes there is room for.
const ADDR_BYTES: usize = 16;
/// Offset of the NUL-terminated path.
const OFFSET_PATH: usize = OFFSET_ADDR + ADDR_BYTES;

/// The whole request record.
pub(super) const PROBE_REQUEST_BYTES: usize = OFFSET_PATH + PROBE_PATH_BYTES;

/// One encoded probe request, as it crosses the gate descriptor.
pub(super) type ProbeWire = [u8; PROBE_REQUEST_BYTES];

/// Request tag: a filesystem operation named by an [`FsMode`].
const OP_OPEN_PATH: u8 = 0x01;
/// Request tag: `connect(2)`.
const OP_CONNECT: u8 = 0x02;
/// Request tag: `bind(2)`.
const OP_BIND: u8 = 0x03;

/// Address family tag: IPv4.
const FAMILY_V4: u8 = 0x04;
/// Address family tag: IPv6.
const FAMILY_V6: u8 = 0x06;

/// Transport tag: `SOCK_STREAM`.
const PROTO_TCP: u8 = 0x01;
/// Transport tag: `SOCK_DGRAM`.
const PROTO_UDP: u8 = 0x02;

/// The wire tag for one filesystem operation.
///
/// A local mapping rather than a method on [`FsMode`]: these bytes are this
/// channel's contract and nothing else's, and putting them on the shared type
/// would make every consumer of that type inherit a wire format it has no use
/// for. [`FsMode::Execute`] and [`FsMode::AtomicWrite`] have no tag because
/// neither ever reaches the child — the supervisor answers both before writing
/// anything.
fn fs_mode_tag(mode: FsMode) -> Option<u8> {
    let tag = match mode {
        FsMode::ReadContents => 0x01,
        FsMode::ReadDir => 0x02,
        FsMode::ReadMetadata => 0x03,
        FsMode::Write => 0x04,
        FsMode::Append => 0x05,
        FsMode::Create => 0x06,
        FsMode::Truncate => 0x07,
        FsMode::RemoveFile => 0x08,
        FsMode::RemoveDir => 0x09,
        FsMode::Rename => 0x0A,
        FsMode::UnixSocketConnect => 0x0B,
        FsMode::Execute | FsMode::AtomicWrite => return None,
    };
    Some(tag)
}

// ---------------------------------------------------------------------------
// The supervisor's side.

/// The mechanism this build installs, or `None` where it installs nothing.
///
/// `None` is unreachable in practice: `PlatformSandbox::build` in
/// [`super::prepare`] refuses on a platform with neither mechanism, so no
/// child is ever forked there and no `PreparedSandbox` exists to probe. It is
/// returned rather than guessed at because there is no honest fourth value.
///
/// Written with `cfg!` rather than `#[cfg]` blocks so that every arm is
/// type-checked on every host. The compiler folds it to one constant; what it
/// buys is that a change to the Linux arm cannot compile on macOS and break on
/// Linux, which on this codebase is a real hazard rather than a theoretical
/// one — there is no Linux toolchain here to catch it.
pub(super) fn installed_mechanism() -> Option<EnforcementMechanism> {
    if cfg!(target_os = "linux") {
        Some(EnforcementMechanism::Landlock)
    } else if cfg!(target_os = "macos") {
        Some(EnforcementMechanism::Seatbelt)
    } else {
        None
    }
}

/// The answer that is settled before the child is asked anything, if there is
/// one.
///
/// Two kinds live here. An operation with no in-scope probe must not be sent —
/// there is nothing the child could do with it that would be an answer. An
/// operation the mechanism has no check for must not be sent either, because
/// the child *would* answer, and the answer would be `Permitted` for every
/// policy including one that meant to forbid it.
pub(super) fn settled_before_asking(op: &ProbeOp) -> Option<ProbeIndeterminate> {
    match op {
        // TODO(probe): post-activation scope. A re-derived sibling is
        // disposable, so it *can* `execve` the named program and report what
        // the kernel said. That probe is `ProbeScope::RederivedSibling` and
        // proves the mechanism is still installable, not that the child under
        // question is still confined.
        ProbeOp::Execute { .. }
        | ProbeOp::OpenPath {
            mode: FsMode::Execute,
            ..
        }
        | ProbeOp::OpenPath {
            mode: FsMode::AtomicWrite,
            ..
        } => Some(ProbeIndeterminate::PlatformHasNoInScopeProbe),

        // Landlock has no right covering `stat(2)`, so on Linux a metadata
        // probe cannot be refused by the mechanism no matter what the policy
        // says. Answering `Permitted` there would be a fact about the kernel's
        // vocabulary dressed up as a fact about the policy. Seatbelt has
        // `file-read-metadata` and really does restrict it, so on macOS the
        // question is a real one and reaches the child.
        //
        // A `cfg!` guard rather than a `#[cfg]` arm, for the reason given on
        // `installed_mechanism`: the arm is then type-checked on both hosts.
        ProbeOp::OpenPath {
            mode: FsMode::ReadMetadata,
            ..
        } if cfg!(target_os = "linux") => Some(ProbeIndeterminate::MechanismCannotExpress {
            mechanism: EnforcementMechanism::Landlock,
        }),

        _ => None,
    }
}

/// Turn an operation into the record the child reads.
///
/// `Err` carries the number the kernel would have produced had the request been
/// attempted, so a caller sees the same `errno` whether the limit was caught
/// here or by the syscall.
pub(super) fn encode_request(op: &ProbeOp) -> Result<ProbeWire, i32> {
    let mut wire: ProbeWire = [0_u8; PROBE_REQUEST_BYTES];
    match op {
        ProbeOp::OpenPath { path, mode } => {
            // `settled_before_asking` has already taken the two modes with no
            // tag, so this is a request that should never have been encoded.
            let Some(tag) = fs_mode_tag(*mode) else {
                return Err(libc::EINVAL);
            };
            wire[OFFSET_OP] = OP_OPEN_PATH;
            wire[OFFSET_DETAIL] = tag;
            encode_path(&mut wire, path)?;
        }
        // Refused by `settled_before_asking`; encoding it would be a bug.
        ProbeOp::Execute { .. } => return Err(libc::EINVAL),
        ProbeOp::Connect { protocol, addr } => {
            wire[OFFSET_OP] = OP_CONNECT;
            wire[OFFSET_DETAIL] = protocol_tag(*protocol);
            encode_addr(&mut wire, addr);
        }
        ProbeOp::Bind { protocol, addr } => {
            wire[OFFSET_OP] = OP_BIND;
            wire[OFFSET_DETAIL] = protocol_tag(*protocol);
            encode_addr(&mut wire, addr);
        }
    }
    Ok(wire)
}

fn protocol_tag(protocol: TransportProtocol) -> u8 {
    match protocol {
        TransportProtocol::Tcp => PROTO_TCP,
        TransportProtocol::Udp => PROTO_UDP,
    }
}

/// Copy the path into the record, leaving the NUL the child relies on.
fn encode_path(wire: &mut ProbeWire, path: &Path) -> Result<(), i32> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    // An interior NUL would make the child's C string a different, shorter
    // path — the classic truncation. Refused with the number `openat` gives a
    // path it cannot use.
    if bytes.contains(&0) {
        return Err(libc::EINVAL);
    }
    // Strictly less than, so the region always ends in at least one zero byte.
    if bytes.len() >= PROBE_PATH_BYTES {
        return Err(libc::ENAMETOOLONG);
    }
    let end = OFFSET_PATH.saturating_add(bytes.len());
    let Some(region) = wire.get_mut(OFFSET_PATH..end) else {
        return Err(libc::ENAMETOOLONG);
    };
    region.copy_from_slice(bytes);
    Ok(())
}

/// Copy the address into the record, in network order.
///
/// An IPv6 flow label and scope id are not carried: the record has no room for
/// them and a probe of a link-local address is not something this slice claims
/// to answer.
fn encode_addr(wire: &mut ProbeWire, addr: &SocketAddr) {
    let port = addr.port().to_le_bytes();
    wire[OFFSET_PORT] = port[0];
    wire[OFFSET_PORT.saturating_add(1)] = port[1];
    match addr {
        SocketAddr::V4(v4) => {
            wire[OFFSET_FAMILY] = FAMILY_V4;
            let octets = v4.ip().octets();
            wire[OFFSET_ADDR..OFFSET_ADDR.saturating_add(octets.len())].copy_from_slice(&octets);
        }
        SocketAddr::V6(v6) => {
            wire[OFFSET_FAMILY] = FAMILY_V6;
            let octets = v6.ip().octets();
            wire[OFFSET_ADDR..OFFSET_ADDR.saturating_add(octets.len())].copy_from_slice(&octets);
        }
    }
}

/// Decode one reply record, or say it was not a reply at all.
///
/// `None` means the record on the status descriptor was something else — a
/// pre-exec failure the child wrote because it was dying. That is not an answer
/// to the probe and is never dressed up as one.
pub(super) fn classify_reply(tag: u8, errno: i32) -> Option<ProbeOutcome> {
    match tag {
        TAG_PROBE_PERMITTED => Some(ProbeOutcome::Permitted),
        TAG_PROBE_REFUSED => Some(ProbeOutcome::Refused { errno }),
        TAG_PROBE_COULD_NOT_RUN => Some(ProbeOutcome::Indeterminate {
            reason: ProbeIndeterminate::ProbeCouldNotRun { errno },
        }),
        _ => None,
    }
}

/// Build the observation around an outcome.
///
/// One constructor for every path, so `denial_observed` and `scope` cannot
/// drift apart between them: this slice has exactly one honest value for each
/// and it is written down once.
pub(super) fn observation(
    id: ProbeId,
    outcome: ProbeOutcome,
    mechanism: EnforcementMechanism,
) -> ProbeObservation {
    ProbeObservation {
        id,
        outcome,
        mechanism,
        // TODO(probe): post-activation scope. The re-derived sibling path is
        // the only thing that may pass `RederivedSibling` here, and it must
        // never reach this constructor by accident — a probe of a fresh
        // process labelled `InstalledChild` would be the one lie this whole
        // mechanism exists to prevent.
        scope: ProbeScope::InstalledChild,
        // Never optimistic, never derived from the outcome. See the field's
        // documentation, `super::support`, and `super::events`.
        denial_observed: false,
        observed_at: SystemTime::now(),
    }
}

// ---------------------------------------------------------------------------
// The held child's side.
//
// Everything below runs after `fork` and after the sandbox has been applied,
// between the child's arrival at the gate and its `execve`. It allocates
// nothing, takes no lock, and returns to the child's fixed sequence rather than
// into Rust that could unwind. Every index is a constant into a fixed-size
// array, so nothing here can panic.

/// Attempt the requested operation and say what the kernel answered.
///
/// Returns the `(tag, errno)` pair the child writes into one status record.
pub(super) fn run_probe_in_child(wire: &ProbeWire) -> (u8, i32) {
    let detail = wire[OFFSET_DETAIL];
    match wire[OFFSET_OP] {
        OP_OPEN_PATH => path_probe(wire, detail),
        op @ (OP_CONNECT | OP_BIND) => socket_probe(wire, op, detail),
        // A record the supervisor never writes. Reported rather than acted on.
        _ => (TAG_PROBE_COULD_NOT_RUN, libc::EINVAL),
    }
}

/// The path region, as the NUL-terminated C string the syscalls take.
fn path_ptr(wire: &ProbeWire) -> *const c_char {
    // SAFETY: `OFFSET_PATH` is a constant strictly inside a `PROBE_REQUEST_BYTES`
    // array, and the supervisor leaves at least one zero byte at the end of the
    // region, so the result is a NUL-terminated string within `wire`.
    unsafe { wire.as_ptr().add(OFFSET_PATH).cast::<c_char>() }
}

/// Attempt one filesystem operation.
///
/// Each arm is a single syscall against the path — the operation the caller
/// named, not a stand-in for it. Two of them are deliberately harmless in the
/// permitted case and are worth naming: [`FsMode::Rename`] renames the path
/// onto itself, which POSIX defines as a successful no-op for a path that
/// already resolves to one file, and [`FsMode::ReadMetadata`] only reads. The
/// rest really do what they say.
fn path_probe(wire: &ProbeWire, mode_tag: u8) -> (u8, i32) {
    let path = path_ptr(wire);
    match mode_tag {
        0x01 => open_probe(path, libc::O_RDONLY),
        0x02 => open_probe(path, libc::O_RDONLY | libc::O_DIRECTORY),
        0x03 => stat_probe(path),
        0x04 => open_probe(path, libc::O_WRONLY),
        0x05 => open_probe(path, libc::O_WRONLY | libc::O_APPEND),
        0x06 => create_probe(path),
        0x07 => open_probe(path, libc::O_WRONLY | libc::O_TRUNC),
        // SAFETY: `path` is a NUL-terminated string inside `wire`, which
        // outlives the call. Both are async-signal-safe.
        0x08 => classify(unsafe { libc::unlink(path) }),
        // SAFETY: as above.
        0x09 => classify(unsafe { libc::rmdir(path) }),
        // SAFETY: as above. Naming the same path twice is what makes this a
        // real `rename(2)` with nothing moved.
        0x0A => classify(unsafe { libc::rename(path, path) }),
        0x0B => unix_connect_probe(path),
        _ => (TAG_PROBE_COULD_NOT_RUN, libc::EINVAL),
    }
}

/// `open(2)` with the given flags, closing whatever it produced.
///
/// The descriptor is closed immediately because a held child must not carry a
/// probe's descriptor into `execve`. `errno` is read before the close, since a
/// successful `close` may still write to it.
fn open_probe(path: *const c_char, flags: libc::c_int) -> (u8, i32) {
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    // `O_CLOEXEC` is added so that even a child killed between here and the
    // close below leaves nothing inheritable.
    let fd = unsafe { libc::open(path, flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return classify_errno(super::prepare::last_errno());
    }
    // SAFETY: `fd` is a descriptor this process just opened and owns.
    unsafe { libc::close(fd) };
    (TAG_PROBE_PERMITTED, 0)
}

/// `open(2)` with `O_CREAT | O_EXCL`, which really creates the file.
fn create_probe(path: *const c_char) -> (u8, i32) {
    // SAFETY: `path` is a NUL-terminated string that outlives the call. The
    // mode is passed as a `c_int` because this is a variadic call and C
    // promotes it to `int`.
    let fd = unsafe {
        libc::open(
            path,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600 as libc::c_int,
        )
    };
    if fd < 0 {
        return classify_errno(super::prepare::last_errno());
    }
    // SAFETY: `fd` is a descriptor this process just opened and owns.
    unsafe { libc::close(fd) };
    (TAG_PROBE_PERMITTED, 0)
}

/// `stat(2)`, into a buffer this frame owns.
fn stat_probe(path: *const c_char) -> (u8, i32) {
    let mut buf = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `path` is a NUL-terminated string that outlives the call and
    // `buf` is a live, correctly-sized, correctly-aligned `stat` slot. `stat`
    // writes it only on success, and nothing here reads it either way.
    classify(unsafe { libc::stat(path, buf.as_mut_ptr()) })
}

/// `connect(2)` to a pathname `AF_UNIX` socket.
///
/// The `socket(2)` that has to come first is setup, not the operation under
/// question, so a failure there is reported as
/// [`ProbeIndeterminate::ProbeCouldNotRun`] rather than as a refusal of the
/// connect that never happened.
fn unix_connect_probe(path: *const c_char) -> (u8, i32) {
    let mut addr = zeroed_sockaddr_un();
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // SAFETY: `path` is a NUL-terminated string inside the request record.
    let length = unsafe { libc::strlen(path) };
    if length >= addr.sun_path.len() {
        return (TAG_PROBE_COULD_NOT_RUN, libc::ENAMETOOLONG);
    }
    // SAFETY: source and destination are distinct, both live for the call, and
    // `length` was just checked against the destination's size.
    unsafe { std::ptr::copy_nonoverlapping(path, addr.sun_path.as_mut_ptr(), length) };

    let fd = match open_socket(libc::AF_UNIX, libc::SOCK_STREAM) {
        Ok(fd) => fd,
        Err(errno) => return (TAG_PROBE_COULD_NOT_RUN, errno),
    };
    // SAFETY: `fd` is a live socket this process owns, and the address is a
    // fully-initialised `sockaddr_un` in this frame.
    let result = unsafe {
        libc::connect(
            fd,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    let answer = classify_connect(result);
    // SAFETY: `fd` is a descriptor this process opened and owns.
    unsafe { libc::close(fd) };
    answer
}

/// `connect(2)` or `bind(2)` against an internet address.
fn socket_probe(wire: &ProbeWire, op: u8, protocol_tag: u8) -> (u8, i32) {
    let socket_type = match protocol_tag {
        PROTO_TCP => libc::SOCK_STREAM,
        PROTO_UDP => libc::SOCK_DGRAM,
        _ => return (TAG_PROBE_COULD_NOT_RUN, libc::EINVAL),
    };
    let port = u16::from_le_bytes([wire[OFFSET_PORT], wire[OFFSET_PORT.saturating_add(1)]]);

    match wire[OFFSET_FAMILY] {
        FAMILY_V4 => {
            let mut addr = zeroed_sockaddr_in();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = port.to_be();
            let mut octets = [0_u8; 4];
            octets.copy_from_slice(&wire[OFFSET_ADDR..OFFSET_ADDR.saturating_add(4)]);
            // The octets are already in network order, so laying them down as
            // native-endian bytes puts the right value in memory.
            addr.sin_addr.s_addr = u32::from_ne_bytes(octets);
            attempt_socket_op(
                libc::AF_INET,
                socket_type,
                op,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        FAMILY_V6 => {
            let mut addr = zeroed_sockaddr_in6();
            addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr.sin6_port = port.to_be();
            addr.sin6_addr
                .s6_addr
                .copy_from_slice(&wire[OFFSET_ADDR..OFFSET_ADDR.saturating_add(ADDR_BYTES)]);
            attempt_socket_op(
                libc::AF_INET6,
                socket_type,
                op,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
        _ => (TAG_PROBE_COULD_NOT_RUN, libc::EINVAL),
    }
}

/// Create the socket, attempt the one operation, and close it again.
fn attempt_socket_op(
    domain: libc::c_int,
    socket_type: libc::c_int,
    op: u8,
    addr: *const libc::sockaddr,
    length: libc::socklen_t,
) -> (u8, i32) {
    let fd = match open_socket(domain, socket_type) {
        Ok(fd) => fd,
        Err(errno) => return (TAG_PROBE_COULD_NOT_RUN, errno),
    };
    let answer = if op == OP_CONNECT {
        // SAFETY: `fd` is a live socket this process owns and `addr`/`length`
        // describe a fully-initialised address in the caller's frame.
        classify_connect(unsafe { libc::connect(fd, addr, length) })
    } else {
        // SAFETY: as above.
        classify(unsafe { libc::bind(fd, addr, length) })
    };
    // SAFETY: `fd` is a descriptor this process opened and owns.
    unsafe { libc::close(fd) };
    answer
}

/// A close-on-exec, non-blocking socket, or the `errno` that stopped it.
///
/// Non-blocking is not a detail: a blocking `connect` to an address that
/// silently drops packets would hold the child — and the supervisor waiting on
/// its reply — for the kernel's whole SYN timeout. With `O_NONBLOCK` the kernel
/// answers immediately, and an accepted-but-unfinished connection says
/// `EINPROGRESS`, which is the enforcement letting it through.
fn open_socket(domain: libc::c_int, socket_type: libc::c_int) -> Result<libc::c_int, i32> {
    // SAFETY: three integers; the call touches no memory of ours.
    let fd = unsafe { libc::socket(domain, socket_type, 0) };
    if fd < 0 {
        return Err(super::prepare::last_errno());
    }
    // SAFETY: `fd` is a descriptor this process just opened. Both calls take
    // integers and are async-signal-safe. Best effort: a failure here makes the
    // probe slower or leaves an inheritable descriptor for the microseconds
    // before the close, neither of which changes the answer.
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
    }
    Ok(fd)
}

/// Turn a syscall's return value into a reply.
fn classify(result: libc::c_int) -> (u8, i32) {
    if result == 0 {
        return (TAG_PROBE_PERMITTED, 0);
    }
    classify_errno(super::prepare::last_errno())
}

/// Turn a `connect(2)` return value into a reply.
///
/// Identical to [`classify`] but for `EINPROGRESS`, which a non-blocking
/// `connect` returns when the kernel has accepted the operation and is
/// completing it in the background. The enforcement did not refuse it, so it is
/// [`ProbeOutcome::Permitted`].
fn classify_connect(result: libc::c_int) -> (u8, i32) {
    if result == 0 {
        return (TAG_PROBE_PERMITTED, 0);
    }
    let errno = super::prepare::last_errno();
    if errno == libc::EINPROGRESS {
        return (TAG_PROBE_PERMITTED, 0);
    }
    classify_errno(errno)
}

/// The one place a number becomes a verdict.
fn classify_errno(errno: i32) -> (u8, i32) {
    if errno == libc::EPERM || errno == libc::EACCES {
        (TAG_PROBE_REFUSED, errno)
    } else {
        (TAG_PROBE_COULD_NOT_RUN, errno)
    }
}

/// A zeroed `sockaddr_un`.
///
/// The C structs below are plain old data whose every field is valid at zero —
/// which is also what C code gets from `memset`. Written as small helpers so
/// each `zeroed` call has one safety comment rather than three.
fn zeroed_sockaddr_un() -> libc::sockaddr_un {
    // SAFETY: `sockaddr_un` is a C aggregate of integers and a byte array, all
    // of which have valid all-zero representations.
    unsafe { std::mem::zeroed() }
}

/// A zeroed `sockaddr_in`.
fn zeroed_sockaddr_in() -> libc::sockaddr_in {
    // SAFETY: as above.
    unsafe { std::mem::zeroed() }
}

/// A zeroed `sockaddr_in6`.
fn zeroed_sockaddr_in6() -> libc::sockaddr_in6 {
    // SAFETY: as above.
    unsafe { std::mem::zeroed() }
}

/// The reply record is the same shape as every other record on the status
/// descriptor, so the two can never need different readers.
const _: () = assert!(STATUS_RECORD_LEN == 5);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn every_reply_tag_is_distinct_and_is_not_a_pre_exec_stage() {
        use crate::lifecycle::PreExecStage;

        let replies = [
            TAG_PROBE_PERMITTED,
            TAG_PROBE_REFUSED,
            TAG_PROBE_COULD_NOT_RUN,
        ];
        for (index, tag) in replies.iter().enumerate() {
            for other in replies.iter().skip(index.saturating_add(1)) {
                assert_ne!(tag, other, "reply tags must be distinct");
            }
            // A reply that decoded as a stage would let a probe answer be
            // mistaken for a dying child, and vice versa.
            assert_eq!(
                PreExecStage::from_tag(*tag),
                PreExecStage::Unknown,
                "reply tag {tag:#04x} collides with a pre-exec stage"
            );
            assert!(
                classify_reply(*tag, 0).is_some(),
                "reply tag {tag:#04x} must decode"
            );
        }
    }

    #[test]
    fn a_record_that_is_not_a_reply_decodes_to_nothing() {
        use crate::lifecycle::PreExecStage;

        // The child writes these when it is dying, not when it is answering.
        assert_eq!(classify_reply(PreExecStage::SandboxApply.as_tag(), 1), None);
        assert_eq!(classify_reply(PreExecStage::GateAborted.as_tag(), 0), None);
        assert_eq!(classify_reply(0xFF, 0), None);
    }

    #[test]
    fn replies_decode_to_the_outcome_they_name() {
        assert_eq!(
            classify_reply(TAG_PROBE_PERMITTED, 0),
            Some(ProbeOutcome::Permitted)
        );
        assert_eq!(
            classify_reply(TAG_PROBE_REFUSED, libc::EPERM),
            Some(ProbeOutcome::Refused { errno: libc::EPERM })
        );
        assert_eq!(
            classify_reply(TAG_PROBE_COULD_NOT_RUN, libc::ENOENT),
            Some(ProbeOutcome::Indeterminate {
                reason: ProbeIndeterminate::ProbeCouldNotRun {
                    errno: libc::ENOENT
                }
            })
        );
    }

    #[test]
    fn only_a_refusal_is_a_refusal() {
        assert_eq!(
            classify_errno(libc::EPERM),
            (TAG_PROBE_REFUSED, libc::EPERM)
        );
        assert_eq!(
            classify_errno(libc::EACCES),
            (TAG_PROBE_REFUSED, libc::EACCES)
        );
        // ENOENT says the object is not there. It says nothing about what the
        // enforcement would have done, so it must not become `Permitted`.
        assert_eq!(
            classify_errno(libc::ENOENT),
            (TAG_PROBE_COULD_NOT_RUN, libc::ENOENT)
        );
        assert_eq!(
            classify_errno(libc::ECONNREFUSED),
            (TAG_PROBE_COULD_NOT_RUN, libc::ECONNREFUSED)
        );
    }

    #[test]
    fn exec_has_no_probe_that_is_in_scope_for_a_held_child() {
        // Executing anything would destroy the process under question, and
        // forking a helper to execute it would run a program. Neither answers
        // the question that was asked.
        assert_eq!(
            settled_before_asking(&ProbeOp::Execute {
                program: PathBuf::from("/bin/echo")
            }),
            Some(ProbeIndeterminate::PlatformHasNoInScopeProbe)
        );
        assert_eq!(
            settled_before_asking(&ProbeOp::OpenPath {
                path: PathBuf::from("/bin/echo"),
                mode: FsMode::Execute,
            }),
            Some(ProbeIndeterminate::PlatformHasNoInScopeProbe)
        );
        // A bundle is four questions; one syscall asks one.
        assert_eq!(
            settled_before_asking(&ProbeOp::OpenPath {
                path: PathBuf::from("/tmp/x"),
                mode: FsMode::AtomicWrite,
            }),
            Some(ProbeIndeterminate::PlatformHasNoInScopeProbe)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_cannot_be_asked_about_stat() {
        assert_eq!(
            settled_before_asking(&ProbeOp::OpenPath {
                path: PathBuf::from("/etc/hosts"),
                mode: FsMode::ReadMetadata,
            }),
            Some(ProbeIndeterminate::MechanismCannotExpress {
                mechanism: EnforcementMechanism::Landlock
            })
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_can_be_asked_about_stat() {
        // Seatbelt has `file-read-metadata`, so the question is a real one
        // there and must reach the child.
        assert_eq!(
            settled_before_asking(&ProbeOp::OpenPath {
                path: PathBuf::from("/etc/hosts"),
                mode: FsMode::ReadMetadata,
            }),
            None
        );
    }

    #[test]
    fn every_mode_that_reaches_the_child_has_a_distinct_tag() {
        let mut tags = Vec::new();
        for mode in FsMode::ALL {
            let settled = settled_before_asking(&ProbeOp::OpenPath {
                path: PathBuf::from("/tmp/x"),
                mode,
            });
            match fs_mode_tag(mode) {
                Some(tag) => {
                    assert!(!tags.contains(&tag), "{mode:?} reuses tag {tag:#04x}");
                    tags.push(tag);
                }
                // A mode with no tag must never be sent, which is exactly what
                // `settled_before_asking` guarantees.
                None => assert!(
                    settled.is_some(),
                    "{mode:?} has no wire tag and no settled answer"
                ),
            }
        }
    }

    #[test]
    fn a_path_request_carries_its_path_and_a_terminating_nul() -> Result<(), i32> {
        let wire = encode_request(&ProbeOp::OpenPath {
            path: PathBuf::from("/etc/hosts"),
            mode: FsMode::ReadContents,
        })?;
        assert_eq!(wire[OFFSET_OP], OP_OPEN_PATH);
        assert_eq!(Some(wire[OFFSET_DETAIL]), fs_mode_tag(FsMode::ReadContents));
        let end = OFFSET_PATH.saturating_add("/etc/hosts".len());
        assert_eq!(&wire[OFFSET_PATH..end], b"/etc/hosts");
        assert_eq!(wire[end], 0, "the child reads this region as a C string");
        Ok(())
    }

    #[test]
    fn a_path_that_cannot_be_a_c_string_is_refused_before_the_child_sees_it() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let interior_nul = PathBuf::from(OsString::from_vec(b"/etc/ho\0sts".to_vec()));
        assert_eq!(
            encode_request(&ProbeOp::OpenPath {
                path: interior_nul,
                mode: FsMode::ReadContents,
            }),
            Err(libc::EINVAL)
        );

        let mut long = String::from("/");
        while long.len() < PROBE_PATH_BYTES {
            long.push('a');
        }
        assert_eq!(
            encode_request(&ProbeOp::OpenPath {
                path: PathBuf::from(long),
                mode: FsMode::ReadContents,
            }),
            Err(libc::ENAMETOOLONG)
        );
    }

    #[test]
    fn an_operation_with_no_wire_tag_is_never_encoded() {
        // Belt and braces with `settled_before_asking`: even if a future caller
        // reached the encoder directly, these two cannot become a record.
        assert_eq!(
            encode_request(&ProbeOp::Execute {
                program: PathBuf::from("/bin/echo")
            }),
            Err(libc::EINVAL)
        );
        assert_eq!(
            encode_request(&ProbeOp::OpenPath {
                path: PathBuf::from("/bin/echo"),
                mode: FsMode::Execute,
            }),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn an_address_request_carries_the_address_in_network_order() -> Result<(), i32> {
        let v4 = encode_request(&ProbeOp::Connect {
            protocol: TransportProtocol::Tcp,
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 8080)),
        })?;
        assert_eq!(v4[OFFSET_OP], OP_CONNECT);
        assert_eq!(v4[OFFSET_DETAIL], PROTO_TCP);
        assert_eq!(v4[OFFSET_FAMILY], FAMILY_V4);
        assert_eq!(
            u16::from_le_bytes([v4[OFFSET_PORT], v4[OFFSET_PORT.saturating_add(1)]]),
            8080
        );
        assert_eq!(
            &v4[OFFSET_ADDR..OFFSET_ADDR.saturating_add(4)],
            &[203, 0, 113, 7]
        );

        let v6 = encode_request(&ProbeOp::Bind {
            protocol: TransportProtocol::Udp,
            addr: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9, 0, 0)),
        })?;
        assert_eq!(v6[OFFSET_OP], OP_BIND);
        assert_eq!(v6[OFFSET_DETAIL], PROTO_UDP);
        assert_eq!(v6[OFFSET_FAMILY], FAMILY_V6);
        assert_eq!(
            &v6[OFFSET_ADDR..OFFSET_ADDR.saturating_add(ADDR_BYTES)],
            &Ipv6Addr::LOCALHOST.octets()
        );
        Ok(())
    }

    #[test]
    fn an_unknown_request_record_is_reported_rather_than_acted_on() {
        // The supervisor never writes one of these; a child that received one
        // must not fall through to a syscall.
        let mut wire: ProbeWire = [0_u8; PROBE_REQUEST_BYTES];
        wire[OFFSET_OP] = 0x7F;
        assert_eq!(
            run_probe_in_child(&wire),
            (TAG_PROBE_COULD_NOT_RUN, libc::EINVAL)
        );

        // An op we do know about with a detail byte we do not.
        wire[OFFSET_OP] = OP_OPEN_PATH;
        wire[OFFSET_DETAIL] = 0x7F;
        assert_eq!(
            run_probe_in_child(&wire),
            (TAG_PROBE_COULD_NOT_RUN, libc::EINVAL)
        );
    }

    #[test]
    fn an_observation_never_claims_a_denial_record() {
        // `denial_observed` is false on every outcome, including a refusal.
        // The library observes no denial events on either platform — see
        // `super::support`'s KernelDenial entry (NotObserved) and the first
        // paragraph of `super::events`.
        for outcome in [
            ProbeOutcome::Permitted,
            ProbeOutcome::Refused { errno: libc::EPERM },
            ProbeOutcome::Indeterminate {
                reason: ProbeIndeterminate::PlatformHasNoInScopeProbe,
            },
        ] {
            let observed = observation(
                ProbeId::new("denial"),
                outcome,
                EnforcementMechanism::Seatbelt,
            );
            assert!(!observed.denial_observed);
            assert_eq!(observed.scope, ProbeScope::InstalledChild);
        }
    }

    #[test]
    fn this_build_installs_exactly_one_mechanism() {
        let installed = installed_mechanism();
        #[cfg(target_os = "macos")]
        assert_eq!(installed, Some(EnforcementMechanism::Seatbelt));
        #[cfg(target_os = "linux")]
        assert_eq!(installed, Some(EnforcementMechanism::Landlock));
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert_eq!(installed, None);
    }

    #[test]
    fn the_vocabularies_render_distinctly() {
        let mut seen = Vec::new();
        for mechanism in EnforcementMechanism::ALL {
            assert!(!seen.contains(&mechanism.as_str()));
            seen.push(mechanism.as_str());
            assert_eq!(mechanism.to_string(), mechanism.as_str());
        }
        for scope in ProbeScope::ALL {
            assert_eq!(scope.to_string(), scope.as_str());
        }
        for protocol in TransportProtocol::ALL {
            assert_eq!(protocol.to_string(), protocol.as_str());
        }
        assert_eq!(
            ProbeIndeterminate::MechanismCannotExpress {
                mechanism: EnforcementMechanism::Landlock
            }
            .to_string(),
            "mechanism_cannot_express"
        );
        assert_eq!(ProbeId::new("tag").to_string(), "tag");
        assert_eq!(ProbeId::new("tag").as_str(), "tag");
    }
}

/// Live probes against real held children.
///
/// Every test here forks a process, applies the real platform sandbox to it,
/// and asks the real kernel. That is the only kind of test that can fail the way
/// this mechanism must be able to fail: a probe answered from the grant table
/// would pass any test that only checks the *shape* of an observation, which is
/// exactly why [`kernel_and_grant_table_disagree_and_the_kernel_wins`] asserts
/// the two disagree.
#[cfg(test)]
mod live {
    use super::*;
    use crate::capability::{AccessMode, CapabilitySet};
    use crate::lifecycle::{
        LifecycleState, PreparedSandbox, ProbeError, ProbeId, ProbeObservation, ProbeOp,
        ProbeOutcome, ProbeRequest, SandboxPlan,
    };
    use std::path::Path;
    use tempfile::TempDir;

    fn temp_dir() -> TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("test needs a temporary directory: {err}"),
        }
    }

    fn write_file(path: &Path) {
        if let Err(err) = std::fs::write(path, b"probe target\n") {
            panic!("test needs a file at {}: {err}", path.display());
        }
    }

    /// Read everything, write only inside `writable`.
    fn capabilities(writable: &Path) -> CapabilitySet {
        let caps = CapabilitySet::new()
            .allow_path("/", AccessMode::Read)
            .and_then(|caps| caps.allow_path(writable, AccessMode::ReadWrite));
        match caps {
            Ok(caps) => caps,
            Err(err) => panic!("test capabilities must build: {err}"),
        }
    }

    /// A held `/bin/echo` confined by `caps`.
    fn held(caps: CapabilitySet) -> PreparedSandbox {
        let plan = SandboxPlan::new("/bin/echo").arg("held").capabilities(caps);
        let plan = match plan.validate() {
            Ok(plan) => plan,
            Err(err) => panic!("test plan must validate: {err}"),
        };
        match PreparedSandbox::prepare(plan) {
            Ok((held, _handle)) => held,
            Err(err) => panic!("prepare must succeed: {err}"),
        }
    }

    fn probe(held: &PreparedSandbox, id: &str, op: ProbeOp) -> ProbeObservation {
        let request = ProbeRequest {
            id: ProbeId::new(id),
            op,
        };
        match held.probe_enforcement(&request) {
            Ok(observation) => observation,
            Err(err) => panic!("the held child must answer probe {id}: {err}"),
        }
    }

    fn open_path(path: &Path, mode: FsMode) -> ProbeOp {
        ProbeOp::OpenPath {
            path: path.to_path_buf(),
            mode,
        }
    }

    /// A refusal, whichever of the two numbers the platform used.
    fn assert_refused(observation: &ProbeObservation) {
        match observation.outcome {
            ProbeOutcome::Refused { errno } => assert!(
                errno == libc::EPERM || errno == libc::EACCES,
                "a refusal must carry the kernel's own number, got {errno}"
            ),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_kernel_answers_for_a_granted_path_and_for_one_it_never_granted() {
        // The load-bearing test. Both answers come from a real syscall made by
        // the confined child; neither is a lookup in the capability set.
        let granted_dir = temp_dir();
        let ungranted_dir = temp_dir();
        let granted = granted_dir.path().join("granted.txt");
        let ungranted = ungranted_dir.path().join("ungranted.txt");
        write_file(&granted);
        write_file(&ungranted);

        let held = held(capabilities(granted_dir.path()));

        let permitted = probe(&held, "granted", open_path(&granted, FsMode::Write));
        assert_eq!(
            permitted.outcome,
            ProbeOutcome::Permitted,
            "a path the plan granted for writing must open for writing"
        );
        assert_eq!(permitted.id, ProbeId::new("granted"));
        assert_eq!(permitted.scope, ProbeScope::InstalledChild);

        // The ungranted file is one this user owns and can write: ordinary Unix
        // permissions would allow it, so the refusal below can only be the
        // sandbox.
        let refused = probe(&held, "ungranted", open_path(&ungranted, FsMode::Write));
        assert_refused(&refused);
    }

    /// The mutation detector, in the direction where the table is stricter than
    /// the kernel.
    ///
    /// macOS only, and not because the property is: it is because the
    /// *disagreement* is. Every Seatbelt profile this library generates allows
    /// reading the root directory entry unconditionally — exec path resolution
    /// needs it — while the grant table below has no rule covering `/` at all.
    /// Landlock has no equivalent unconditional allowance, so the same
    /// capability set really would deny `/` there and the two would agree. The
    /// other direction is asserted on both platforms by
    /// [`a_path_that_is_not_there_establishes_nothing`].
    #[cfg(target_os = "macos")]
    #[test]
    fn kernel_and_grant_table_disagree_and_the_kernel_wins() {
        let dir = temp_dir();
        let caps = match CapabilitySet::new().allow_path(dir.path(), AccessMode::ReadWrite) {
            Ok(caps) => caps,
            Err(err) => panic!("test capabilities must build: {err}"),
        };

        let table = crate::query::QueryContext::new(caps.clone());
        let table_says = table.query_path(Path::new("/"), AccessMode::Read);
        assert!(
            matches!(table_says, crate::query::QueryResult::Denied(_)),
            "the grant table must deny \"/\" for this capability set, got {table_says:?}"
        );

        let held = held(caps);
        let observed = probe(&held, "root", open_path(Path::new("/"), FsMode::ReadDir));
        assert_eq!(
            observed.outcome,
            ProbeOutcome::Permitted,
            "the installed profile allows reading \"/\"; the probe must report what the kernel \
             did, not what the grant table would have said"
        );
    }

    #[test]
    fn a_probe_runs_no_program_and_leaves_the_child_held() {
        // The plan's program would create this file if it ever ran. Probing
        // must not run it — and the second half of the test proves the sentinel
        // is real by activating an identical run and finding the file.
        let dir = temp_dir();
        let marker = dir.path().join("the-program-ran");
        let command = format!("touch {}", marker.display());

        let build = |dir: &Path, command: &str| {
            let plan = SandboxPlan::new("/bin/sh")
                .arg("-c")
                .arg(command)
                .capabilities(capabilities(dir));
            match plan.validate() {
                Ok(plan) => plan,
                Err(err) => panic!("test plan must validate: {err}"),
            }
        };

        let held = match PreparedSandbox::prepare(build(dir.path(), &command)) {
            Ok((held, _handle)) => held,
            Err(err) => panic!("prepare must succeed: {err}"),
        };
        let probed = dir.path().join("probed.txt");
        write_file(&probed);
        let observed = probe(&held, "no-exec", open_path(&probed, FsMode::ReadContents));
        assert_eq!(observed.outcome, ProbeOutcome::Permitted);
        assert!(
            !marker.exists(),
            "the plan's program must not have been executed by a probe"
        );
        assert_eq!(
            held.state(),
            LifecycleState::Prepared,
            "the child must still be held after answering"
        );
        drop(held);
        assert!(
            !marker.exists(),
            "a dropped probe target must not have run the program either"
        );

        // The positive control: the same plan, activated, really does create
        // the marker. Without this the assertion above could pass for a plan
        // that could never have written the file at all.
        let (mut running, handle) = match PreparedSandbox::prepare(build(dir.path(), &command)) {
            Ok(pair) => pair,
            Err(err) => panic!("prepare must succeed: {err}"),
        };
        match running.activate(&handle) {
            Ok(mut activated) => {
                if let Err(err) = activated.wait() {
                    panic!("wait must observe the exit: {err}");
                }
            }
            Err(err) => panic!("activation must succeed: {err}"),
        }
        assert!(
            marker.exists(),
            "the sentinel is only meaningful if running the program really creates it"
        );
    }

    #[test]
    fn two_identical_probes_both_reach_the_kernel() {
        // `Create` is the operation that makes memoisation visible: the first
        // probe really creates the file, so an identical second probe gets
        // EEXIST from the kernel. A cached answer would repeat the first.
        let dir = temp_dir();
        let target = dir.path().join("created-by-the-probe.txt");
        let held = held(capabilities(dir.path()));

        let request = ProbeRequest {
            id: ProbeId::new("create"),
            op: open_path(&target, FsMode::Create),
        };
        let first = match held.probe_enforcement(&request) {
            Ok(observation) => observation,
            Err(err) => panic!("the held child must answer: {err}"),
        };
        assert_eq!(
            first.outcome,
            ProbeOutcome::Permitted,
            "a create probe inside the writable grant must succeed"
        );
        assert!(
            target.exists(),
            "a probe is not a simulation: a permitted create has created the file"
        );

        let second = match held.probe_enforcement(&request) {
            Ok(observation) => observation,
            Err(err) => panic!("the held child must answer twice: {err}"),
        };
        assert_eq!(
            second.outcome,
            ProbeOutcome::Indeterminate {
                reason: ProbeIndeterminate::ProbeCouldNotRun {
                    errno: libc::EEXIST
                }
            },
            "the second probe must be a second syscall, not a replay of the first"
        );
        assert!(
            second.observed_at >= first.observed_at,
            "each observation is stamped when its own answer arrived"
        );
    }

    #[test]
    fn a_refusal_is_never_reported_as_an_observed_denial() {
        // `denial_observed` is false even here, on the one outcome where an
        // optimistic implementation would be tempted to set it. This library
        // observes no kernel denial events on either platform: `super::support`
        // records EventFamily::KernelDenial with EventFidelity::NotObserved,
        // and `super::events` says in its first paragraph that there is no
        // KernelDenial variant because this library does not observe them. An
        // errno is the syscall's return value, not a denial record.
        let granted_dir = temp_dir();
        let ungranted_dir = temp_dir();
        let ungranted = ungranted_dir.path().join("ungranted.txt");
        write_file(&ungranted);

        let held = held(capabilities(granted_dir.path()));
        let refused = probe(&held, "denial", open_path(&ungranted, FsMode::Write));
        assert_refused(&refused);
        assert!(
            !refused.denial_observed,
            "a refused syscall is not a captured denial record"
        );

        // And it is false on the other two outcomes too, so nothing can read it
        // as "the outcome, restated".
        let permitted = probe(
            &held,
            "denial-permitted",
            open_path(Path::new("/"), FsMode::ReadDir),
        );
        assert!(!permitted.denial_observed);
        let indeterminate = probe(
            &held,
            "denial-indeterminate",
            ProbeOp::Execute {
                program: std::path::PathBuf::from("/bin/echo"),
            },
        );
        assert!(!indeterminate.denial_observed);
    }

    #[test]
    fn exec_has_no_in_scope_probe_and_the_child_survives_being_asked() {
        let dir = temp_dir();
        let held = held(capabilities(dir.path()));
        let observed = probe(
            &held,
            "exec",
            ProbeOp::Execute {
                program: std::path::PathBuf::from("/bin/echo"),
            },
        );
        assert_eq!(
            observed.outcome,
            ProbeOutcome::Indeterminate {
                reason: ProbeIndeterminate::PlatformHasNoInScopeProbe
            }
        );
        // Nothing was sent, so the child never left the gate and can still be
        // asked a question it does have an answer to.
        assert_eq!(held.state(), LifecycleState::Prepared);
        let after = probe(
            &held,
            "after-exec",
            open_path(Path::new("/"), FsMode::ReadDir),
        );
        assert_eq!(after.outcome, ProbeOutcome::Permitted);
    }

    #[test]
    fn a_path_that_is_not_there_establishes_nothing() {
        // ENOENT says the object is absent. It does not say the mechanism would
        // have allowed reaching it, so it must not become `Permitted`.
        //
        // This is also the mutation detector that holds on both platforms, in
        // the direction where the table is *looser* than the kernel: the path
        // is inside a granted subtree, so the grant table answers "allowed" for
        // a file that does not exist. Only a real syscall can say ENOENT.
        let dir = temp_dir();
        let absent = dir.path().join("never-created");
        let caps = capabilities(dir.path());

        let table = crate::query::QueryContext::new(caps.clone());
        let table_says = table.query_path(&absent, AccessMode::Read);
        assert!(
            matches!(table_says, crate::query::QueryResult::Allowed(_)),
            "the grant table must allow a path inside the granted subtree, got {table_says:?}"
        );

        let held = held(caps);
        let observed = probe(&held, "absent", open_path(&absent, FsMode::ReadContents));
        assert_eq!(
            observed.outcome,
            ProbeOutcome::Indeterminate {
                reason: ProbeIndeterminate::ProbeCouldNotRun {
                    errno: libc::ENOENT
                }
            },
            "the probe must report the kernel's own number, not the grant table's verdict"
        );
    }

    #[test]
    fn a_probe_is_refused_once_there_is_no_held_child_to_ask() {
        let dir = temp_dir();
        let mut held = held(capabilities(dir.path()));
        if let Err(err) = held.stop_before_activation() {
            panic!("the stop must be observed: {err}");
        }
        let refused = held.probe_enforcement(&ProbeRequest {
            id: ProbeId::new("too-late"),
            op: open_path(Path::new("/"), FsMode::ReadDir),
        });
        assert_eq!(
            refused,
            Err(ProbeError::NotLegalInState {
                state: LifecycleState::Stopped
            }),
            "a probe of the installed enforcement needs the installed child"
        );
    }

    #[test]
    fn a_blocked_network_refuses_what_an_open_one_permits() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

        // Same address, same child shape, two policies. Neither answer is
        // looked up: the child creates a socket and makes one real `connect` or
        // `bind`, and the kernel decides.
        let unreachable = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        let ephemeral = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let open_dir = temp_dir();
        let open = held(capabilities(open_dir.path()));
        let connected = probe(
            &open,
            "connect-open",
            ProbeOp::Connect {
                protocol: TransportProtocol::Tcp,
                addr: unreachable,
            },
        );
        assert_eq!(
            connected.outcome,
            ProbeOutcome::Permitted,
            "a policy that does not block the network must let the connect through"
        );
        let bound = probe(
            &open,
            "bind-open",
            ProbeOp::Bind {
                protocol: TransportProtocol::Tcp,
                addr: ephemeral,
            },
        );
        assert_eq!(bound.outcome, ProbeOutcome::Permitted);

        let blocked_dir = temp_dir();
        let blocked = held(capabilities(blocked_dir.path()).block_network());
        assert_refused(&probe(
            &blocked,
            "connect-blocked",
            ProbeOp::Connect {
                protocol: TransportProtocol::Tcp,
                addr: unreachable,
            },
        ));
        assert_refused(&probe(
            &blocked,
            "bind-blocked",
            ProbeOp::Bind {
                protocol: TransportProtocol::Tcp,
                addr: ephemeral,
            },
        ));
        // UDP is a different socket type and therefore a different question.
        assert_refused(&probe(
            &blocked,
            "udp-blocked",
            ProbeOp::Connect {
                protocol: TransportProtocol::Udp,
                addr: unreachable,
            },
        ));
    }

    #[test]
    fn a_probe_really_does_what_it_says_except_where_it_says_otherwise() {
        // The two ends of "a probe is not a simulation". `RemoveFile` really
        // unlinks, so a permitted removal leaves nothing behind; `Rename`
        // renames the path onto itself, which is a real `rename(2)` the kernel
        // checks and a no-op if it passes. A caller that wants neither plants
        // its probe on a path it does not mind either way.
        let dir = temp_dir();
        let renamed = dir.path().join("renamed.txt");
        let removed = dir.path().join("removed.txt");
        write_file(&renamed);
        write_file(&removed);

        let held = held(capabilities(dir.path()));

        let observed = probe(&held, "rename", open_path(&renamed, FsMode::Rename));
        assert_eq!(observed.outcome, ProbeOutcome::Permitted);
        assert!(
            renamed.exists(),
            "a rename onto the same path must move nothing"
        );

        let observed = probe(&held, "remove", open_path(&removed, FsMode::RemoveFile));
        assert_eq!(observed.outcome, ProbeOutcome::Permitted);
        assert!(
            !removed.exists(),
            "a permitted removal has removed the file; the probe is the operation"
        );
    }

    #[test]
    fn a_unix_socket_connect_reaches_the_kernel_too() {
        // No listener, so the honest answer is ENOENT — the probe ran and
        // established nothing, rather than reporting a permission the kernel
        // never granted or refused.
        let dir = temp_dir();
        let held = held(capabilities(dir.path()));
        let observed = probe(
            &held,
            "unix",
            open_path(&dir.path().join("absent.sock"), FsMode::UnixSocketConnect),
        );
        assert_eq!(
            observed.outcome,
            ProbeOutcome::Indeterminate {
                reason: ProbeIndeterminate::ProbeCouldNotRun {
                    errno: libc::ENOENT
                }
            }
        );
    }
}
