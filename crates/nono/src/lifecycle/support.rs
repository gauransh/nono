//! What this build can actually enforce, as data rather than a boolean.
//!
//! [`SupportInfo`][crate::SupportInfo] answers "is sandboxing supported?" with
//! one `bool` and a sentence of prose. That is the wrong shape for a consumer
//! that has to *decide* something: "supported" is never true or false as a
//! whole, it is true of some mechanisms, false of others, and — this is the
//! part a boolean cannot say at all — sometimes merely *believed* rather than
//! observed.
//!
//! [`SupportReport`] answers the same question as a tree of [`Capability`]
//! values, each carrying three things:
//!
//! - a [`SupportStatus`]: available, partial, unavailable, or honestly unknown;
//! - a [`Determination`]: whether a probe ran *here and now*
//!   ([`Determination::ProbedLive`]), whether the answer rests on a platform
//!   API whose presence is a compile-time fact ([`Determination::PlatformApi`]),
//!   or whether this build is simply stating it ([`Determination::Declared`]);
//! - a typed [`SupportReason`] naming the probe, the refusal, or the missing
//!   implementation.
//!
//! The distinction between the first two is the whole point. "Seatbelt is
//! available" and "we opened a pty a microsecond ago" are not the same kind of
//! claim, and a report that flattened them would be lying by omission.
//!
//! # Nothing here guesses
//!
//! [`SupportReport::gather`] cannot fail. Every probe that will not answer
//! produces [`SupportStatus::Unknown`] with the reason it would not answer —
//! never a default, never an optimistic assumption, never a panic. A capability
//! this slice has not built is [`SupportStatus::Unavailable`] with
//! [`SupportReason::NotImplemented`], not a silent omission.
//!
//! # What the report deliberately does not claim
//!
//! The event fidelity map ([`SupportReport::event_observation`]) states which
//! event families *this library* observes. Kernel denial events are not among
//! them on either platform: the lifecycle installs no seccomp
//! user-notification listener, and macOS Seatbelt denials reach userspace only
//! through the system log. `nono-cli` reconstructs those from `log stream`, but
//! that is CLI machinery — claiming it here would credit the library with an
//! observation it does not make.
//!
//! Upstream's [`SupportInfo`][crate::SupportInfo] is untouched and still means
//! what it always meant; this is an addition, not a replacement.

use super::cleanup::{Probe, probe_group, probe_pid};
use super::identity::ProcessIdentity;
use serde::{Deserialize, Serialize};

/// Schema version of the report this build writes.
///
/// Bumped when a field's meaning changes, not when a field is added: a
/// consumer that reads by name survives an addition, and one that reads a
/// renamed or re-meant field must be made to notice.
pub const SUPPORT_REPORT_SCHEMA_VERSION: u32 = 1;

/// Whether a capability is there.
///
/// Four answers, not two. [`Self::Partial`] and [`Self::Unknown`] are the two
/// a boolean cannot express, and they are the two that matter most: a
/// mechanism that exists in a weaker form than asked for, and one this process
/// could not establish without changing itself irreversibly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStatus {
    /// The capability is there in the shape the lifecycle needs.
    Available,
    /// Part of it is there. The capability's own facts say which part.
    Partial,
    /// It is not there. The [`SupportReason`] says why.
    Unavailable,
    /// It could not be established. Never a synonym for "no" — a consumer that
    /// needs certainty must treat this as "ask again in an environment where
    /// the probe can run", not as a refusal.
    Unknown,
}

impl SupportStatus {
    /// The stable snake_case name, identical to the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for SupportStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How this build knows what it says it knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Determination {
    /// A probe ran in this process, during this call, and its result is the
    /// status. The strongest claim in this module.
    ProbedLive,
    /// The answer rests on a platform API this build links against, whose
    /// presence is settled at compile time. Weaker than a probe and stronger
    /// than a guess: the API is certainly *there*, but nothing was asked of it.
    PlatformApi,
    /// This build states it without a probe. Used for facts that are properties
    /// of this source tree — an unimplemented slice, a mechanism that belongs to
    /// another platform — and for an [`SupportStatus::Unknown`] whose probe
    /// could not be run at all.
    Declared,
}

impl Determination {
    /// The stable snake_case name, identical to the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProbedLive => "probed_live",
            Self::PlatformApi => "platform_api",
            Self::Declared => "declared",
        }
    }
}

impl std::fmt::Display for Determination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a capability's status is what it is.
///
/// Typed rather than a log line, because a consumer that has to *decide*
/// something — degrade, refuse, or ask again elsewhere — has to match on this,
/// and matching on prose is not a contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum SupportReason {
    /// A probe ran and its answer *is* the status, whatever the status says.
    Probed {
        /// The syscall or library call that answered.
        probe: String,
    },

    /// The probe could not be completed, so nothing was established by it.
    ProbeRefused {
        /// The syscall or library call that was attempted.
        probe: String,
        /// What the platform said, verbatim where it said anything.
        detail: String,
    },

    /// The mechanism belongs to a platform this build does not target.
    OtherPlatform {
        /// The mechanism that is absent here.
        mechanism: String,
        /// The platform this build was compiled for.
        this_target_os: String,
    },

    /// The platform API is linked into this build, so it is certainly present;
    /// no probe was run, and this says why not.
    PlatformApiLinked {
        /// The API whose presence is the compile-time fact.
        api: String,
        /// Why a live probe was not run. Never empty: an unprobed claim has to
        /// justify itself.
        why_not_probed: String,
    },

    /// Nothing implements this yet.
    NotImplemented {
        /// The work that will implement it, named so the gap is trackable.
        slice: String,
    },

    /// Establishing it would change this process in a way that cannot be
    /// undone, so the library does not establish it.
    NotObservableWithoutIrreversibleChange {
        /// What would have to be done, and to what.
        what: String,
    },

    /// The platform's own mechanism cannot express what was asked for, and the
    /// library refuses rather than widening to something it *can* express.
    PlatformCannotExpress {
        /// The mechanism that falls short.
        mechanism: String,
        /// The refusal this produces at the point of use.
        refusal: String,
    },
}

/// One capability: what it is, how we know, and why.
///
/// `T` carries whatever typed detail the capability has beyond those three —
/// Landlock's per-right table, the host's uname fields — and is `()` for the
/// capabilities that have none. `facts` is absent from the serialization when
/// there are none, so a `()` capability is three fields and no null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability<T = ()> {
    /// Whether the capability is there.
    status: SupportStatus,
    /// How this build knows.
    determination: Determination,
    /// Why the status is what it is.
    reason: SupportReason,
    /// Typed detail, when the capability has any.
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    facts: Option<T>,
}

impl<T> Capability<T> {
    /// A capability with no typed detail beyond status/determination/reason.
    fn plain(status: SupportStatus, determination: Determination, reason: SupportReason) -> Self {
        Self {
            status,
            determination,
            reason,
            facts: None,
        }
    }

    /// A capability with typed detail.
    fn detailed(
        status: SupportStatus,
        determination: Determination,
        reason: SupportReason,
        facts: T,
    ) -> Self {
        Self {
            status,
            determination,
            reason,
            facts: Some(facts),
        }
    }

    /// Whether the capability is there.
    #[must_use]
    pub fn status(&self) -> SupportStatus {
        self.status
    }

    /// How this build knows.
    #[must_use]
    pub fn determination(&self) -> Determination {
        self.determination
    }

    /// Why the status is what it is.
    #[must_use]
    pub fn reason(&self) -> &SupportReason {
        &self.reason
    }

    /// The typed detail, when this capability has any.
    #[must_use]
    pub fn facts(&self) -> Option<&T> {
        self.facts.as_ref()
    }
}

/// The machine this process is running on.
///
/// Two halves that are deliberately not merged: what this binary was *compiled*
/// for, and what `uname` says it is *running* on. They agree almost always, and
/// the almost is exactly when a support report earns its keep.
///
/// The host's node name is deliberately not read. A hostname is not a
/// capability fact, and this report is the kind of thing a consumer pastes into
/// an issue.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostFacts {
    /// `std::env::consts::OS` — the target this build was compiled for.
    compiled_os: String,
    /// `std::env::consts::ARCH` — likewise.
    compiled_arch: String,
    /// What `uname(2)` said, when it said anything.
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    kernel: Option<KernelFacts>,
}

impl HostFacts {
    /// The target OS this build was compiled for.
    #[must_use]
    pub fn compiled_os(&self) -> &str {
        &self.compiled_os
    }

    /// The target architecture this build was compiled for.
    #[must_use]
    pub fn compiled_arch(&self) -> &str {
        &self.compiled_arch
    }

    /// What `uname(2)` reported, if it reported anything.
    #[must_use]
    pub fn kernel(&self) -> Option<&KernelFacts> {
        self.kernel.as_ref()
    }
}

/// The four `uname(2)` fields that describe a kernel.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KernelFacts {
    /// `utsname.sysname`, e.g. `Linux` or `Darwin`.
    sysname: String,
    /// `utsname.release`, e.g. `6.8.0-40-generic` or `23.6.0`.
    release: String,
    /// `utsname.version` — the build string, which on both platforms carries
    /// more than the release does.
    version: String,
    /// `utsname.machine`, e.g. `x86_64` or `arm64`.
    machine: String,
}

impl KernelFacts {
    /// The operating system name the kernel reports.
    #[must_use]
    pub fn sysname(&self) -> &str {
        &self.sysname
    }

    /// The kernel release string.
    #[must_use]
    pub fn release(&self) -> &str {
        &self.release
    }

    /// The kernel build/version string.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The machine (architecture) the kernel reports.
    #[must_use]
    pub fn machine(&self) -> &str {
        &self.machine
    }
}

/// What Landlock offers on this kernel, right down to the individual right.
///
/// The ABI number on its own is not actionable — "V3" says nothing to a
/// consumer that wants to know whether it can rename across directories. The
/// per-right table is the same information in the shape a decision is made
/// from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LandlockFacts {
    /// The detected ABI, e.g. `V4`. `None` when detection did not answer.
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    abi: Option<String>,
    /// One entry per right the lifecycle can ask for.
    rights: Vec<LandlockRightSupport>,
}

impl LandlockFacts {
    /// The detected ABI version string, if detection answered.
    #[must_use]
    pub fn abi(&self) -> Option<&str> {
        self.abi.as_deref()
    }

    /// Per-right availability at the detected ABI.
    #[must_use]
    pub fn rights(&self) -> &[LandlockRightSupport] {
        &self.rights
    }
}

/// One Landlock right, and whether this kernel has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LandlockRightSupport {
    /// The right.
    right: LandlockRight,
    /// Whether the detected ABI carries it.
    status: SupportStatus,
}

impl LandlockRightSupport {
    /// The right this entry is about.
    #[must_use]
    pub fn right(&self) -> LandlockRight {
        self.right
    }

    /// Whether the detected ABI carries it.
    #[must_use]
    pub fn status(&self) -> SupportStatus {
        self.status
    }
}

/// A Landlock right the lifecycle can depend on.
///
/// Names follow `DetectedAbi`'s own accessors rather than the kernel's flag
/// spelling, so the two cannot drift apart silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockRight {
    /// Path-based filesystem access control. Present at every ABI, which is why
    /// its entry exists: a consumer reading the table should not have to know
    /// that V1 is the floor.
    FilesystemBase,
    /// Rename and link across directories (`Refer`, V2+).
    Refer,
    /// Truncation control (`Truncate`, V3+).
    Truncate,
    /// Execute control strong enough for the lifecycle's exec narrowing (V3+).
    Execute,
    /// TCP connect/bind port rules (`AccessNet`, V4+).
    TcpNetwork,
    /// Device `ioctl` filtering (`IoctlDev`, V5+).
    IoctlDev,
    /// Signal and abstract-UNIX-socket scoping (`Scope`, V6+).
    Scoping,
}

/// Which network-filtering mechanisms this platform offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkFilteringFacts {
    /// One entry per mechanism, available or not.
    mechanisms: Vec<NetworkMechanismSupport>,
}

impl NetworkFilteringFacts {
    /// Per-mechanism availability.
    #[must_use]
    pub fn mechanisms(&self) -> &[NetworkMechanismSupport] {
        &self.mechanisms
    }
}

/// One network-filtering mechanism, and whether it is usable here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMechanismSupport {
    /// The mechanism.
    mechanism: NetworkMechanism,
    /// Whether it is usable here.
    status: SupportStatus,
    /// Why.
    reason: SupportReason,
}

impl NetworkMechanismSupport {
    /// The mechanism this entry is about.
    #[must_use]
    pub fn mechanism(&self) -> NetworkMechanism {
        self.mechanism
    }

    /// Whether it is usable here.
    #[must_use]
    pub fn status(&self) -> SupportStatus {
        self.status
    }

    /// Why the status is what it is.
    #[must_use]
    pub fn reason(&self) -> &SupportReason {
        &self.reason
    }
}

/// A way this build can filter network access.
///
/// Each one is a mechanism that already exists in `crate::sandbox`; this enum
/// names them so a report can say which are reachable *here* rather than which
/// ones the code contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMechanism {
    /// Landlock per-port TCP connect/bind rules (ABI V4+).
    LandlockTcpPortRules,
    /// The hand-written seccomp filter that allows only `AF_UNIX`
    /// (`SeccompNetFallback::BlockAll`).
    SeccompBlockAll,
    /// Seccomp user-notification mediation of connect/bind
    /// (`SeccompNetFallback::ProxyOnly`).
    SeccompUserNotifyProxy,
    /// Seatbelt's `(deny network*)` / `(allow network*)`: all or nothing, with
    /// a proxy-port carve-out, and no per-port filtering.
    SeatbeltNetworkAllOrNothing,
    /// Per-port TCP filtering on macOS. Named so its absence is a *stated*
    /// fact rather than a gap in the table.
    SeatbeltPerPortTcp,
}

/// Whether this process can read the facts that make a pid non-reusable.
///
/// Probed against this very process: if we cannot read our *own* start time,
/// every [`ProcessIdentity`] check in the lifecycle fails closed, and a
/// consumer deserves to know that before it trusts a cleanup verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityFacts {
    /// Whether this process's own start time could be read just now.
    start_time: SupportStatus,
    /// Whether a boot identifier could be read just now.
    boot_id: SupportStatus,
    /// Whether the freshly captured identity recognised this process — the
    /// whole check, end to end, run against a process we know the answer for.
    self_recognition: SupportStatus,
}

impl IdentityFacts {
    /// Whether this process's own start time could be read.
    #[must_use]
    pub fn start_time(&self) -> SupportStatus {
        self.start_time
    }

    /// Whether a boot identifier could be read.
    #[must_use]
    pub fn boot_id(&self) -> SupportStatus {
        self.boot_id
    }

    /// Whether the round trip — capture, then re-check — recognised this
    /// process.
    #[must_use]
    pub fn self_recognition(&self) -> SupportStatus {
        self.self_recognition
    }
}

/// Whether the probes cleanup verification is built on answer here.
///
/// Both are signal-0 probes aimed at this process and its own group, so they
/// establish the *mechanism* without touching anything else: signal 0 performs
/// the existence and permission check and delivers nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CleanupFacts {
    /// `kill(pid, 0)`: the probe an unobserved death is verified with.
    pid_probe: SupportStatus,
    /// `killpg(pgid, 0)`: the probe a reaped run's *group* is verified with.
    /// This is the one that makes [`super::AbsenceBasis::ReapedAndGroupEmpty`]
    /// reachable.
    process_group_probe: SupportStatus,
}

impl CleanupFacts {
    /// Whether the pid probe answers here.
    #[must_use]
    pub fn pid_probe(&self) -> SupportStatus {
        self.pid_probe
    }

    /// Whether the process-group probe answers here.
    #[must_use]
    pub fn process_group_probe(&self) -> SupportStatus {
        self.process_group_probe
    }
}

/// A family of events, and how faithfully this library sees it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventObservationSupport {
    /// The family.
    family: EventFamily,
    /// How faithfully the library sees it — including "not at all".
    fidelity: EventFidelity,
    /// What the fidelity rests on, in one sentence a human can check.
    basis: String,
}

impl EventObservationSupport {
    /// The event family this entry is about.
    #[must_use]
    pub fn family(&self) -> EventFamily {
        self.family
    }

    /// How faithfully the library sees it.
    #[must_use]
    pub fn fidelity(&self) -> EventFidelity {
        self.fidelity
    }

    /// What the fidelity rests on.
    #[must_use]
    pub fn basis(&self) -> &str {
        &self.basis
    }
}

/// A family of facts a consumer might expect events about.
///
/// Deliberately includes families the library does *not* observe. A map that
/// listed only what is observed would leave a reader to infer the rest, and the
/// inference a reader makes is usually the optimistic one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventFamily {
    /// Movements of the lifecycle state machine.
    LifecycleTransition,
    /// The child reporting that its sandbox is applied and it is at the gate.
    SandboxApplication,
    /// Activation attempts and their outcomes.
    ActivationOutcome,
    /// `execve` having happened — as far as the status descriptor can say.
    ExecObservation,
    /// The child's death, as `waitpid` reported it.
    ChildExit,
    /// Stop requests and the deaths they produce.
    StopOutcome,
    /// Cleanup verification verdicts.
    CleanupVerdict,
    /// Durable session record writes.
    RecordPersistence,
    /// Kernel-level policy denials: a Landlock refusal, a seccomp trap, a
    /// Seatbelt violation.
    KernelDenial,
}

/// How faithfully the library sees an event family.
///
/// A superset of [`super::Observation`] by exactly one variant, and
/// deliberately a separate type: [`super::Observation`] labels an event that
/// *exists*, and there is no honest way to spell "this event does not exist"
/// on an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventFidelity {
    /// The library witnesses these itself, from a syscall result or a
    /// descriptor state, at the moment they happen.
    DirectlyObserved,
    /// The library rebuilds these after the fact. Ordering and timing are
    /// inferred.
    Reconstructed,
    /// The library does not see these at all. No event of this family is ever
    /// emitted — it is absent, not synthesized.
    NotObserved,
}

/// A known limit of this design that is stated rather than designed away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DarkSpot {
    /// A descendant that calls `setsid` (or `setpgid` on itself) leaves the
    /// run's process group and becomes invisible to both stop and verification.
    ProcessGroupEscapeViaSetsid,
    /// After the direct child is reaped, its pid — and so the process group id,
    /// which is that same number — can in principle be reissued, so a later
    /// group hit means "something is in that group", not "a survivor".
    ProcessGroupIdReuseAfterReap,
    /// A child killed between the gate release and `execve` produces the same
    /// EOF on the status descriptor as one that reached `execve`.
    ExecOrKilledPreExecAmbiguity,
    /// The activation deadline is measured with `Instant`, which does not
    /// advance while the machine is suspended.
    GateExpiryFrozenWhileSuspended,
}

/// One dark spot, with its consequence and where it is written down.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DarkSpotEntry {
    /// Which limit.
    spot: DarkSpot,
    /// What a consumer can and cannot conclude because of it.
    consequence: String,
    /// The module documentation that records it, so this list cannot become the
    /// only place it is said.
    documented_in: String,
}

impl DarkSpotEntry {
    /// Which limit this entry is about.
    #[must_use]
    pub fn spot(&self) -> DarkSpot {
        self.spot
    }

    /// What a consumer can and cannot conclude because of it.
    #[must_use]
    pub fn consequence(&self) -> &str {
        &self.consequence
    }

    /// Where it is documented in the source.
    #[must_use]
    pub fn documented_in(&self) -> &str {
        &self.documented_in
    }
}

/// Everything this build can enforce, observe, and refuse — as data.
///
/// Built by [`SupportReport::gather`], which never fails and never guesses. See
/// the module documentation for the shape of a capability entry, and
/// `docs/lifecycle/support-report-v1.md` for the field table and a golden
/// example.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportReport {
    /// The schema this report was written by. See
    /// [`SUPPORT_REPORT_SCHEMA_VERSION`].
    schema_version: u32,
    /// The machine, as compiled for and as running.
    host: Capability<HostFacts>,
    /// Landlock, with the per-right table (Linux).
    landlock: Capability<LandlockFacts>,
    /// seccomp filter installation (Linux).
    seccomp: Capability,
    /// seccomp user-notification, the mechanism proxy-mode mediation needs
    /// (Linux).
    seccomp_user_notification: Capability,
    /// Seatbelt (macOS).
    seatbelt: Capability,
    /// Network filtering, per mechanism.
    network_filtering: Capability<NetworkFilteringFacts>,
    /// The platform's pseudo-terminal primitive. **Not** a statement that the
    /// lifecycle will give a run a PTY — see [`Self::interactive_session`].
    pty: Capability,
    /// Whether the lifecycle will run an interactive (PTY) session.
    interactive_session: Capability,
    /// Whether a run can outlive its supervisor by design.
    detached_supervisor: Capability,
    /// Whether a caller can attach to a run it did not start.
    attach: Capability,
    /// Whether the facts that make a pid non-reusable are readable here.
    process_identity: Capability<IdentityFacts>,
    /// Whether the probes cleanup verification is built on answer here.
    cleanup_verification: Capability<CleanupFacts>,
    /// Which event families this library observes, and which it does not.
    event_observation: Vec<EventObservationSupport>,
    /// Known limits, stated.
    dark_spots: Vec<DarkSpotEntry>,
}

impl SupportReport {
    /// Probe this host and report what it can do.
    ///
    /// Infallible by construction. A probe that will not answer becomes
    /// [`SupportStatus::Unknown`] with the reason it would not answer; a
    /// capability nothing implements yet becomes [`SupportStatus::Unavailable`]
    /// with [`SupportReason::NotImplemented`]. Nothing here panics, and nothing
    /// here fills a gap with an assumption.
    ///
    /// # Cost
    ///
    /// Every probe is a syscall or two, except one: on Linux the seccomp probe
    /// is upstream's own [`probe_seccomp_block_network_support`][probe], which
    /// forks a short-lived child because installing a filter cannot be undone
    /// in the process that installs it. That is the price of an answer that is
    /// [`Determination::ProbedLive`] rather than assumed, and it is why this is
    /// a call a consumer makes deliberately rather than in a loop.
    ///
    /// [probe]: crate::sandbox
    #[must_use]
    pub fn gather() -> Self {
        // Probed once and then *reused* by the network table below: the seccomp
        // probe forks, and a report that forked twice to answer the same
        // question would be paying the price of honesty twice over.
        let landlock = gather_landlock();
        let seccomp = gather_seccomp();
        let seccomp_user_notification = gather_seccomp_user_notification();
        let network_filtering =
            gather_network_filtering(&landlock, &seccomp, &seccomp_user_notification);

        Self {
            schema_version: SUPPORT_REPORT_SCHEMA_VERSION,
            host: gather_host(),
            landlock,
            seccomp,
            seccomp_user_notification,
            seatbelt: gather_seatbelt(),
            network_filtering,
            pty: gather_pty(),
            interactive_session: Capability::plain(
                SupportStatus::Unavailable,
                Determination::Declared,
                SupportReason::NotImplemented {
                    slice: "interactive session (PTY): PreparedSandbox::prepare refuses \
                            SessionMode::Interactive rather than running headless"
                        .to_string(),
                },
            ),
            detached_supervisor: Capability::plain(
                SupportStatus::Available,
                // Not `ProbedLive`, and the distinction is the whole point:
                // establishing this by probe would mean launching a supervisor,
                // which forks twice, execs, binds a socket, and writes a
                // durable record. A support report has to be cheap enough to
                // call, so what it reports is the mechanism and its
                // precondition.
                Determination::PlatformApi,
                SupportReason::PlatformApiLinked {
                    api: "fork(2) + execve(2) of std::env::current_exe(), setsid(2), and a \
                          unix(7) control socket in the session store"
                        .to_string(),
                    why_not_probed: "PRECONDITION: the embedder must call \
                                     nono::lifecycle::supervisor_entry() as the first statement \
                                     of main(). The supervisor is this binary re-executed, and \
                                     it becomes a supervisor only because that call recognises \
                                     a private environment marker; a library cannot install the \
                                     hook on its embedder's behalf. Whether this binary has it \
                                     cannot be established without launching a supervisor, so \
                                     it is not probed. A detached prepare against a binary \
                                     without the hook fails closed at the readiness deadline \
                                     with PrepareError::SupervisorUnresponsive, which names the \
                                     function. See docs/adr/0002-detached-supervisor.md"
                        .to_string(),
                },
            ),
            attach: Capability::plain(
                SupportStatus::Partial,
                Determination::Declared,
                SupportReason::NotImplemented {
                    slice: "R09 slice C (terminal attach): control attach is implemented — \
                            SessionStore::attach_control and RecoveredSession::attach reach a \
                            detached run's socket and drive it, so exit facts survive a caller \
                            restart. What is not implemented is attaching to a run's terminal: \
                            a headless detached run's standard streams are /dev/null and there \
                            is no PTY to reattach to"
                        .to_string(),
                },
            ),
            process_identity: gather_process_identity(),
            cleanup_verification: gather_cleanup_verification(),
            event_observation: event_observation(),
            dark_spots: dark_spots(),
        }
    }

    /// The schema this report was written by.
    #[must_use]
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The machine, as compiled for and as running.
    #[must_use]
    pub fn host(&self) -> &Capability<HostFacts> {
        &self.host
    }

    /// Landlock and its per-right table.
    #[must_use]
    pub fn landlock(&self) -> &Capability<LandlockFacts> {
        &self.landlock
    }

    /// seccomp filter installation.
    #[must_use]
    pub fn seccomp(&self) -> &Capability {
        &self.seccomp
    }

    /// seccomp user-notification.
    #[must_use]
    pub fn seccomp_user_notification(&self) -> &Capability {
        &self.seccomp_user_notification
    }

    /// Seatbelt.
    #[must_use]
    pub fn seatbelt(&self) -> &Capability {
        &self.seatbelt
    }

    /// Network filtering, per mechanism.
    #[must_use]
    pub fn network_filtering(&self) -> &Capability<NetworkFilteringFacts> {
        &self.network_filtering
    }

    /// The platform's pseudo-terminal primitive.
    #[must_use]
    pub fn pty(&self) -> &Capability {
        &self.pty
    }

    /// Whether the lifecycle will run an interactive session.
    #[must_use]
    pub fn interactive_session(&self) -> &Capability {
        &self.interactive_session
    }

    /// Whether a run can outlive its supervisor by design.
    #[must_use]
    pub fn detached_supervisor(&self) -> &Capability {
        &self.detached_supervisor
    }

    /// Whether a caller can attach to a run it did not start.
    #[must_use]
    pub fn attach(&self) -> &Capability {
        &self.attach
    }

    /// Whether the facts that make a pid non-reusable are readable here.
    #[must_use]
    pub fn process_identity(&self) -> &Capability<IdentityFacts> {
        &self.process_identity
    }

    /// Whether the probes cleanup verification is built on answer here.
    #[must_use]
    pub fn cleanup_verification(&self) -> &Capability<CleanupFacts> {
        &self.cleanup_verification
    }

    /// Which event families this library observes, and which it does not.
    #[must_use]
    pub fn event_observation(&self) -> &[EventObservationSupport] {
        &self.event_observation
    }

    /// Known limits, stated.
    #[must_use]
    pub fn dark_spots(&self) -> &[DarkSpotEntry] {
        &self.dark_spots
    }
}

/// The machine, as compiled for and as `uname(2)` reports it.
fn gather_host() -> Capability<HostFacts> {
    let compiled_os = std::env::consts::OS.to_string();
    let compiled_arch = std::env::consts::ARCH.to_string();
    match uname_facts() {
        Some(kernel) => Capability::detailed(
            SupportStatus::Available,
            Determination::ProbedLive,
            SupportReason::Probed {
                probe: "uname(2)".to_string(),
            },
            HostFacts {
                compiled_os,
                compiled_arch,
                kernel: Some(kernel),
            },
        ),
        // The compile-time half is still a fact, so this is `Partial` rather
        // than a refusal: what is missing is the running kernel's own account
        // of itself.
        None => Capability::detailed(
            SupportStatus::Partial,
            Determination::Declared,
            SupportReason::ProbeRefused {
                probe: "uname(2)".to_string(),
                detail: "the kernel did not fill a usable utsname".to_string(),
            },
            HostFacts {
                compiled_os,
                compiled_arch,
                kernel: None,
            },
        ),
    }
}

/// Read `uname(2)`, or `None` if it would not answer.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn uname_facts() -> Option<KernelFacts> {
    // SAFETY: an all-zero `utsname` is a valid value — every field is an array
    // of `c_char` — so nothing uninitialised is ever read, and `uname` writes
    // NUL-terminated strings into a buffer whose size it knows from the type.
    let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is derived from the live local above and is the only
    // argument; `uname` writes at most `sizeof(utsname)` bytes through it.
    let rc = unsafe { libc::uname(&raw mut buf) };
    if rc != 0 {
        return None;
    }
    Some(KernelFacts {
        sysname: utsname_field(&buf.sysname)?,
        release: utsname_field(&buf.release)?,
        version: utsname_field(&buf.version)?,
        machine: utsname_field(&buf.machine)?,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn uname_facts() -> Option<KernelFacts> {
    None
}

/// One `utsname` field as a `String`, stopping at the first NUL.
///
/// Bounded by the array rather than by the NUL: a field the kernel did not
/// terminate is truncated at the end of its own storage instead of running off
/// it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn utsname_field(field: &[libc::c_char]) -> Option<String> {
    let bytes: Vec<u8> = field
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        // `c_char` is signed on x86-64 and unsigned on aarch64 Linux; the byte
        // pattern is what matters, and this is lossless either way.
        .map(|byte| u8::from_ne_bytes(byte.to_ne_bytes()))
        .collect();
    if bytes.is_empty() {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Landlock's ABI and per-right table, from upstream's own probe.
#[cfg(target_os = "linux")]
fn gather_landlock() -> Capability<LandlockFacts> {
    const PROBE: &str = "landlock ruleset creation probe, V6 down to V1 with \
                         CompatLevel::HardRequirement (Sandbox::detect_abi)";

    match crate::sandbox::detect_abi() {
        Ok(abi) => {
            let rights = vec![
                // V1 is the floor: a detected ABI at all means path-based
                // filesystem control is there.
                right(LandlockRight::FilesystemBase, true),
                right(LandlockRight::Refer, abi.has_refer()),
                right(LandlockRight::Truncate, abi.has_truncate()),
                right(LandlockRight::Execute, abi.has_execute()),
                right(LandlockRight::TcpNetwork, abi.has_network()),
                right(LandlockRight::IoctlDev, abi.has_ioctl_dev()),
                right(LandlockRight::Scoping, abi.has_scoping()),
            ];
            // `Available` only when every right the lifecycle can ask for is
            // there; anything less is `Partial`, because the difference is
            // exactly what a consumer has to plan around.
            let status = if rights
                .iter()
                .all(|entry| entry.status == SupportStatus::Available)
            {
                SupportStatus::Available
            } else {
                SupportStatus::Partial
            };
            Capability::detailed(
                status,
                Determination::ProbedLive,
                SupportReason::Probed {
                    probe: PROBE.to_string(),
                },
                LandlockFacts {
                    abi: Some(abi.version_string().to_string()),
                    rights,
                },
            )
        }
        Err(err) => Capability::detailed(
            SupportStatus::Unavailable,
            Determination::ProbedLive,
            SupportReason::ProbeRefused {
                probe: PROBE.to_string(),
                detail: err.to_string(),
            },
            LandlockFacts {
                abi: None,
                rights: Vec::new(),
            },
        ),
    }
}

#[cfg(not(target_os = "linux"))]
fn gather_landlock() -> Capability<LandlockFacts> {
    Capability::plain(
        SupportStatus::Unavailable,
        Determination::Declared,
        SupportReason::OtherPlatform {
            mechanism: "Landlock LSM".to_string(),
            this_target_os: std::env::consts::OS.to_string(),
        },
    )
}

/// One per-right table entry.
#[cfg(target_os = "linux")]
fn right(right: LandlockRight, available: bool) -> LandlockRightSupport {
    LandlockRightSupport {
        right,
        status: if available {
            SupportStatus::Available
        } else {
            SupportStatus::Unavailable
        },
    }
}

/// Whether a seccomp filter can be installed here, from upstream's own
/// fork-isolated probe.
#[cfg(target_os = "linux")]
fn gather_seccomp() -> Capability {
    const PROBE: &str = "seccomp(SECCOMP_SET_MODE_FILTER) in a forked child \
                         (probe_seccomp_block_network_support)";

    match crate::sandbox::probe_seccomp_block_network_support() {
        Ok(true) => Capability::plain(
            SupportStatus::Available,
            Determination::ProbedLive,
            SupportReason::Probed {
                probe: PROBE.to_string(),
            },
        ),
        Ok(false) => Capability::plain(
            SupportStatus::Unavailable,
            Determination::ProbedLive,
            SupportReason::Probed {
                probe: PROBE.to_string(),
            },
        ),
        // The probe itself could not be run, so nothing was established —
        // `Unknown`, not "no".
        Err(err) => Capability::plain(
            SupportStatus::Unknown,
            Determination::Declared,
            SupportReason::ProbeRefused {
                probe: PROBE.to_string(),
                detail: err.to_string(),
            },
        ),
    }
}

#[cfg(not(target_os = "linux"))]
fn gather_seccomp() -> Capability {
    Capability::plain(
        SupportStatus::Unavailable,
        Determination::Declared,
        SupportReason::OtherPlatform {
            mechanism: "seccomp-bpf".to_string(),
            this_target_os: std::env::consts::OS.to_string(),
        },
    )
}

/// Whether seccomp user-notification is available.
///
/// Honestly unknown on Linux. The only mechanism this crate has for finding out
/// is installing a filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, and a
/// filter cannot be removed from the process that installs it. Upstream's
/// fork-isolated probe covers the static block-all filter only, so it does not
/// answer this question, and inventing a second probe is a mechanism this slice
/// deliberately does not add. A kernel release number is not proof either:
/// `CONFIG_SECCOMP_FILTER` can be off on a kernel new enough to have the flag.
#[cfg(target_os = "linux")]
fn gather_seccomp_user_notification() -> Capability {
    Capability::plain(
        SupportStatus::Unknown,
        Determination::Declared,
        SupportReason::NotObservableWithoutIrreversibleChange {
            what: "establishing SECCOMP_FILTER_FLAG_NEW_LISTENER means installing a seccomp \
                   filter, which cannot be removed from the process that installs it; the \
                   answer becomes a fact when a ProxyOnly fallback is actually prepared"
                .to_string(),
        },
    )
}

#[cfg(not(target_os = "linux"))]
fn gather_seccomp_user_notification() -> Capability {
    Capability::plain(
        SupportStatus::Unavailable,
        Determination::Declared,
        SupportReason::OtherPlatform {
            mechanism: "seccomp user notification (SECCOMP_RET_USER_NOTIF)".to_string(),
            this_target_os: std::env::consts::OS.to_string(),
        },
    )
}

/// Whether Seatbelt is available.
///
/// [`Determination::PlatformApi`], not [`Determination::ProbedLive`], and the
/// difference is deliberate. `sandbox_init` is a platform API this build links
/// against, so its *presence* is settled at compile time — but calling it is
/// irreversible and **process-wide**: a "trivial" probe profile would sandbox
/// the caller's own process for the rest of its life. The only honest live
/// probe is the one `nono setup --check-only` performs, which forks first, and
/// forking the caller's process to answer a diagnostic question is a cost this
/// library does not impose without being asked.
#[cfg(target_os = "macos")]
fn gather_seatbelt() -> Capability {
    Capability::plain(
        SupportStatus::Available,
        Determination::PlatformApi,
        SupportReason::PlatformApiLinked {
            api: "sandbox_init(3) (libSystem)".to_string(),
            why_not_probed: "sandbox_init applies to the calling process and cannot be undone, \
                             so any live probe must fork first; this report does not fork the \
                             caller to answer a question the linker already settled"
                .to_string(),
        },
    )
}

#[cfg(not(target_os = "macos"))]
fn gather_seatbelt() -> Capability {
    Capability::plain(
        SupportStatus::Unavailable,
        Determination::Declared,
        SupportReason::OtherPlatform {
            mechanism: "Seatbelt (sandbox_init)".to_string(),
            this_target_os: std::env::consts::OS.to_string(),
        },
    )
}

/// Which network-filtering mechanisms are reachable here.
///
/// Takes the already-probed capabilities rather than re-probing: every entry in
/// the table is one of them seen from the network's point of view, and a second
/// probe could disagree with the first.
#[cfg(target_os = "linux")]
fn gather_network_filtering(
    landlock: &Capability<LandlockFacts>,
    seccomp: &Capability,
    user_notification: &Capability,
) -> Capability<NetworkFilteringFacts> {
    let tcp_rules = landlock
        .facts()
        .and_then(|facts| {
            facts
                .rights
                .iter()
                .find(|entry| entry.right == LandlockRight::TcpNetwork)
        })
        .map_or(SupportStatus::Unknown, |entry| entry.status);

    let mechanisms = vec![
        NetworkMechanismSupport {
            mechanism: NetworkMechanism::LandlockTcpPortRules,
            status: tcp_rules,
            reason: landlock.reason.clone(),
        },
        NetworkMechanismSupport {
            mechanism: NetworkMechanism::SeccompBlockAll,
            status: seccomp.status,
            reason: seccomp.reason.clone(),
        },
        NetworkMechanismSupport {
            mechanism: NetworkMechanism::SeccompUserNotifyProxy,
            status: user_notification.status,
            reason: user_notification.reason.clone(),
        },
        seatbelt_all_or_nothing(),
        seatbelt_per_port_tcp(),
    ];
    Capability::detailed(
        summarize(&mechanisms),
        Determination::ProbedLive,
        SupportReason::Probed {
            probe: "per-mechanism: the Landlock ABI probe and the forked seccomp probe".to_string(),
        },
        NetworkFilteringFacts { mechanisms },
    )
}

#[cfg(target_os = "macos")]
fn gather_network_filtering(
    _landlock: &Capability<LandlockFacts>,
    _seccomp: &Capability,
    _user_notification: &Capability,
) -> Capability<NetworkFilteringFacts> {
    let mechanisms = vec![
        NetworkMechanismSupport {
            mechanism: NetworkMechanism::LandlockTcpPortRules,
            status: SupportStatus::Unavailable,
            reason: SupportReason::OtherPlatform {
                mechanism: "Landlock TCP port rules".to_string(),
                this_target_os: std::env::consts::OS.to_string(),
            },
        },
        NetworkMechanismSupport {
            mechanism: NetworkMechanism::SeccompBlockAll,
            status: SupportStatus::Unavailable,
            reason: SupportReason::OtherPlatform {
                mechanism: "seccomp-bpf".to_string(),
                this_target_os: std::env::consts::OS.to_string(),
            },
        },
        NetworkMechanismSupport {
            mechanism: NetworkMechanism::SeccompUserNotifyProxy,
            status: SupportStatus::Unavailable,
            reason: SupportReason::OtherPlatform {
                mechanism: "seccomp user notification (SECCOMP_RET_USER_NOTIF)".to_string(),
                this_target_os: std::env::consts::OS.to_string(),
            },
        },
        seatbelt_all_or_nothing(),
        seatbelt_per_port_tcp(),
    ];
    Capability::detailed(
        summarize(&mechanisms),
        Determination::PlatformApi,
        SupportReason::PlatformApiLinked {
            api: "sandbox_init(3) SBPL network rules".to_string(),
            why_not_probed: "the SBPL a policy compiles to is a compile-time property of this \
                             build; what it cannot express is stated per mechanism below"
                .to_string(),
        },
        NetworkFilteringFacts { mechanisms },
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn gather_network_filtering(
    _landlock: &Capability<LandlockFacts>,
    _seccomp: &Capability,
    _user_notification: &Capability,
) -> Capability<NetworkFilteringFacts> {
    Capability::plain(
        SupportStatus::Unavailable,
        Determination::Declared,
        SupportReason::OtherPlatform {
            mechanism: "network filtering".to_string(),
            this_target_os: std::env::consts::OS.to_string(),
        },
    )
}

/// Seatbelt's all-or-nothing network rule, from either platform's point of
/// view.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn seatbelt_all_or_nothing() -> NetworkMechanismSupport {
    let seatbelt = gather_seatbelt();
    NetworkMechanismSupport {
        mechanism: NetworkMechanism::SeatbeltNetworkAllOrNothing,
        status: seatbelt.status,
        reason: seatbelt.reason,
    }
}

/// Per-port TCP filtering on macOS: named so its absence is stated rather than
/// inferred from a table that does not mention it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn seatbelt_per_port_tcp() -> NetworkMechanismSupport {
    NetworkMechanismSupport {
        mechanism: NetworkMechanism::SeatbeltPerPortTcp,
        status: SupportStatus::Unavailable,
        reason: SupportReason::PlatformCannotExpress {
            mechanism: "Seatbelt SBPL has no TCP port predicate".to_string(),
            refusal: "NonoError::NetworkFilterUnsupported — a port-scoped policy is refused \
                      rather than widened to (allow network*)"
                .to_string(),
        },
    }
}

/// Roll a mechanism table up into one status without losing the shape of it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn summarize(mechanisms: &[NetworkMechanismSupport]) -> SupportStatus {
    if mechanisms
        .iter()
        .any(|entry| entry.status == SupportStatus::Available)
    {
        // Some mechanism works and some does not — which is the permanent
        // state of both platforms, so `Available` would be a claim no host can
        // support.
        SupportStatus::Partial
    } else {
        SupportStatus::Unavailable
    }
}

/// Open a pseudo-terminal and close it again.
///
/// A real probe: `posix_openpt` allocates a controlling-terminal master, which
/// is the primitive an interactive session would be built on. It is closed
/// immediately, so nothing is left behind and no terminal is ever attached to
/// this process.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn gather_pty() -> Capability {
    const PROBE: &str = "posix_openpt(O_RDWR | O_NOCTTY), closed immediately";

    // SAFETY: `posix_openpt` takes flags and returns a descriptor or -1. No
    // memory is passed. `O_NOCTTY` keeps the master from becoming this
    // process's controlling terminal.
    let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if fd < 0 {
        let detail = std::io::Error::last_os_error().to_string();
        return Capability::plain(
            SupportStatus::Unavailable,
            Determination::ProbedLive,
            SupportReason::ProbeRefused {
                probe: PROBE.to_string(),
                detail,
            },
        );
    }
    // SAFETY: `fd` is the descriptor `posix_openpt` just returned and nothing
    // else holds it.
    unsafe {
        libc::close(fd);
    }
    Capability::plain(
        SupportStatus::Available,
        Determination::ProbedLive,
        SupportReason::Probed {
            probe: PROBE.to_string(),
        },
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn gather_pty() -> Capability {
    Capability::plain(
        SupportStatus::Unavailable,
        Determination::Declared,
        SupportReason::OtherPlatform {
            mechanism: "posix_openpt".to_string(),
            this_target_os: std::env::consts::OS.to_string(),
        },
    )
}

/// Capture this process's own identity and re-check it, right now.
///
/// The strongest identity probe available: we know the answer — this process is
/// itself — so a `false` here is a statement about the *platform*, not about
/// the process.
fn gather_process_identity() -> Capability<IdentityFacts> {
    let Some(pid) = own_pid() else {
        return Capability::plain(
            SupportStatus::Unknown,
            Determination::Declared,
            SupportReason::ProbeRefused {
                probe: "self identity capture".to_string(),
                detail: "this process's own pid does not fit an i32".to_string(),
            },
        );
    };
    let identity = ProcessIdentity::capture(pid);
    let facts = IdentityFacts {
        start_time: presence(identity.start_time().is_some()),
        boot_id: presence(identity.boot_id().is_some()),
        self_recognition: presence(identity.is_same_process()),
    };
    let status = if facts.self_recognition == SupportStatus::Available {
        SupportStatus::Available
    } else if facts.start_time == SupportStatus::Available
        || facts.boot_id == SupportStatus::Available
    {
        // Half the evidence is readable, which is not enough: every
        // `is_same_process` check fails closed, and cleanup verification of an
        // unobserved death degrades to `Indeterminate`.
        SupportStatus::Partial
    } else {
        SupportStatus::Unavailable
    };
    Capability::detailed(
        status,
        Determination::ProbedLive,
        SupportReason::Probed {
            probe: "ProcessIdentity::capture(self) then is_same_process()".to_string(),
        },
        facts,
    )
}

/// Probe this process and its own group with signal 0.
///
/// Signal 0 performs the existence and permission check and delivers nothing,
/// so this establishes the mechanism without touching any process — including
/// this one.
fn gather_cleanup_verification() -> Capability<CleanupFacts> {
    let (Some(pid), Some(pgid)) = (own_pid(), own_process_group()) else {
        return Capability::plain(
            SupportStatus::Unknown,
            Determination::Declared,
            SupportReason::ProbeRefused {
                probe: "kill(self, 0) / killpg(own group, 0)".to_string(),
                detail: "this process's own pid or process group does not fit an i32".to_string(),
            },
        );
    };
    let facts = CleanupFacts {
        pid_probe: probe_status(probe_pid(pid)),
        process_group_probe: probe_status(probe_group(pgid)),
    };
    let status = match (facts.pid_probe, facts.process_group_probe) {
        (SupportStatus::Available, SupportStatus::Available) => SupportStatus::Available,
        (SupportStatus::Unavailable, SupportStatus::Unavailable) => SupportStatus::Unavailable,
        _ => SupportStatus::Partial,
    };
    Capability::detailed(
        status,
        Determination::ProbedLive,
        SupportReason::Probed {
            probe: "kill(self, 0) and killpg(own group, 0) — signal 0 delivers nothing".to_string(),
        },
        facts,
    )
}

/// What a signal-0 probe of a target we know exists says about the mechanism.
fn probe_status(probe: Result<Probe, super::UnsupportedReason>) -> SupportStatus {
    match probe {
        // The target is this process (or its group), so `Present` means the
        // probe works. Anything else is the probe failing on a target that is
        // certainly there.
        Ok(Probe::Present) => SupportStatus::Available,
        Ok(Probe::Absent | Probe::Denied | Probe::Failed(_)) => SupportStatus::Unknown,
        Err(_) => SupportStatus::Unavailable,
    }
}

/// This process's pid, or `None` if it does not fit the kernel's own type.
fn own_pid() -> Option<i32> {
    i32::try_from(std::process::id())
        .ok()
        .filter(|pid| *pid > 0)
}

/// This process's process group, or `None` if it is not a probeable number.
///
/// The same `targets <= 1` rule the stop and verification paths use: 0 means
/// "the caller's own group" to `kill` and 1 is init's.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn own_process_group() -> Option<i32> {
    // SAFETY: `getpgrp` takes no arguments, touches no memory, and cannot fail.
    let pgid = unsafe { libc::getpgrp() };
    if pgid > 1 { Some(pgid) } else { None }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn own_process_group() -> Option<i32> {
    None
}

/// A present/absent fact as a status.
fn presence(present: bool) -> SupportStatus {
    if present {
        SupportStatus::Available
    } else {
        SupportStatus::Unavailable
    }
}

/// Which event families this library observes, and which it does not.
///
/// Identical on both platforms today, and written as one list rather than two
/// so that a future divergence has to be an edit rather than an omission.
fn event_observation() -> Vec<EventObservationSupport> {
    vec![
        observed(
            EventFamily::LifecycleTransition,
            "every transition goes through the shared lifecycle core, and the sink is told \
             after the state moved",
        ),
        observed(
            EventFamily::SandboxApplication,
            "the trusted child writes its at-the-gate record only after the sandbox applied; \
             the parent reads that record",
        ),
        observed(
            EventFamily::ActivationOutcome,
            "the gate's single-use claim decides the outcome in this process",
        ),
        observed(
            EventFamily::ExecObservation,
            "EOF on the close-on-exec status descriptor, which is why the observation is the \
             three-valued ActivationObservation and not a bool",
        ),
        observed(
            EventFamily::ChildExit,
            "waitpid on this process's own child",
        ),
        observed(
            EventFamily::StopOutcome,
            "the stop request is this process's own, and the death is the waitpid that follows \
             it",
        ),
        observed(
            EventFamily::CleanupVerdict,
            "a signal-0 probe made after the fact; a sent signal is never the evidence",
        ),
        observed(
            EventFamily::RecordPersistence,
            "the durable write returns before the event is emitted",
        ),
        EventObservationSupport {
            family: EventFamily::KernelDenial,
            fidelity: EventFidelity::NotObserved,
            basis: "this library emits no denial events on either platform. The lifecycle \
                    installs no seccomp user-notification listener, and macOS Seatbelt denials \
                    reach userspace only through the system log. nono-cli reconstructs those \
                    from `log stream`, but that is CLI machinery and is not claimed here."
                .to_string(),
        },
    ]
}

/// One directly observed family.
fn observed(family: EventFamily, basis: &str) -> EventObservationSupport {
    EventObservationSupport {
        family,
        fidelity: EventFidelity::DirectlyObserved,
        basis: basis.to_string(),
    }
}

/// The limits this design has and does not hide.
///
/// Each one is already recorded in the module that owns it; this list is the
/// machine-readable index of them, not a second source of truth.
fn dark_spots() -> Vec<DarkSpotEntry> {
    vec![
        DarkSpotEntry {
            spot: DarkSpot::ProcessGroupEscapeViaSetsid,
            consequence: "a descendant that leaves the run's process group is signalled by \
                          neither stop nor drop, and is invisible to cleanup verification: it \
                          shows up as neither killed nor confirmed absent. Closing it needs a \
                          cgroup-class mechanism this slice does not build."
                .to_string(),
            documented_in: "crates/nono/src/lifecycle/prepare.rs (module docs, \"The run is a \
                            process group, not a process\")"
                .to_string(),
        },
        DarkSpotEntry {
            spot: DarkSpot::ProcessGroupIdReuseAfterReap,
            consequence: "once the direct child is reaped its pid — and so its process group id \
                          — can be reissued, so a later group hit is reported as StillPresent \
                          (\"something is in that group\") rather than as proof of a survivor. \
                          The boot id is re-checked, which stops a number reused across a \
                          reboot from answering."
                .to_string(),
            documented_in: "crates/nono/src/lifecycle/cleanup.rs (module docs, \"The caveat \
                            that is not designed away\")"
                .to_string(),
        },
        DarkSpotEntry {
            spot: DarkSpot::ExecOrKilledPreExecAmbiguity,
            consequence: "a child killed between the gate release and execve closes the status \
                          descriptor exactly as a successful execve does, so activation is the \
                          three-valued ActivationObservation; wait() resolves it only when the \
                          exit status is one that only a real execve could produce."
                .to_string(),
            documented_in: "crates/nono/src/lifecycle/prepare.rs (module docs, \"Descriptors\")"
                .to_string(),
        },
        DarkSpotEntry {
            spot: DarkSpot::GateExpiryFrozenWhileSuspended,
            consequence: "the activation deadline is measured with Instant, which does not \
                          advance while the machine is suspended, and is evaluated lazily at \
                          the next activate/stop/drop: a gate given five minutes still has time \
                          left after an hour of sleep, and an expired gate is discovered rather \
                          than fired."
                .to_string(),
            documented_in: "crates/nono/src/lifecycle/plan.rs (GateConfig, \"How the deadline \
                            is measured\")"
                .to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden example locked by the schema doc, and the one place a
    /// constructed report exists.
    const GOLDEN_DOC: &str = include_str!("../../../../docs/lifecycle/support-report-v1.md");
    const GOLDEN_PATH: &str = "docs/lifecycle/support-report-v1.md";

    /// A report with every field at a fixed value, so the doc can show one.
    ///
    /// Deliberately a macOS report: it is the platform this stream verifies
    /// live, so the example is the shape `gather()` really produces here rather
    /// than a Linux capture nobody on this stream has taken.
    fn golden_report() -> SupportReport {
        SupportReport {
            schema_version: SUPPORT_REPORT_SCHEMA_VERSION,
            host: Capability::detailed(
                SupportStatus::Available,
                Determination::ProbedLive,
                SupportReason::Probed {
                    probe: "uname(2)".to_string(),
                },
                HostFacts {
                    compiled_os: "macos".to_string(),
                    compiled_arch: "aarch64".to_string(),
                    kernel: Some(KernelFacts {
                        sysname: "Darwin".to_string(),
                        release: "23.6.0".to_string(),
                        version: "Darwin Kernel Version 23.6.0".to_string(),
                        machine: "arm64".to_string(),
                    }),
                },
            ),
            landlock: gather_landlock_for_other_platform(),
            seccomp: Capability::plain(
                SupportStatus::Unavailable,
                Determination::Declared,
                SupportReason::OtherPlatform {
                    mechanism: "seccomp-bpf".to_string(),
                    this_target_os: "macos".to_string(),
                },
            ),
            seccomp_user_notification: Capability::plain(
                SupportStatus::Unavailable,
                Determination::Declared,
                SupportReason::OtherPlatform {
                    mechanism: "seccomp user notification (SECCOMP_RET_USER_NOTIF)".to_string(),
                    this_target_os: "macos".to_string(),
                },
            ),
            seatbelt: Capability::plain(
                SupportStatus::Available,
                Determination::PlatformApi,
                SupportReason::PlatformApiLinked {
                    api: "sandbox_init(3) (libSystem)".to_string(),
                    why_not_probed: "sandbox_init applies to the calling process and cannot be \
                                     undone, so any live probe must fork first; this report does \
                                     not fork the caller to answer a question the linker already \
                                     settled"
                        .to_string(),
                },
            ),
            network_filtering: Capability::detailed(
                SupportStatus::Partial,
                Determination::PlatformApi,
                SupportReason::PlatformApiLinked {
                    api: "sandbox_init(3) SBPL network rules".to_string(),
                    why_not_probed: "the SBPL a policy compiles to is a compile-time property \
                                     of this build; what it cannot express is stated per \
                                     mechanism below"
                        .to_string(),
                },
                NetworkFilteringFacts {
                    mechanisms: vec![
                        NetworkMechanismSupport {
                            mechanism: NetworkMechanism::SeatbeltNetworkAllOrNothing,
                            status: SupportStatus::Available,
                            reason: SupportReason::PlatformApiLinked {
                                api: "sandbox_init(3) (libSystem)".to_string(),
                                why_not_probed: "sandbox_init applies to the calling process and \
                                                 cannot be undone, so any live probe must fork \
                                                 first; this report does not fork the caller to \
                                                 answer a question the linker already settled"
                                    .to_string(),
                            },
                        },
                        NetworkMechanismSupport {
                            mechanism: NetworkMechanism::SeatbeltPerPortTcp,
                            status: SupportStatus::Unavailable,
                            reason: SupportReason::PlatformCannotExpress {
                                mechanism: "Seatbelt SBPL has no TCP port predicate".to_string(),
                                refusal: "NonoError::NetworkFilterUnsupported — a port-scoped \
                                          policy is refused rather than widened to (allow \
                                          network*)"
                                    .to_string(),
                            },
                        },
                    ],
                },
            ),
            pty: Capability::plain(
                SupportStatus::Available,
                Determination::ProbedLive,
                SupportReason::Probed {
                    probe: "posix_openpt(O_RDWR | O_NOCTTY), closed immediately".to_string(),
                },
            ),
            interactive_session: Capability::plain(
                SupportStatus::Unavailable,
                Determination::Declared,
                SupportReason::NotImplemented {
                    slice: "interactive session (PTY): PreparedSandbox::prepare refuses \
                            SessionMode::Interactive rather than running headless"
                        .to_string(),
                },
            ),
            detached_supervisor: Capability::plain(
                SupportStatus::Available,
                // Not `ProbedLive`, and the distinction is the whole point:
                // establishing this by probe would mean launching a supervisor,
                // which forks twice, execs, binds a socket, and writes a
                // durable record. A support report has to be cheap enough to
                // call, so what it reports is the mechanism and its
                // precondition.
                Determination::PlatformApi,
                SupportReason::PlatformApiLinked {
                    api: "fork(2) + execve(2) of std::env::current_exe(), setsid(2), and a \
                          unix(7) control socket in the session store"
                        .to_string(),
                    why_not_probed: "PRECONDITION: the embedder must call \
                                     nono::lifecycle::supervisor_entry() as the first statement \
                                     of main(). The supervisor is this binary re-executed, and \
                                     it becomes a supervisor only because that call recognises \
                                     a private environment marker; a library cannot install the \
                                     hook on its embedder's behalf. Whether this binary has it \
                                     cannot be established without launching a supervisor, so \
                                     it is not probed. A detached prepare against a binary \
                                     without the hook fails closed at the readiness deadline \
                                     with PrepareError::SupervisorUnresponsive, which names the \
                                     function. See docs/adr/0002-detached-supervisor.md"
                        .to_string(),
                },
            ),
            attach: Capability::plain(
                SupportStatus::Partial,
                Determination::Declared,
                SupportReason::NotImplemented {
                    slice: "R09 slice C (terminal attach): control attach is implemented — \
                            SessionStore::attach_control and RecoveredSession::attach reach a \
                            detached run's socket and drive it, so exit facts survive a caller \
                            restart. What is not implemented is attaching to a run's terminal: \
                            a headless detached run's standard streams are /dev/null and there \
                            is no PTY to reattach to"
                        .to_string(),
                },
            ),
            process_identity: Capability::detailed(
                SupportStatus::Available,
                Determination::ProbedLive,
                SupportReason::Probed {
                    probe: "ProcessIdentity::capture(self) then is_same_process()".to_string(),
                },
                IdentityFacts {
                    start_time: SupportStatus::Available,
                    boot_id: SupportStatus::Available,
                    self_recognition: SupportStatus::Available,
                },
            ),
            cleanup_verification: Capability::detailed(
                SupportStatus::Available,
                Determination::ProbedLive,
                SupportReason::Probed {
                    probe: "kill(self, 0) and killpg(own group, 0) — signal 0 delivers nothing"
                        .to_string(),
                },
                CleanupFacts {
                    pid_probe: SupportStatus::Available,
                    process_group_probe: SupportStatus::Available,
                },
            ),
            event_observation: event_observation(),
            dark_spots: dark_spots(),
        }
    }

    /// The Landlock entry a non-Linux host reports, spelled out rather than
    /// taken from `gather_landlock()` so the golden example is the same on
    /// every host the test runs on.
    fn gather_landlock_for_other_platform() -> Capability<LandlockFacts> {
        Capability::plain(
            SupportStatus::Unavailable,
            Determination::Declared,
            SupportReason::OtherPlatform {
                mechanism: "Landlock LSM".to_string(),
                this_target_os: "macos".to_string(),
            },
        )
    }

    /// Every `Value::Bool` in a serialized tree, by JSON pointer.
    fn booleans(value: &serde_json::Value, path: &str, found: &mut Vec<String>) {
        match value {
            serde_json::Value::Bool(_) => found.push(path.to_string()),
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    booleans(child, &format!("{path}/{key}"), found);
                }
            }
            serde_json::Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    booleans(child, &format!("{path}/{index}"), found);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn no_field_of_a_gathered_report_is_a_bare_boolean() -> Result<(), serde_json::Error> {
        // The structural lock on the contract this type exists for. A boolean
        // anywhere in the tree is a capability that lost its determination and
        // its reason on the way to the wire — which is exactly what
        // `SupportInfo { is_supported: bool }` does.
        let value = serde_json::to_value(SupportReport::gather())?;
        let mut found = Vec::new();
        booleans(&value, "", &mut found);
        assert!(
            found.is_empty(),
            "a support report must carry no bare booleans; found at: {found:?}"
        );
        Ok(())
    }

    #[test]
    fn no_field_of_the_golden_report_is_a_bare_boolean() -> Result<(), serde_json::Error> {
        // The same lock over the shapes this host cannot produce: the golden
        // report carries the not-implemented and other-platform arms that
        // `gather()` on macOS never builds.
        let value = serde_json::to_value(golden_report())?;
        let mut found = Vec::new();
        booleans(&value, "", &mut found);
        assert!(found.is_empty(), "found bare booleans at: {found:?}");
        Ok(())
    }

    #[test]
    fn a_gathered_report_round_trips_through_serde() -> Result<(), serde_json::Error> {
        let report = SupportReport::gather();
        let json = serde_json::to_string(&report)?;
        assert_eq!(serde_json::from_str::<SupportReport>(&json)?, report);
        Ok(())
    }

    #[test]
    fn the_golden_example_in_the_schema_doc_still_matches() -> Result<(), serde_json::Error> {
        let serialized = serde_json::to_string_pretty(&golden_report())?;
        assert_eq!(
            serialized,
            super::super::doc_golden_example(GOLDEN_DOC, GOLDEN_PATH),
            "the golden example in {GOLDEN_PATH} no longer matches a serialized SupportReport; \
             the doc and the type must be updated together"
        );
        let parsed: SupportReport = serde_json::from_str(&serialized)?;
        assert_eq!(parsed, golden_report());
        Ok(())
    }

    #[test]
    fn gather_never_leaves_a_capability_without_a_reason() -> Result<(), serde_json::Error> {
        // Every capability object carries all three of status, determination,
        // and reason — the shape a consumer matches on. Checked over the
        // serialized tree so a future field cannot quietly skip one.
        let value = serde_json::to_value(SupportReport::gather())?;
        let Some(map) = value.as_object() else {
            panic!("a report serializes to an object");
        };
        for (name, field) in map {
            let Some(object) = field.as_object() else {
                continue;
            };
            if !object.contains_key("status") {
                continue;
            }
            for key in ["status", "determination", "reason"] {
                assert!(
                    object.contains_key(key),
                    "capability {name} has no {key}: {field}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn this_host_probes_its_pty_and_its_identity_live() {
        let report = SupportReport::gather();

        assert_eq!(report.pty().status(), SupportStatus::Available);
        assert_eq!(report.pty().determination(), Determination::ProbedLive);

        assert_eq!(report.process_identity().status(), SupportStatus::Available);
        assert_eq!(
            report.process_identity().determination(),
            Determination::ProbedLive
        );
        let Some(identity) = report.process_identity().facts() else {
            panic!("a probed identity carries its facts");
        };
        assert_eq!(identity.start_time(), SupportStatus::Available);
        assert_eq!(identity.boot_id(), SupportStatus::Available);
        assert_eq!(identity.self_recognition(), SupportStatus::Available);
    }

    #[test]
    fn this_host_probes_both_cleanup_mechanisms_live() {
        let report = SupportReport::gather();
        assert_eq!(
            report.cleanup_verification().status(),
            SupportStatus::Available
        );
        assert_eq!(
            report.cleanup_verification().determination(),
            Determination::ProbedLive
        );
        let Some(facts) = report.cleanup_verification().facts() else {
            panic!("a probed cleanup capability carries its facts");
        };
        assert_eq!(facts.pid_probe(), SupportStatus::Available);
        assert_eq!(facts.process_group_probe(), SupportStatus::Available);
    }

    #[test]
    fn detached_supervision_reports_its_mechanism_and_its_precondition() {
        // The one capability whose honest answer needs *two* facts: it is built
        // and it is conditional. A probe would have to launch a supervisor —
        // two forks, an exec, a bound socket, a durable record — so what is
        // reported is the mechanism, at `PlatformApi`, with the precondition
        // spelled out where a reader looking at machine-readable output will
        // find it.
        let report = SupportReport::gather();
        let detached = report.detached_supervisor();
        assert_eq!(detached.status(), SupportStatus::Available);
        assert_eq!(detached.determination(), Determination::PlatformApi);
        let SupportReason::PlatformApiLinked {
            api,
            why_not_probed,
        } = detached.reason()
        else {
            panic!(
                "detached supervision rests on a linked platform API: {:?}",
                detached.reason()
            );
        };
        assert!(api.contains("execve"), "{api}");
        assert!(
            why_not_probed.contains("supervisor_entry()"),
            "the precondition must name the hook an embedder has to install: {why_not_probed}"
        );
        assert!(
            why_not_probed.contains("SupervisorUnresponsive"),
            "and the typed failure a missing hook produces: {why_not_probed}"
        );
    }

    #[test]
    fn terminal_attach_is_still_honestly_incomplete() {
        // Control attach landed; terminal attach did not. Reporting the pair as
        // one `available` would tell a consumer it can reattach to a run's
        // output, which it cannot: a headless detached run's streams are
        // /dev/null.
        let report = SupportReport::gather();
        let attach = report.attach();
        assert_eq!(attach.status(), SupportStatus::Partial);
        assert_eq!(attach.determination(), Determination::Declared);
        let SupportReason::NotImplemented { slice } = attach.reason() else {
            panic!(
                "a partial capability must name the work that would finish it: {:?}",
                attach.reason()
            );
        };
        assert!(slice.contains("attach_control"), "{slice}");
        assert!(slice.contains("PTY"), "{slice}");
    }

    #[test]
    fn kernel_denials_are_reported_as_unobserved_by_this_library() {
        let report = SupportReport::gather();
        let Some(denials) = report
            .event_observation()
            .iter()
            .find(|entry| entry.family() == EventFamily::KernelDenial)
        else {
            panic!("the event map must mention kernel denials, even to disclaim them");
        };
        assert_eq!(denials.fidelity(), EventFidelity::NotObserved);
        assert!(
            !denials.basis().is_empty(),
            "a disclaimed family must say what it rests on"
        );
    }

    #[test]
    fn every_lifecycle_event_family_is_accounted_for() {
        // A family that exists in the vocabulary but not in the map would be a
        // silent claim of nothing.
        let report = SupportReport::gather();
        let families: Vec<EventFamily> = report
            .event_observation()
            .iter()
            .map(EventObservationSupport::family)
            .collect();
        for family in [
            EventFamily::LifecycleTransition,
            EventFamily::SandboxApplication,
            EventFamily::ActivationOutcome,
            EventFamily::ExecObservation,
            EventFamily::ChildExit,
            EventFamily::StopOutcome,
            EventFamily::CleanupVerdict,
            EventFamily::RecordPersistence,
            EventFamily::KernelDenial,
        ] {
            assert!(families.contains(&family), "{family:?} is not in the map");
        }
    }

    #[test]
    fn every_documented_dark_spot_is_listed() {
        let report = SupportReport::gather();
        let spots: Vec<DarkSpot> = report
            .dark_spots()
            .iter()
            .map(DarkSpotEntry::spot)
            .collect();
        for spot in [
            DarkSpot::ProcessGroupEscapeViaSetsid,
            DarkSpot::ProcessGroupIdReuseAfterReap,
            DarkSpot::ExecOrKilledPreExecAmbiguity,
            DarkSpot::GateExpiryFrozenWhileSuspended,
        ] {
            assert!(spots.contains(&spot), "{spot:?} is not listed");
        }
        for entry in report.dark_spots() {
            assert!(
                !entry.consequence().is_empty() && !entry.documented_in().is_empty(),
                "a dark spot must say what follows from it and where it is written down: {entry:?}"
            );
        }
    }

    #[test]
    fn the_host_report_names_both_the_compiled_target_and_the_running_kernel() {
        let report = SupportReport::gather();
        let Some(host) = report.host().facts() else {
            panic!("the host capability always carries its facts");
        };
        assert_eq!(host.compiled_os(), std::env::consts::OS);
        assert_eq!(host.compiled_arch(), std::env::consts::ARCH);
        let Some(kernel) = host.kernel() else {
            panic!("uname must answer on a supported platform");
        };
        assert!(!kernel.sysname().is_empty());
        assert!(!kernel.release().is_empty());
        assert!(!kernel.machine().is_empty());
    }

    #[test]
    fn status_and_determination_names_are_stable() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::to_string(&SupportStatus::Available)?,
            "\"available\""
        );
        assert_eq!(
            serde_json::to_string(&SupportStatus::Partial)?,
            "\"partial\""
        );
        assert_eq!(
            serde_json::to_string(&SupportStatus::Unavailable)?,
            "\"unavailable\""
        );
        assert_eq!(
            serde_json::to_string(&SupportStatus::Unknown)?,
            "\"unknown\""
        );
        assert_eq!(
            serde_json::to_string(&Determination::ProbedLive)?,
            "\"probed_live\""
        );
        assert_eq!(
            serde_json::to_string(&Determination::PlatformApi)?,
            "\"platform_api\""
        );
        assert_eq!(
            serde_json::to_string(&Determination::Declared)?,
            "\"declared\""
        );
        Ok(())
    }

    #[test]
    fn a_capability_without_facts_serializes_without_a_null() -> Result<(), serde_json::Error> {
        let capability: Capability = Capability::plain(
            SupportStatus::Available,
            Determination::ProbedLive,
            SupportReason::Probed {
                probe: "x".to_string(),
            },
        );
        let json = serde_json::to_string(&capability)?;
        assert_eq!(
            json,
            r#"{"status":"available","determination":"probed_live","reason":{"reason":"probed","probe":"x"}}"#
        );
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    #[test]
    fn seatbelt_is_a_platform_api_claim_not_a_probe() {
        // The honesty this field exists for: `sandbox_init` is certainly
        // linked, and nothing was asked of it. A `ProbedLive` here would be a
        // claim no macOS build can make without forking.
        let report = SupportReport::gather();
        assert_eq!(report.seatbelt().status(), SupportStatus::Available);
        assert_eq!(
            report.seatbelt().determination(),
            Determination::PlatformApi
        );
        let SupportReason::PlatformApiLinked {
            api,
            why_not_probed,
        } = report.seatbelt().reason()
        else {
            panic!(
                "seatbelt must name the API it rests on: {:?}",
                report.seatbelt().reason()
            );
        };
        assert!(api.contains("sandbox_init"));
        assert!(
            why_not_probed.contains("fork"),
            "the rationale must say why no live probe was run: {why_not_probed}"
        );
    }

    #[test]
    fn landlock_and_seccomp_are_other_platform_here() {
        let report = SupportReport::gather();
        assert_eq!(report.landlock().status(), SupportStatus::Unavailable);
        assert!(matches!(
            report.landlock().reason(),
            SupportReason::OtherPlatform { .. }
        ));
        for capability in [report.seccomp(), report.seccomp_user_notification()] {
            assert_eq!(capability.status(), SupportStatus::Unavailable);
            assert!(matches!(
                capability.reason(),
                SupportReason::OtherPlatform { .. }
            ));
        }
    }

    #[test]
    fn per_port_tcp_filtering_is_refused_rather_than_widened() {
        let report = SupportReport::gather();
        assert_eq!(
            report.network_filtering().status(),
            SupportStatus::Partial,
            "macOS can deny or allow the network, and cannot filter by port"
        );
        let Some(facts) = report.network_filtering().facts() else {
            panic!("network filtering carries its mechanism table");
        };
        let Some(per_port) = facts
            .mechanisms()
            .iter()
            .find(|entry| entry.mechanism() == NetworkMechanism::SeatbeltPerPortTcp)
        else {
            panic!("the table must mention per-port TCP, even to refuse it");
        };
        assert_eq!(per_port.status(), SupportStatus::Unavailable);
        assert!(matches!(
            per_port.reason(),
            SupportReason::PlatformCannotExpress { .. }
        ));
    }
}
