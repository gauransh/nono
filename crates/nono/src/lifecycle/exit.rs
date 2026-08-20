//! Typed exit facts and the running sandbox that produces them.
//!
//! [`SandboxExit`] carries only what was directly observed: a `waitpid` status,
//! or a fixed-size failure record the child wrote before it could `execve`.
//! There is no "probably crashed", no product status, and no reconstruction of
//! a death nobody saw.
//!
//! # Exit codes are not a protocol
//!
//! A pre-exec failure is reported by the *record on the status descriptor*,
//! never by the child's exit code. The child of a lifecycle run exits with
//! [`PRE_EXEC_EXIT_CODE`] whenever it fails before `execve`, and that number is
//! deliberately meaningless: the customer program owns the entire exit-code
//! space, so any sentinel value nono picked (126, 127, 1, …) would be a value
//! some real program also returns. Reading a sentinel back as "nono failed"
//! would silently mislabel a customer's own exit. Once `execve` succeeds the
//! exit code belongs wholly to the customer program and is reported verbatim.
//!
//! # Signals are not collapsed
//!
//! A death by signal is [`ExitOutcome::Signaled`] carrying the signal number,
//! not `Exited(128 + n)`. The shell convention conflates "killed by signal 9"
//! with "exited with status 137", and a program really can exit 137.
//!
//! # "Did it run?" has three answers, not two
//!
//! EOF on the status descriptor with no error record is *nearly* proof that
//! `execve` happened — but not quite. A child that is killed between the
//! release and the `execve` also closes that descriptor without writing
//! anything, and produces exactly the same EOF. So the fact is three-valued:
//! see [`ActivationObservation`]. The library reports which of the three it
//! can support and never rounds an ambiguity up to a certainty.

use super::cleanup::{CleanupError, CleanupVerification, DeathObservation, verify_and_record};
use super::events::{EventEmitter, LifecycleEventKind};
use super::gate::StopError;
use super::identity::ProcessIdentity;
use super::session_store::SessionHandle;
use super::state::{LifecycleOp, LifecycleState};
use super::sync_core::{SharedLifecycle, Transition};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

/// Exit status of a lifecycle child that failed before `execve`.
///
/// Carries no protocol meaning — see the module docs. The binding fact is the
/// record on the status descriptor.
pub const PRE_EXEC_EXIT_CODE: i32 = 1;

/// Size of one status-descriptor record: a stage tag plus a little-endian
/// `i32` errno.
pub(crate) const STATUS_RECORD_LEN: usize = 5;

/// Record tag meaning "sandbox applied, now blocking at the gate".
///
/// Not a [`PreExecStage`]: it reports progress, not failure, and it is the one
/// record the parent hopes to read during `prepare`.
pub(crate) const TAG_GATE_READY: u8 = 0x01;

/// The child is handing the parent a seccomp-notify listener.
///
/// The `errno` slot of the record carries the descriptor *number* in the
/// child's table, not an error. The number is useless to anyone who cannot
/// reach that table, and the parent turns it into a descriptor of its own with
/// `pidfd_getfd`. Sending it this way rather than over `SCM_RIGHTS` is forced:
/// the filter the child just installed traps `sendmsg`, so passing a descriptor
/// through a socket would be mediated by the very listener nobody is servicing
/// yet.
///
/// Written before [`TAG_GATE_READY`], so a parent that sees the gate record has
/// already seen this one if there was one.
pub(crate) const TAG_NOTIFY_FD: u8 = 0x05;

/// How far the child got before it gave up.
///
/// Each variant is a point in the child's fixed pre-exec sequence, in order.
/// The wire tags are contract: they cross a `fork` boundary inside a
/// fixed-size record, and a durable session record may hold them later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreExecStage {
    /// Putting the child into its own process group failed, so a later stop
    /// could not have reached everything the run started and cleanup
    /// verification would have had no group to probe. The child dies here
    /// rather than run without either guarantee.
    ProcessGroup,
    /// Taking the pseudo-terminal as this session's controlling terminal
    /// failed, so a run that asked to be interactive would have got a terminal
    /// that delivers no `SIGINT`, no `SIGWINCH`, and no hangup. The child dies
    /// here rather than run something that only looks like a terminal session.
    ControllingTerminal,
    /// Applying the platform sandbox to the child itself failed. Nothing ran
    /// unconfined: the child died instead.
    SandboxApply,
    /// Installing the seccomp network filter failed, so a policy that asked
    /// for the network to be blocked would have run with it open. Linux only:
    /// it is the step that denies the socket families Landlock cannot express
    /// — UDP among them — and a policy enforced only as far as Landlock
    /// reaches is not the policy the caller asked for. The child dies here
    /// rather than run partially confined.
    NetworkFilter,
    /// Reading the gate descriptor failed for a reason other than EOF.
    GateWait,
    /// The gate reached EOF before a release message arrived: every writer is
    /// gone, so the supervisor died and the run can no longer be observed.
    GateClosed,
    /// The abort message arrived: the run was stopped before activation.
    GateAborted,
    /// A message arrived that matched neither of the gate's secrets. Whoever
    /// wrote it holds the descriptor but not the secret, so it is treated as
    /// hostile and refused rather than guessed at.
    GateProtocol,
    /// Entering the plan's working directory failed.
    WorkingDirectory,
    /// `execve` returned, which it only does on failure.
    Exec,
    /// The child died without leaving a complete record. The stage is a fact
    /// we do not have, so it is named rather than guessed.
    Unknown,
}

impl PreExecStage {
    /// The stable snake_case name, identical to the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessGroup => "process_group",
            Self::ControllingTerminal => "controlling_terminal",
            Self::SandboxApply => "sandbox_apply",
            Self::NetworkFilter => "network_filter",
            Self::GateWait => "gate_wait",
            Self::GateClosed => "gate_closed",
            Self::GateAborted => "gate_aborted",
            Self::GateProtocol => "gate_protocol",
            Self::WorkingDirectory => "working_directory",
            Self::Exec => "exec",
            Self::Unknown => "unknown",
        }
    }

    /// The wire tag written into a status record.
    ///
    /// [`Self::Unknown`] has no tag of its own — it is what the parent
    /// concludes when no complete record arrived — so it shares `0xFF` with any
    /// unrecognised byte.
    #[must_use]
    pub(crate) fn as_tag(self) -> u8 {
        match self {
            // Numbered below `SandboxApply` rather than appended after `Exec`:
            // this stage happens *before* the sandbox apply, so the tags keep
            // reading in sequence order. The existing tags are contract and
            // could not be moved to make room.
            Self::ProcessGroup => 0x0F,
            Self::SandboxApply => 0x10,
            Self::GateWait => 0x11,
            Self::GateClosed => 0x12,
            Self::GateAborted => 0x13,
            Self::GateProtocol => 0x14,
            Self::WorkingDirectory => 0x15,
            Self::Exec => 0x16,
            // Appended rather than slotted in after `ProcessGroup`, which is
            // where the sequence would put it: 0x10 is `SandboxApply` and the
            // existing tags are contract. So the numbers no longer read in
            // sequence order, and `as_tag` is the only place that matters.
            Self::ControllingTerminal => 0x17,
            // Appended for the same reason: this stage runs immediately after
            // `SandboxApply`, whose 0x10 neighbourhood is long since spoken
            // for.
            Self::NetworkFilter => 0x18,
            Self::Unknown => 0xFF,
        }
    }

    /// Decode a wire tag. Anything unrecognised is [`Self::Unknown`]: a child
    /// that wrote a byte we do not know about told us nothing we can trust.
    #[must_use]
    pub(crate) fn from_tag(tag: u8) -> Self {
        match tag {
            0x0F => Self::ProcessGroup,
            0x10 => Self::SandboxApply,
            0x11 => Self::GateWait,
            0x12 => Self::GateClosed,
            0x13 => Self::GateAborted,
            0x14 => Self::GateProtocol,
            0x15 => Self::WorkingDirectory,
            0x16 => Self::Exec,
            0x17 => Self::ControllingTerminal,
            0x18 => Self::NetworkFilter,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for PreExecStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which piece of the supervisor's own machinery failed.
///
/// Distinct from a child failure: nothing is known about the child when one of
/// these happens, which is exactly why it is reported as its own outcome
/// instead of being folded into an exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorStage {
    /// Delivering the release message to the gate failed.
    Release,
    /// Reading the status descriptor failed.
    StatusRead,
    /// `waitpid` failed, so the child's death was never observed.
    Reap,
}

impl SupervisorStage {
    /// The stable snake_case name, identical to the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::StatusRead => "status_read",
            Self::Reap => "reap",
        }
    }
}

impl std::fmt::Display for SupervisorStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether the customer's program ever started, to the precision the platform
/// actually supports.
///
/// Deliberately three-valued. A two-valued `bool` would have to round
/// [`Self::ExecOrKilledPreExec`] to one side or the other, and both roundings
/// are lies a consumer could act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationObservation {
    /// The program definitely ran.
    ///
    /// Reached when the status descriptor hit EOF with no record *and* the
    /// child was later reaped with a normal exit. Every pre-exec path in the
    /// child writes a record before it calls `_exit`, and the parent holds the
    /// read end open until the outcome is known, so a normal exit with no
    /// record cannot have come from a child that never reached `execve`.
    Observed,

    /// The program definitely never ran.
    ///
    /// Reached when the child reported a typed pre-exec failure, when the gate
    /// was stopped or expired before release, or when nothing was ever
    /// released.
    NotActivated,

    /// The gate was released and the child then vanished without a word.
    ///
    /// Either `execve` succeeded (closing the close-on-exec status descriptor)
    /// or the child was killed in the window between the release and the
    /// `execve`. Both produce the same EOF, and nothing observable
    /// distinguishes them, so neither is claimed.
    ExecOrKilledPreExec,
}

impl ActivationObservation {
    /// The stable snake_case name, identical to the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::NotActivated => "not_activated",
            Self::ExecOrKilledPreExec => "exec_or_killed_pre_exec",
        }
    }
}

impl std::fmt::Display for ActivationObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a run ended, as one directly observed fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExitOutcome {
    /// `waitpid` reported a normal exit with this status.
    Exited {
        /// The status the program passed to `exit`.
        code: i32,
    },
    /// `waitpid` reported death by this signal number. Never collapsed into
    /// `128 + n`.
    Signaled {
        /// The signal number, as the platform numbers it.
        signal: i32,
    },
    /// The child could not apply its own sandbox and died instead of running
    /// unconfined.
    SandboxApplicationFailure {
        /// Which step of the confinement did not go on:
        /// [`PreExecStage::SandboxApply`] for the platform sandbox itself, or
        /// [`PreExecStage::NetworkFilter`] for the seccomp network filter that
        /// covers what Landlock cannot express. Carried so the two failure
        /// outcomes read alike.
        stage: PreExecStage,
        /// Platform error number. On macOS this is `sandbox_init`'s non-zero
        /// return value, which is not an errno — see [`SandboxExit`].
        errno: i32,
    },
    /// The child reached the gate and reported why it stopped there instead of
    /// reaching `execve`.
    ///
    /// Covers deliberate endings as well as failures: a gate that was aborted
    /// or whose supervisor vanished lands here with the matching
    /// [`PreExecStage`]. That is on purpose — the alternative would be
    /// reporting a stop as `Exited { code: 1 }`, and a bare `1` is a status the
    /// customer's own program returns all the time.
    PreExecFailure {
        /// Where in the pre-exec sequence it stopped.
        stage: PreExecStage,
        /// Platform error number captured at that point.
        errno: i32,
    },
    /// The supervisor's own machinery failed, so the child's fate is unknown.
    SupervisorFailure {
        /// Which supervisor step failed.
        stage: SupervisorStage,
        /// Platform error number captured at that point.
        errno: i32,
    },
}

/// Everything directly observed about how a run ended.
///
/// # Platform note
///
/// On macOS the `errno` of an [`ExitOutcome::SandboxApplicationFailure`] is
/// `sandbox_init`'s return value rather than a `errno(3)` code: that API
/// reports failure through its return value and an allocated message the child
/// cannot safely format. The number is still a directly observed fact, it is
/// just not an errno on that platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxExit {
    outcome: ExitOutcome,
    activation: ActivationObservation,
    identity: ProcessIdentity,
}

impl SandboxExit {
    pub(crate) fn new(
        outcome: ExitOutcome,
        activation: ActivationObservation,
        identity: ProcessIdentity,
    ) -> Self {
        Self {
            outcome,
            activation,
            identity,
        }
    }

    /// How the run ended.
    #[must_use]
    pub fn outcome(&self) -> ExitOutcome {
        self.outcome
    }

    /// The identity of the process these facts are about.
    ///
    /// Carried so a caller can re-check the pid it is about to act on rather
    /// than trusting a number that may already have been reissued.
    #[must_use]
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Whether the customer's program ever started.
    ///
    /// Three-valued on purpose — see [`ActivationObservation`]. There is no
    /// `bool` accessor beside it, because collapsing the ambiguous case is
    /// exactly the mistake this type exists to prevent.
    #[must_use]
    pub fn activation(&self) -> ActivationObservation {
        self.activation
    }
}

/// `waitpid` failed, so the child's death was not observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Error)]
#[error("waitpid failed for pid {pid}: errno {errno}")]
pub struct ReapError {
    /// The pid that was being waited for.
    pub pid: i32,
    /// Platform error number from `waitpid`.
    pub errno: i32,
}

/// A sandboxed run whose gate was released and whose child then vanished from
/// the status descriptor.
///
/// Only reachable from a successful activation, so the run is at worst
/// [`ActivationObservation::ExecOrKilledPreExec`]; [`Self::wait`] resolves it
/// to [`ActivationObservation::Observed`] when the exit status allows.
///
/// This is the authoritative handle for the run once activation succeeds. The
/// [`super::PreparedSandbox`] it came from keeps reporting the state it had at
/// the handoff and does not follow the run any further.
pub struct ActivatedSandbox {
    identity: ProcessIdentity,
    /// The process group the child leads, which is the child's own pid: the
    /// child called `setpgid(0, 0)` before it did anything else. Everything
    /// the customer's program forks lands here too unless it deliberately
    /// leaves — see [`super::PreparedSandbox`].
    process_group: i32,
    /// The cgroup this run was placed in, when the host allowed one.
    ///
    /// A process group is escapable — `setsid(2)` is the call that leaves one —
    /// and a cgroup is not. When this is present the stop kills by cgroup as
    /// well, which reaches a descendant that left the group; when it is absent
    /// the run is contained exactly as it was before, by its process group
    /// alone, and a descendant that leaves is still lost.
    ///
    /// `None` on macOS, and on a Linux host that would not give this process a
    /// cgroup — an unprivileged container, most often.
    #[cfg(target_os = "linux")]
    cgroup: Option<super::cgroup::RunCgroup>,
    /// This handle's own core, started at the state the handoff observed.
    ///
    /// Deliberately not shared with the [`super::PreparedSandbox`] it came
    /// from: that handle reports the state it had at the handoff and does not
    /// follow the run, which is a promise its docs make and its live tests
    /// check. One core between them would silently break it.
    shared: SharedLifecycle,
    activation: ActivationObservation,
    reaped: Option<SandboxExit>,
    /// The run's emitter, shared with the [`super::PreparedSandbox`] this came
    /// from so the event sequence continues across the handoff instead of
    /// restarting in the middle of the run.
    events: Arc<EventEmitter>,
    /// The durable record this run writes to, when it has one.
    ///
    /// The same record the [`super::PreparedSandbox`] was writing, shared by
    /// `Arc` rather than copied: one session has one record, and two writers
    /// with two copies of it would eventually disagree about which state was
    /// last.
    session: Option<Arc<SessionHandle>>,
}

impl ActivatedSandbox {
    pub(crate) fn new(
        identity: ProcessIdentity,
        process_group: i32,
        #[cfg(target_os = "linux")] cgroup: Option<super::cgroup::RunCgroup>,
        state: LifecycleState,
        activation: ActivationObservation,
        events: Arc<EventEmitter>,
        session: Option<Arc<SessionHandle>>,
    ) -> Self {
        // The handoff itself is worth a write: the prepared handle recorded the
        // state but could not know the activation fact until this moment, and
        // between here and the next transition the record would otherwise say
        // "running" with nothing said about whether the program started.
        if let Some(session) = &session {
            session.persist(state, Some(activation));
        }
        Self {
            identity,
            process_group,
            #[cfg(target_os = "linux")]
            cgroup,
            shared: SharedLifecycle::new(state),
            activation,
            reaped: None,
            events,
            session,
        }
    }

    /// What is known so far about whether the program started.
    ///
    /// Sharpens from [`ActivationObservation::ExecOrKilledPreExec`] to
    /// [`ActivationObservation::Observed`] once [`Self::wait`] sees an exit
    /// status only a real `execve` could have produced.
    #[must_use]
    pub fn activation(&self) -> ActivationObservation {
        self.activation
    }

    /// The child's identity, captured at fork.
    #[must_use]
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Where the run currently is.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.shared.state()
    }

    /// Wait for the program to end and report what was observed.
    ///
    /// Blocks until `waitpid` reaps the child, retrying through `EINTR` and
    /// ignoring stop/continue reports — a stopped process has not ended.
    ///
    /// A normal exit also resolves the activation question: only a child that
    /// reached `execve` can exit normally without having written a status
    /// record first, so this is where
    /// [`ActivationObservation::ExecOrKilledPreExec`] becomes
    /// [`ActivationObservation::Observed`]. A death by signal leaves the
    /// question open, because a signal can arrive on either side of `execve`.
    ///
    /// Calling this again after it has returned reports the same recorded
    /// facts without touching the process again: the death is observed once,
    /// and re-reading the record is not a second observation.
    ///
    /// # Errors
    ///
    /// [`ReapError`] when `waitpid` itself fails, in which case the death was
    /// never observed and nothing is recorded.
    pub fn wait(&mut self) -> Result<SandboxExit, ReapError> {
        if let Some(exit) = &self.reaped {
            return Ok(exit.clone());
        }
        let outcome = reap(self.identity.pid())?;
        Ok(self.record_child_exit(outcome))
    }

    /// Ask whether the program has ended, without waiting for it to.
    ///
    /// The same observation as [`Self::wait`] and with the same bookkeeping —
    /// the activation question is sharpened, the event is emitted, the record is
    /// written — but through `WNOHANG`, so a run that is still going answers
    /// `None` instead of parking the caller.
    ///
    /// Exists because the detached supervisor has one thread and several things
    /// to watch: a blocking `waitpid` there would stop it serving its control
    /// socket for as long as the customer's program chose to run. A stop or
    /// continue report is *not* a death, so it answers `None` too.
    ///
    /// # Errors
    ///
    /// [`ReapError`] when `waitpid` itself fails, in which case nothing was
    /// observed and nothing is recorded.
    pub(crate) fn try_wait(&mut self) -> Result<Option<SandboxExit>, ReapError> {
        if let Some(exit) = &self.reaped {
            return Ok(Some(exit.clone()));
        }
        let Some(outcome) = try_reap(self.identity.pid())? else {
            return Ok(None);
        };
        Ok(Some(self.record_child_exit(outcome)))
    }

    /// Shared tail of the two waits: sharpen, report, transition, cache.
    ///
    /// A normal exit resolves the activation question, because only a child
    /// that reached `execve` can exit normally without having written a status
    /// record first.
    fn record_child_exit(&mut self, outcome: ExitOutcome) -> SandboxExit {
        if matches!(outcome, ExitOutcome::Exited { .. }) {
            self.activation = ActivationObservation::Observed;
        }
        self.events
            .emit(LifecycleEventKind::ChildExited { outcome });
        let exit = SandboxExit::new(outcome, self.activation, self.identity.clone());
        // The state machine refuses a second ChildExited, which is why the
        // cached reads above return before reaching this line.
        self.transition(LifecycleOp::ChildExited);
        self.reaped = Some(exit.clone());
        exit
    }

    /// End the run now, and wait until the death is observed.
    ///
    /// `SIGKILL` goes to the whole process group, not just the child: the
    /// customer's program may have forked, and killing only the process nono
    /// happens to hold a pid for would leave those children running while the
    /// run reported itself stopped. The child is then signalled by pid as well,
    /// which covers the one case the group cannot — a program that made itself
    /// a session leader and so left the group it was born in.
    ///
    /// The signal is not the result. This returns only after `waitpid` observes
    /// the child's death, and the [`SandboxExit`] carries what that observation
    /// said — a `SIGKILL` death is [`ExitOutcome::Signaled`], and a program that
    /// happened to exit on its own first is reported as the exit it actually
    /// had. Whether anything *else* survived is a separate question, answered by
    /// [`Self::verify_cleanup`] and not assumed here.
    ///
    /// # Errors
    ///
    /// [`StopError::NotStoppable`] if the run already ended or was already
    /// stopped; [`StopError::SignalFailed`] if the kill could not be delivered,
    /// in which case nothing is claimed and nothing was reaped;
    /// [`StopError::Reap`] if the death could not be observed.
    pub fn stop(&mut self) -> Result<SandboxExit, StopError> {
        // Through the shared core, like every other mutation: `begin_stop`
        // refuses a run that already ended rather than sending a signal at a
        // pid whose death was already recorded.
        let change = self
            .shared
            .begin_stop()
            .map_err(|err| StopError::NotStoppable { state: err.from })?;
        self.events.emit(LifecycleEventKind::StopRequested);
        self.report(change);

        // The cgroup first, when there is one. It is the only reach that
        // catches a descendant which left the process group, and it kills every
        // member in a single write — no set to enumerate, and nothing that can
        // leave between the enumeration and the signal.
        //
        // A failure here is reported and does not stop the group kill from
        // following: the group kill is what this run had before, and skipping
        // it because the stronger mechanism faltered would make the stop weaker
        // than it used to be.
        #[cfg(target_os = "linux")]
        if let Some(cgroup) = self.cgroup.as_ref()
            && let Err(error) = cgroup.kill_all()
        {
            self.events.emit(LifecycleEventKind::StopCgroupFailed {
                detail: error.to_string(),
            });
        }

        kill_own_group(self.process_group).map_err(|errno| StopError::SignalFailed {
            target: self.process_group,
            errno,
        })?;
        // The direct child by pid too. It is ours and unreaped, so the number
        // cannot have been reissued; without this a child that called `setsid`
        // would survive the group kill and leave the reap below waiting for a
        // process nothing had signalled.
        kill_pid(self.identity.pid()).map_err(|errno| StopError::SignalFailed {
            target: self.identity.pid(),
            errno,
        })?;

        let outcome = reap(self.identity.pid())?;
        self.events
            .emit(LifecycleEventKind::StopObserved { outcome });
        self.transition(LifecycleOp::StopObserved);
        let exit = SandboxExit::new(outcome, self.activation, self.identity.clone());
        self.reaped = Some(exit.clone());
        Ok(exit)
    }

    /// Prove the run's processes are gone — or report honestly that they are
    /// not.
    ///
    /// Legal only once the run's end has been observed: after [`Self::wait`]
    /// returned, or after [`Self::stop`] completed. Before that there is
    /// nothing to verify and the call is refused rather than answered.
    ///
    /// Only [`CleanupVerification::ConfirmedAbsent`] moves the run to
    /// [`LifecycleState::CleanupVerified`]. A survivor or an unsettled probe
    /// leaves the state exactly where it was, so the caller can act and verify
    /// again — the library never launders "we tried" into "it is gone".
    ///
    /// # Errors
    ///
    /// [`CleanupError`] naming the state that refused: the run has not ended
    /// yet, or its cleanup was already verified.
    pub fn verify_cleanup(&mut self) -> Result<CleanupVerification, CleanupError> {
        let death = if self.reaped.is_some() {
            DeathObservation::Reaped
        } else {
            DeathObservation::NotReaped
        };
        let (verification, change) =
            verify_and_record(&self.shared, &self.identity, self.process_group, death)?;
        // Every verdict, not only a proof of absence: a survivor is a fact a
        // consumer has to act on, and one it would never hear about if only
        // successes were reported.
        self.events.emit(LifecycleEventKind::CleanupVerdict {
            verdict: verification.clone(),
        });
        if let Some(change) = change {
            self.report(change);
        }
        Ok(verification)
    }

    /// Apply an observed fact and tell the sink, if there is one.
    ///
    /// A refused transition is a library bug rather than a caller error, and
    /// this path cannot return one, so the state simply does not move.
    fn transition(&mut self, op: LifecycleOp) {
        let Ok(change) = self.shared.mark(op) else {
            return;
        };
        self.report(change);
    }

    /// Tell the sink, and the durable record, about a change that already
    /// happened.
    ///
    /// Always outside the shared core's lock: the sink is consumer code and
    /// the record write is filesystem I/O. Both run after the transition, so
    /// the record can lag the live run by one step — see
    /// [`super::SessionStore::recover`], which is what makes that safe.
    fn report(&self, change: Transition) {
        self.events.emit(LifecycleEventKind::StateChanged {
            from: change.from,
            to: change.to,
        });
        if let Some(session) = &self.session {
            session.persist(change.to, Some(self.activation));
        }
    }
}

/// Debug that names the run without pulling in the sink's own `Debug`.
impl std::fmt::Debug for ActivatedSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivatedSandbox")
            .field("identity", &self.identity)
            .field("process_group", &self.process_group)
            .field("state", &self.shared.state())
            .field("activation", &self.activation)
            .field("reaped", &self.reaped)
            .field("events", &self.events)
            .finish()
    }
}

/// Kill and reap on drop unless [`ActivatedSandbox::wait`] already reaped.
///
/// The non-detached default: a dropped handle must not leave a running child
/// or a zombie behind. Detached runs that outlive their supervisor arrive with
/// the durable-supervisor slice; until then, dropping the handle ends the run.
///
/// The signal goes to the whole process group first, exactly as
/// [`ActivatedSandbox::stop`] does and for the same reason: the customer's
/// program may have forked, and killing only the pid this handle happens to
/// hold would leave those children running while the run reported itself over.
/// A drop that ended less than a stop would make "let it go out of scope" a
/// quietly weaker guarantee than calling `stop`. The group id is refused if it
/// would name the caller's own group — the same `targets <= 1` guard, made in
/// [`kill_group`] itself.
impl Drop for ActivatedSandbox {
    fn drop(&mut self) {
        if self.reaped.is_some() {
            return;
        }
        // Best effort, in the order a stop uses: the group, then the direct
        // child by pid (which covers a descendant that left the group), then
        // the wait that turns the request into an observation.
        let _ = kill_own_group(self.process_group);
        kill_and_reap(self.identity.pid());
    }
}

/// Block until `pid` is reaped, retrying through `EINTR` and stop/continue.
pub(crate) fn reap(pid: i32) -> Result<ExitOutcome, ReapError> {
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::Pid;

    let target = Pid::from_raw(pid);
    loop {
        match waitpid(target, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(ExitOutcome::Exited { code }),
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                return Ok(ExitOutcome::Signaled {
                    signal: signal as i32,
                });
            }
            // Stopped, continued, and ptrace reports are not deaths; keep
            // waiting for one.
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => {}
            Err(errno) => {
                return Err(ReapError {
                    pid,
                    errno: errno as i32,
                });
            }
        }
    }
}

/// Ask whether `pid` has been reaped, without waiting for it.
///
/// `Ok(None)` means the process is still there — either running, or stopped and
/// continued, neither of which is a death. `WNOHANG` makes this safe to call
/// from a poll loop that must not park.
pub(crate) fn try_reap(pid: i32) -> Result<Option<ExitOutcome>, ReapError> {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::Pid;

    let target = Pid::from_raw(pid);
    loop {
        match waitpid(target, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(Some(ExitOutcome::Exited { code })),
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                return Ok(Some(ExitOutcome::Signaled {
                    signal: signal as i32,
                }));
            }
            // `StillAlive` is what `WNOHANG` answers with when there is nothing
            // to reap; stop, continue, and ptrace reports are not deaths
            // either, and neither is worth blocking for.
            Ok(_) => return Ok(None),
            Err(nix::errno::Errno::EINTR) => {}
            Err(errno) => {
                return Err(ReapError {
                    pid,
                    errno: errno as i32,
                });
            }
        }
    }
}

/// `SIGKILL` then block until the death is observed.
///
/// Used wherever the caller cannot afford to wait for the customer's program
/// to finish on its own — a bare `reap` after a released gate would block for
/// as long as that program chooses to run.
pub(crate) fn kill_and_reap_observed(pid: i32) -> Result<ExitOutcome, ReapError> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    // An already-dead child returns ESRCH here and is still reaped below; a
    // failure to signal is not a reason to skip the wait.
    let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
    reap(pid)
}

/// Best-effort `SIGKILL` + reap, for drop paths that cannot report failure.
pub(crate) fn kill_and_reap(pid: i32) {
    let _ = kill_and_reap_observed(pid);
}

/// `SIGKILL` every member of a process group, reporting what the kernel said.
///
/// `ESRCH` — no member left — is success with nothing to do, not a failure:
/// the caller wanted the group gone and it already is. Every other error is
/// returned, because a stop that could not deliver its signal must not be
/// reported as a stop.
///
/// A group id of 0, 1, or below is refused before the syscall: `kill(0, …)`
/// signals the *caller's own* process group and `kill(-1, …)` signals
/// everything the caller may signal. A corrupt record must never turn into
/// either.
pub(crate) fn kill_group(pgid: i32) -> Result<(), i32> {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    if pgid <= 1 {
        return Err(libc::EINVAL);
    }
    match killpg(Pid::from_raw(pgid), Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(errno) => Err(errno as i32),
    }
}

/// `SIGKILL` a group this process's own unreaped child leads.
///
/// [`kill_group`] with one extra reading, and the reading is only sound here.
///
/// The two platforms spell "there is nothing in this group left to signal"
/// differently once its members are zombies: Linux answers `ESRCH`, and macOS
/// answers **`EPERM`** — `killpg` reports success only if it signalled at least
/// one process, and a zombie is not one it will signal. Reported as a failure,
/// that turns "the run had already ended" into "the stop could not be
/// delivered", which is a lie about a race every stop can lose.
///
/// It is safe to read `EPERM` that way *here* and nowhere else: this group's id
/// is the unreaped child's own pid, so the kernel cannot have reissued it to a
/// process belonging to somebody else, and every member is descended from a
/// child this process forked. [`super::RecoveredSession`] deliberately does not
/// get this treatment — its recorded group id may well have been reissued, and
/// there an `EPERM` really could be somebody else's process.
///
/// What this does *not* do is claim the group is gone. Nothing here treats a
/// sent signal as proof; [`ActivatedSandbox::verify_cleanup`] is what answers
/// that question, and it probes rather than assuming.
fn kill_own_group(pgid: i32) -> Result<(), i32> {
    match kill_group(pgid) {
        Err(errno) if errno == libc::EPERM => Ok(()),
        other => other,
    }
}

/// `SIGKILL` one process, reporting what the kernel said.
///
/// Same treatment of `ESRCH` as [`kill_group`], and the same refusal of pids
/// that would name a group rather than a process.
pub(crate) fn kill_pid(pid: i32) -> Result<(), i32> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    if pid <= 0 {
        return Err(libc::EINVAL);
    }
    match kill(Pid::from_raw(pid), Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(errno) => Err(errno as i32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_STAGES: [PreExecStage; 11] = [
        PreExecStage::ProcessGroup,
        PreExecStage::ControllingTerminal,
        PreExecStage::SandboxApply,
        PreExecStage::NetworkFilter,
        PreExecStage::GateWait,
        PreExecStage::GateClosed,
        PreExecStage::GateAborted,
        PreExecStage::GateProtocol,
        PreExecStage::WorkingDirectory,
        PreExecStage::Exec,
        PreExecStage::Unknown,
    ];

    #[test]
    fn a_group_of_zombies_is_nothing_left_to_signal_not_a_refusal() {
        // The platform difference this exists for, exercised rather than
        // asserted about. A child that leads its own group and has exited is a
        // zombie in a group with no signalable member; `killpg` answers ESRCH
        // on Linux and EPERM on macOS, and both mean the run had already ended.
        //
        // Removal detection: dropping the `EPERM` arm from `kill_own_group`
        // fails this test on macOS, and with it every detached stop that raced
        // the run's own exit.
        //
        // SAFETY: `fork` duplicates this process. The child branch runs two
        // syscalls and `_exit`s, so it never returns into Rust, never unwinds,
        // and never runs a destructor.
        let child = unsafe { libc::fork() };
        if child == 0 {
            // SAFETY: `setpgid` and `_exit` are async-signal-safe, take
            // integers, and touch no memory.
            unsafe {
                libc::setpgid(0, 0);
                libc::_exit(0);
            }
        }
        assert!(child > 0, "the test fork must succeed");

        // Wait until the group stops accepting signals. Deliberately *not* by
        // reaping: a reaped child is gone from the table entirely, and the
        // state under test is the one in between — exited, unreaped, and no
        // longer signalable.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut refused = None;
        while std::time::Instant::now() < deadline {
            // ESRCH is folded into `Ok` by `kill_group` itself, so the loop
            // watches for the raw refusal and for the folded one alike.
            if let Err(errno) = kill_group(child) {
                refused = Some(errno);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        match refused {
            // macOS: the group holds a zombie and nothing signalable.
            Some(errno) => {
                assert_eq!(errno, libc::EPERM, "the only refusal expected here");
                assert_eq!(
                    kill_own_group(child),
                    Ok(()),
                    "a group whose every member is already a zombie is not a refusal"
                );
            }
            // Linux: `killpg` answers ESRCH, which `kill_group` already folds
            // into success, so the loop above never saw a refusal. The
            // tolerance is unreachable there and correctly makes no difference.
            None => assert_eq!(kill_own_group(child), Ok(())),
        }
        kill_and_reap(child);
    }

    #[test]
    fn every_failure_stage_round_trips_through_its_wire_tag() {
        for stage in ALL_STAGES {
            assert_eq!(
                PreExecStage::from_tag(stage.as_tag()),
                stage,
                "{stage} must survive the fork boundary"
            );
        }
    }

    #[test]
    fn stage_tags_are_distinct_and_never_collide_with_the_ready_marker() {
        for (index, stage) in ALL_STAGES.iter().enumerate() {
            assert_ne!(
                stage.as_tag(),
                TAG_GATE_READY,
                "{stage} must not be mistaken for the ready marker"
            );
            for other in &ALL_STAGES[index.saturating_add(1)..] {
                assert_ne!(stage.as_tag(), other.as_tag(), "{stage} vs {other}");
            }
        }
    }

    #[test]
    fn an_unrecognised_tag_decodes_to_unknown_not_a_guess() {
        for tag in [0x00_u8, 0x02, 0x7F, 0xAB, 0xFF] {
            assert_eq!(PreExecStage::from_tag(tag), PreExecStage::Unknown);
        }
    }

    #[test]
    fn stage_serde_names_are_stable_snake_case() -> Result<(), serde_json::Error> {
        for stage in ALL_STAGES {
            let json = serde_json::to_string(&stage)?;
            assert_eq!(json, format!("\"{}\"", stage.as_str()));
            assert_eq!(serde_json::from_str::<PreExecStage>(&json)?, stage);
            assert_eq!(stage.to_string(), stage.as_str());
        }
        Ok(())
    }

    #[test]
    fn supervisor_stage_serde_names_are_stable_snake_case() -> Result<(), serde_json::Error> {
        for stage in [
            SupervisorStage::Release,
            SupervisorStage::StatusRead,
            SupervisorStage::Reap,
        ] {
            let json = serde_json::to_string(&stage)?;
            assert_eq!(json, format!("\"{}\"", stage.as_str()));
            assert_eq!(serde_json::from_str::<SupervisorStage>(&json)?, stage);
            assert_eq!(stage.to_string(), stage.as_str());
        }
        Ok(())
    }

    fn test_identity() -> ProcessIdentity {
        ProcessIdentity::capture(i32::try_from(std::process::id()).unwrap_or(0))
    }

    #[test]
    fn a_signal_death_is_not_reported_as_an_exit_code() {
        let signaled = SandboxExit::new(
            ExitOutcome::Signaled { signal: 9 },
            ActivationObservation::Observed,
            test_identity(),
        );
        let exited = SandboxExit::new(
            ExitOutcome::Exited { code: 137 },
            ActivationObservation::Observed,
            test_identity(),
        );
        assert_ne!(
            signaled.outcome(),
            exited.outcome(),
            "128+n collapsing would make these the same fact"
        );
    }

    #[test]
    fn exit_outcome_serde_round_trips() -> Result<(), serde_json::Error> {
        let outcomes = [
            ExitOutcome::Exited { code: 0 },
            ExitOutcome::Signaled { signal: 9 },
            ExitOutcome::SandboxApplicationFailure {
                stage: PreExecStage::SandboxApply,
                errno: 1,
            },
            ExitOutcome::PreExecFailure {
                stage: PreExecStage::Exec,
                errno: 2,
            },
            ExitOutcome::SupervisorFailure {
                stage: SupervisorStage::Reap,
                errno: 10,
            },
        ];
        for outcome in outcomes {
            let json = serde_json::to_string(&outcome)?;
            assert_eq!(serde_json::from_str::<ExitOutcome>(&json)?, outcome);
        }
        Ok(())
    }

    #[test]
    fn sandbox_exit_reports_whether_the_program_ever_ran() {
        let ran = SandboxExit::new(
            ExitOutcome::Exited { code: 0 },
            ActivationObservation::Observed,
            test_identity(),
        );
        let never_ran = SandboxExit::new(
            ExitOutcome::PreExecFailure {
                stage: PreExecStage::Exec,
                errno: 2,
            },
            ActivationObservation::NotActivated,
            test_identity(),
        );
        let unknown = SandboxExit::new(
            ExitOutcome::Signaled { signal: 9 },
            ActivationObservation::ExecOrKilledPreExec,
            test_identity(),
        );
        assert_eq!(ran.activation(), ActivationObservation::Observed);
        assert_eq!(never_ran.activation(), ActivationObservation::NotActivated);
        assert_eq!(
            unknown.activation(),
            ActivationObservation::ExecOrKilledPreExec
        );
        assert_eq!(ran.identity(), never_ran.identity());
    }

    #[test]
    fn the_ambiguous_activation_answer_is_distinct_from_both_certain_ones() {
        // A two-valued answer would have to collapse this into one of the
        // others, and both collapses are claims the platform cannot support.
        assert_ne!(
            ActivationObservation::ExecOrKilledPreExec,
            ActivationObservation::Observed
        );
        assert_ne!(
            ActivationObservation::ExecOrKilledPreExec,
            ActivationObservation::NotActivated
        );
    }

    #[test]
    fn activation_observation_serde_names_are_stable() -> Result<(), serde_json::Error> {
        for observation in [
            ActivationObservation::Observed,
            ActivationObservation::NotActivated,
            ActivationObservation::ExecOrKilledPreExec,
        ] {
            let json = serde_json::to_string(&observation)?;
            assert_eq!(json, format!("\"{}\"", observation.as_str()));
            assert_eq!(
                serde_json::from_str::<ActivationObservation>(&json)?,
                observation
            );
            assert_eq!(observation.to_string(), observation.as_str());
        }
        Ok(())
    }

    #[test]
    fn sandbox_exit_round_trips_through_serde() -> Result<(), serde_json::Error> {
        let exit = SandboxExit::new(
            ExitOutcome::Exited { code: 3 },
            ActivationObservation::Observed,
            test_identity(),
        );
        let json = serde_json::to_string(&exit)?;
        assert_eq!(serde_json::from_str::<SandboxExit>(&json)?, exit);
        Ok(())
    }
}
