//! Proving a process is gone, instead of assuming the signal worked.
//!
//! A `SIGKILL` that returned zero says the kernel accepted the signal. It does
//! not say the process died, and it certainly does not say the children it
//! started died. Every verdict here is therefore built from a *probe made after
//! the fact* — [`CleanupVerification`] never records that a signal was sent,
//! because a sent signal is not evidence of absence.
//!
//! # What is probed
//!
//! Two different questions, answered by two different probes.
//!
//! When the direct child was reaped, `waitpid` already proved that *the child
//! itself* is gone: a reaped pid is no longer a process object at all. The open
//! question is what it left behind, so verification probes the **process
//! group** the child leads — `kill(-pgid, 0)` — which is the set the child and
//! everything it forked belong to.
//!
//! When the death was never observed — a supervisor whose `waitpid` failed, and
//! later a session recovered from a durable record — the question is still
//! about the original process, so verification probes the **identity**: the
//! pid, its start time, and the boot it was issued in.
//!
//! # Absence has more than one proof
//!
//! Three different facts each prove the recorded process is gone, and they are
//! kept distinct rather than collapsed into one boolean:
//!
//! - the probe found nothing under that pid or group ([`AbsenceBasis::PidAbsent`],
//!   [`AbsenceBasis::ReapedAndGroupEmpty`]);
//! - the pid is alive but is a *different* process, because its start time no
//!   longer matches ([`AbsenceBasis::IdentityMismatch`]) — the recorded process
//!   ended and the kernel reissued its number;
//! - the machine rebooted since the identity was captured
//!   ([`AbsenceBasis::BootIdChanged`]) — nothing survives a boot, so the
//!   recorded process cannot still be running.
//!
//! The reboot case is deliberately [`CleanupVerification::ConfirmedAbsent`] and
//! not [`CleanupVerification::Indeterminate`]. A reboot destroys every process
//! that existed before it; refusing to say so would be false modesty, not
//! honesty. What a reboot does *not* license is any claim about a live pid that
//! merely looks similar, which is why the boot check runs before the probe and
//! ends the question on its own.
//!
//! # The caveat that is not designed away
//!
//! Once the direct child is reaped its pid — and therefore its process group
//! id, which is that same number — can in principle be reissued to something
//! unrelated. A `kill(-pgid, 0)` that succeeds afterwards may then be seeing a
//! stranger rather than a survivor. Nothing in POSIX closes that window, so it
//! is not hidden: the boot id is re-checked (a reused number from another boot
//! cannot masquerade), a successful probe is reported as
//! [`CleanupVerification::StillPresent`] rather than as a certainty of survival,
//! and a probe that is refused by permissions is
//! [`CleanupVerification::Indeterminate`] rather than a guess in either
//! direction. The honest answer to "is this a survivor or a reused number" is
//! "something is there"; acting on it is the consumer's decision.
//!
//! # Verification observes; it never acts
//!
//! Nothing in this module sends a signal, kills a group, or reaps anything.
//! Stopping is [`super::ActivatedSandbox::stop`]'s job. Keeping the two apart is
//! what makes the verdict trustworthy: a verifier that killed the survivors it
//! found could only ever report success.

use super::identity::{ProcessIdentity, boot_id, process_start_time};
use super::state::{LifecycleOp, LifecycleState};
use super::sync_core::{SharedLifecycle, Transition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// What was established about a run's processes after it ended.
///
/// A closed enum on purpose: these four answers are the contract, and a
/// consumer that matches all four today must keep compiling — but must also be
/// made to revisit its handling if the set ever changes, which a
/// `#[non_exhaustive]` catch-all arm would silently prevent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CleanupVerification {
    /// Nothing of the run remains, and this is what proved it.
    ConfirmedAbsent {
        /// The observation the conclusion rests on. Never a sent signal.
        basis: AbsenceBasis,
    },
    /// Something was still there when the probe ran.
    ///
    /// Reported rather than acted on: verification observes, and stopping is a
    /// separate, deliberate step.
    StillPresent {
        /// What was seen.
        survivors: SurvivorEvidence,
    },
    /// The probe could not settle the question.
    Indeterminate {
        /// Why no conclusion was reached.
        reason: IndeterminateReason,
    },
    /// This platform offers no probe that could answer the question.
    Unsupported {
        /// What is missing.
        reason: UnsupportedReason,
    },
}

impl CleanupVerification {
    /// The stable snake_case name of the verdict, identical to the serde tag.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConfirmedAbsent { .. } => "confirmed_absent",
            Self::StillPresent { .. } => "still_present",
            Self::Indeterminate { .. } => "indeterminate",
            Self::Unsupported { .. } => "unsupported",
        }
    }

    /// Whether this verdict proves absence.
    ///
    /// The one question the state machine acts on: only a proof of absence
    /// records [`LifecycleOp::CleanupConfirmed`]. Every other verdict leaves
    /// the run exactly where it was.
    #[must_use]
    pub fn is_confirmed_absent(&self) -> bool {
        matches!(self, Self::ConfirmedAbsent { .. })
    }
}

impl std::fmt::Display for CleanupVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What proved that the recorded process is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum AbsenceBasis {
    /// `waitpid` reaped the direct child, *and* a probe of the process group it
    /// led found no members left, *and* the boot id still matches the one
    /// recorded at fork.
    ///
    /// The strongest answer this library can give for a run it supervised: the
    /// child is gone as a process object because it was reaped, and nothing it
    /// started remains in its group.
    ReapedAndGroupEmpty {
        /// The process group that was probed.
        pgid: i32,
    },

    /// A probe of the pid returned `ESRCH`: no process bears that number.
    PidAbsent {
        /// The pid that was probed.
        pid: i32,
    },

    /// The pid is alive but its start time differs from the recorded one, so
    /// the number was reissued and the recorded process is gone.
    IdentityMismatch {
        /// The pid whose current occupant is a different process.
        pid: i32,
    },

    /// The machine has rebooted since the identity was captured.
    ///
    /// No process survives a boot, so the recorded one cannot be running. This
    /// is checked before any pid probe: after a reboot a pid probe would be
    /// asking about a number that means something else entirely.
    BootIdChanged,
}

/// What was seen that is still there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "evidence", rename_all = "snake_case")]
pub enum SurvivorEvidence {
    /// `kill(-pgid, 0)` succeeded: at least one process remains in the run's
    /// process group.
    ///
    /// Which process is not reported, because the probe does not say. Note the
    /// module-level caveat: after the direct child is reaped its group number
    /// can in principle be reissued, so this is "something is in that group",
    /// not "a descendant of the run is provably alive".
    ProcessGroupMember {
        /// The process group that answered.
        pgid: i32,
    },

    /// The pid is alive and its start time still matches the recorded one, so
    /// it is the same process the identity was captured from.
    IdentityMatch {
        /// The pid that matched.
        pid: i32,
    },
}

/// Why a probe settled nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum IndeterminateReason {
    /// The recorded process group is not a number that may be probed.
    ///
    /// `kill(0, …)` names the *caller's own* process group and `kill(-1, …)`
    /// names everything the caller may signal. A group id of 0, 1, or below is
    /// therefore never handed to the kernel: a corrupt or fabricated record
    /// must not turn into a probe — and, on the stop path, a signal — aimed at
    /// the supervisor itself.
    UnprobableProcessGroup {
        /// The value that was refused.
        pgid: i32,
    },

    /// The recorded pid is not a number that may be probed, for the same
    /// reason as [`Self::UnprobableProcessGroup`].
    UnprobablePid {
        /// The value that was refused.
        pid: i32,
    },

    /// Something exists in that process group, but this process may not signal
    /// it (`EPERM`).
    ///
    /// Nothing follows from that in either direction: it may be a survivor of
    /// the run, or an unrelated process that was issued the same group number
    /// after the child was reaped.
    ProcessGroupProbeDenied {
        /// The process group that was probed.
        pgid: i32,
    },

    /// A process bears that pid, but this process may not signal it (`EPERM`),
    /// so it cannot be told apart from a reissued number.
    PidProbeDenied {
        /// The pid that was probed.
        pid: i32,
    },

    /// The probe failed for a reason that is neither absence nor denial.
    ProbeFailed {
        /// The pid or process group that was probed.
        target: i32,
        /// Platform error number from the probe.
        errno: i32,
    },

    /// The pid is alive, but its start time could not be read — now, or when
    /// the identity was captured — so a survivor cannot be told apart from a
    /// reissued pid.
    ///
    /// Deliberately not folded into either certainty. The fail-closed answer
    /// used by [`ProcessIdentity::is_same_process`] ("not the same process")
    /// would become a *proof of absence* here, which is the one place that
    /// conservatism inverts into an over-claim.
    IdentityUnreadable {
        /// The pid whose start time is unreadable.
        pid: i32,
    },
}

/// What a platform is missing that makes verification impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum UnsupportedReason {
    /// The platform has no process-existence probe this library can use.
    ///
    /// Unreachable on Linux and macOS, which both have `kill(pid, 0)`. The
    /// variant exists so a future port answers honestly instead of inheriting
    /// a verdict it cannot support.
    NoProcessProbe,
}

/// Cleanup verification was refused, naming the state that refused it.
///
/// Two situations reach this, and they are the same fact from the machine's
/// point of view: the run's end has not been observed yet (verification would
/// be probing a live run), or it has already been verified (a second
/// confirmation would count one proof twice).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Error)]
#[error("cleanup verification is not legal in state {state}")]
pub struct CleanupError {
    /// The state the machine was in when verification was attempted.
    pub state: LifecycleState,
}

/// Whether the run's own death was directly observed.
///
/// Chooses the probe, and nothing else. `Reaped` means `waitpid` returned for
/// the direct child, which is what makes the group the only remaining question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeathObservation {
    /// `waitpid` observed the child's death.
    Reaped,
    /// The death was never observed.
    NotReaped,
}

/// Probe, then record the confirmation if there was one.
///
/// The single implementation both handles share, so "when may cleanup be
/// verified" and "what moves the machine" have one definition. The transition
/// is returned rather than reported here: telling an event sink is consumer
/// code, and this runs with the shared core's lock in reach.
///
/// # Errors
///
/// [`CleanupError`] when verification is not legal in the state this call
/// found. Nothing is probed in that case.
pub(crate) fn verify_and_record(
    shared: &SharedLifecycle,
    identity: &ProcessIdentity,
    pgid: i32,
    death: DeathObservation,
) -> Result<(CleanupVerification, Option<Transition>), CleanupError> {
    // Advisory, and deliberately the same pure function the recording below
    // goes through: it is not a second source of truth, it is the same one read
    // early so that a run whose end was never observed is refused *before* a
    // probe is made about it.
    let observed = shared.state();
    if observed.apply(LifecycleOp::CleanupConfirmed).is_err() {
        return Err(CleanupError { state: observed });
    }

    let verification = match death {
        DeathObservation::Reaped => verify_after_reap(identity, pgid),
        DeathObservation::NotReaped => verify_identity(identity),
    };
    if !verification.is_confirmed_absent() {
        // Only a proof of absence moves the machine. A survivor, an
        // indeterminate probe, and an unsupported platform all leave the run
        // exactly where it was, so the caller can verify again later.
        return Ok((verification, None));
    }
    let change = shared
        .mark(LifecycleOp::CleanupConfirmed)
        .map_err(|err| CleanupError { state: err.from })?;
    Ok((verification, Some(change)))
}

/// Probe an identity and report the verdict, moving no state machine.
///
/// The read-only half of [`verify_and_record`], for the one caller that needs
/// the verdict *before* it has a state machine to move: a session recovered
/// from a durable record, which must reconcile what the record claims against
/// what the kernel says before it trusts either. Recording the answer is still
/// [`verify_and_record`]'s job.
pub(crate) fn probe_identity(identity: &ProcessIdentity) -> CleanupVerification {
    verify_identity(identity)
}

/// Verify a run whose direct child was reaped, by probing its process group.
///
/// `waitpid` already settled the child itself: a reaped pid names no process.
/// What remains is whatever it forked, which shares its process group because
/// the child made itself a group leader before it ran anything.
fn verify_after_reap(identity: &ProcessIdentity, pgid: i32) -> CleanupVerification {
    if let Some(rebooted) = rebooted_since_capture(identity) {
        return rebooted;
    }
    if pgid <= 1 {
        return CleanupVerification::Indeterminate {
            reason: IndeterminateReason::UnprobableProcessGroup { pgid },
        };
    }
    match probe_group(pgid) {
        Err(reason) => CleanupVerification::Unsupported { reason },
        Ok(Probe::Absent) => CleanupVerification::ConfirmedAbsent {
            basis: AbsenceBasis::ReapedAndGroupEmpty { pgid },
        },
        Ok(Probe::Present) => CleanupVerification::StillPresent {
            survivors: SurvivorEvidence::ProcessGroupMember { pgid },
        },
        Ok(Probe::Denied) => CleanupVerification::Indeterminate {
            reason: IndeterminateReason::ProcessGroupProbeDenied { pgid },
        },
        Ok(Probe::Failed(errno)) => CleanupVerification::Indeterminate {
            reason: IndeterminateReason::ProbeFailed {
                target: pgid,
                errno,
            },
        },
    }
}

/// Verify a process whose death was never observed, from its identity alone.
///
/// General over [`ProcessIdentity`] on purpose: the same function answers for a
/// supervisor whose own `waitpid` failed and for a session recovered from a
/// durable record after a restart, neither of which has a reap to lean on.
///
/// [`ProcessIdentity::is_same_process`] is deliberately *not* used here. It
/// fails closed to "not the same process", which is the safe answer when the
/// question is "may I trust this pid" — and exactly the wrong one when the
/// question is "is it gone", where it would turn an unreadable start time into
/// a proof of absence.
fn verify_identity(identity: &ProcessIdentity) -> CleanupVerification {
    if let Some(rebooted) = rebooted_since_capture(identity) {
        return rebooted;
    }
    let pid = identity.pid();
    if pid <= 0 {
        return CleanupVerification::Indeterminate {
            reason: IndeterminateReason::UnprobablePid { pid },
        };
    }
    match probe_pid(pid) {
        Err(reason) => CleanupVerification::Unsupported { reason },
        Ok(Probe::Absent) => CleanupVerification::ConfirmedAbsent {
            basis: AbsenceBasis::PidAbsent { pid },
        },
        Ok(Probe::Denied) => CleanupVerification::Indeterminate {
            reason: IndeterminateReason::PidProbeDenied { pid },
        },
        Ok(Probe::Failed(errno)) => CleanupVerification::Indeterminate {
            reason: IndeterminateReason::ProbeFailed { target: pid, errno },
        },
        // The pid is taken. Whether it is taken by *our* process is what the
        // start time answers.
        Ok(Probe::Present) => match (identity.start_time(), process_start_time(pid)) {
            (Some(recorded), Some(current)) if recorded == current => {
                CleanupVerification::StillPresent {
                    survivors: SurvivorEvidence::IdentityMatch { pid },
                }
            }
            (Some(_), Some(_)) => CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::IdentityMismatch { pid },
            },
            _ => CleanupVerification::Indeterminate {
                reason: IndeterminateReason::IdentityUnreadable { pid },
            },
        },
    }
}

/// `ConfirmedAbsent` when the boot changed since the identity was captured.
///
/// `None` when the two boot ids agree, and also when either read produced
/// nothing: a platform that will not name the boot leaves the question to the
/// probe rather than answering it by default in either direction.
fn rebooted_since_capture(identity: &ProcessIdentity) -> Option<CleanupVerification> {
    let (Some(recorded), Some(current)) = (identity.boot_id(), boot_id()) else {
        return None;
    };
    if recorded == current {
        return None;
    }
    Some(CleanupVerification::ConfirmedAbsent {
        basis: AbsenceBasis::BootIdChanged,
    })
}

/// What a signal-0 probe found.
///
/// Crate-internal rather than private to this module: [`super::SupportReport`]
/// reports whether the probes cleanup verification is built on answer at all on
/// this host, and it must ask that question with the *same* mechanism this
/// module uses rather than a second copy that could drift from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    /// The target exists and is signalable by this process.
    Present,
    /// `ESRCH`: nothing under that number.
    Absent,
    /// `EPERM`: something is there, and it is not ours to signal.
    Denied,
    /// Anything else the platform returned.
    Failed(i32),
}

/// Does a process with this pid exist? Signal 0 checks without delivering.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn probe_pid(pid: i32) -> Result<Probe, UnsupportedReason> {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    Ok(classify(kill(Pid::from_raw(pid), None)))
}

/// Does any process remain in this group? Signal 0 checks without delivering.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn probe_group(pgid: i32) -> Result<Probe, UnsupportedReason> {
    use nix::sys::signal::killpg;
    use nix::unistd::Pid;

    Ok(classify(killpg(Pid::from_raw(pgid), None)))
}

/// Turn a signal-0 result into the three answers it can carry.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn classify(result: nix::Result<()>) -> Probe {
    match result {
        Ok(()) => Probe::Present,
        Err(nix::errno::Errno::ESRCH) => Probe::Absent,
        Err(nix::errno::Errno::EPERM) => Probe::Denied,
        Err(errno) => Probe::Failed(errno as i32),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn probe_pid(_pid: i32) -> Result<Probe, UnsupportedReason> {
    Err(UnsupportedReason::NoProcessProbe)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn probe_group(_pgid: i32) -> Result<Probe, UnsupportedReason> {
    Err(UnsupportedReason::NoProcessProbe)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_pid() -> i32 {
        i32::try_from(std::process::id()).unwrap_or(0)
    }

    /// This process, as it really is: alive, with a readable start time and the
    /// current boot id.
    fn live_identity() -> ProcessIdentity {
        ProcessIdentity::capture(current_pid())
    }

    // -----------------------------------------------------------------------
    // The not-reaped path: pid reuse, reboot, and the live case.
    // -----------------------------------------------------------------------

    #[test]
    fn a_reused_pid_proves_the_recorded_process_is_gone() {
        // The pid is live — it is this test process — but the recorded start
        // time belongs to a process that ran earlier under the same number.
        // "Something answers to pid N" must not be read as "our process is
        // still running".
        let live = live_identity();
        let reused = ProcessIdentity::from_parts(
            live.pid(),
            live.start_time().map(|value| value.wrapping_sub(1)),
            live.boot_id().map(str::to_string),
        );
        assert_eq!(
            verify_identity(&reused),
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::IdentityMismatch { pid: reused.pid() }
            }
        );
    }

    #[test]
    fn a_live_matching_identity_is_reported_as_still_present() {
        // The same probe, one field different: this is what keeps the reused-pid
        // verdict above from being a function that always says "absent".
        let live = live_identity();
        assert_eq!(
            verify_identity(&live),
            CleanupVerification::StillPresent {
                survivors: SurvivorEvidence::IdentityMatch { pid: live.pid() }
            }
        );
    }

    #[test]
    fn a_boot_change_proves_absence_without_probing_the_pid() {
        // The pid is this live process, so a probe would answer "present". The
        // boot check runs first and ends the question: nothing survives a
        // reboot, and after one the number means something else entirely.
        let live = live_identity();
        let previous_boot = ProcessIdentity::from_parts(
            live.pid(),
            live.start_time(),
            Some("boot-that-is-not-this-one".to_string()),
        );
        assert_eq!(
            verify_identity(&previous_boot),
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::BootIdChanged
            }
        );
        // And on the reaped path too, where the group number would otherwise be
        // probed against whatever now holds it.
        assert_eq!(
            verify_after_reap(&previous_boot, live.pid()),
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::BootIdChanged
            }
        );
    }

    #[test]
    fn an_unreadable_start_time_is_indeterminate_not_a_proof_of_absence() {
        // Fail-closed identity checking answers "not the same process" here,
        // which would become "the process is gone" — the one place that
        // conservatism inverts into an over-claim.
        let live = live_identity();
        let unrecorded =
            ProcessIdentity::from_parts(live.pid(), None, live.boot_id().map(str::to_string));
        assert_eq!(
            verify_identity(&unrecorded),
            CleanupVerification::Indeterminate {
                reason: IndeterminateReason::IdentityUnreadable { pid: live.pid() }
            }
        );
    }

    #[test]
    fn a_pid_no_process_can_hold_is_confirmed_absent() {
        // Far above any pid the platform issues, so the probe reliably returns
        // ESRCH rather than finding a bystander.
        let absent = ProcessIdentity::from_parts(i32::MAX, Some(1), boot_id());
        assert_eq!(
            verify_identity(&absent),
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::PidAbsent { pid: i32::MAX }
            }
        );
    }

    // -----------------------------------------------------------------------
    // Targets that must never reach the kernel.
    // -----------------------------------------------------------------------

    #[test]
    fn a_process_group_that_would_name_our_own_is_never_probed() {
        // kill(0, …) means "my own process group" and kill(-1, …) means
        // "everything I may signal". A record carrying either would make the
        // supervisor probe — and, on the stop path, signal — itself.
        let live = live_identity();
        for pgid in [0, 1, -1, i32::MIN] {
            assert_eq!(
                verify_after_reap(&live, pgid),
                CleanupVerification::Indeterminate {
                    reason: IndeterminateReason::UnprobableProcessGroup { pgid }
                },
                "pgid {pgid} must never be probed"
            );
        }
    }

    #[test]
    fn a_pid_that_would_name_our_own_group_is_never_probed() {
        for pid in [0, -1, i32::MIN] {
            let identity = ProcessIdentity::from_parts(pid, Some(1), boot_id());
            assert_eq!(
                verify_identity(&identity),
                CleanupVerification::Indeterminate {
                    reason: IndeterminateReason::UnprobablePid { pid }
                },
                "pid {pid} must never be probed"
            );
        }
    }

    // -----------------------------------------------------------------------
    // The reaped path.
    // -----------------------------------------------------------------------

    #[test]
    fn a_group_with_a_live_member_is_reported_as_still_present() {
        // This test process is in some process group, and it is alive, so the
        // probe must find it. A verifier that reported absence here would
        // report absence for a run that was still going.
        let live = live_identity();
        // SAFETY: `getpgrp` takes no arguments, touches no memory, and cannot
        // fail; it reports the caller's own process group.
        let own_group = unsafe { libc::getpgrp() };
        assert!(own_group > 1, "test harness must be in a real group");
        assert_eq!(
            verify_after_reap(&live, own_group),
            CleanupVerification::StillPresent {
                survivors: SurvivorEvidence::ProcessGroupMember { pgid: own_group }
            }
        );
    }

    #[test]
    fn an_empty_group_after_a_reap_is_confirmed_absent() {
        let live = live_identity();
        assert_eq!(
            verify_after_reap(&live, i32::MAX),
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::ReapedAndGroupEmpty { pgid: i32::MAX }
            }
        );
    }

    // -----------------------------------------------------------------------
    // Recording: only absence moves the machine.
    // -----------------------------------------------------------------------

    #[test]
    fn only_a_proof_of_absence_records_the_confirmation() {
        let shared = SharedLifecycle::new(LifecycleState::Exited);
        let live = live_identity();
        // SAFETY: as above.
        let own_group = unsafe { libc::getpgrp() };

        let (verdict, change) =
            match verify_and_record(&shared, &live, own_group, DeathObservation::Reaped) {
                Ok(pair) => pair,
                Err(err) => panic!("verification must be legal in Exited: {err}"),
            };
        assert!(matches!(verdict, CleanupVerification::StillPresent { .. }));
        assert_eq!(change, None, "a survivor must not move the machine");
        assert_eq!(shared.state(), LifecycleState::Exited);
    }

    #[test]
    fn a_confirmed_absence_moves_the_machine_exactly_once() {
        let shared = SharedLifecycle::new(LifecycleState::Stopped);
        let absent = ProcessIdentity::from_parts(i32::MAX, Some(1), boot_id());

        let (verdict, change) =
            match verify_and_record(&shared, &absent, i32::MAX, DeathObservation::Reaped) {
                Ok(pair) => pair,
                Err(err) => panic!("verification must be legal in Stopped: {err}"),
            };
        assert!(verdict.is_confirmed_absent());
        assert_eq!(
            change,
            Some(Transition {
                from: LifecycleState::Stopped,
                to: LifecycleState::CleanupVerified,
            })
        );

        // The second attempt is refused by the machine, not absorbed: counting
        // one proof twice is a caller bug worth seeing.
        assert_eq!(
            verify_and_record(&shared, &absent, i32::MAX, DeathObservation::Reaped),
            Err(CleanupError {
                state: LifecycleState::CleanupVerified
            })
        );
    }

    #[test]
    fn a_run_whose_end_was_never_observed_is_refused_before_anything_is_probed() {
        for state in [
            LifecycleState::Planning,
            LifecycleState::Preparing,
            LifecycleState::Prepared,
            LifecycleState::Activating,
            LifecycleState::Running,
            LifecycleState::Stopping,
        ] {
            let shared = SharedLifecycle::new(state);
            assert_eq!(
                verify_and_record(
                    &shared,
                    &live_identity(),
                    i32::MAX,
                    DeathObservation::NotReaped
                ),
                Err(CleanupError { state }),
                "verification must be refused in {state}"
            );
            assert_eq!(shared.state(), state, "a refusal must move nothing");
        }
    }

    #[test]
    fn the_death_observation_chooses_the_probe() {
        // Same inputs, two different questions: reaped asks about the group,
        // not-reaped asks about the pid. A single shared implementation that
        // ignored the distinction would answer the wrong one.
        let live = live_identity();
        let shared = SharedLifecycle::new(LifecycleState::Failed);
        let (reaped, _) =
            match verify_and_record(&shared, &live, i32::MAX, DeathObservation::Reaped) {
                Ok(pair) => pair,
                Err(err) => panic!("verification must be legal in Failed: {err}"),
            };
        assert_eq!(
            reaped,
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::ReapedAndGroupEmpty { pgid: i32::MAX }
            }
        );

        let shared = SharedLifecycle::new(LifecycleState::Failed);
        let (not_reaped, _) =
            match verify_and_record(&shared, &live, i32::MAX, DeathObservation::NotReaped) {
                Ok(pair) => pair,
                Err(err) => panic!("verification must be legal in Failed: {err}"),
            };
        assert_eq!(
            not_reaped,
            CleanupVerification::StillPresent {
                survivors: SurvivorEvidence::IdentityMatch { pid: live.pid() }
            }
        );
    }

    // -----------------------------------------------------------------------
    // Wire shape.
    // -----------------------------------------------------------------------

    #[test]
    fn every_verdict_round_trips_through_serde() -> Result<(), serde_json::Error> {
        let verdicts = [
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::ReapedAndGroupEmpty { pgid: 42 },
            },
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::PidAbsent { pid: 42 },
            },
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::IdentityMismatch { pid: 42 },
            },
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::BootIdChanged,
            },
            CleanupVerification::StillPresent {
                survivors: SurvivorEvidence::ProcessGroupMember { pgid: 42 },
            },
            CleanupVerification::StillPresent {
                survivors: SurvivorEvidence::IdentityMatch { pid: 42 },
            },
            CleanupVerification::Indeterminate {
                reason: IndeterminateReason::UnprobableProcessGroup { pgid: 0 },
            },
            CleanupVerification::Indeterminate {
                reason: IndeterminateReason::UnprobablePid { pid: 0 },
            },
            CleanupVerification::Indeterminate {
                reason: IndeterminateReason::ProcessGroupProbeDenied { pgid: 42 },
            },
            CleanupVerification::Indeterminate {
                reason: IndeterminateReason::PidProbeDenied { pid: 42 },
            },
            CleanupVerification::Indeterminate {
                reason: IndeterminateReason::ProbeFailed {
                    target: 42,
                    errno: 22,
                },
            },
            CleanupVerification::Indeterminate {
                reason: IndeterminateReason::IdentityUnreadable { pid: 42 },
            },
            CleanupVerification::Unsupported {
                reason: UnsupportedReason::NoProcessProbe,
            },
        ];
        for verdict in verdicts {
            let json = serde_json::to_string(&verdict)?;
            assert_eq!(serde_json::from_str::<CleanupVerification>(&json)?, verdict);
            assert!(
                json.contains(&format!("\"kind\":\"{}\"", verdict.as_str())),
                "{json}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_sent_signal_is_never_part_of_a_verdict() {
        // The type cannot express "we killed it, so it must be gone": every
        // basis names an observation made after the fact. This test is the
        // written form of that contract — it fails to compile, not to assert,
        // if a "signalled" basis is ever added.
        let bases = [
            AbsenceBasis::ReapedAndGroupEmpty { pgid: 2 },
            AbsenceBasis::PidAbsent { pid: 2 },
            AbsenceBasis::IdentityMismatch { pid: 2 },
            AbsenceBasis::BootIdChanged,
        ];
        for basis in bases {
            match basis {
                AbsenceBasis::ReapedAndGroupEmpty { .. }
                | AbsenceBasis::PidAbsent { .. }
                | AbsenceBasis::IdentityMismatch { .. }
                | AbsenceBasis::BootIdChanged => {}
            }
        }
    }

    #[test]
    fn verdict_display_matches_the_serde_tag() {
        let verdict = CleanupVerification::Unsupported {
            reason: UnsupportedReason::NoProcessProbe,
        };
        assert_eq!(verdict.to_string(), "unsupported");
        assert_eq!(verdict.as_str(), "unsupported");
        assert!(!verdict.is_confirmed_absent());
    }

    #[test]
    fn cleanup_error_names_the_state_that_refused() {
        let err = CleanupError {
            state: LifecycleState::Running,
        };
        assert!(err.to_string().contains("running"), "{err}");
    }
}
