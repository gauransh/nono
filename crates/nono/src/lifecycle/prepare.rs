//! Forking a child that sandboxes itself and then *waits* before `execve`.
//!
//! Everything expensive happens in the parent, before the fork: the program
//! path is resolved, the argv and environment are turned into C buffers, and
//! the platform sandbox policy is fully built (on Linux, down to the opened
//! path descriptors). What is left for the child is a short, fixed sequence of
//! async-signal-safe syscalls.
//!
//! # The child's sequence
//!
//! 1. close the parent's end of both channels
//! 2. apply the platform sandbox to itself
//! 3. close every other inherited descriptor
//! 4. write the "at the gate" record to the status descriptor
//! 5. block in `read()` on the gate descriptor
//! 6. on the release message: enter the working directory, then `execve`
//!
//! Any failure writes a fixed-size record to the status descriptor and exits.
//! Nothing between step 2 and `execve` runs unconfined, and the customer's
//! program never runs at all unless step 5 produced the release message.
//!
//! Step 3 sits after the sandbox apply rather than before it because on Linux
//! the prepared Landlock ruleset *is* a set of open path descriptors, and
//! `apply_raw` needs them. It sits before step 4 so that by the time `prepare`
//! returns, the held child holds nothing but its own two channel ends — see
//! below.
//!
//! # Descriptors
//!
//! Two pipes, four ends, every one close-on-exec and every one above the
//! standard stream numbers:
//!
//! | End | Parent | Child |
//! |-----|--------|-------|
//! | gate read | closed immediately after fork | held; read once; closed by `execve` |
//! | gate write | held until release, stop, expiry, or drop | closed immediately after fork |
//! | status read | held until the activation outcome is known | closed immediately after fork |
//! | status write | closed immediately after fork | held; written on failure; closed by `execve` |
//! | everything else | untouched | closed in step 3 |
//!
//! Three properties fall out of that table.
//!
//! The parent closing the status write end is what makes EOF meaningful: once
//! the child `execve`s, the last copy of that descriptor closes atomically. A
//! read of zero bytes with no record is therefore *almost* proof that exec
//! happened — a child killed between release and `execve` produces the same
//! EOF, which is why the result is the three-valued
//! [`ActivationObservation`][super::ActivationObservation] rather than a bool.
//!
//! The child closing the gate write end is what makes supervisor death
//! survivable: if the parent goes away, the gate's last writer is gone, the
//! child's `read()` returns 0, and it exits instead of waiting forever. This
//! only works if *no other process* is holding a copy — which is exactly what
//! step 3 guarantees. Without it, two overlapping `prepare` calls would each
//! leave the other's child holding its gate open, and neither could ever
//! observe a dead supervisor.
//!
//! Both channel ends are close-on-exec and everything else is already gone, so
//! the customer's program starts with descriptors 0, 1, and 2 and nothing
//! else: no channel of nono's, and nothing the embedding process happened to
//! have open.
//!
//! # The gate messages are secrets, not constants
//!
//! A held child is released by a 16-byte value drawn from the system CSPRNG
//! before the fork, not by a fixed byte. A descriptor can be inherited, sent
//! over a socket, or left behind by a fork nobody intended; if the release
//! were a constant, every one of those copies would be a start button. With a
//! secret, a copy of the descriptor without the secret can only make the child
//! refuse and exit. See [`super::gate`].
//!
//! # Failures are records, not exit codes
//!
//! A child that cannot start reports *why* through a five-byte record on the
//! status descriptor — a stage tag and an errno — and only then exits. The exit
//! code is deliberately not the protocol: the customer program owns the whole
//! exit-code space, so any sentinel nono chose would also be a status some real
//! program returns, and reading it back would mislabel that program's own exit.
//! See [`super::exit`].

use super::events::{EventSink, LifecycleEvent, Observation};
use super::exit::{
    ActivatedSandbox, ActivationObservation, ExitOutcome, PRE_EXEC_EXIT_CODE, PreExecStage,
    STATUS_RECORD_LEN, SandboxExit, SupervisorStage, TAG_GATE_READY, kill_and_reap,
    kill_and_reap_observed, reap,
};
use super::gate::{
    ACTIVATION_TOKEN_BYTES, ActivationError, ActivationHandle, GATE_MESSAGE_BYTES, GateDecision,
    GateSecrets, StopError, TOKEN_DIGEST_BYTES, ct_eq, token_digest,
};
use super::identity::ProcessIdentity;
use super::plan::{ResourceLimits, SessionMode, ValidatedPlan};
use super::state::{LifecycleOp, LifecycleState, TransitionError};
use std::ffi::{CString, c_char};
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// The generation of a freshly prepared session.
///
/// Generations climb when a session is re-prepared, which needs the durable
/// store; until that lands every prepared sandbox is generation 1.
const FIRST_GENERATION: u64 = 1;

/// Everything `prepare` can refuse to do.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PrepareError {
    /// The program is not an absolute path.
    ///
    /// The library never searches `PATH`: doing it in the parent would resolve
    /// against the supervisor's environment rather than the plan's, and doing
    /// it in the child would mean running a name lookup after the sandbox is
    /// applied. A caller who wants `PATH` semantics resolves them itself and
    /// puts the answer in the plan.
    #[error("plan program must be an absolute path: {program}")]
    ProgramNotAbsolute {
        /// The program as the plan named it.
        program: String,
    },

    /// The program could not be inspected at prepare time.
    #[error("plan program {program} is unusable: errno {errno}")]
    ProgramUnusable {
        /// The path that was inspected.
        program: PathBuf,
        /// Platform error number from the inspection.
        errno: i32,
    },

    /// The program path names something that is not a regular file.
    #[error("plan program {program} is not a regular file")]
    ProgramNotAFile {
        /// The path that was inspected.
        program: PathBuf,
    },

    /// The plan asks for something this slice does not implement.
    ///
    /// Refused rather than quietly ignored. A caller who asked for a PTY, a
    /// detached run, or a memory ceiling and silently received none of them
    /// would be relying on a guarantee that is not there — which is exactly
    /// the failure mode the whole module exists to avoid.
    #[error("plan feature not supported by this lifecycle: {feature}")]
    UnsupportedPlanFeature {
        /// The feature that was asked for.
        feature: &'static str,
    },

    /// The platform sandbox policy could not be built from the plan's
    /// capabilities.
    #[error("sandbox policy could not be prepared: {reason}")]
    SandboxSpec {
        /// Why the policy was refused.
        reason: String,
    },

    /// A gate or status channel could not be created.
    #[error("lifecycle channel setup failed: errno {errno}")]
    ChannelSetup {
        /// Platform error number.
        errno: i32,
    },

    /// The activation token could not be generated. Without unforgeable
    /// randomness there is no gate, so this is fatal rather than degraded.
    #[error("activation token could not be generated")]
    TokenGeneration,

    /// `fork` failed, so no child exists.
    #[error("fork failed: errno {errno}")]
    Fork {
        /// Platform error number.
        errno: i32,
    },

    /// The child died before reaching the gate. Carries the typed facts.
    #[error("child failed before reaching the activation gate")]
    ChildFailed {
        /// What was observed about the child's death.
        exit: SandboxExit,
    },

    /// The state machine refused a transition. A library bug if it is ever
    /// seen, reported rather than panicked on.
    #[error(transparent)]
    Transition(#[from] TransitionError),
}

/// A forked, sandboxed child held at the activation gate.
///
/// The child has already applied its sandbox and is blocked before `execve`.
/// It runs the customer's program only if [`Self::activate`] is given the
/// matching [`ActivationHandle`]; if this value is dropped first, the child is
/// killed and reaped instead.
///
/// # After a successful activation
///
/// Ownership of the run moves to the returned [`ActivatedSandbox`]. This value
/// keeps reporting the state it had at that moment — [`LifecycleState::Running`]
/// — and does not follow the run any further: it never learns that the program
/// exited, and its [`Self::exit`] stays empty. Ask the [`ActivatedSandbox`]
/// instead. Keeping it frozen is deliberate; a second handle that silently went
/// stale would be worse than one that visibly stopped at the handoff.
///
/// # Example
///
/// ```no_run
/// use nono::lifecycle::{ActivationObservation, PreparedSandbox, SandboxPlan};
///
/// let plan = SandboxPlan::new("/bin/echo").arg("hello").validate()?;
/// let (mut prepared, handle) = PreparedSandbox::prepare(plan)?;
///
/// // Nothing has run yet: the child is sandboxed and waiting.
/// let mut activated = prepared.activate(&handle)?;
/// let exit = activated.wait()?;
/// assert_eq!(exit.activation(), ActivationObservation::Observed);
/// # Ok::<(), nono::NonoError>(())
/// ```
pub struct PreparedSandbox {
    session_id: Uuid,
    generation: u64,
    identity: ProcessIdentity,
    state: LifecycleState,
    gate: Option<PipeWriter>,
    status: Option<PipeReader>,
    token_digest: [u8; TOKEN_DIGEST_BYTES],
    /// The release/abort pair this child will accept. Dropped — and so
    /// zeroized — as soon as the gate closes.
    secrets: Option<GateSecrets>,
    expiry: Option<Duration>,
    prepared_at: Instant,
    child_owned: bool,
    last_exit: Option<SandboxExit>,
    event_sink: Option<Arc<dyn EventSink>>,
}

impl PreparedSandbox {
    /// Fork a child, sandbox it, and hold it at the gate.
    ///
    /// Returns the held child and the one handle that can release it. The
    /// handle is the only copy of the token; this value keeps a digest.
    ///
    /// Blocks until the child reports that its sandbox is applied and it has
    /// reached the gate, so a returned `PreparedSandbox` is a *confined* child,
    /// not merely a forked one.
    ///
    /// # Errors
    ///
    /// [`PrepareError`] if the plan cannot be turned into a runnable image, the
    /// platform policy cannot be built, the channels or the token cannot be
    /// created, `fork` fails, or the child dies before reaching the gate. In
    /// every case no child is left behind.
    #[must_use = "a prepared child is held until it is activated, stopped, or dropped"]
    pub fn prepare(plan: ValidatedPlan) -> Result<(Self, ActivationHandle), PrepareError> {
        refuse_unsupported(&plan)?;
        let program = resolve_program(plan.program())?;
        let image = ExecImage::build(&program, &plan)?;
        let sandbox = PlatformSandbox::build(&plan)?;
        let (argv_ptrs, envp_ptrs) = image.pointers();

        // Both pairs are moved above the standard stream numbers if they
        // landed on one, which they can when the embedding process has closed
        // stdin, stdout, or stderr. That keeps two invariants simple: the
        // child's close-everything sweep can start at 3, and the customer's
        // program never finds a nono channel sitting on descriptor 0.
        let (gate_read, gate_write) = open_channel()?;
        let (status_read, status_write) = open_channel()?;

        let secrets = GateSecrets::generate().map_err(|_| PrepareError::TokenGeneration)?;
        let session_id = Uuid::now_v7();
        let prepared_at = Instant::now();
        let state = LifecycleState::Planning.apply(LifecycleOp::BeginPrepare)?;

        // Built before the fork so the child's path allocates nothing. The
        // parent never touches it: after the fork its descriptor numbers name
        // ends the parent has closed.
        let context = ChildContext {
            gate_read: gate_read.as_raw_fd(),
            gate_write: gate_write.as_raw_fd(),
            status_read: status_read.as_raw_fd(),
            status_write: status_write.as_raw_fd(),
            program: image.program.as_ptr(),
            argv: argv_ptrs.as_ptr(),
            envp: envp_ptrs.as_ptr(),
            working_dir: image
                .working_dir
                .as_ref()
                .map_or(std::ptr::null(), |dir| dir.as_ptr()),
            sandbox: &sandbox,
            secrets: &secrets,
        };

        // SAFETY: `fork` duplicates this process. The child branch below runs
        // only async-signal-safe syscalls over buffers built above and then
        // `_exit`s or `execve`s, so it never returns into Rust code, never
        // unwinds, and never runs a destructor. The one exception is the macOS
        // sandbox apply, which allocates inside `sandbox_init`; that matches
        // upstream's Supervised strategy and is documented on
        // `PlatformSandbox::apply_in_child`.
        let forked = unsafe { nix::unistd::fork() }.map_err(|errno| PrepareError::Fork {
            errno: errno as i32,
        })?;

        match forked {
            nix::unistd::ForkResult::Child => child_main(&context),
            nix::unistd::ForkResult::Parent { child } => {
                // Order matters: the parent's copies of the child's ends close
                // first, so that a later EOF on the status descriptor can only
                // mean the child's own copy went away.
                drop(gate_read);
                drop(status_write);

                let mut prepared = Self {
                    session_id,
                    generation: FIRST_GENERATION,
                    identity: ProcessIdentity::capture(child.as_raw()),
                    state,
                    gate: Some(gate_write),
                    status: Some(status_read),
                    // Replaced two lines down. A digest of all zeros matches no
                    // token anyone can present, so the gate is shut for the
                    // moment it holds this value; if the draw below fails,
                    // `prepared` is dropped and the child never runs.
                    token_digest: [0_u8; TOKEN_DIGEST_BYTES],
                    secrets: Some(secrets),
                    expiry: plan.gate().activation_expiry,
                    prepared_at,
                    child_owned: true,
                    last_exit: None,
                    event_sink: plan.event_sink().cloned(),
                };

                // Drawn *after* the fork so the token never exists in the
                // child's address space at all — not even for the microseconds
                // between fork and exec. The child has no use for it: it holds
                // the gate secrets, and the token is what proves a caller may
                // send one.
                let mut token = Zeroizing::new([0_u8; ACTIVATION_TOKEN_BYTES]);
                getrandom::fill(token.as_mut()).map_err(|_| PrepareError::TokenGeneration)?;
                prepared.token_digest = token_digest(&token);

                // On failure `prepared` is dropped here, which aborts the gate
                // and reaps the child: no zombie, no held process.
                prepared.observe_prepare()?;
                Ok((
                    prepared,
                    ActivationHandle::new(session_id, FIRST_GENERATION, *token),
                ))
            }
        }
    }

    /// The session this prepared child belongs to.
    #[must_use]
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// The generation of this preparation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Where the run was when this handle last touched it.
    ///
    /// After a successful [`Self::activate`] this stays at
    /// [`LifecycleState::Running`] for good; the [`ActivatedSandbox`] is what
    /// tracks the run from there.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.state
    }

    /// The child's identity, captured at fork.
    #[must_use]
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// The exit facts recorded on this handle, if the run ended here.
    ///
    /// Set when the run ends before the customer's program takes over: a failed
    /// activation, a stop, or an expiry. A successful activation moves the run
    /// to the [`ActivatedSandbox`], and this stays empty — that handle reports
    /// the exit instead.
    #[must_use]
    pub fn exit(&self) -> Option<&SandboxExit> {
        self.last_exit.as_ref()
    }

    /// Release the held child, exactly once.
    ///
    /// Checks, in order: the handle names this session, it names this
    /// generation, the gate is still open, the gate has not expired, and the
    /// token matches (compared in constant time). Only then is the release
    /// message written, and the return waits for a directly observed outcome.
    ///
    /// Expiry is checked *before* the token, so presenting a wrong token to an
    /// expired gate still stops the child: the deadline is a property of the
    /// gate, not a judgement about the caller.
    ///
    /// Takes the handle by reference on purpose: the single-use guarantee must
    /// hold against a caller who kept a copy of it, so it lives in the gate's
    /// state rather than in Rust's move semantics.
    ///
    /// # Errors
    ///
    /// [`ActivationError`] naming exactly which check refused. A second call —
    /// with this handle or any other — never releases anything.
    pub fn activate(
        &mut self,
        handle: &ActivationHandle,
    ) -> Result<ActivatedSandbox, ActivationError> {
        if handle.session_id() != self.session_id {
            return Err(ActivationError::WrongSession {
                expected: self.session_id,
                supplied: handle.session_id(),
            });
        }
        if handle.generation() != self.generation {
            return Err(ActivationError::WrongGeneration {
                expected: self.generation,
                supplied: handle.generation(),
            });
        }
        // The gate is open in exactly one state, and leaving that state is the
        // only thing that closes it. Once closed, no token opens it, the
        // digest has already been zeroized, and the state machine already
        // knows why — so the checks below run only while their answers could
        // still matter. This is not a second source of truth: it reads the
        // same machine the transition further down advances.
        if self.state != LifecycleState::Prepared {
            return Err(ActivationError::from_closed_gate(self.state));
        }
        if self.has_expired() {
            // Expiry is terminal: a correct token presented late must not work
            // now or ever, so the gate is closed and the child is stopped
            // before the token is even looked at. A later attempt finds the
            // stopped state this leaves behind.
            return Err(self.expire());
        }
        if !ct_eq(&token_digest(handle.token()), &self.token_digest) {
            return Err(ActivationError::InvalidActivationToken);
        }

        // The compare-and-swap. The state machine, not a flag beside it,
        // decides whether this activation is the one that wins.
        if self.transition(LifecycleOp::BeginActivate).is_err() {
            return Err(ActivationError::from_closed_gate(self.state));
        }

        if let Err(errno) = self.release() {
            return Err(self.fail_activation(SupervisorStage::Release, errno));
        }

        let record = match self.status.as_mut() {
            Some(status) => read_status_record(status),
            None => Err(0),
        };
        match record {
            // EOF with no record: the close-on-exec status descriptor went
            // away. `execve` does that — and so does a child killed in the
            // window just before it, which is why the observation handed on
            // here is the ambiguous one. `wait` resolves it.
            Ok(None) => {
                self.transition(LifecycleOp::ExecObserved)
                    .map_err(|err| ActivationError::GateUnavailable { state: err.from })?;
                self.close_gate();
                // Both channels have done their work; the child now owns
                // nothing of ours and nothing of the child's remains open here.
                self.status = None;
                self.child_owned = false;
                self.zeroize_secrets();
                Ok(ActivatedSandbox::new(
                    self.identity.clone(),
                    self.state,
                    ActivationObservation::ExecOrKilledPreExec,
                    self.event_sink.clone(),
                ))
            }
            Ok(Some((tag, errno))) => {
                let stage = PreExecStage::from_tag(tag);
                Err(self.fail_pre_exec(stage, errno))
            }
            Err(errno) => Err(self.fail_activation(SupervisorStage::StatusRead, errno)),
        }
    }

    /// Stop a held child that has not been activated.
    ///
    /// Aborts the gate, closes it, and waits for the child to actually die.
    /// After this, activation is refused forever: the state machine has left
    /// `Prepared` and can never return to it.
    ///
    /// # Errors
    ///
    /// [`StopError::NotStoppable`] if the run has already been activated,
    /// stopped, or failed; [`StopError::Reap`] if the death could not be
    /// observed, in which case nothing is claimed about the process.
    pub fn stop_before_activation(&mut self) -> Result<SandboxExit, StopError> {
        self.transition(LifecycleOp::BeginStop)
            .map_err(|err| StopError::NotStoppable { state: err.from })?;
        self.abort_gate();

        // Read before reaping. A child that took the abort says so in a record,
        // and that record is the fact worth keeping: its exit *code* is nono's
        // own pre-exec constant, and reporting `Exited { code: 1 }` for a
        // deliberate stop would be the sentinel-as-fact mistake this module
        // exists to avoid.
        let outcome = self.observe_gate_ending();
        let reaped = reap(self.identity.pid())?;
        self.child_owned = false;
        self.transition(LifecycleOp::StopObserved)
            .map_err(|err| StopError::NotStoppable { state: err.from })?;
        self.status = None;
        self.zeroize_secrets();

        let exit = SandboxExit::new(
            outcome.unwrap_or(reaped),
            ActivationObservation::NotActivated,
            self.identity.clone(),
        );
        self.last_exit = Some(exit.clone());
        Ok(exit)
    }

    /// Apply an observed fact, recording it and telling the sink.
    ///
    /// Every state change in this module goes through here, so there is exactly
    /// one place where the machine can move and no way to keep a second,
    /// disagreeing copy of "where we are".
    fn transition(&mut self, op: LifecycleOp) -> Result<LifecycleState, TransitionError> {
        let from = self.state;
        let to = from.apply(op)?;
        self.state = to;
        if let Some(sink) = &self.event_sink {
            sink.emit(&LifecycleEvent::StateChanged {
                from,
                to,
                observation: Observation::DirectlyObserved,
            });
        }
        Ok(to)
    }

    /// Wait for the child's "sandbox applied, at the gate" record.
    fn observe_prepare(&mut self) -> Result<(), PrepareError> {
        let record = match self.status.as_mut() {
            Some(status) => read_status_record(status),
            None => Err(0),
        };
        match classify_prepare_record(record) {
            Ok(()) => {
                self.transition(LifecycleOp::PrepareSucceeded)?;
                Ok(())
            }
            Err((stage, errno)) => Err(self.fail_prepare(stage, errno)),
        }
    }

    /// Whether the gate's configured lifetime has run out.
    fn has_expired(&self) -> bool {
        self.expiry
            .is_some_and(|limit| self.prepared_at.elapsed() >= limit)
    }

    /// Write the release message and close the gate behind it.
    fn release(&mut self) -> Result<(), i32> {
        let message = *self.secrets.as_ref().ok_or(0)?.release();
        let mut gate = self.gate.take().ok_or(0)?;
        gate.write_all(&message)
            .map_err(|err| err.raw_os_error().unwrap_or(0))?;
        // Closed immediately: the gate opens once, and a descriptor that no
        // longer exists cannot be written a second time.
        drop(gate);
        Ok(())
    }

    /// Close the gate without a message. The child sees EOF and exits.
    fn close_gate(&mut self) {
        self.gate = None;
    }

    /// Tell a held child to give up, then close the gate.
    fn abort_gate(&mut self) {
        let message = self.secrets.as_ref().map(|secrets| *secrets.abort());
        if let Some(mut gate) = self.gate.take() {
            // Best effort. The close below is the part that is guaranteed to
            // land: the child's `read` returns 0 and it exits either way.
            if let Some(message) = message {
                let _ = gate.write_all(&message);
            }
        }
    }

    /// Read the record an aborted child leaves behind, if it left one.
    ///
    /// Returns `None` when the child died without writing — nothing to report
    /// beyond what `waitpid` will say.
    fn observe_gate_ending(&mut self) -> Option<ExitOutcome> {
        let record = self.status.as_mut().map(read_status_record);
        match record {
            Some(Ok(Some((tag, errno)))) => Some(ExitOutcome::PreExecFailure {
                stage: PreExecStage::from_tag(tag),
                errno,
            }),
            _ => None,
        }
    }

    /// Forget both halves of the gate's secret material.
    ///
    /// The digest and the release/abort pair die together, because after the
    /// gate closes neither can open anything and both are worth stealing.
    fn zeroize_secrets(&mut self) {
        self.token_digest.zeroize();
        // Dropping the pair zeroizes it: `GateSecrets` is `ZeroizeOnDrop`.
        self.secrets = None;
    }

    /// Record a prepare-time child failure and name it.
    fn fail_prepare(&mut self, stage: PreExecStage, errno: i32) -> PrepareError {
        let outcome = if stage == PreExecStage::SandboxApply {
            ExitOutcome::SandboxApplicationFailure { stage, errno }
        } else {
            ExitOutcome::PreExecFailure { stage, errno }
        };
        let _ = self.transition(LifecycleOp::PrepareFailed);
        let exit = SandboxExit::new(
            outcome,
            ActivationObservation::NotActivated,
            self.identity.clone(),
        );
        self.last_exit = Some(exit.clone());
        // The child is reaped by this value's `Drop`, which the caller reaches
        // by propagating the error.
        PrepareError::ChildFailed { exit }
    }

    /// Record a post-release child failure and name it.
    ///
    /// The child told us where it stopped, so this is one of the cases where
    /// "the program never ran" is a fact rather than a guess.
    fn fail_pre_exec(&mut self, stage: PreExecStage, errno: i32) -> ActivationError {
        let _ = self.transition(LifecycleOp::ActivateFailed);
        self.finish_failed(
            Some(ExitOutcome::PreExecFailure { stage, errno }),
            ActivationObservation::NotActivated,
        );
        ActivationError::PreExecFailed { stage, errno }
    }

    /// Record a failure of the supervisor's own machinery and name it.
    ///
    /// Nothing is known about the child here, including whether it got as far
    /// as `execve` — so the child is killed rather than waited for, and the
    /// activation question is left open.
    fn fail_activation(&mut self, stage: SupervisorStage, errno: i32) -> ActivationError {
        let _ = self.transition(LifecycleOp::ActivateFailed);
        let observation = match stage {
            // The release never landed, so the child never left the gate.
            SupervisorStage::Release => ActivationObservation::NotActivated,
            SupervisorStage::StatusRead | SupervisorStage::Reap => {
                ActivationObservation::ExecOrKilledPreExec
            }
        };
        self.finish_failed(None, observation);
        ActivationError::SupervisorFailed { stage, errno }
    }

    /// Shared tail of the failed-activation paths: close everything, end the
    /// child, and forget the secrets.
    ///
    /// `recorded` is the outcome the child itself reported, when there was
    /// one. Otherwise the outcome is whatever the reap observes — which is a
    /// real fact about how the process ended, unlike a placeholder.
    ///
    /// The child is *killed* before the wait. A plain wait here would block for
    /// as long as the customer's program chose to run, and by this point the
    /// supervisor has already lost track of it.
    fn finish_failed(&mut self, recorded: Option<ExitOutcome>, activation: ActivationObservation) {
        self.abort_gate();
        let reaped = kill_and_reap_observed(self.identity.pid());
        if reaped.is_ok() {
            self.child_owned = false;
        }
        let outcome = match (recorded, reaped) {
            (Some(outcome), _) => outcome,
            (None, Ok(outcome)) => outcome,
            (None, Err(err)) => ExitOutcome::SupervisorFailure {
                stage: SupervisorStage::Reap,
                errno: err.errno,
            },
        };
        self.status = None;
        self.zeroize_secrets();
        self.last_exit = Some(SandboxExit::new(outcome, activation, self.identity.clone()));
    }

    /// Close an expired gate and stop the child behind it.
    fn expire(&mut self) -> ActivationError {
        if self.transition(LifecycleOp::BeginStop).is_ok() {
            self.abort_gate();
            // Same reasoning as the stop path: the abort record, not the exit
            // code, is what says the child was stopped rather than run.
            let recorded = self.observe_gate_ending();
            if let Ok(reaped) = reap(self.identity.pid()) {
                self.child_owned = false;
                let _ = self.transition(LifecycleOp::StopObserved);
                self.last_exit = Some(SandboxExit::new(
                    recorded.unwrap_or(reaped),
                    ActivationObservation::NotActivated,
                    self.identity.clone(),
                ));
            }
        }
        self.status = None;
        self.zeroize_secrets();
        ActivationError::ActivationExpired
    }
}

/// Debug that names the session without naming the secret.
///
/// The digest is not the token, but it is still the value the gate compares
/// against, so it stays out of logs alongside it.
impl std::fmt::Debug for PreparedSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedSandbox")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("state", &self.state)
            .field("identity", &self.identity)
            .field("token_digest", &"<redacted>")
            .field("expiry", &self.expiry)
            .field("child_owned", &self.child_owned)
            .finish()
    }
}

/// End the run rather than leak it.
///
/// A dropped `PreparedSandbox` aborts the gate, kills the child, and reaps it.
/// This is the non-detached default: nothing survives its supervisor, so a
/// dropped handle can never leave a held process or a zombie behind. Detached
/// runs that deliberately outlive their supervisor arrive with the durable
/// supervisor slice; until then, dropping is stopping.
impl Drop for PreparedSandbox {
    fn drop(&mut self) {
        if self.child_owned {
            // Before the zeroize below: the abort message is itself one of the
            // secrets being forgotten.
            self.abort_gate();
            kill_and_reap(self.identity.pid());
        }
        // Unconditional: every path that hands the child off has already
        // zeroized, and repeating it here means no future path can forget.
        self.zeroize_secrets();
    }
}

/// Refuse a plan whose promises this slice cannot keep.
///
/// A PTY, a detached run, and resource ceilings are each a separate mechanism
/// that arrives in a later slice. Until then, asking for one is an error
/// rather than a no-op: silently running headless, attached, and unlimited
/// would leave a caller believing in confinement that was never applied.
fn refuse_unsupported(plan: &ValidatedPlan) -> Result<(), PrepareError> {
    if plan.session_mode() != SessionMode::Headless {
        return Err(PrepareError::UnsupportedPlanFeature {
            feature: "interactive session (PTY)",
        });
    }
    if plan.is_detached() {
        return Err(PrepareError::UnsupportedPlanFeature {
            feature: "detached run",
        });
    }
    if plan.resource_limits() != ResourceLimits::default() {
        return Err(PrepareError::UnsupportedPlanFeature {
            feature: "resource limits",
        });
    }
    Ok(())
}

/// Turn the plan's program into a path that can be `execve`d directly.
///
/// The existence check is advisory and racy by nature — the file can be
/// replaced or removed between here and `execve`. It exists to give the caller
/// a clear error before a child is forked; the binding fact is still the exec
/// record the child writes.
fn resolve_program(program: &str) -> Result<PathBuf, PrepareError> {
    let path = Path::new(program);
    if !path.is_absolute() {
        return Err(PrepareError::ProgramNotAbsolute {
            program: program.to_string(),
        });
    }
    // Follows symlinks deliberately: the path handed to `execve` stays the one
    // the plan named, so a multi-call binary reached through a symlink still
    // sees its own name in argv[0].
    let metadata = std::fs::metadata(path).map_err(|err| PrepareError::ProgramUnusable {
        program: path.to_path_buf(),
        errno: err.raw_os_error().unwrap_or(0),
    })?;
    if !metadata.is_file() {
        return Err(PrepareError::ProgramNotAFile {
            program: path.to_path_buf(),
        });
    }
    Ok(path.to_path_buf())
}

fn channel_error(err: std::io::Error) -> PrepareError {
    PrepareError::ChannelSetup {
        errno: err.raw_os_error().unwrap_or(0),
    }
}

/// A close-on-exec pipe whose ends are both above the standard streams.
///
/// `pipe` hands back the lowest free numbers, which are 0, 1, or 2 when the
/// embedding process has closed one of them. A channel end sitting on
/// descriptor 0 would be inherited by the customer's program as its stdin and
/// would be invisible to the child's close-everything sweep, so both ends are
/// moved up front.
fn open_channel() -> Result<(PipeReader, PipeWriter), PrepareError> {
    let (reader, writer) = std::io::pipe().map_err(channel_error)?;
    let reader = PipeReader::from(above_standard_streams(OwnedFd::from(reader))?);
    let writer = PipeWriter::from(above_standard_streams(OwnedFd::from(writer))?);
    Ok((reader, writer))
}

/// Move `fd` to the lowest free number at or above 3, if it is not there
/// already.
///
/// The duplicate is created close-on-exec in the same syscall, so there is no
/// window where an inheritable copy exists.
fn above_standard_streams(fd: OwnedFd) -> Result<OwnedFd, PrepareError> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    // SAFETY: `fd` is a live descriptor owned for the duration of the call.
    // `F_DUPFD_CLOEXEC` returns a fresh, independently-owned descriptor at or
    // above the requested number, or -1.
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(channel_error(std::io::Error::last_os_error()));
    }
    // The original is closed here, restoring whichever standard stream slot it
    // had taken.
    drop(fd);
    // SAFETY: `duplicate` is a fresh descriptor with no other owner, so taking
    // sole ownership of it is sound.
    Ok(unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(duplicate) })
}

/// The plan's program, argv, environment, and working directory as C buffers.
///
/// Built entirely in the parent: after the fork the child only reads pointers.
struct ExecImage {
    program: CString,
    working_dir: Option<CString>,
    argv: Vec<CString>,
    envp: Vec<CString>,
}

impl ExecImage {
    fn build(program: &Path, plan: &ValidatedPlan) -> Result<Self, PrepareError> {
        use std::os::unix::ffi::OsStrExt;

        let nul = |_| PrepareError::ProgramUnusable {
            program: program.to_path_buf(),
            // A NUL here is unreachable — plan validation rejects interior
            // NULs — but a path is bytes, so the case is handled rather than
            // assumed away.
            errno: 0,
        };
        let program_c = CString::new(program.as_os_str().as_bytes()).map_err(nul)?;

        let mut argv = Vec::with_capacity(plan.args().len().saturating_add(1));
        argv.push(program_c.clone());
        for arg in plan.args() {
            argv.push(CString::new(arg.as_bytes()).map_err(nul)?);
        }

        // Duplicate keys are a plan-validation rule, so a `ValidatedPlan`
        // cannot carry them and there is nothing to check here.
        let mut envp = Vec::with_capacity(plan.env().len());
        for (key, value) in plan.env() {
            let mut entry =
                Vec::with_capacity(key.len().saturating_add(value.len()).saturating_add(1));
            entry.extend_from_slice(key.as_bytes());
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            envp.push(CString::new(entry).map_err(nul)?);
        }

        let working_dir = match plan.working_dir() {
            Some(dir) => Some(CString::new(dir.as_os_str().as_bytes()).map_err(nul)?),
            None => None,
        };

        Ok(Self {
            program: program_c,
            working_dir,
            argv,
            envp,
        })
    }

    /// NULL-terminated pointer arrays for `execve`.
    ///
    /// Allocated here, in the parent; the pointers address the `CString` heap
    /// buffers this value owns, so both must outlive the fork.
    fn pointers(&self) -> (Vec<*const c_char>, Vec<*const c_char>) {
        let argv = self
            .argv
            .iter()
            .map(|entry| entry.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp = self
            .envp
            .iter()
            .map(|entry| entry.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        (argv, envp)
    }
}

/// Everything the child needs, as values it can use without allocating.
struct ChildContext<'a> {
    gate_read: RawFd,
    gate_write: RawFd,
    status_read: RawFd,
    status_write: RawFd,
    program: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    /// Null when the plan set no working directory.
    working_dir: *const c_char,
    sandbox: &'a PlatformSandbox,
    /// The only two messages this child will act on.
    secrets: &'a GateSecrets,
}

/// The whole of the child's life before `execve`.
///
/// Runs only async-signal-safe syscalls over buffers the parent built, never
/// returns, and never unwinds. The single exception is the macOS sandbox apply
/// — see [`PlatformSandbox::apply_in_child`].
fn child_main(context: &ChildContext<'_>) -> ! {
    // The parent's ends. Closing the gate's write end here is what lets the
    // child notice a dead supervisor: with no writer left, `read` returns 0.
    // SAFETY: both are descriptors this process owns, closed exactly once.
    unsafe {
        libc::close(context.gate_write);
        libc::close(context.status_read);
    }

    if let Err((stage, errno)) = context.sandbox.apply_in_child() {
        child_fail(context.status_write, stage, errno);
    }

    // Everything else this process inherited goes now — after the sandbox
    // apply, because on Linux the prepared ruleset *is* a set of open path
    // descriptors, and before the wait below, so that a held child holds
    // nothing that could keep another session's gate or status channel alive.
    // A failure here is not reportable and not fatal: the sweep is
    // best-effort per descriptor, and the ones that matter are the ones the
    // parent knows about.
    close_inherited_descriptors(context.gate_read, context.status_write);

    // Confined, holding nothing spare, and about to wait. This record is what
    // turns the parent's `prepare` into an observation instead of an
    // assumption.
    if !write_record(context.status_write, TAG_GATE_READY, 0) {
        // Nothing can be reported if the report channel itself is gone.
        // SAFETY: `_exit` is async-signal-safe and does not return.
        unsafe { libc::_exit(PRE_EXEC_EXIT_CODE) }
    }

    let mut message = [0_u8; GATE_MESSAGE_BYTES];
    let mut filled: usize = 0;
    while filled < GATE_MESSAGE_BYTES {
        let remaining = GATE_MESSAGE_BYTES.saturating_sub(filled);
        // SAFETY: `message` is a live 16-byte local and `filled < 16`, so the
        // offset pointer and length stay inside it. `read` is
        // async-signal-safe.
        let count = unsafe {
            libc::read(
                context.gate_read,
                message.as_mut_ptr().add(filled).cast::<libc::c_void>(),
                remaining,
            )
        };
        match usize::try_from(count) {
            // Every writer is gone: the supervisor died while we waited. A
            // partial message ends the same way — it can never complete.
            Ok(0) => child_fail(context.status_write, PreExecStage::GateClosed, 0),
            Ok(count) => filled = filled.saturating_add(count),
            Err(_) => {
                let errno = last_errno();
                if errno != libc::EINTR {
                    child_fail(context.status_write, PreExecStage::GateWait, errno);
                }
            }
        }
    }

    match context.secrets.classify(&message) {
        GateDecision::Release => {}
        GateDecision::Abort => child_fail(context.status_write, PreExecStage::GateAborted, 0),
        // Whoever wrote this holds the descriptor but not the secret. Refuse
        // rather than guess: a gate that starts a program for an unrecognised
        // message is not a gate.
        GateDecision::Unknown => child_fail(context.status_write, PreExecStage::GateProtocol, 0),
    }

    if !context.working_dir.is_null() {
        // Deliberately after the sandbox is applied: the working directory the
        // plan asked for is subject to the same policy as everything else, and
        // a directory the sandbox forbids is a typed failure rather than a
        // quietly-granted exception.
        // SAFETY: the pointer is a NUL-terminated C string owned by the parent
        // and still mapped in this address space; `chdir` is async-signal-safe.
        if unsafe { libc::chdir(context.working_dir) } != 0 {
            child_fail(
                context.status_write,
                PreExecStage::WorkingDirectory,
                last_errno(),
            );
        }
    }

    // Both channel descriptors are close-on-exec, so a successful `execve`
    // closes them atomically: the customer's program never sees either, and
    // the parent's read of the status descriptor reaches EOF with no record.
    // SAFETY: all three pointers address NUL-terminated buffers built by the
    // parent, and the two vectors are NULL-terminated.
    unsafe { libc::execve(context.program, context.argv, context.envp) };
    child_fail(context.status_write, PreExecStage::Exec, last_errno())
}

/// Close every descriptor this process inherited except the two channel ends
/// and the standard streams.
///
/// Runs in the forked child, so it is syscalls only: no allocation, no
/// iterator over `/proc` or `/dev/fd`, nothing that could take a lock the fork
/// left held.
///
/// Both keepers are guaranteed to be at or above 3 by [`open_channel`], so the
/// sweep starts there and 0/1/2 are never touched — a customer's program still
/// gets the stdin, stdout, and stderr its embedder set up.
fn close_inherited_descriptors(keep_first: RawFd, keep_second: RawFd) {
    let (lower, upper) = if keep_first <= keep_second {
        (keep_first, keep_second)
    } else {
        (keep_second, keep_first)
    };

    #[cfg(target_os = "linux")]
    {
        // Three ranges: below the first keeper, between the keepers, and
        // above the second. `close_range` closes each in one syscall, so the
        // cost does not scale with the descriptor limit. `RawFd::MAX` is the
        // whole space — a descriptor is an `int`, so nothing can sit above it.
        if close_range(3, lower.saturating_sub(1))
            && close_range(lower.saturating_add(1), upper.saturating_sub(1))
            && close_range(upper.saturating_add(1), RawFd::MAX)
        {
            return;
        }
        // Pre-5.9 kernels have no `close_range`; fall through to the loop.
    }

    let limit = descriptor_limit();
    let mut fd: RawFd = 3;
    while fd < limit {
        if fd != lower && fd != upper {
            // SAFETY: closing a descriptor this process does not own returns
            // EBADF and changes nothing. `close` is async-signal-safe.
            unsafe { libc::close(fd) };
        }
        fd = fd.saturating_add(1);
    }
}

/// `close_range(first..=last)`, or `false` if the kernel does not have it.
///
/// An empty range (`first > last`) is a success with nothing to do.
#[cfg(target_os = "linux")]
fn close_range(first: RawFd, last: RawFd) -> bool {
    if first > last {
        return true;
    }
    // SAFETY: a raw syscall taking three integers. Closing descriptors this
    // process does not own is not an error for `close_range`, and the call
    // touches no memory.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            first as libc::c_uint,
            last as libc::c_uint,
            0 as libc::c_uint,
        )
    };
    result == 0
}

/// The exclusive upper bound for the sweep's fallback loop.
///
/// `getdtablesize` reports the current soft limit, which is what bounds the
/// descriptors this process can be holding.
fn descriptor_limit() -> RawFd {
    // SAFETY: takes no arguments, touches no memory, and cannot fail.
    let limit = unsafe { libc::getdtablesize() };
    // A nonsense answer would silently skip the sweep, so fall back to the
    // POSIX minimum-maximum rather than trusting it.
    if limit > 3 { limit } else { 1024 }
}

/// Report a pre-exec failure and leave.
///
/// The record is the protocol; [`PRE_EXEC_EXIT_CODE`] is not.
fn child_fail(status_write: RawFd, stage: PreExecStage, errno: i32) -> ! {
    write_record(status_write, stage.as_tag(), errno);
    // SAFETY: `_exit` is async-signal-safe, skips every destructor and atexit
    // handler — which is what a forked child must do — and does not return.
    unsafe { libc::_exit(PRE_EXEC_EXIT_CODE) }
}

/// Write one fixed-size status record. Returns whether all of it landed.
///
/// Fixed size and stack-allocated so the child never needs an allocator, and
/// small enough that a pipe write of the whole record is atomic.
fn write_record(status_write: RawFd, tag: u8, errno: i32) -> bool {
    let mut record = [0_u8; STATUS_RECORD_LEN];
    record[0] = tag;
    record[1..].copy_from_slice(&errno.to_le_bytes());

    let mut written: usize = 0;
    while written < STATUS_RECORD_LEN {
        let remaining = STATUS_RECORD_LEN.saturating_sub(written);
        // SAFETY: `record` is a live 5-byte local and `written < 5`, so the
        // offset pointer and length stay inside it. `write` is
        // async-signal-safe.
        let count = unsafe {
            libc::write(
                status_write,
                record.as_ptr().add(written).cast::<libc::c_void>(),
                remaining,
            )
        };
        match usize::try_from(count) {
            Ok(0) => return false,
            Ok(count) => written = written.saturating_add(count),
            // Negative: a real error. Retry only the interruption case.
            Err(_) if last_errno() == libc::EINTR => {}
            Err(_) => return false,
        }
    }
    true
}

/// The current `errno`.
///
/// `Error::last_os_error` reads the thread's `errno` and wraps it in a
/// pointer-sized value; nothing is allocated, which is what makes it usable on
/// the child's path.
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Decide what the first thing on the status descriptor means for `prepare`.
///
/// Split out from [`PreparedSandbox::observe_prepare`] because the interesting
/// case is the one that is awkward to provoke through a real fork: EOF with
/// nothing read means the child died before it could even say why, and that
/// must be a failure rather than a silently-successful prepare.
fn classify_prepare_record(
    record: Result<Option<(u8, i32)>, i32>,
) -> Result<(), (PreExecStage, i32)> {
    match record {
        Ok(Some((TAG_GATE_READY, _))) => Ok(()),
        Ok(Some((tag, errno))) => Err((PreExecStage::from_tag(tag), errno)),
        // The child died without leaving a record, or the read itself failed.
        // Either way the stage is a fact we do not have.
        Ok(None) => Err((PreExecStage::Unknown, 0)),
        Err(errno) => Err((PreExecStage::Unknown, errno)),
    }
}

/// Read one status record, or observe EOF.
///
/// `Ok(None)` is a clean EOF with nothing read — the positive observation that
/// `execve` happened. `Ok(Some(_))` is a record. `Err(errno)` is a failed read,
/// which says nothing about the child.
fn read_status_record(status: &mut PipeReader) -> Result<Option<(u8, i32)>, i32> {
    let mut record = [0_u8; STATUS_RECORD_LEN];
    let mut filled: usize = 0;
    while filled < STATUS_RECORD_LEN {
        match status.read(&mut record[filled..]) {
            Ok(0) => break,
            Ok(count) => filled = filled.saturating_add(count),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err.raw_os_error().unwrap_or(0)),
        }
    }
    if filled == 0 {
        return Ok(None);
    }
    if filled < STATUS_RECORD_LEN {
        // A truncated record names no stage we can trust.
        return Ok(Some((PreExecStage::Unknown.as_tag(), 0)));
    }
    let errno = i32::from_le_bytes([record[1], record[2], record[3], record[4]]);
    Ok(Some((record[0], errno)))
}

/// Refuse a Linux policy whose enforcement this slice cannot complete.
///
/// Proxy-only network mediation is not self-contained: the kernel traps
/// `connect`/`bind` to a seccomp-notify descriptor that *some supervisor* must
/// poll and answer, and this slice creates no such supervisor. Applying the
/// prepared policy anyway would leave those syscalls unmediated — a policy the
/// caller asked for, silently not enforced. Refusing is the fail-closed answer.
#[cfg(target_os = "linux")]
fn refuse_unsupported_fallback(
    fallback: &crate::sandbox::SeccompNetFallback,
) -> Result<(), PrepareError> {
    if matches!(
        fallback,
        crate::sandbox::SeccompNetFallback::ProxyOnly { .. }
    ) {
        return Err(PrepareError::SandboxSpec {
            reason: "proxy-only network mediation requires a supervisor-held seccomp-notify \
                     descriptor, which the lifecycle does not yet provide"
                .to_string(),
        });
    }
    Ok(())
}

/// The platform policy, fully built in the parent.
#[cfg(target_os = "linux")]
struct PlatformSandbox {
    prepared: crate::sandbox::PreparedLandlockSandbox,
}

/// The platform policy, fully built in the parent.
#[cfg(target_os = "macos")]
struct PlatformSandbox {
    profile: CString,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct PlatformSandbox;

impl PlatformSandbox {
    /// Build the policy from the plan's capabilities.
    ///
    /// Everything that can allocate, open a descriptor, or fail happens here,
    /// in the parent, so that the child's apply is a fixed sequence of
    /// syscalls with a typed error.
    #[cfg(target_os = "linux")]
    fn build(plan: &ValidatedPlan) -> Result<Self, PrepareError> {
        use crate::sandbox::{Sandbox, SeccompNetFallback, SeccompOpts};

        let abi = Sandbox::detect_abi().map_err(|err| PrepareError::SandboxSpec {
            reason: err.to_string(),
        })?;
        let prepared = Sandbox::prepare_seccomp_with_abi(
            plan.capabilities(),
            &abi,
            SeccompOpts::network_fallback(),
        )
        .map_err(|err| PrepareError::SandboxSpec {
            reason: err.to_string(),
        })?;
        refuse_unsupported_fallback(prepared.fallback())?;
        Ok(Self { prepared })
    }

    /// Build the policy from the plan's capabilities.
    #[cfg(target_os = "macos")]
    fn build(plan: &ValidatedPlan) -> Result<Self, PrepareError> {
        let profile =
            crate::sandbox::generate_seatbelt_profile(plan.capabilities()).map_err(|err| {
                PrepareError::SandboxSpec {
                    reason: err.to_string(),
                }
            })?;
        let profile = CString::new(profile).map_err(|_| PrepareError::SandboxSpec {
            reason: "seatbelt profile contains an interior NUL byte".to_string(),
        })?;
        Ok(Self { profile })
    }

    /// Build the policy from the plan's capabilities.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn build(_plan: &ValidatedPlan) -> Result<Self, PrepareError> {
        Err(PrepareError::SandboxSpec {
            reason: format!("no sandbox mechanism on {}", std::env::consts::OS),
        })
    }

    /// Apply the policy to the calling (child) process.
    ///
    /// Allocation-free on Linux: the ruleset descriptors and rule vectors were
    /// built in the parent and are applied with raw syscalls.
    #[cfg(target_os = "linux")]
    fn apply_in_child(&self) -> Result<(), (PreExecStage, i32)> {
        // The Landlock sub-stage (create/add-rule/restrict) is not carried in
        // the fixed-size record; the errno is.
        self.prepared
            .apply_raw()
            .map_err(|err| (PreExecStage::SandboxApply, err.errno()))
    }

    /// Apply the policy to the calling (child) process.
    ///
    /// `sandbox_init` allocates. That is accepted here for the same reason
    /// upstream accepts it in the Supervised strategy: macOS offers no
    /// allocation-free way to install a Seatbelt profile, and the alternative
    /// — applying the profile before the fork — would confine the supervisor
    /// too. The child is forked from a process whose allocator installs
    /// `fork` handlers, and it does nothing else between the fork and this
    /// call.
    ///
    /// The `errno` reported is `sandbox_init`'s return value, which is not an
    /// `errno(3)` code on this platform.
    #[cfg(target_os = "macos")]
    fn apply_in_child(&self) -> Result<(), (PreExecStage, i32)> {
        // SAFETY: the profile is a NUL-terminated C string owned by the parent
        // and still mapped here. The call is made once, in a freshly forked
        // child that has run nothing else.
        let result = unsafe { crate::sandbox::sandbox_init_raw(self.profile.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err((PreExecStage::SandboxApply, result))
        }
    }

    /// Apply the policy to the calling (child) process.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn apply_in_child(&self) -> Result<(), (PreExecStage, i32)> {
        // Unreachable: `build` refuses on this platform, so no child exists.
        Err((PreExecStage::SandboxApply, libc::ENOSYS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::SandboxPlan;
    use std::os::fd::AsFd;

    /// Seal a plan for a test, naming the failure if the plan is the bug.
    fn sealed(plan: SandboxPlan) -> ValidatedPlan {
        match plan.validate() {
            Ok(plan) => plan,
            Err(err) => panic!("test plan must validate: {err}"),
        }
    }

    #[test]
    fn both_pipe_ends_are_close_on_exec() -> Result<(), std::io::Error> {
        // The whole descriptor discipline rests on this: if an end were not
        // close-on-exec, the customer's program would inherit a channel it can
        // write records into, or hold the gate open forever.
        let (reader, writer) = std::io::pipe()?;
        for fd in [reader.as_fd().as_raw_fd(), writer.as_fd().as_raw_fd()] {
            // SAFETY: `fd` is borrowed from a live pipe end for the duration
            // of the call; `F_GETFD` only reads flags.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "F_GETFD failed for fd {fd}");
            assert_ne!(
                flags & libc::FD_CLOEXEC,
                0,
                "pipe end {fd} must be close-on-exec"
            );
        }
        Ok(())
    }

    #[test]
    fn a_relative_program_is_refused_before_anything_is_forked() {
        assert_eq!(
            resolve_program("echo"),
            Err(PrepareError::ProgramNotAbsolute {
                program: "echo".to_string()
            })
        );
        assert_eq!(
            resolve_program("./echo"),
            Err(PrepareError::ProgramNotAbsolute {
                program: "./echo".to_string()
            })
        );
    }

    #[test]
    fn a_missing_program_is_refused_with_its_errno() {
        let error = resolve_program("/nonexistent-nono-lifecycle-program");
        assert_eq!(
            error,
            Err(PrepareError::ProgramUnusable {
                program: PathBuf::from("/nonexistent-nono-lifecycle-program"),
                errno: libc::ENOENT,
            })
        );
    }

    #[test]
    fn a_directory_is_not_a_program() {
        assert_eq!(
            resolve_program("/tmp"),
            Err(PrepareError::ProgramNotAFile {
                program: PathBuf::from("/tmp")
            })
        );
    }

    #[test]
    fn a_real_program_resolves() -> Result<(), PrepareError> {
        assert_eq!(resolve_program("/bin/sh")?, PathBuf::from("/bin/sh"));
        Ok(())
    }

    #[test]
    fn exec_image_puts_the_program_first_in_argv() -> Result<(), PrepareError> {
        let plan = sealed(SandboxPlan::new("/bin/echo").arg("one").arg("two"));
        let image = ExecImage::build(Path::new("/bin/echo"), &plan)?;
        let rendered: Vec<&[u8]> = image.argv.iter().map(|entry| entry.as_bytes()).collect();
        assert_eq!(rendered, [b"/bin/echo".as_slice(), b"one", b"two"]);
        Ok(())
    }

    #[test]
    fn exec_image_keeps_arguments_literal() -> Result<(), PrepareError> {
        // No shell is involved anywhere, so shell metacharacters are just
        // bytes. This is the parent-side half of that guarantee; the live
        // tests prove the child side.
        let weird = "$(touch /tmp/nono-should-not-exist); `id`; a b";
        let plan = sealed(SandboxPlan::new("/bin/echo").arg(weird));
        let image = ExecImage::build(Path::new("/bin/echo"), &plan)?;
        assert_eq!(
            image.argv.get(1).map(|entry| entry.as_bytes()),
            Some(weird.as_bytes())
        );
        Ok(())
    }

    #[test]
    fn exec_image_renders_the_environment_as_key_equals_value() -> Result<(), PrepareError> {
        let plan = sealed(
            SandboxPlan::new("/bin/echo")
                .env("LANG", "C")
                .env("EMPTY", ""),
        );
        let image = ExecImage::build(Path::new("/bin/echo"), &plan)?;
        let rendered: Vec<&[u8]> = image.envp.iter().map(|entry| entry.as_bytes()).collect();
        assert_eq!(rendered, [b"LANG=C".as_slice(), b"EMPTY="]);
        Ok(())
    }

    #[test]
    fn pointer_arrays_are_null_terminated() -> Result<(), PrepareError> {
        let plan = sealed(SandboxPlan::new("/bin/echo").arg("x").env("LANG", "C"));
        let image = ExecImage::build(Path::new("/bin/echo"), &plan)?;
        let (argv, envp) = image.pointers();
        assert_eq!(argv.len(), 3, "program + 1 arg + NULL");
        assert_eq!(envp.len(), 2, "1 entry + NULL");
        assert!(argv.last().is_some_and(|entry| entry.is_null()));
        assert!(envp.last().is_some_and(|entry| entry.is_null()));
        Ok(())
    }

    #[test]
    fn features_this_slice_cannot_deliver_are_refused_not_ignored() {
        use std::num::NonZeroU64;

        let interactive =
            sealed(SandboxPlan::new("/bin/echo").session_mode(SessionMode::Interactive));
        assert_eq!(
            refuse_unsupported(&interactive).err(),
            Some(PrepareError::UnsupportedPlanFeature {
                feature: "interactive session (PTY)"
            })
        );

        let detached = sealed(SandboxPlan::new("/bin/echo").detached(true));
        assert_eq!(
            refuse_unsupported(&detached).err(),
            Some(PrepareError::UnsupportedPlanFeature {
                feature: "detached run"
            })
        );

        let limited = sealed(
            SandboxPlan::new("/bin/echo").resource_limits(ResourceLimits {
                max_memory_bytes: NonZeroU64::new(1024),
                ..ResourceLimits::default()
            }),
        );
        assert_eq!(
            refuse_unsupported(&limited).err(),
            Some(PrepareError::UnsupportedPlanFeature {
                feature: "resource limits"
            })
        );

        // The defaults this slice does implement are accepted.
        assert_eq!(
            refuse_unsupported(&sealed(SandboxPlan::new("/bin/echo"))),
            Ok(())
        );
    }

    #[test]
    fn an_absent_prepare_record_is_a_failure_not_a_silent_success() {
        // EOF here means the child died before it could say why. Treating it
        // as success would hand the caller a `PreparedSandbox` for a process
        // that no longer exists.
        assert_eq!(
            classify_prepare_record(Ok(None)),
            Err((PreExecStage::Unknown, 0))
        );
        // A failed read says nothing about the child either.
        assert_eq!(
            classify_prepare_record(Err(libc::EIO)),
            Err((PreExecStage::Unknown, libc::EIO))
        );
        // A truncated record decodes to the same "no stage we can trust".
        assert_eq!(
            classify_prepare_record(Ok(Some((PreExecStage::Unknown.as_tag(), 0)))),
            Err((PreExecStage::Unknown, 0))
        );
    }

    #[test]
    fn a_prepare_record_is_only_success_when_it_says_so() {
        assert_eq!(
            classify_prepare_record(Ok(Some((TAG_GATE_READY, 0)))),
            Ok(())
        );
        assert_eq!(
            classify_prepare_record(Ok(Some((PreExecStage::SandboxApply.as_tag(), libc::EPERM)))),
            Err((PreExecStage::SandboxApply, libc::EPERM))
        );
        assert_eq!(
            classify_prepare_record(Ok(Some((PreExecStage::Exec.as_tag(), libc::ENOENT)))),
            Err((PreExecStage::Exec, libc::ENOENT))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_policy_needing_a_supervisor_we_do_not_run_is_refused() {
        use crate::sandbox::SeccompNetFallback;

        // Proxy-only mediation without a notify-descriptor poller would leave
        // connect/bind unmediated. Fail closed instead.
        let refused = refuse_unsupported_fallback(&SeccompNetFallback::ProxyOnly {
            proxy_port: 8080,
            bind_ports: vec![],
        });
        assert!(
            matches!(refused, Err(PrepareError::SandboxSpec { .. })),
            "proxy-only must be refused, got {refused:?}"
        );

        // The self-contained policies still pass.
        assert_eq!(
            refuse_unsupported_fallback(&SeccompNetFallback::None),
            Ok(())
        );
        assert_eq!(
            refuse_unsupported_fallback(&SeccompNetFallback::BlockAll),
            Ok(())
        );
    }

    #[test]
    fn channel_ends_never_land_on_a_standard_stream_number() -> Result<(), PrepareError> {
        let (reader, writer) = open_channel()?;
        assert!(reader.as_raw_fd() >= 3, "{}", reader.as_raw_fd());
        assert!(writer.as_raw_fd() >= 3, "{}", writer.as_raw_fd());
        Ok(())
    }

    // The two refusals below need a live prepared child *and* the crate-private
    // `ActivationHandle::new`, so they live here rather than in
    // `tests/lifecycle_live.rs`: a forged handle is precisely the thing the
    // public API will not let a caller build.

    /// A held `/bin/echo` with read access to the whole filesystem.
    fn held_child() -> (PreparedSandbox, ActivationHandle) {
        use crate::capability::{AccessMode, CapabilitySet};

        let caps = match CapabilitySet::new().allow_path("/", AccessMode::Read) {
            Ok(caps) => caps,
            Err(err) => panic!("test capabilities must build: {err}"),
        };
        let plan = sealed(SandboxPlan::new("/bin/echo").arg("held").capabilities(caps));
        match PreparedSandbox::prepare(plan) {
            Ok(pair) => pair,
            Err(err) => panic!("prepare must succeed: {err}"),
        }
    }

    #[test]
    fn a_forged_handle_with_the_wrong_token_is_refused() {
        let (mut held, handle) = held_child();
        // Right session, right generation, wrong 32 bytes.
        let forged = ActivationHandle::new(
            handle.session_id(),
            handle.generation(),
            [0xEE; ACTIVATION_TOKEN_BYTES],
        );
        assert_eq!(
            held.activate(&forged).err(),
            Some(ActivationError::InvalidActivationToken)
        );
        assert_eq!(
            held.state(),
            LifecycleState::Prepared,
            "a refused token must leave the gate open for the real handle"
        );

        // The genuine handle still works, which proves the refusal was about
        // the token and not about the gate having been consumed.
        match held.activate(&handle) {
            Ok(mut running) => {
                if let Err(err) = running.wait() {
                    panic!("wait must observe the exit: {err}");
                }
            }
            Err(err) => panic!("the genuine handle must still work: {err}"),
        }
    }

    #[test]
    fn a_handle_for_another_generation_is_refused() {
        let (mut held, handle) = held_child();
        // Generations climb when a session is re-prepared, which needs the
        // durable store; a handle from a later generation is forged here so the
        // check is covered before that slice exists.
        let next_generation = ActivationHandle::new(
            handle.session_id(),
            handle.generation().saturating_add(1),
            *handle.token(),
        );
        assert_eq!(
            held.activate(&next_generation).err(),
            Some(ActivationError::WrongGeneration {
                expected: FIRST_GENERATION,
                supplied: FIRST_GENERATION.saturating_add(1),
            })
        );
        assert_eq!(held.state(), LifecycleState::Prepared);
    }
}
