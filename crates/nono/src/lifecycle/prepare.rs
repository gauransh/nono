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
//! 2. become the leader of a new process group
//! 3. apply the platform sandbox to itself
//! 4. close every other inherited descriptor
//! 5. write the "at the gate" record to the status descriptor
//! 6. block in `read()` on the gate descriptor
//! 7. on the release message: enter the working directory, then `execve`
//!
//! Any failure writes a fixed-size record to the status descriptor and exits.
//! Nothing between step 3 and `execve` runs unconfined, and the customer's
//! program never runs at all unless step 6 produced the release message.
//!
//! Step 6 is a loop, because one of the three messages the gate speaks does not
//! end the wait: a *probe* asks the child to attempt one operation and answer
//! on the status descriptor, after which it goes back to waiting — still
//! confined, still before `execve`. That window is the only place in this
//! library where the enforcement can be observed rather than assumed, which is
//! why it exists. See [`super::probe`].
//!
//! Step 4 sits after the sandbox apply rather than before it because on Linux
//! the prepared Landlock ruleset *is* a set of open path descriptors, and
//! `apply_raw` needs them. It sits before step 5 so that by the time `prepare`
//! returns, the held child holds nothing but its own two channel ends — see
//! below.
//!
//! # The run is a process group, not a process
//!
//! Step 2 is `setpgid(0, 0)`: the child becomes the leader of a new process
//! group whose id is its own pid. Everything the customer's program forks
//! inherits that group, so a stop can signal the whole run
//! ([`super::ActivatedSandbox::stop`]) and cleanup verification has a *set* to
//! probe rather than a single pid that `waitpid` already consumed
//! ([`super::CleanupVerification`]).
//!
//! Two consequences, both deliberate and neither hidden:
//!
//! - **A descendant that calls `setsid` — or `setpgid` on itself — leaves the
//!   group and stops being visible to either mechanism.** Nothing in POSIX
//!   prevents that, and no bookkeeping the parent does can follow it. It is a
//!   dark spot of this design, not an oversight.
//!
//!   This note used to add that an escapee "shows up as neither killed nor
//!   confirmed absent rather than as a silent success". **That was wrong, and
//!   the correction matters more than the original claim did.** An escapee
//!   survives the stop *and* cleanup verification certifies the run absent,
//!   because the process group it probes is genuinely empty — every member
//!   except the escapee was killed, and the escapee is no longer a member. The
//!   caller is told the run is gone while it is still running. Measured, not
//!   argued: `verified == true` with the escaped process observed alive
//!   afterwards.
//!
//!   Closing it needs a container-level mechanism (a cgroup on Linux, a job
//!   object equivalent elsewhere). [`super::cgroup`] is that mechanism, and
//!   nothing here uses it yet: placing the run in a cgroup and killing by it is
//!   a change to this containment model, not a patch to it.
//! - **The run is no longer in the supervisor's own process group**, so a
//!   terminal's Ctrl-C — which signals the foreground *group* — no longer
//!   reaches the customer's program by accident. A consumer that wants that
//!   behaviour forwards the signal deliberately.
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

use super::cleanup::{CleanupError, CleanupVerification, DeathObservation, verify_and_record};
use super::events::{ActivationOutcome, EventEmitter, LifecycleEventKind};
use super::exit::{
    ActivatedSandbox, ActivationObservation, ExitOutcome, PRE_EXEC_EXIT_CODE, PreExecStage,
    STATUS_RECORD_LEN, SandboxExit, SupervisorStage, TAG_GATE_READY, TAG_NOTIFY_FD, kill_and_reap,
    kill_and_reap_observed, reap,
};
use super::gate::{
    ACTIVATION_TOKEN_BYTES, ActivationError, ActivationHandle, GATE_MESSAGE_BYTES, GateDecision,
    GateSecrets, StopError, TOKEN_DIGEST_BYTES, ct_eq, token_digest,
};
use super::identity::ProcessIdentity;
use super::plan::{ResourceLimits, SessionMode, ValidatedPlan};
use super::probe::{PROBE_REQUEST_BYTES, ProbeError, ProbeObservation, ProbeOutcome, ProbeRequest};
use super::session_store::SessionHandle;
use super::state::{LifecycleOp, LifecycleState, TransitionError};
use super::sync_core::{SharedLifecycle, Transition};
use std::ffi::{CString, c_char};
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// The generation of a freshly prepared session.
///
/// Generations climb when a session is re-prepared, which needs the durable
/// store; until that lands every prepared sandbox is generation 1.
/// The generation a plan carries when the caller does not choose one.
///
/// A caller that versions its policy sets its own with
/// [`SandboxPlan::generation`][g]; this is only the default.
///
/// [g]: super::plan::SandboxPlan::generation
pub(super) const FIRST_GENERATION: u64 = 1;

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
    /// Refused rather than quietly ignored. A caller who asked for a PTY or a
    /// memory ceiling and silently received neither would be relying on a
    /// guarantee that is not there — which is exactly the failure mode the
    /// whole module exists to avoid.
    #[error("plan feature not supported by this lifecycle: {feature}")]
    UnsupportedPlanFeature {
        /// The feature that was asked for.
        feature: &'static str,
    },

    /// A detached plan reached a path that cannot supervise one.
    ///
    /// Detachment is not a flag this path can honour: a run that outlives its
    /// caller needs a *process* that outlives the caller, which is what
    /// [`super::SessionStore::prepare_detached`] launches. Both the storeless
    /// [`PreparedSandbox::prepare`] and the attached
    /// [`super::SessionStore::prepare`] refuse rather than running the plan
    /// undetached and letting the caller believe otherwise.
    #[error(
        "a detached run needs a supervisor process; use SessionStore::prepare_detached, and \
         call nono::lifecycle::supervisor_entry() at the top of main()"
    )]
    DetachedNeedsSupervisor,

    /// The detaching entry point was called with a plan that did not ask to be
    /// detached.
    ///
    /// The symmetric half of [`Self::DetachedNeedsSupervisor`]: detachment has
    /// to be asked for in the plan *and* reached through the method that
    /// implements it, so neither the flag nor the call site can silently mean
    /// something the other does not.
    #[error("SessionStore::prepare_detached needs a plan built with .detached(true)")]
    DetachedNotRequested,

    /// An interactive plan reached a path with nobody to own the terminal.
    ///
    /// A PTY's master has to live somewhere for as long as the run does, and on
    /// the ephemeral paths the only candidate is the caller's own process —
    /// which would mean a terminal that closed the moment the caller returned,
    /// and a run whose output went to a descriptor nobody held. The supervisor
    /// of [`super::SessionStore::prepare_detached`] is the process that can own
    /// one, so an interactive plan has to be a detached plan.
    #[error(
        "an interactive (PTY) run needs a supervisor to own the terminal; build the plan with \
         .detached(true) and use SessionStore::prepare_detached"
    )]
    InteractiveNeedsSupervisor,

    /// The pseudo-terminal could not be allocated.
    #[error("pseudo-terminal setup failed at stage {stage}: errno {errno}")]
    Terminal {
        /// Which step of the allocation failed.
        stage: &'static str,
        /// Platform error number.
        errno: i32,
    },

    /// This process's own executable could not be resolved, so there is no
    /// image to re-execute as a supervisor.
    ///
    /// Canonicalized at prepare time rather than trusted: `argv[0]` is whatever
    /// the launcher chose, and a relative or since-replaced path would launch
    /// something else entirely.
    #[error("this executable could not be resolved for re-execution: errno {errno}")]
    SupervisorImageUnreadable {
        /// Platform error number from the resolution.
        errno: i32,
    },

    /// The supervisor's control socket could not be created.
    #[error("control socket {path} could not be created: errno {errno}")]
    ControlSocket {
        /// The socket path that was refused.
        path: PathBuf,
        /// Platform error number.
        errno: i32,
    },

    /// The store directory's path leaves no room for a control socket name.
    ///
    /// A Unix socket address is a fixed-size buffer — 104 bytes on macOS, 108
    /// on Linux — and the session store's path plus `<session>.sock` has to fit
    /// in it. Refused with both numbers rather than truncated, because a
    /// truncated socket path is a socket at a *different* address.
    #[error("control socket path for the store {path} needs {needed} bytes (limit {limit})")]
    ControlSocketPathTooLong {
        /// The store directory the socket would live in.
        path: PathBuf,
        /// The length the full socket path would have had, with its NUL.
        needed: usize,
        /// What the platform's `sockaddr_un` can hold.
        limit: usize,
    },

    /// The supervisor never reported that it was ready.
    ///
    /// The overwhelmingly likely cause is the one this message names: the
    /// embedder's `main` does not call [`supervisor_entry`], so the re-executed
    /// image ran the embedder's own program instead of the supervisor loop and
    /// never wrote the readiness handshake. See ADR-0002.
    ///
    /// [`supervisor_entry`]: super::supervisor_entry
    #[error(
        "the re-executed supervisor {image} did not report readiness within {waited:?}; the \
         usual cause is that nono::lifecycle::supervisor_entry() is not called at the top of \
         this binary's main()"
    )]
    SupervisorUnresponsive {
        /// The image that was re-executed.
        image: PathBuf,
        /// How long the handshake was waited for.
        waited: Duration,
    },

    /// The supervisor process died, or its handshake could not be read.
    #[error("the supervisor handshake failed at stage {stage}: errno {errno}")]
    SupervisorHandshake {
        /// Where the handshake stopped.
        stage: &'static str,
        /// Platform error number, or 0 where the failure was not an OS error.
        errno: i32,
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
    /// The process group the child leads.
    ///
    /// Equal to the child's pid by construction: the child calls
    /// `setpgid(0, 0)` before anything else, so the group id *is* that pid.
    /// Recorded here rather than re-derived later because a reaped pid is a
    /// number the kernel may reissue, while the group this run used is a fact
    /// about the run. It is a *fact* by the time `prepare` returns: the child
    /// writes its "at the gate" record only after the call succeeded, and a
    /// failure kills the child with [`PreExecStage::ProcessGroup`] instead.
    process_group: i32,
    /// The state and the one-shot gate write, behind one lock. Held by value
    /// rather than shared today — nothing else has a reference to this run —
    /// but every operation goes through `&self`, so the durable supervisor can
    /// put it in an `Arc` without any of this file changing shape.
    shared: SharedLifecycle,
    gate: Option<PipeWriter>,
    status: Option<PipeReader>,
    /// The proxy-only rule the notification servicer answers from.
    ///
    /// `None` when the plan asked for no proxy mediation, in which case no
    /// listener is ever reported either. A listener arriving without one is a
    /// refusal, not a default: answering from a policy nobody wrote is the
    /// failure this field exists to make impossible.
    proxy_policy: Option<crate::sandbox::ProxyOnlyPolicy>,
    /// What the notification servicer has decided, for the run's evidence.
    ///
    /// A run reporting zero decisions and zero refusals did not have a working
    /// listener, and nothing else about it would say so.
    notify_stats: std::sync::Arc<crate::sandbox::ProxyNotifyStats>,
    token_digest: [u8; TOKEN_DIGEST_BYTES],
    /// The release/abort pair this child will accept. Dropped — and so
    /// zeroized — as soon as the gate closes.
    secrets: Option<GateSecrets>,
    expiry: Option<Duration>,
    prepared_at: Instant,
    child_owned: bool,
    last_exit: Option<SandboxExit>,
    /// This run's event vocabulary and its `seq` counter.
    ///
    /// Shared by `Arc` with the [`ActivatedSandbox`] this hands off to, so the
    /// run keeps one unbroken sequence across the handoff rather than starting
    /// a second one in the middle of itself.
    events: Arc<EventEmitter>,
    /// The durable record this run writes to, when it has one.
    ///
    /// `None` for [`Self::prepare`], which is unchanged and leaves nothing on
    /// disk; `Some` only for a run created through
    /// [`super::SessionStore::prepare`]. Shared by `Arc` so the
    /// [`ActivatedSandbox`] this hands off to writes the same record rather
    /// than a second copy that could disagree with it.
    session: Option<Arc<SessionHandle>>,
    /// Serialises the probe request/reply exchange with the held child.
    ///
    /// [`Self::probe_enforcement`] takes `&self`, so two threads could reach it
    /// at once; the two channels it uses carry fixed-size records with no
    /// sequence number, so two interleaved exchanges would each read the
    /// other's answer. Every other operation on this type takes `&mut self`,
    /// which is what stops a probe from interleaving with an activation or a
    /// stop — this lock is only needed against a second probe.
    probe_exchange: Mutex<()>,
}

/// A child forked by a launcher and inherited across an `execve`.
///
/// Everything [`PreparedSandbox::adopt`] needs that the exec destroyed: the two
/// channel ends, the gate's secret pair, and the facts about the child that
/// were established before this image existed. The secrets travel through the
/// launcher's private bootstrap pipe rather than the environment or the command
/// line — an environment is readable from `/proc` by the same uid and a command
/// line is readable by anyone — and the buffer they arrive in is zeroized as
/// soon as it is parsed.
pub(super) struct AdoptedChild {
    /// The session the launcher chose, which also names the record and the
    /// control socket.
    pub(super) session_id: Uuid,
    /// Which preparation of that session this is.
    pub(super) generation: u64,
    /// The child, as the launcher captured it at fork.
    pub(super) identity: ProcessIdentity,
    /// The group the child leads, which is its own pid.
    pub(super) process_group: i32,
    /// The gate's write end. Sole remaining writer, so closing it is what makes
    /// a dead supervisor visible to the held child.
    pub(super) gate: PipeWriter,
    /// The status descriptor's read end.
    pub(super) status: PipeReader,
    /// The release/abort pair the child was forked with.
    pub(super) secrets: GateSecrets,
    /// The gate's configured lifetime, from the plan.
    pub(super) expiry: Option<Duration>,
    /// The proxy-only rule to answer notifications from, if the plan asked for
    /// mediated egress.
    pub(super) proxy_policy: Option<crate::sandbox::ProxyOnlyPolicy>,
    /// The emitter this run reports through, already carrying the supervisor's
    /// own ring sink.
    pub(super) events: Arc<EventEmitter>,
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
        refuse_unsupported(&plan, false)?;
        let program = resolve_program(plan.program())?;
        let image = ExecImage::build(&program, &plan)?;
        let sandbox = PlatformSandbox::build(&plan)?;
        let proxy_policy = proxy_policy_for(&plan);
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

        // Built before the fork so the first event can be reported before the
        // child exists — which is also why it is the one event with no
        // identity. The child inherits the `Arc` and never touches it: every
        // child path ends in `_exit` or `execve`, so nothing on that side ever
        // emits or drops.
        let events = Arc::new(EventEmitter::new(
            plan.event_sink().cloned(),
            session_id,
            plan.generation(),
        ));
        events.emit(LifecycleEventKind::PrepareStarted);

        // Built before the fork so the child's path allocates nothing. The
        // parent never touches it: after the fork its descriptor numbers name
        // ends the parent has closed.
        let context = ChildContext {
            gate_read: gate_read.as_raw_fd(),
            gate_write: gate_write.as_raw_fd(),
            status_read: status_read.as_raw_fd(),
            status_write: status_write.as_raw_fd(),
            // Headless by construction: `refuse_unsupported` above has already
            // refused an interactive plan on this path, because nothing here
            // outlives the call to own a terminal.
            terminal: None,
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

                let identity = ProcessIdentity::capture(child.as_raw());
                // Every event from here on names the child. Set once: a run has
                // one child, and an identity that could be replaced would let a
                // later event relabel an earlier one.
                events.set_identity(identity.clone());

                let mut prepared = Self {
                    session_id,
                    generation: plan.generation(),
                    identity,
                    // The child makes this true with `setpgid(0, 0)`; the
                    // "at the gate" record the parent waits for below is what
                    // confirms it did.
                    process_group: child.as_raw(),
                    shared: SharedLifecycle::new(state),
                    gate: Some(gate_write),
                    status: Some(status_read),
                    proxy_policy: proxy_policy.clone(),
                    notify_stats: std::sync::Arc::default(),
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
                    events,
                    // Attached afterwards by `SessionStore::prepare`, which can
                    // only build the record once the identity and process group
                    // below are facts.
                    session: None,
                    probe_exchange: Mutex::new(()),
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
                    ActivationHandle::new(session_id, plan.generation(), *token),
                ))
            }
        }
    }

    /// Take ownership of a child that another process forked, and finish
    /// preparing it here.
    ///
    /// The detached path splits `prepare` across an `execve`, and this is its
    /// far half. The launcher builds the exec image and the platform policy,
    /// forks an intermediate that forks the customer child and then re-executes
    /// this binary as a supervisor; what crosses the exec is the *child* (still
    /// this process's child, because `execve` changes the image and not the
    /// process) and its two channel descriptors. Everything from the gate-ready
    /// record onwards happens here, through exactly the code the attached path
    /// uses.
    ///
    /// The token is drawn *here*, on this side of the exec, and handed back to
    /// the launcher over the private handshake channel. That is stronger than
    /// the attached path, not weaker: the customer child was forked before this
    /// process existed in its supervisor form, so the token never existed in
    /// the child's address space at any point, not even between fork and exec.
    ///
    /// # Errors
    ///
    /// [`PrepareError::ChildFailed`] if the adopted child reported a pre-gate
    /// failure or died without reaching the gate, and
    /// [`PrepareError::TokenGeneration`] if the token could not be drawn. In
    /// both cases the child is killed and reaped by the returned value's drop.
    pub(super) fn adopt(adopted: AdoptedChild) -> Result<(Self, ActivationHandle), PrepareError> {
        let AdoptedChild {
            session_id,
            generation,
            identity,
            process_group,
            gate,
            status,
            secrets,
            expiry,
            proxy_policy,
            events,
        } = adopted;

        events.set_identity(identity.clone());
        // Reconstructed, not witnessed: the fork this run started with happened
        // in the launcher, before this image existed. Labelling it as directly
        // observed would be this module's own vocabulary lying about which
        // process saw what.
        events.emit_with(
            LifecycleEventKind::PrepareStarted,
            super::events::Observation::Reconstructed,
        );

        let state = LifecycleState::Planning.apply(LifecycleOp::BeginPrepare)?;
        let mut prepared = Self {
            session_id,
            generation,
            identity,
            process_group,
            shared: SharedLifecycle::new(state),
            gate: Some(gate),
            status: Some(status),
            // Carried across the exec in the bootstrap blob: this process is
            // the one that services the listener, and it never sees the plan.
            proxy_policy,
            notify_stats: std::sync::Arc::default(),
            // Replaced immediately below; a digest of all zeros matches no
            // token anyone can present, so the gate is shut for the moment it
            // holds this value.
            token_digest: [0_u8; TOKEN_DIGEST_BYTES],
            secrets: Some(secrets),
            expiry,
            prepared_at: Instant::now(),
            child_owned: true,
            last_exit: None,
            events,
            session: None,
            probe_exchange: Mutex::new(()),
        };

        let mut token = Zeroizing::new([0_u8; ACTIVATION_TOKEN_BYTES]);
        getrandom::fill(token.as_mut()).map_err(|_| PrepareError::TokenGeneration)?;
        prepared.token_digest = token_digest(&token);

        prepared.observe_prepare()?;
        Ok((
            prepared,
            ActivationHandle::new(session_id, generation, *token),
        ))
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
        self.shared.state()
    }

    /// The child's identity, captured at fork.
    #[must_use]
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// The process group the child leads, which is its own pid.
    pub(crate) fn process_group(&self) -> i32 {
        self.process_group
    }

    /// The status descriptor's number, while the run still has one.
    ///
    /// The detached supervisor polls it: before activation, a child that dies
    /// at the gate announces itself by writing a record or by closing that
    /// descriptor, and a supervisor with nothing else to watch would otherwise
    /// only find out at the next control operation. `None` once the run has
    /// been activated or has ended, at which point the descriptor is gone and
    /// `SIGCHLD` is the only report there is.
    pub(super) fn status_fd(&self) -> Option<RawFd> {
        self.status.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// This run's emitter, for the durable record to report its own writes
    /// through.
    ///
    /// Handed out rather than copied: a record that reported its writes on a
    /// second counter would interleave two sequences into one sink.
    pub(crate) fn events(&self) -> Arc<EventEmitter> {
        Arc::clone(&self.events)
    }

    /// Start writing this run's state to a durable record.
    ///
    /// Called by [`super::SessionStore::prepare`] once the record exists, which
    /// is the only path that has one. Attaching after the fork is deliberate:
    /// the record names the child's identity and process group, and neither is
    /// a fact until the child's "at the gate" message has arrived.
    pub(crate) fn attach_session(&mut self, session: Arc<SessionHandle>) {
        self.session = Some(session);
    }

    /// Give up the child without ending it, for tests that need a run to
    /// outlive its handle.
    ///
    /// Reproduces what a *crashed* caller leaves behind, which no ordinary API
    /// on this type can: the gate and status descriptors are closed (so the
    /// child's `read` returns 0 and it exits by itself, exactly as it would if
    /// the supervisor process had died) while the kill-and-reap that
    /// [`Drop`] would otherwise perform is skipped.
    ///
    /// Test-only, and deliberately not public. The supported way for a run to
    /// outlive its supervisor is the detached supervisor of a later slice; this
    /// is a way to *simulate a crash*, not a way to detach.
    #[cfg(test)]
    pub(crate) fn abandon(mut self) {
        self.gate = None;
        self.status = None;
        self.child_owned = false;
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
            self.report_activation(ActivationOutcome::RefusedWrongSession);
            return Err(ActivationError::WrongSession {
                expected: self.session_id,
                supplied: handle.session_id(),
            });
        }
        if handle.generation() != self.generation {
            self.report_activation(ActivationOutcome::RefusedWrongGeneration);
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
        // same machine the claim further down advances, and it is advisory —
        // a caller that passes it can still lose the claim to another party,
        // which is exactly what the claim is for.
        let observed = self.shared.state();
        if observed != LifecycleState::Prepared {
            self.report_activation(ActivationOutcome::RefusedGateClosed { state: observed });
            return Err(ActivationError::from_closed_gate(observed));
        }
        if self.has_expired() {
            // Expiry is terminal: a correct token presented late must not work
            // now or ever, so the gate is closed and the child is stopped
            // before the token is even looked at. A later attempt finds the
            // stopped state this leaves behind.
            self.report_activation(ActivationOutcome::RefusedExpired);
            return Err(self.expire());
        }
        if !ct_eq(&token_digest(handle.token()), &self.token_digest) {
            self.report_activation(ActivationOutcome::RefusedInvalidToken);
            return Err(ActivationError::InvalidActivationToken);
        }

        // Into a cgroup BEFORE the gate opens, while the child is still held and
        // has started nothing. Everything it forks after the release inherits
        // the cgroup, so the whole run is contained by something a descendant
        // cannot leave — `setsid` moves a process between process groups and
        // does nothing to its cgroup.
        //
        // Best effort, and the fallback is exactly what this run had before: a
        // host that will not give this process a cgroup (an unprivileged
        // container, most often) still gets process-group containment. That is
        // weaker, and the stop says so with `StopCgroupFailed` rather than
        // leaving the caller to assume otherwise.
        #[cfg(target_os = "linux")]
        let cgroup = self.place_in_cgroup();

        // The compare-and-swap, and the release write it authorises, in one
        // critical section. The state machine — not a flag beside it — decides
        // whether this activation is the one that wins, and the winner writes
        // the gate before any other party can observe that the gate moved.
        // Destructured so the closure borrows only the two fields the write
        // touches while `shared` is borrowed alongside them.
        let Self {
            shared,
            gate,
            secrets,
            ..
        } = self;
        let claimed = shared.try_begin_activate(|| release(gate, secrets.as_ref()));

        let (change, released) = match claimed {
            Ok(claimed) => claimed,
            Err(err) => {
                // Lost the claim to another party, which is the same fact from
                // the caller's side as finding the gate already closed.
                self.report_activation(ActivationOutcome::RefusedGateClosed { state: err.from });
                return Err(ActivationError::from_closed_gate(err.from));
            }
        };
        // Reported after the write, not before: a sink is consumer code and
        // must never run inside the lock that the gate's single-use guarantee
        // depends on. The fact first, then the transition it caused — the same
        // order every other pair in this module uses.
        self.report_activation(ActivationOutcome::Accepted);
        self.report(change);

        if let Err(errno) = released {
            return Err(self.fail_activation(SupervisorStage::Release, errno));
        }
        // The release write landed inside the claim above; this is the report
        // of it, not the doing of it.
        self.events.emit(LifecycleEventKind::Released);

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
                self.events.emit(LifecycleEventKind::ExecObserved);
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
                    self.process_group,
                    #[cfg(target_os = "linux")]
                    cgroup,
                    self.shared.state(),
                    ActivationObservation::ExecOrKilledPreExec,
                    Arc::clone(&self.events),
                    self.session.clone(),
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
    /// Create this run's cgroup and put the held child in it.
    ///
    /// Returns `None` when the host will not allow it, which is not an error:
    /// the run then keeps the process-group containment it has always had. What
    /// must not happen is a *silent* downgrade, so the stop reports one.
    ///
    /// Named for the run's session so two runs never share a cgroup and a
    /// stray directory says which run left it.
    #[cfg(target_os = "linux")]
    fn place_in_cgroup(&self) -> Option<super::cgroup::RunCgroup> {
        use super::cgroup::{CGROUP2_ROOT, RunCgroup};

        let name = format!("nono-{}", self.session_id.simple());
        let cgroup = RunCgroup::create(std::path::Path::new(CGROUP2_ROOT), &name).ok()?;
        match cgroup.place(self.identity.pid()) {
            Ok(()) => Some(cgroup),
            // Created but unusable. Removed rather than left behind: a cgroup
            // holding nothing is litter, and one this run cannot place into is
            // not containment.
            Err(_) => {
                let _ = cgroup.remove();
                None
            }
        }
    }

    pub fn stop_before_activation(&mut self) -> Result<SandboxExit, StopError> {
        self.begin_stop()
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
        let ended = outcome.unwrap_or(reaped);
        self.events
            .emit(LifecycleEventKind::StopObserved { outcome: ended });
        self.transition(LifecycleOp::StopObserved)
            .map_err(|err| StopError::NotStoppable { state: err.from })?;
        self.status = None;
        self.zeroize_secrets();

        let exit = SandboxExit::new(
            ended,
            ActivationObservation::NotActivated,
            self.identity.clone(),
        );
        self.last_exit = Some(exit.clone());
        self.persist_exit();
        Ok(exit)
    }

    /// Prove the child and everything it started are gone — or report honestly
    /// that they are not.
    ///
    /// Legal only once the run's end has been observed here: after
    /// [`Self::stop_before_activation`], or after a failure that ended the run
    /// on this handle. A run that was successfully activated belongs to the
    /// [`ActivatedSandbox`] and is verified there; this handle refuses, naming
    /// the state it is frozen in.
    ///
    /// Which question is asked depends on what was observed. When the child was
    /// reaped, `waitpid` already proved the child itself gone and the probe asks
    /// about its process group. When the death was never observed — a stop whose
    /// reap failed — the probe asks about the recorded identity instead, so a
    /// reissued pid cannot pass as a survivor or as a proof of absence.
    ///
    /// Only [`CleanupVerification::ConfirmedAbsent`] moves the run to
    /// [`LifecycleState::CleanupVerified`].
    ///
    /// # Errors
    ///
    /// [`CleanupError`] naming the state that refused: the run has not ended
    /// here, or its cleanup was already verified.
    pub fn verify_cleanup(&mut self) -> Result<CleanupVerification, CleanupError> {
        // `child_owned` is exactly "we still hold an unreaped child": every
        // path that reaps clears it, and the handoff to an `ActivatedSandbox`
        // clears it too (that handle is then the one with a death to observe).
        let death = if self.child_owned {
            DeathObservation::NotReaped
        } else {
            DeathObservation::Reaped
        };
        let (verification, change) = verify_and_record(
            &self.shared,
            &self.identity,
            self.process_group,
            // A run that never activated was never placed in a cgroup:
            // placement happens as the gate opens.
            #[cfg(target_os = "linux")]
            None,
            death,
        )?;
        // Every verdict is reported, not only a proof of absence: "something is
        // still there" is exactly as much a fact as "nothing is".
        self.events.emit(LifecycleEventKind::CleanupVerdict {
            verdict: verification.clone(),
        });
        if let Some(change) = change {
            self.report(change);
        }
        Ok(verification)
    }

    /// Ask the kernel what the child's *installed* enforcement does with one
    /// operation.
    ///
    /// The held child attempts the operation with a single real syscall and the
    /// kernel's own `errno` comes back. **The answer is never derived from the
    /// plan's [`CapabilitySet`][crate::CapabilitySet], from a
    /// [`QueryContext`][crate::query::QueryContext], or from anything else in
    /// [`crate::query`] — a grant table is what the caller asked for, and this
    /// method exists to find out what the kernel did with it.** The same note
    /// that [`super::cleanup`] makes about signals applies here: a policy that
    /// was applied without an error is not evidence that it is enforced, in
    /// exactly the way a signal that was sent is not evidence that a process
    /// died.
    ///
    /// No customer code runs. The child is the one this session forked, still
    /// sandboxed and still blocked before `execve`; nothing on this path reads
    /// [`ValidatedPlan::program`][super::ValidatedPlan::program], and the probe
    /// is answered from the gate wait, which the child returns to afterwards.
    ///
    /// Nothing is memoised. Two identical requests are two exchanges with the
    /// child and two syscalls; a cached answer would be a claim about a moment
    /// that has passed.
    ///
    /// The operation really happens — see [`super::probe`] for what that means
    /// for the operations that create or remove things.
    ///
    /// # Errors
    ///
    /// [`ProbeError::NotLegalInState`] unless the run is held at the gate: a
    /// probe of the *installed* enforcement needs the installed child, and
    /// outside [`LifecycleState::Prepared`] there is none to reach.
    /// [`ProbeError::ChildUnreachable`] if the exchange could not be completed,
    /// which on this path means the child died during it.
    pub fn probe_enforcement(
        &self,
        request: &ProbeRequest,
    ) -> Result<ProbeObservation, ProbeError> {
        // A probe is only meaningful against the held child, and the state
        // machine is the only thing that knows whether there still is one.
        let observed = self.shared.state();
        if observed != LifecycleState::Prepared {
            return Err(ProbeError::NotLegalInState { state: observed });
        }
        let Some(mechanism) = super::probe::installed_mechanism() else {
            // No mechanism means `PlatformSandbox::build` refused, so no child
            // was ever forked. Unreachable in practice, and honest if it ever
            // is not.
            return Err(ProbeError::ChildUnreachable {
                errno: libc::ENOSYS,
            });
        };

        // Two answers are settled before the child is asked anything: an
        // operation with no in-scope probe, and one the mechanism has no check
        // for. Neither is sent, because in both cases whatever the child came
        // back with would not be an answer to the question.
        if let Some(reason) = super::probe::settled_before_asking(&request.op) {
            return Ok(super::probe::observation(
                request.id.clone(),
                ProbeOutcome::Indeterminate { reason },
                mechanism,
            ));
        }
        let wire = match super::probe::encode_request(&request.op) {
            Ok(wire) => wire,
            // The request cannot cross the channel. Reported with the number
            // the syscall would have produced, rather than as a refusal it
            // never received.
            Err(errno) => {
                return Ok(super::probe::observation(
                    request.id.clone(),
                    ProbeOutcome::Indeterminate {
                        reason: super::probe::ProbeIndeterminate::ProbeCouldNotRun { errno },
                    },
                    mechanism,
                ));
            }
        };

        // One exchange at a time. Nothing between the writes and the read can
        // panic — raw I/O over fixed-size arrays — so a poisoned lock cannot
        // mean a half-finished exchange; it is taken anyway rather than turning
        // an unrelated panic into a permanent refusal.
        let _exchange = match self.probe_exchange.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let (Some(gate), Some(status), Some(secrets)) = (
            self.gate.as_ref(),
            self.status.as_ref(),
            self.secrets.as_ref(),
        ) else {
            // The state check above already proves the gate is open, so this is
            // defence against a future path that closes one without leaving
            // `Prepared`.
            return Err(ProbeError::ChildUnreachable { errno: libc::EPIPE });
        };

        // The secret first, then the record it announces. Both are written
        // through `&PipeWriter`, which is what lets this method take `&self`;
        // the exchange lock above is what makes that safe.
        //
        // A failure between the two leaves the child waiting for a record that
        // will never arrive, which is safe in the only direction that matters:
        // it waits at the gate, still confined and still pre-exec, until the
        // gate closes and it exits. `write_all` on a pipe fails only when the
        // far end is gone, so in practice the child is already dead by then.
        let mut sink: &PipeWriter = gate;
        write_probe(&mut sink, secrets.probe())?;
        write_probe(&mut sink, &wire)?;

        match read_status_record(status) {
            Ok(Some((tag, errno))) => match super::probe::classify_reply(tag, errno) {
                Some(outcome) => Ok(super::probe::observation(
                    request.id.clone(),
                    outcome,
                    mechanism,
                )),
                // Not a reply: the child wrote a record because it was dying,
                // not because it was answering. Its death is reported by the
                // next operation that touches the child — this one refuses to
                // dress a failure record up as a verdict.
                None => Err(ProbeError::ChildUnreachable { errno }),
            },
            // EOF with nothing read: the child's copy of the status descriptor
            // went away, which before `execve` means it died.
            Ok(None) => Err(ProbeError::ChildUnreachable { errno: 0 }),
            Err(errno) => Err(ProbeError::ChildUnreachable { errno }),
        }
    }

    /// Apply an observed fact, recording it and telling the sink.
    ///
    /// Every state change in this module goes through here or through
    /// [`Self::begin_stop`], and both go through the same shared core, so
    /// there is exactly one place where the machine can move and no way to
    /// keep a second, disagreeing copy of "where we are".
    fn transition(&mut self, op: LifecycleOp) -> Result<LifecycleState, TransitionError> {
        let change = self.shared.mark(op)?;
        self.report(change);
        Ok(change.to)
    }

    /// Request a stop, shutting the gate to activation at the same instant.
    ///
    /// Separate from [`Self::transition`] because a stop is the one
    /// observation that also settles who may write the gate: after this
    /// returns `Ok`, no interleaving can still reach the release write.
    fn begin_stop(&mut self) -> Result<LifecycleState, TransitionError> {
        let change = self.shared.begin_stop()?;
        self.events.emit(LifecycleEventKind::StopRequested);
        self.report(change);
        Ok(change.to)
    }

    /// Tell the sink, and the durable record, about a change that already
    /// happened.
    ///
    /// Always outside the shared core's lock, and always *after* the change:
    /// the sink is consumer code and may do anything, including calling back
    /// in, and the record write is filesystem I/O that must never happen with
    /// the lock the gate's single-use guarantee depends on in hand.
    ///
    /// The consequence of writing after the fact is stated rather than hidden:
    /// a supervisor that dies between the transition and this call leaves a
    /// record one step stale. That is why
    /// [`super::SessionStore::recover`] reconciles a loaded record against the
    /// live system instead of believing it.
    fn report(&self, change: Transition) {
        self.events.emit(LifecycleEventKind::StateChanged {
            from: change.from,
            to: change.to,
        });
        if let Some(session) = &self.session {
            session.persist(change.to, self.recorded_activation());
        }
    }

    /// Report what an activation attempt did.
    ///
    /// One event per attempt, emitted at the point the outcome is known and
    /// carrying no token material — see [`ActivationOutcome`].
    fn report_activation(&self, outcome: ActivationOutcome) {
        self.events
            .emit(LifecycleEventKind::ActivationAttempted { outcome });
    }

    /// Write the run's end to the durable record, if there is one.
    ///
    /// Called by the paths that record a [`SandboxExit`] *after* the transition
    /// that produced it, so the activation fact the exit carries reaches the
    /// record instead of arriving one write too late.
    fn persist_exit(&self) {
        if let Some(session) = &self.session {
            session.persist(self.shared.state(), self.recorded_activation());
        }
    }

    /// Whether the customer's program was observed to start, as far as this
    /// handle knows. `None` until the run ends here.
    fn recorded_activation(&self) -> Option<ActivationObservation> {
        self.last_exit.as_ref().map(SandboxExit::activation)
    }

    /// Wait for the child's "sandbox applied, at the gate" record.
    fn observe_prepare(&mut self) -> Result<(), PrepareError> {
        // A listener record, if the policy needed one, arrives before the gate
        // record. Reading it here rather than treating it as an unexpected tag
        // is what turns "the child installed a filter" into "the parent holds
        // the descriptor that answers it".
        let record = match self.status.as_mut() {
            Some(status) => read_status_record(status),
            None => Err(0),
        };
        let record = match record {
            Ok(Some((TAG_NOTIFY_FD, raw))) => {
                self.adopt_notify_listener(raw)?;
                match self.status.as_mut() {
                    Some(status) => read_status_record(status),
                    None => Err(0),
                }
            }
            other => other,
        };
        match classify_prepare_record(record) {
            Ok(()) => {
                // Two facts from one record, and deliberately so: the trusted
                // child writes it *after* the sandbox is applied and *while*
                // waiting at the gate, so the record's arrival is a direct
                // observation of both.
                self.events.emit(LifecycleEventKind::SandboxApplied);
                self.events.emit(LifecycleEventKind::GateReady);
                self.transition(LifecycleOp::PrepareSucceeded)?;
                Ok(())
            }
            Err((stage, errno)) => Err(self.fail_prepare(stage, errno)),
        }
    }

    /// Take the child's seccomp-notify listener into this process.
    ///
    /// `pidfd_getfd` rather than `SCM_RIGHTS`: the filter the child installed
    /// traps `sendmsg`, so a socket handoff would be mediated by the listener
    /// nobody is servicing yet. The number alone is useless without access to
    /// the child's descriptor table, which is what makes sending it in the
    /// clear acceptable.
    ///
    /// A failure here fails `prepare`. The alternative is a confined child
    /// whose every network syscall blocks against a listener nobody reads,
    /// which is a hang rather than a refusal — and a hang is the one outcome
    /// that tells an operator nothing.
    #[cfg(target_os = "linux")]
    fn adopt_notify_listener(&mut self, raw: i32) -> Result<(), PrepareError> {
        let listener = crate::sandbox::steal_child_fd(self.process_group, raw).map_err(|errno| {
            self.fail_prepare(PreExecStage::NetworkFilter, errno);
            PrepareError::SandboxSpec {
                reason: format!(
                    "could not take the child's seccomp-notify listener (fd {raw} in pid {}): {}",
                    self.process_group,
                    std::io::Error::from_raw_os_error(errno)
                ),
            }
        })?;

        let Some(policy) = self.proxy_policy.clone() else {
            // A listener with no policy to answer from would block the child on
            // its first network syscall for ever. Refusing is the only outcome
            // that is not a hang.
            self.fail_prepare(PreExecStage::NetworkFilter, libc::EINVAL);
            return Err(PrepareError::SandboxSpec {
                reason: "the child installed a seccomp-notify listener for a plan that carries no \
                         proxy-only policy; there would be nothing to answer it with"
                    .to_string(),
            });
        };

        // Serviced on its own thread for the run's whole life. The thread owns
        // the listener and returns when the child is gone, so nothing has to
        // remember to stop it — and nothing can hold a listener without
        // answering it, which is the arrangement that turns a hang into a
        // decision.
        let stats = std::sync::Arc::clone(&self.notify_stats);
        std::thread::Builder::new()
            .name("nono-proxy-notify".to_string())
            .spawn(move || {
                crate::sandbox::serve_proxy_notifications(&listener, &policy, &stats);
            })
            .map_err(|error| PrepareError::SandboxSpec {
                reason: format!("could not start the proxy notification servicer: {error}"),
            })?;
        Ok(())
    }

    /// No listener is ever reported on a platform that installs none.
    #[cfg(not(target_os = "linux"))]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "mirrors the Linux signature, which is fallible"
    )]
    fn adopt_notify_listener(&mut self, _raw: i32) -> Result<(), PrepareError> {
        Ok(())
    }

    /// The proxy-only confinement in force for this run, if any.
    ///
    /// A caller that wants to know whether egress is mediated asks here rather
    /// than inferring it from the capability set: this is what the supervisor
    /// is actually answering from.
    #[must_use]
    pub fn proxy_mediation(&self) -> Option<&crate::sandbox::ProxyOnlyPolicy> {
        self.proxy_policy.as_ref()
    }

    /// How many trapped network syscalls this run has decided, and how many it
    /// refused.
    ///
    /// Evidence rather than decoration. A run under proxy mediation that
    /// reports zero decisions did not have a working listener, and nothing else
    /// about it would say so.
    #[must_use]
    pub fn network_mediation_stats(&self) -> (u64, u64) {
        (self.notify_stats.decided(), self.notify_stats.denied())
    }

    /// Whether the gate's configured lifetime has run out.
    fn has_expired(&self) -> bool {
        self.expiry
            .is_some_and(|limit| self.prepared_at.elapsed() >= limit)
    }

    /// Close the gate without a message. The child sees EOF and exits.
    fn close_gate(&mut self) {
        self.gate = None;
    }

    /// Tell a held child to give up, then close the gate.
    ///
    /// The claim, not the descriptor, is what makes this once-only against a
    /// concurrent release: a caller that does not hold the gate write says
    /// nothing and only lets the descriptor go, which the child reads as EOF.
    fn abort_gate(&mut self) {
        let may_write = self.shared.claim_gate_close();
        let message = self.secrets.as_ref().map(|secrets| *secrets.abort());
        if let Some(mut gate) = self.gate.take() {
            // Best effort. The close below is the part that is guaranteed to
            // land: the child's `read` returns 0 and it exits either way.
            if may_write && let Some(message) = message {
                let _ = gate.write_all(&message);
            }
            // Reported only when a live gate was actually closed here, so a
            // second abort — a stop followed by a drop, say — is not a second
            // event about the same gate.
            self.events.emit(LifecycleEventKind::GateAborted);
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
        let outcome = prepare_outcome(stage, errno);
        // The child's own record is how its death was observed here, so the
        // fact is reported before the transition it causes.
        self.events
            .emit(LifecycleEventKind::ChildExited { outcome });
        let _ = self.transition(LifecycleOp::PrepareFailed);
        let exit = SandboxExit::new(
            outcome,
            ActivationObservation::NotActivated,
            self.identity.clone(),
        );
        self.last_exit = Some(exit.clone());
        self.persist_exit();
        // The child is reaped by this value's `Drop`, which the caller reaches
        // by propagating the error.
        PrepareError::ChildFailed { exit }
    }

    /// Record a post-release child failure and name it.
    ///
    /// The child told us where it stopped, so this is one of the cases where
    /// "the program never ran" is a fact rather than a guess.
    fn fail_pre_exec(&mut self, stage: PreExecStage, errno: i32) -> ActivationError {
        let outcome = ExitOutcome::PreExecFailure { stage, errno };
        self.events
            .emit(LifecycleEventKind::ChildExited { outcome });
        let _ = self.transition(LifecycleOp::ActivateFailed);
        self.finish_failed(Some(outcome), ActivationObservation::NotActivated);
        ActivationError::PreExecFailed { stage, errno }
    }

    /// Record a failure of the supervisor's own machinery and name it.
    ///
    /// Nothing is known about the child here, including whether it got as far
    /// as `execve` — so the child is killed rather than waited for, and the
    /// activation question is left open.
    fn fail_activation(&mut self, stage: SupervisorStage, errno: i32) -> ActivationError {
        self.events
            .emit(LifecycleEventKind::SupervisorFailure { stage, errno });
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
        self.persist_exit();
    }

    /// Close an expired gate and stop the child behind it.
    fn expire(&mut self) -> ActivationError {
        if self.begin_stop().is_ok() {
            self.abort_gate();
            // Same reasoning as the stop path: the abort record, not the exit
            // code, is what says the child was stopped rather than run.
            let recorded = self.observe_gate_ending();
            if let Ok(reaped) = reap(self.identity.pid()) {
                self.child_owned = false;
                let ended = recorded.unwrap_or(reaped);
                self.events
                    .emit(LifecycleEventKind::StopObserved { outcome: ended });
                let _ = self.transition(LifecycleOp::StopObserved);
                self.last_exit = Some(SandboxExit::new(
                    ended,
                    ActivationObservation::NotActivated,
                    self.identity.clone(),
                ));
                self.persist_exit();
            }
        }
        self.status = None;
        self.zeroize_secrets();
        ActivationError::ActivationExpired
    }
}

/// Write the release message and close the gate behind it.
///
/// A free function rather than a method because it is the effect
/// [`super::sync_core::SharedLifecycle::try_begin_activate`] runs on the
/// winning path: it borrows the two fields the write touches and nothing else,
/// so the shared core can be borrowed alongside them. Calling it from anywhere
/// but inside that claim would be the bug the claim exists to prevent.
///
/// TODO(probe): post-activation scope. The `drop` below is the end of the probe
/// channel: once the gate closes there is no way to reach the running child,
/// and keeping the descriptor alive is not the answer — the customer's program
/// would then be able to read it. A post-activation probe has to fork a fresh
/// sibling and re-apply [`ValidatedPlan::capabilities`], which is
/// [`super::ProbeScope::RederivedSibling`] and proves something strictly
/// weaker. See [`super::probe`].
fn release(gate: &mut Option<PipeWriter>, secrets: Option<&GateSecrets>) -> Result<(), i32> {
    let message = *secrets.ok_or(0)?.release();
    let mut gate = gate.take().ok_or(0)?;
    gate.write_all(&message)
        .map_err(|err| err.raw_os_error().unwrap_or(0))?;
    // Closed immediately: the gate opens once, and a descriptor that no longer
    // exists cannot be written a second time.
    drop(gate);
    Ok(())
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
            .field("state", &self.shared.state())
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

/// Refuse a plan whose promises this path cannot keep.
///
/// Resource ceilings are a separate mechanism that arrives in a later slice.
/// Until then, asking for one is an error rather than a no-op: silently running
/// unlimited would leave a caller believing in confinement that was never
/// applied.
///
/// Detachment is judged differently, because it is implemented: `detached`
/// names *who owns the run*, and only the supervisor launch of
/// [`super::SessionStore::prepare_detached`] can own one that outlives the
/// caller. `supervised` is true on exactly that path — it is set by the code
/// that has already forked a supervisor to hold the child — and false on the
/// two paths that would otherwise run a detached plan attached.
///
/// An interactive plan is judged by the same question and answered the same
/// way. A PTY's master must be held for as long as the run lives, and the
/// ephemeral paths have no process that outlives the call to hold it, so
/// interactive is refused there with a reason that names the path that works.
pub(super) fn refuse_unsupported(
    plan: &ValidatedPlan,
    supervised: bool,
) -> Result<(), PrepareError> {
    if plan.session_mode() == SessionMode::Interactive && !supervised {
        return Err(PrepareError::InteractiveNeedsSupervisor);
    }
    if plan.is_detached() && !supervised {
        return Err(PrepareError::DetachedNeedsSupervisor);
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
pub(super) fn resolve_program(program: &str) -> Result<PathBuf, PrepareError> {
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

pub(super) fn channel_error(err: std::io::Error) -> PrepareError {
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
pub(super) fn open_channel() -> Result<(PipeReader, PipeWriter), PrepareError> {
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
pub(super) fn above_standard_streams(fd: OwnedFd) -> Result<OwnedFd, PrepareError> {
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
pub(super) struct ExecImage {
    pub(super) program: CString,
    pub(super) working_dir: Option<CString>,
    pub(super) argv: Vec<CString>,
    pub(super) envp: Vec<CString>,
}

impl ExecImage {
    pub(super) fn build(program: &Path, plan: &ValidatedPlan) -> Result<Self, PrepareError> {
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
    pub(super) fn pointers(&self) -> (Vec<*const c_char>, Vec<*const c_char>) {
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

/// The two descriptors an interactive child is given, and what it does with
/// them.
///
/// Both numbers name descriptors the launcher opened before any fork: the
/// slave becomes 0, 1, and 2, and the master is closed, because a program
/// holding the master of its own terminal could read back everything it wrote
/// and everything typed at it.
#[derive(Debug, Clone, Copy)]
pub(super) struct ChildTerminal {
    /// The slave end, which becomes the customer's standard streams.
    pub(super) slave: RawFd,
    /// The master end, closed here so the supervisor is its only holder.
    pub(super) master: RawFd,
}

/// Everything the child needs, as values it can use without allocating.
pub(super) struct ChildContext<'a> {
    pub(super) gate_read: RawFd,
    pub(super) gate_write: RawFd,
    pub(super) status_read: RawFd,
    pub(super) status_write: RawFd,
    /// The terminal, when the plan asked for an interactive session.
    ///
    /// `None` is a headless run, whose standard streams are whatever the
    /// launcher set up — `/dev/null` on the detached path.
    pub(super) terminal: Option<ChildTerminal>,
    pub(super) program: *const c_char,
    pub(super) argv: *const *const c_char,
    pub(super) envp: *const *const c_char,
    /// Null when the plan set no working directory.
    pub(super) working_dir: *const c_char,
    pub(super) sandbox: &'a PlatformSandbox,
    /// The only two messages this child will act on.
    pub(super) secrets: &'a GateSecrets,
}

/// The whole of the child's life before `execve`.
///
/// Runs only async-signal-safe syscalls over buffers the parent built, never
/// returns, and never unwinds. The single exception is the macOS sandbox apply
/// — see [`PlatformSandbox::apply_in_child`].
pub(super) fn child_main(context: &ChildContext<'_>) -> ! {
    // The parent's ends. Closing the gate's write end here is what lets the
    // child notice a dead supervisor: with no writer left, `read` returns 0.
    // SAFETY: both are descriptors this process owns, closed exactly once.
    unsafe {
        libc::close(context.gate_write);
        libc::close(context.status_read);
    }

    // Lead a new process group, whose id is this child's own pid — the number
    // the parent recorded at fork. Everything the customer's program forks
    // lands in it, which is what makes a stop reach the whole run and gives
    // cleanup verification a group to probe after `waitpid` has consumed the
    // pid. Before the sandbox apply, so a policy that refuses the call fails
    // here with its own stage rather than being mistaken for a sandbox
    // failure; before the gate wait, so the group exists for the whole run.
    //
    // **An interactive child leads a SESSION, not just a group.** `TIOCSCTTY`
    // is refused for a process that is not a session leader, and a terminal
    // nobody controls delivers no `SIGINT`, no `SIGWINCH`, and no hangup — so
    // an interactive run has to be a session of its own or it is not really a
    // terminal session at all. Nothing downstream loses by it: `setsid` puts
    // the process in a *new process group* as well, whose id is again this
    // child's own pid, so the group the parent recorded is still the group the
    // run lives in and cleanup verification's group probe is unchanged.
    // SAFETY: both calls take integers, touch no memory, and are
    // async-signal-safe. `setpgid(0, 0)` names "this process" and "a new group
    // of its own"; `setsid` cannot fail for the usual reason (a fresh fork is
    // never already a process group leader). A non-zero return is a plain
    // failure with `errno` set, which the record written below carries.
    let led = match context.terminal {
        Some(_) => unsafe { libc::setsid() },
        None => unsafe { libc::setpgid(0, 0) },
    };
    if led < 0 {
        child_fail(
            context.status_write,
            PreExecStage::ProcessGroup,
            last_errno(),
        );
    }

    // The terminal, before the sandbox apply and therefore before any policy
    // could refuse it. That ordering is not convenience: the slave was opened
    // by the launcher, so a confined child never has to be granted the right to
    // open a device node, and the only terminal it can reach is the one it was
    // given.
    if let Some(terminal) = context.terminal
        && let Err(errno) =
            super::terminal::adopt_controlling_terminal(terminal.slave, terminal.master)
    {
        child_fail(
            context.status_write,
            PreExecStage::ControllingTerminal,
            errno,
        );
    }

    let notify_fd = match context.sandbox.apply_in_child() {
        Ok(fd) => fd,
        Err((stage, errno)) => child_fail(context.status_write, stage, errno),
    };

    // Hand the listener to the parent by number. It has to travel before the
    // descriptor sweep below, and it cannot travel through a socket: the filter
    // just installed traps `sendmsg`, so an `SCM_RIGHTS` handoff would be
    // mediated by the very listener nobody is servicing yet.
    if let Some(fd) = notify_fd
        && !write_record(context.status_write, TAG_NOTIFY_FD, fd)
    {
        // The listener exists and the parent will never learn of it, so every
        // network syscall would block for ever against a listener nobody reads.
        // SAFETY: `_exit` is async-signal-safe and does not return.
        unsafe { libc::_exit(PRE_EXEC_EXIT_CODE) }
    }

    // Everything else this process inherited goes now — after the sandbox
    // apply, because on Linux the prepared ruleset *is* a set of open path
    // descriptors, and before the wait below, so that a held child holds
    // nothing that could keep another session's gate or status channel alive.
    // A failure here is not reportable and not fatal: the sweep is
    // best-effort per descriptor, and the ones that matter are the ones the
    // parent knows about.
    // The listener stays open through the sweep: the parent reaches it with
    // `pidfd_getfd`, which needs the descriptor to still be in this table when
    // it looks. It is `O_CLOEXEC`, so `execve` closes it a moment later — by
    // which time the parent holds its own.
    let mut keep = [
        context.gate_read,
        context.status_write,
        notify_fd.unwrap_or(-1),
    ];
    close_inherited_descriptors(&mut keep);

    // Confined, holding nothing spare, and about to wait. This record is what
    // turns the parent's `prepare` into an observation instead of an
    // assumption.
    if !write_record(context.status_write, TAG_GATE_READY, 0) {
        // Nothing can be reported if the report channel itself is gone.
        // SAFETY: `_exit` is async-signal-safe and does not return.
        unsafe { libc::_exit(PRE_EXEC_EXIT_CODE) }
    }

    // The wait is a loop rather than a single read because one of the three
    // messages the gate speaks does not end it: a probe is answered and the
    // child goes back to waiting, still confined and still pre-exec. The other
    // two leave through `execve` or `child_fail`, so the loop has exactly one
    // ordinary exit.
    let mut request = [0_u8; PROBE_REQUEST_BYTES];
    loop {
        let mut message = [0_u8; GATE_MESSAGE_BYTES];
        read_gate_exact(context, &mut message);

        match context.secrets.classify(&message) {
            GateDecision::Release => break,
            GateDecision::Abort => child_fail(context.status_write, PreExecStage::GateAborted, 0),
            GateDecision::Probe => {
                read_gate_exact(context, &mut request);
                let (tag, errno) = super::probe::run_probe_in_child(&request);
                if !write_record(context.status_write, tag, errno) {
                    // The answer cannot be delivered, so the supervisor is
                    // waiting for something that will never arrive. Nothing can
                    // be reported if the report channel itself is gone.
                    // SAFETY: `_exit` is async-signal-safe and does not return.
                    unsafe { libc::_exit(PRE_EXEC_EXIT_CODE) }
                }
            }
            // Whoever wrote this holds the descriptor but not the secret.
            // Refuse rather than guess: a gate that starts a program for an
            // unrecognised message is not a gate.
            GateDecision::Unknown => {
                child_fail(context.status_write, PreExecStage::GateProtocol, 0)
            }
        }
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

/// Fill `buffer` from the gate descriptor, or die naming why it could not be.
///
/// The child's only reader. Never returns short: a partial message is a message
/// that can never complete, so the two ways it can stop early — every writer
/// gone, or a read error that is not an interruption — end the child with the
/// same stages the single-message wait used before the loop existed.
///
/// Runs in a forked child, so it is syscalls over a caller-owned buffer only.
fn read_gate_exact(context: &ChildContext<'_>, buffer: &mut [u8]) {
    let wanted = buffer.len();
    let mut filled: usize = 0;
    while filled < wanted {
        let remaining = wanted.saturating_sub(filled);
        // SAFETY: `buffer` is live for the call and `filled < wanted`, so the
        // offset pointer and length stay inside it. `read` is
        // async-signal-safe.
        let count = unsafe {
            libc::read(
                context.gate_read,
                buffer.as_mut_ptr().add(filled).cast::<libc::c_void>(),
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
}

/// Close every descriptor this process inherited except the named keepers and
/// the standard streams.
///
/// Runs in a forked child, so it is syscalls only: no allocation, no iterator
/// over `/proc` or `/dev/fd`, nothing that could take a lock the fork left
/// held. `keep` is sorted in place with an insertion sort over a caller-owned
/// stack array — integer comparisons and swaps only, no allocation — because
/// the Linux fast path below closes the *gaps* between keepers and needs them
/// in order.
///
/// The customer child keeps its two channel ends; the intermediate that becomes
/// a detached supervisor keeps rather more — its gate and status ends, the
/// bound control socket, and its handshake and bootstrap descriptors — and that
/// is the whole reason this takes a set rather than a pair.
///
/// Every keeper is guaranteed to be at or above 3 by [`open_channel`] and
/// [`above_standard_streams`], so the sweep starts there and 0/1/2 are never
/// touched — a customer's program still gets the stdin, stdout, and stderr its
/// launcher set up for it.
pub(super) fn close_inherited_descriptors(keep: &mut [RawFd]) {
    // Insertion sort: the sets here are two to six descriptors long, and the
    // alternative — `sort_unstable`, which is a pattern-defeating quicksort —
    // is more machinery than a forked child should run.
    let mut index: usize = 1;
    while index < keep.len() {
        let mut position = index;
        while position > 0 && keep.get(position.saturating_sub(1)) > keep.get(position) {
            keep.swap(position.saturating_sub(1), position);
            position = position.saturating_sub(1);
        }
        index = index.saturating_add(1);
    }

    #[cfg(target_os = "linux")]
    {
        // One `close_range` per gap between keepers, so the cost does not scale
        // with the descriptor limit. `RawFd::MAX` is the whole space — a
        // descriptor is an `int`, so nothing can sit above it.
        let mut first: RawFd = 3;
        let mut swept = true;
        for keeper in keep.iter() {
            // A keeper below 3 is not one this sweep could touch anyway: the
            // standard streams are never swept, and `-1` is how a caller
            // spells "no such descriptor" in a fixed-size set it may not
            // allocate (the detached launcher's terminal master, which only an
            // interactive run has). Skipping it matters: the set is sorted, so
            // a `-1` left in would move `first` to 0 and the next gap would
            // close 0, 1, and 2.
            if *keeper < 3 {
                continue;
            }
            swept = swept && close_range(first, keeper.saturating_sub(1));
            first = keeper.saturating_add(1);
        }
        if swept && close_range(first, RawFd::MAX) {
            return;
        }
        // Pre-5.9 kernels have no `close_range`; fall through to the loop.
    }

    let limit = descriptor_limit();
    let mut fd: RawFd = 3;
    while fd < limit {
        // A linear scan of a handful of keepers, deliberately: a set would
        // allocate, and this runs between `fork` and `execve`.
        let mut keeping = false;
        for keeper in keep.iter() {
            keeping = keeping || *keeper == fd;
        }
        if !keeping {
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
pub(super) fn write_record(status_write: RawFd, tag: u8, errno: i32) -> bool {
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
pub(super) fn last_errno() -> i32 {
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

/// What a stage reported during `prepare` is, as an outcome.
///
/// Two stages mean the same thing — the confinement was never established, so
/// nothing ran unconfined — and they are reported alike. Everything else is an
/// ordinary pre-exec ending. Filing a refused network filter under
/// [`ExitOutcome::PreExecFailure`] would hand the consumer a "your
/// configuration is malformed" diagnostic for a security mechanism that did
/// not go on.
///
/// Split out from [`PreparedSandbox::fail_prepare`] because no test can make
/// the kernel refuse `seccomp(2)` for one child on demand, while the record
/// such a child writes is fixed and what the parent must make of it is a pure
/// function.
fn prepare_outcome(stage: PreExecStage, errno: i32) -> ExitOutcome {
    if matches!(
        stage,
        PreExecStage::SandboxApply | PreExecStage::NetworkFilter
    ) {
        ExitOutcome::SandboxApplicationFailure { stage, errno }
    } else {
        ExitOutcome::PreExecFailure { stage, errno }
    }
}

/// Write one piece of a probe exchange, or say the child is gone.
///
/// `write_all` is what handles a short write on a record larger than the pipe's
/// atomic size; the only thing this adds is the errno translation, so that a
/// dead child on the far end reads as [`ProbeError::ChildUnreachable`] rather
/// than as an I/O error the caller has to classify itself.
fn write_probe(gate: &mut &PipeWriter, bytes: &[u8]) -> Result<(), ProbeError> {
    gate.write_all(bytes)
        .map_err(|err| ProbeError::ChildUnreachable {
            errno: err.raw_os_error().unwrap_or(0),
        })
}

/// Read one status record, or observe EOF.
///
/// `Ok(None)` is a clean EOF with nothing read — the positive observation that
/// `execve` happened. `Ok(Some(_))` is a record. `Err(errno)` is a failed read,
/// which says nothing about the child.
///
/// Generic over the reader so the probe exchange, which holds the descriptor
/// through `&self`, uses exactly the framing every other reader of this channel
/// uses. Two readers with two ideas of what a record looks like would be two
/// protocols.
fn read_status_record<R: Read>(mut status: R) -> Result<Option<(u8, i32)>, i32> {
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

/// Which static seccomp network filter this policy needs, if any.
///
/// Landlock is a filesystem-and-TCP mechanism: it has no vocabulary for UDP,
/// for raw sockets, or for any other address family, so a kernel that supports
/// [`AccessNet`][net] enforces a network policy only as far as TCP connect and
/// bind. Everything else stays open, which is the difference between a network
/// that is restricted and one that merely refuses two syscalls.
///
/// Both restrictive shapes therefore need a filter, and asking only about the
/// first is what left DEF-04 open:
///
/// * `block_network()` with no exceptions -> `BlockAll`: no internet sockets at
///   all.
/// * `block_network()` **with TCP port exceptions** -> `TcpOnly`: Landlock
///   enforces the port allowlist, and this denies every family it cannot
///   express. Without it a policy granting TCP:443 left UDP entirely
///   unmediated, which is a usable exfiltration path out of a sandbox that
///   reported the network as blocked.
///
/// `AllowAll` with no port rules needs nothing. The selection itself is
/// `sandbox::required_static_network_filter`, which already handled every case
/// correctly and was simply unreachable from here.
///
/// [net]: https://docs.kernel.org/userspace-api/landlock.html
#[cfg(target_os = "linux")]
fn required_network_filter(caps: &crate::CapabilitySet) -> crate::sandbox::StaticNetworkFilter {
    crate::sandbox::required_static_network_filter(caps)
}

/// The proxy-only rule this plan asks for, if any.
///
/// Derived from the capability set rather than from what the kernel turned out
/// to support, for the same reason the filter is: what the caller asked for
/// does not change with the host, so neither does what has to answer for it.
pub(super) fn proxy_policy_for(plan: &ValidatedPlan) -> Option<crate::sandbox::ProxyOnlyPolicy> {
    match plan.capabilities().network_mode() {
        crate::NetworkMode::ProxyOnly { port, bind_ports } => {
            Some(crate::sandbox::ProxyOnlyPolicy {
                proxy_port: *port,
                bind_ports: bind_ports.clone(),
                bind_port_ranges: plan.capabilities().localhost_port_ranges().to_vec(),
            })
        }
        crate::NetworkMode::Blocked | crate::NetworkMode::AllowAll => None,
    }
}

/// The platform policy, fully built in the parent.
#[cfg(target_os = "linux")]
pub(super) struct PlatformSandbox {
    prepared: crate::sandbox::PreparedLandlockSandbox,
    /// Decided here, in the parent, from the capability set — see
    /// [`required_network_filter`]. The child only reads the answer, and
    /// `StaticNetworkFilter` is `Copy`, so reading it allocates nothing.
    network_filter: crate::sandbox::StaticNetworkFilter,
    /// The seccomp-notify program for proxy-only egress, built in the parent.
    ///
    /// Built here for the same reason everything else is: the child's apply has
    /// to be a fixed sequence of syscalls, and assembling a BPF program is not
    /// one. `install_raw` in the child is a single `seccomp(2)` call over
    /// memory the parent already laid out.
    proxy_notify: Option<crate::sandbox::PreparedSeccompNotifyFilter>,
}

/// The platform policy, fully built in the parent.
#[cfg(target_os = "macos")]
pub(super) struct PlatformSandbox {
    profile: CString,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) struct PlatformSandbox;

impl PlatformSandbox {
    /// Build the policy from the plan's capabilities.
    ///
    /// Everything that can allocate, open a descriptor, or fail happens here,
    /// in the parent, so that the child's apply is a fixed sequence of
    /// syscalls with a typed error.
    #[cfg(target_os = "linux")]
    pub(super) fn build(plan: &ValidatedPlan) -> Result<Self, PrepareError> {
        use crate::sandbox::{Sandbox, SeccompOpts};

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
        // Asked about what the POLICY requested, not about `prepared.fallback()`.
        // `prepare_with_abi_inner` assigns that field only when the kernel's
        // Landlock ABI carries no network rights at all; on ABI V4 and above it
        // stays `None`, so asking it meant a proxy-only plan behaved differently
        // on a modern kernel — accepted and enforced by Landlock port rules
        // alone, with no supervisor, no notify descriptor and no UDP
        // restriction. What the caller asked for does not change with the
        // kernel, so neither does what gets installed.
        //
        // Landlock cannot express proxy-only on *any* kernel: its network
        // rights are per-port, so "only port P" permits reaching every host in
        // the world on port P, and the workload picks the port it dials. Only a
        // supervisor that reads the destination address can answer this, which
        // is what the notify listener is for.
        let proxy_notify = match crate::sandbox::seccomp_network_fallback_mode(plan.capabilities())
        {
            crate::sandbox::SeccompNetFallback::ProxyOnly { bind_ports, .. } => Some(
                crate::sandbox::prepare_seccomp_proxy_filter(!bind_ports.is_empty()),
            ),
            crate::sandbox::SeccompNetFallback::BlockAll
            | crate::sandbox::SeccompNetFallback::None => None,
        };
        Ok(Self {
            prepared,
            network_filter: required_network_filter(plan.capabilities()),
            proxy_notify,
        })
    }

    /// Build the policy from the plan's capabilities.
    #[cfg(target_os = "macos")]
    pub(super) fn build(plan: &ValidatedPlan) -> Result<Self, PrepareError> {
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
    pub(super) fn build(_plan: &ValidatedPlan) -> Result<Self, PrepareError> {
        Err(PrepareError::SandboxSpec {
            reason: format!("no sandbox mechanism on {}", std::env::consts::OS),
        })
    }

    /// Apply the policy to the calling (child) process.
    ///
    /// Allocation-free on Linux: the ruleset descriptors and rule vectors were
    /// built in the parent and are applied with raw syscalls. The seccomp
    /// program is a fixed-size array built on the child's own stack, which is
    /// the only shape a post-`fork` caller may build one in.
    ///
    /// **Two mechanisms, in this order.** Landlock first, then the filter:
    ///
    /// - `seccomp(SET_MODE_FILTER)` needs `CAP_SYS_ADMIN` or
    ///   `PR_SET_NO_NEW_PRIVS`, and `apply_raw` sets no-new-privs before
    ///   `landlock_restrict_self` — but the installer sets it again itself, so
    ///   the order is not what makes the install legal, and reversing it would
    ///   not break that.
    /// - What the order does buy: the Landlock syscalls run before any filter
    ///   of ours can mediate them. Today's program traps only `socket`,
    ///   `socketpair`, and `io_uring_setup`, so it would not touch them either
    ///   way; keeping the sequence in this order makes that a property of the
    ///   sequence rather than of the program's current contents.
    /// - It also matches [`PreparedLandlockSandbox::apply_raw`][raw], which
    ///   installs its own static filter last for the same reason.
    ///
    /// Neither step degrades: a failure at either one returns, and the caller
    /// ([`child_main`]) writes the record and `_exit`s. The child never reaches
    /// the gate, so it can never be released, so the customer's program never
    /// runs with half a policy.
    ///
    /// [raw]: crate::sandbox::PreparedLandlockSandbox::apply_raw
    #[cfg(target_os = "linux")]
    pub(super) fn apply_in_child(&self) -> Result<Option<RawFd>, (PreExecStage, i32)> {
        // The Landlock sub-stage (create/add-rule/restrict) is not carried in
        // the fixed-size record; the errno is.
        self.prepared
            .apply_raw()
            .map_err(|err| (PreExecStage::SandboxApply, err.errno()))?;
        // On a kernel whose Landlock has no network support the prepared policy
        // installs the same program itself, so the child can end up with two
        // identical filters. That is deliberate: they are a few instructions
        // each and both answer EPERM, whereas skipping this on the strength of
        // what the other module decided would make enforcement depend on an
        // inference instead of on the capability set.
        //
        // The match is exhaustive with no wildcard: a new filter variant must
        // be handled here rather than silently installing nothing, which is the
        // shape of the bug this replaced.
        match self.network_filter {
            crate::sandbox::StaticNetworkFilter::None => {}
            crate::sandbox::StaticNetworkFilter::BlockAll => {
                crate::sandbox::install_seccomp_block_network_raw()
                    .map_err(|err| (PreExecStage::NetworkFilter, err.errno()))?;
            }
            crate::sandbox::StaticNetworkFilter::TcpOnly => {
                crate::sandbox::install_seccomp_tcp_only_network_raw()
                    .map_err(|err| (PreExecStage::NetworkFilter, err.errno()))?;
            }
        }

        // Last, so that everything above it is already in force if this one
        // fails. The listener is returned rather than kept: this process is
        // about to be confined by it, and the only useful holder is the parent.
        //
        // The static filter above and this one stack. Their combination is the
        // whole policy: the static one refuses every address family that is not
        // TCP, and this one asks a supervisor about the TCP destinations that
        // remain. Neither is sufficient alone — the static filter cannot read a
        // `sockaddr`, and the listener would never see a UDP socket the static
        // filter had already refused to create.
        match self.proxy_notify.as_ref() {
            None => Ok(None),
            Some(filter) => filter
                .install_raw()
                .map(Some)
                .map_err(|err| (PreExecStage::NetworkFilter, err.errno())),
        }
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
    pub(super) fn apply_in_child(&self) -> Result<Option<RawFd>, (PreExecStage, i32)> {
        // SAFETY: the profile is a NUL-terminated C string owned by the parent
        // and still mapped here. The call is made once, in a freshly forked
        // child that has run nothing else.
        let result = unsafe { crate::sandbox::sandbox_init_raw(self.profile.as_ptr()) };
        if result == 0 {
            // Seatbelt needs no supervisor: the profile expresses "only this
            // localhost port" directly, so there is no listener to hand back.
            Ok(None)
        } else {
            Err((PreExecStage::SandboxApply, result))
        }
    }

    /// Apply the policy to the calling (child) process.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn apply_in_child(&self) -> Result<Option<RawFd>, (PreExecStage, i32)> {
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

        // A PTY is not a missing feature any more; it is a question of
        // *ownership*, exactly like detachment. The master has to be held for
        // as long as the run lives, and only the supervisor outlives the call.
        let interactive =
            sealed(SandboxPlan::new("/bin/echo").session_mode(SessionMode::Interactive));
        assert_eq!(
            refuse_unsupported(&interactive, false).err(),
            Some(PrepareError::InteractiveNeedsSupervisor),
            "an ephemeral path has nobody to own a terminal"
        );
        assert_eq!(
            refuse_unsupported(&interactive, true),
            Ok(()),
            "the supervisor's own path owns one"
        );

        let limited = sealed(
            SandboxPlan::new("/bin/echo").resource_limits(ResourceLimits {
                max_memory_bytes: NonZeroU64::new(1024),
                ..ResourceLimits::default()
            }),
        );
        assert_eq!(
            refuse_unsupported(&limited, false).err(),
            Some(PrepareError::UnsupportedPlanFeature {
                feature: "resource limits"
            })
        );

        // The defaults this slice does implement are accepted.
        assert_eq!(
            refuse_unsupported(&sealed(SandboxPlan::new("/bin/echo")), false),
            Ok(())
        );
    }

    #[test]
    fn a_detached_plan_is_refused_by_every_path_that_cannot_supervise_one() {
        // The refusal is about *ownership*, not about the feature being
        // missing: a detached run needs a process that outlives the caller, and
        // the two paths below have none. The supervisor's own path — which has
        // already forked one — accepts the same plan.
        let detached = sealed(SandboxPlan::new("/bin/echo").detached(true));
        assert_eq!(
            refuse_unsupported(&detached, false).err(),
            Some(PrepareError::DetachedNeedsSupervisor)
        );
        assert_eq!(refuse_unsupported(&detached, true), Ok(()));

        // And the public storeless entry point refuses before it forks
        // anything, so a caller who set the flag never gets an attached run
        // silently.
        let refused =
            PreparedSandbox::prepare(sealed(SandboxPlan::new("/bin/echo").detached(true)));
        assert!(
            matches!(refused, Err(PrepareError::DetachedNeedsSupervisor)),
            "expected a typed refusal, got {refused:?}"
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
    fn a_proxy_only_policy_prepares_the_supervisor_it_needs() {
        use crate::capability::CapabilitySet;

        // Proxy-only mediation is not self-contained: the kernel traps
        // connect/bind/send to a listener that somebody must answer. This slice
        // used to refuse such a policy outright, because it created no such
        // supervisor. It now builds one, and the filter is prepared in the
        // parent so the child's install is a single syscall.
        let plan = sealed(
            SandboxPlan::new("/bin/echo").capabilities(CapabilitySet::new().proxy_only(8080)),
        );
        let sandbox = PlatformSandbox::build(&plan).expect("a proxy-only plan must now build");
        assert!(
            sandbox.proxy_notify.is_some(),
            "a proxy-only plan must carry the listener that answers for it; \
             without one the child blocks on its first network syscall"
        );

        let policy = proxy_policy_for(&plan).expect("the rule the supervisor answers from");
        assert_eq!(policy.proxy_port, 8080);
        assert!(
            policy.bind_ports.is_empty(),
            "nothing asked to listen, so nothing may"
        );
    }

    /// The listener is prepared from what the *policy* asked for, never from
    /// what the kernel turned out to support.
    ///
    /// This was a real hole, in the other direction. `build` used to consult
    /// `prepared.fallback()`, which `prepare_with_abi_inner` assigns only when
    /// the kernel's Landlock ABI carries no network rights at all. On ABI V4
    /// and above it stays `None`, so on precisely the kernels most likely to
    /// run this, a proxy-only policy was enforced by Landlock port rules alone:
    /// no supervisor, no notify descriptor, no UDP restriction. Landlock's
    /// network rights are per-port, so "only port P" permits reaching every
    /// host in the world on port P — and the workload picks the port it dials.
    ///
    /// What the caller asked for does not change with the kernel, so neither
    /// does what gets installed to answer for it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_listener_is_prepared_from_the_policy_not_from_the_kernel() {
        use crate::capability::CapabilitySet;

        let mediated = sealed(
            SandboxPlan::new("/bin/echo").capabilities(CapabilitySet::new().proxy_only(8080)),
        );
        assert!(
            PlatformSandbox::build(&mediated)
                .expect("build")
                .proxy_notify
                .is_some()
        );

        // The shapes that need no supervisor prepare none: a listener nobody
        // needs is a thread nobody stops and a descriptor nobody closes.
        for capabilities in [
            CapabilitySet::new().block_network(),
            CapabilitySet::new().block_network().allow_tcp_connect(443),
        ] {
            let plan = sealed(SandboxPlan::new("/bin/echo").capabilities(capabilities));
            assert!(
                PlatformSandbox::build(&plan)
                    .expect("build")
                    .proxy_notify
                    .is_none()
            );
            assert!(proxy_policy_for(&plan).is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_restrictive_network_policy_arms_the_filter_it_needs() {
        use crate::capability::CapabilitySet;
        use crate::sandbox::StaticNetworkFilter;

        // Landlock has no vocabulary for UDP, for raw sockets, or for any
        // family but TCP, so a kernel that supports `AccessNet` enforces a
        // network policy as far as TCP connect and bind and no further. A held
        // child carrying only the ruleset would report "network blocked" and
        // still send datagrams.
        //
        // Both restrictive shapes therefore need a filter. Asking only about
        // the first is what left DEF-04 open, and this test now covers both.
        assert_eq!(
            required_network_filter(&CapabilitySet::new().block_network()),
            StaticNetworkFilter::BlockAll,
            "a blocked network with no exceptions must deny every socket"
        );
        assert_eq!(
            required_network_filter(&CapabilitySet::new().block_network().allow_tcp_connect(443)),
            StaticNetworkFilter::TcpOnly,
            "a TCP port exception must still deny every family Landlock cannot \
             express -- otherwise granting TCP:443 leaves UDP wide open"
        );

        // And they are armed in the built policy, not merely computable from
        // the capability set: this is the field `apply_in_child` reads.
        // Removing the seccomp step from that path leaves these true and the
        // live probes in `super::probe` red — the tests fail at different ends
        // of the same wire on purpose.
        for (caps, expected) in [
            (
                CapabilitySet::new().block_network(),
                StaticNetworkFilter::BlockAll,
            ),
            (
                CapabilitySet::new().block_network().allow_tcp_connect(443),
                StaticNetworkFilter::TcpOnly,
            ),
        ] {
            let plan = sealed(SandboxPlan::new("/bin/echo").capabilities(caps));
            match PlatformSandbox::build(&plan) {
                Ok(sandbox) => assert_eq!(sandbox.network_filter, expected),
                Err(err) => panic!("a restrictive plan must build: {err}"),
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_policy_that_did_not_ask_for_the_filter_does_not_get_one() {
        use crate::capability::CapabilitySet;
        use crate::sandbox::StaticNetworkFilter;

        // A filter nobody asked for is a capability silently taken away, which
        // is the same class of error as one silently left in place.
        assert_eq!(
            required_network_filter(&CapabilitySet::new()),
            StaticNetworkFilter::None,
            "an open policy must not be filtered"
        );

        let plan = sealed(SandboxPlan::new("/bin/echo").capabilities(CapabilitySet::new()));
        match PlatformSandbox::build(&plan) {
            Ok(sandbox) => assert_eq!(
                sandbox.network_filter,
                StaticNetworkFilter::None,
                "an open policy must build without the filter step"
            ),
            Err(err) => panic!("an open plan must build: {err}"),
        }
    }

    #[test]
    fn a_filter_that_could_not_be_installed_is_a_failed_confinement() {
        // The child half of this cannot be simulated: making the install fail
        // needs a kernel that refuses `seccomp(2)` for one process, and no
        // scaffolding here can arrange that. What is testable is everything
        // the parent does with the record such a child writes, and the first
        // thing is that it is not a success — `prepare` returns the failure
        // instead of a `PreparedSandbox`, so the gate is never opened and the
        // program never runs.
        assert_eq!(
            classify_prepare_record(Ok(Some((
                PreExecStage::NetworkFilter.as_tag(),
                libc::EPERM
            )))),
            Err((PreExecStage::NetworkFilter, libc::EPERM))
        );

        // And it is reported as confinement that was never established, not as
        // a malformed configuration — the same outcome a failed Landlock apply
        // gets, because it is the same fact.
        assert_eq!(
            prepare_outcome(PreExecStage::NetworkFilter, libc::EPERM),
            ExitOutcome::SandboxApplicationFailure {
                stage: PreExecStage::NetworkFilter,
                errno: libc::EPERM,
            }
        );
        assert_eq!(
            prepare_outcome(PreExecStage::SandboxApply, libc::ENOSYS),
            ExitOutcome::SandboxApplicationFailure {
                stage: PreExecStage::SandboxApply,
                errno: libc::ENOSYS,
            }
        );
        // A stage that is not about the confinement keeps the other outcome.
        assert_eq!(
            prepare_outcome(PreExecStage::GateAborted, 0),
            ExitOutcome::PreExecFailure {
                stage: PreExecStage::GateAborted,
                errno: 0,
            }
        );

        // Which the consumer sees as a sandbox failure rather than "your
        // configuration is malformed".
        let exit = SandboxExit::new(
            prepare_outcome(PreExecStage::NetworkFilter, libc::EPERM),
            ActivationObservation::NotActivated,
            ProcessIdentity::capture(0),
        );
        let err: crate::NonoError = PrepareError::ChildFailed { exit }.into();
        assert_eq!(
            err.diagnostic_code(),
            crate::diagnostic::NonoDiagnosticCode::SandboxDeniedPath
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
        held_child_at(FIRST_GENERATION)
    }

    fn held_child_at(generation: u64) -> (PreparedSandbox, ActivationHandle) {
        use crate::capability::{AccessMode, CapabilitySet};

        let caps = match CapabilitySet::new().allow_path("/", AccessMode::Read) {
            Ok(caps) => caps,
            Err(err) => panic!("test capabilities must build: {err}"),
        };
        let plan = sealed(
            SandboxPlan::new("/bin/echo")
                .arg("held")
                .capabilities(caps)
                .generation(generation),
        );
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
    fn the_generation_compared_on_release_is_the_one_the_caller_chose() {
        // `a_handle_for_another_generation_is_refused` only ever exercises the
        // default, so it passes whether or not the plan's generation is read at
        // all: the comparison is `1 != 2` either way. Before `SandboxPlan::
        // generation` existed the field was hardcoded to FIRST_GENERATION, so
        // the check was `1 != 1` for every real caller -- present, and deciding
        // nothing.
        const CHOSEN: u64 = 7;
        let (mut held, handle) = held_child_at(CHOSEN);

        // The caller's generation reached the handle, rather than the default.
        assert_eq!(handle.generation(), CHOSEN);
        assert_ne!(handle.generation(), FIRST_GENERATION);

        // A handle from the generation before this one -- the shape a stale
        // control-plane release actually takes -- is refused, and the error
        // names the caller's generation rather than the default.
        let stale = ActivationHandle::new(
            handle.session_id(),
            CHOSEN.saturating_sub(1),
            *handle.token(),
        );
        assert_eq!(
            held.activate(&stale).err(),
            Some(ActivationError::WrongGeneration {
                expected: CHOSEN,
                supplied: CHOSEN - 1,
            })
        );
        assert_eq!(held.state(), LifecycleState::Prepared);

        // And the genuine handle still activates: the binding refuses the wrong
        // generation without refusing the right one.
        assert!(held.activate(&handle).is_ok());
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
