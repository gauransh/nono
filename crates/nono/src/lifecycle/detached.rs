//! Talking to a run that is not this process's child.
//!
//! [`DetachedSession`] is the caller's end of the control protocol: a connected
//! Unix socket, a session id, a generation, and the identity of the supervisor
//! on the other end. Everything it offers mirrors the in-process API —
//! activate, wait, stop, status, verify cleanup, probe enforcement — and every
//! one of those goes over the wire to a *different process* that owns the
//! child.
//!
//! # What is different from the in-process handles
//!
//! Dropping a [`super::PreparedSandbox`] or an [`super::ActivatedSandbox`]
//! kills and reaps the run: nothing survives its supervisor, because in those
//! paths the caller *is* the supervisor. Dropping a `DetachedSession` closes a
//! socket. The run carries on, the supervisor carries on watching it, and a
//! later connection — from this process or from its replacement after a restart
//! — picks up where this one left off. That is the whole point of R09, and it
//! is why [`Self::detach`] exists as a name for what a drop already does: the
//! intent deserves to be stated at the call site rather than inferred from a
//! scope ending.
//!
//! # Every operation is bounded
//!
//! There is no unbounded read here. Each request carries a deadline, each reply
//! is waited for with `poll`, and a supervisor that stops answering produces
//! [`DetachedError::Timeout`] rather than a parked caller. [`Self::wait`] is
//! bounded twice over: the caller's own duration, and the per-frame bound the
//! supervisor applies so that one client cannot park the single thread that
//! also serves everything else.
//!
//! # Events while detached
//!
//! [`super::EventSink`] is caller-side by design, so a supervisor with no
//! caller has nowhere to deliver events *to*. It keeps the last
//! [`DETACHED_EVENT_RING_CAPACITY`][cap] of them in the session record instead,
//! and [`Self::status`] is how a reconnecting caller reads them. The fidelity
//! is stated rather than implied: the ring is bounded and drops its oldest
//! entry, so a caller that needs every event has to stay connected.
//!
//! [cap]: super::DETACHED_EVENT_RING_CAPACITY

use super::cleanup::CleanupVerification;
use super::exit::SandboxExit;
use super::gate::ActivationHandle;
use super::identity::ProcessIdentity;
use super::probe::{ProbeObservation, ProbeRequest};
use super::protocol::{
    CONTROL_PROTOCOL_VERSION, ControlRefusal, ControlReply, ControlRequest, FrameError,
    SessionStatus, WaitOutcome, read_frame, set_nonblocking, write_frame,
};
use super::session_store::SessionStoreError;
use super::state::LifecycleState;
use super::terminal::{AttachAck, AttachedTerminal, WindowSize};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

/// How long a single control exchange may take before it is abandoned.
///
/// Generous, because the operations behind it can involve a `waitpid`, a
/// `fsync`, and a process probe — and mean, because the alternative is a caller
/// parked forever on a supervisor that stopped answering.
pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest a supervisor will hold one [`ControlRequest::Wait`] open.
///
/// A wait is the one operation whose natural duration is the caller's to
/// choose, and the one that would otherwise let a single client hold the
/// supervisor's only thread for as long as it liked. The supervisor answers
/// [`WaitOutcome::StillRunning`] at this bound; [`DetachedSession::wait`] then
/// asks again until the caller's own deadline is spent, so the caller still
/// gets exactly the wait it asked for.
pub const MAX_CONTROL_WAIT: Duration = Duration::from_secs(30);

/// Everything talking to a detached supervisor can fail with.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DetachedError {
    /// The record names no live supervisor, so there is nothing to connect to.
    #[error("session {session_id} has no live supervisor to attach to")]
    NoSupervisor {
        /// The session that was asked for.
        session_id: Uuid,
    },

    /// The control socket could not be connected to.
    ///
    /// A socket file with nobody listening answers `ECONNREFUSED`; that is what
    /// a supervisor that died without unlinking leaves behind, and
    /// [`super::SessionStore::recover`] is what cleans it up.
    #[error("control socket {path} could not be connected to: errno {errno}")]
    Connect {
        /// The socket that was tried.
        path: PathBuf,
        /// Platform error number.
        errno: i32,
    },

    /// The conversation itself failed.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// The supervisor refused, and this is which check refused.
    #[error(transparent)]
    Refused(ControlRefusal),

    /// The supervisor answered something this request has no use for.
    ///
    /// A protocol bug rather than a caller error, reported rather than panicked
    /// on: a library that aborted on a surprising frame would turn a peer's
    /// mistake into this process's crash.
    #[error("the supervisor answered {received} where {expected} was expected")]
    UnexpectedReply {
        /// What the request needed back.
        expected: &'static str,
        /// What arrived instead.
        received: String,
    },

    /// The store could not be read.
    #[error(transparent)]
    Session(#[from] SessionStoreError),
}

impl DetachedError {
    /// The refusal, when the supervisor refused.
    #[must_use]
    pub fn refusal(&self) -> Option<&ControlRefusal> {
        match self {
            Self::Refused(refusal) => Some(refusal),
            _ => None,
        }
    }
}

/// A connected conversation with the supervisor of a detached run.
///
/// Built by [`super::SessionStore::prepare_detached`] (which launches the
/// supervisor), [`super::SessionStore::attach_control`] (which connects to one
/// by session id), or [`super::RecoveredSession::attach`] (which connects to
/// one a recovery has just proven alive).
pub struct DetachedSession {
    session_id: Uuid,
    generation: u64,
    supervisor: ProcessIdentity,
    stream: UnixStream,
    /// The state the supervisor reported when this connection opened. Not
    /// followed afterwards: [`Self::status`] asks.
    opened_in: LifecycleState,
    /// The cgroup the run was placed in, learned at activation.
    ///
    /// `None` before activation because the placement happens as the gate
    /// opens, and `None` afterwards on a host that would not give the
    /// supervisor a cgroup. Both mean "there is no cgroup to attach to", which
    /// is the only thing a consumer can act on.
    cgroup: Option<String>,
}

impl DetachedSession {
    /// The cgroup the run was placed in, if any.
    ///
    /// Learned from the activation reply, so it answers `None` before the run
    /// is activated as well as on a host that would not give the supervisor a
    /// cgroup. A consumer attaching its own enforcement to the run needs the
    /// cgroup the workload is actually in; deriving a path from the session id
    /// would be guessing at this library's naming.
    #[must_use]
    pub fn cgroup(&self) -> Option<&str> {
        self.cgroup.as_deref()
    }

    /// Connect and exchange hellos.
    ///
    /// The hello is not a formality: it is where the protocol version, the
    /// session, and the generation are agreed, and a mismatch in any of the
    /// three ends the connection before an operation can be sent against the
    /// wrong run.
    pub(super) fn connect(
        socket: &Path,
        session_id: Uuid,
        generation: u64,
        supervisor: ProcessIdentity,
    ) -> Result<Self, DetachedError> {
        let stream = UnixStream::connect(socket).map_err(|err| DetachedError::Connect {
            path: socket.to_path_buf(),
            errno: err.raw_os_error().unwrap_or(0),
        })?;
        set_nonblocking(stream.as_raw_fd())?;

        let mut session = Self {
            session_id,
            generation,
            supervisor,
            stream,
            opened_in: LifecycleState::Planning,
            // Not known until activation, which is when the placement happens.
            cgroup: None,
        };
        let hello = ControlRequest::Hello {
            protocol: CONTROL_PROTOCOL_VERSION,
            session_id,
            generation,
        };
        match session.exchange(&hello, CONTROL_TIMEOUT)? {
            ControlReply::Hello {
                protocol,
                session_id: theirs,
                generation: their_generation,
                state,
            } => {
                // Checked on this side too. The supervisor has already checked
                // the same three things about us; a hello that agreed in one
                // direction and not the other would mean the two ends disagree
                // about which run they are holding.
                if protocol != CONTROL_PROTOCOL_VERSION {
                    return Err(DetachedError::Refused(ControlRefusal::ProtocolVersion {
                        expected: CONTROL_PROTOCOL_VERSION,
                        supplied: protocol,
                    }));
                }
                if theirs != session_id {
                    return Err(DetachedError::Refused(ControlRefusal::WrongSession {
                        expected: session_id,
                        supplied: theirs,
                    }));
                }
                if their_generation != generation {
                    return Err(DetachedError::Refused(ControlRefusal::WrongGeneration {
                        expected: generation,
                        supplied: their_generation,
                    }));
                }
                session.opened_in = state;
                Ok(session)
            }
            other => Err(unexpected("hello", &other)),
        }
    }

    /// The session this conversation is about.
    #[must_use]
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// The generation this conversation is about.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The supervisor process on the other end, with the facts that make its
    /// pid non-reusable.
    #[must_use]
    pub fn supervisor(&self) -> &ProcessIdentity {
        &self.supervisor
    }

    /// Where the run was when this connection opened.
    ///
    /// A snapshot, deliberately not followed: [`Self::status`] asks the
    /// supervisor rather than reporting a value that went stale the moment it
    /// was read.
    #[must_use]
    pub fn opened_in(&self) -> LifecycleState {
        self.opened_in
    }

    /// Release the held child, exactly once.
    ///
    /// The token travels over this socket — in a `0700` directory, with the
    /// peer's uid checked at accept — and is compared supervisor-side by
    /// digest. It is never written to the record and never rendered by a
    /// `Debug`.
    ///
    /// Single use is enforced where it always is: in the gate's state machine,
    /// in the supervisor. A second call with the same handle, or with a copy of
    /// it, is refused there and the refusal comes back as
    /// [`ControlRefusal::Activation`].
    ///
    /// # Errors
    ///
    /// [`DetachedError::Refused`] carrying the [`super::ActivationError`] the
    /// gate produced, or a transport failure.
    pub fn activate(&mut self, handle: &ActivationHandle) -> Result<LifecycleState, DetachedError> {
        // A third copy of the token — the handle's, the frame's, and this one —
        // and the only one without an owner that zeroizes it. Wiped as soon as
        // the exchange is over, whichever way it went, so the caller's copy in
        // the handle stays the only one alive.
        let mut request = ControlRequest::Activate {
            token: *handle.token(),
        };
        let outcome = self.exchange(&request, CONTROL_TIMEOUT);
        if let ControlRequest::Activate { token } = &mut request {
            token.zeroize();
        }
        match outcome? {
            ControlReply::Activated { state, cgroup } => {
                self.cgroup = cgroup;
                Ok(state)
            }
            other => Err(unexpected("activated", &other)),
        }
    }

    /// Wait up to `timeout` for the run to end.
    ///
    /// Answers [`WaitOutcome::Exit`] with the facts the *supervisor* witnessed
    /// — it is the process that called `waitpid`, so the exit code or signal is
    /// a directly observed fact even though this process never forked the
    /// child. [`WaitOutcome::StillRunning`] means exactly what it says: the run
    /// had not ended by the deadline. It is never rounded into an exit.
    ///
    /// Long waits are made of short ones. The supervisor holds a single wait
    /// for at most [`MAX_CONTROL_WAIT`] so that one client cannot occupy the
    /// thread that also serves everything else; this asks again until
    /// `timeout` is spent.
    ///
    /// # Errors
    ///
    /// A transport failure, or a refusal from a supervisor whose run is in a
    /// state where waiting has no meaning.
    pub fn wait(&mut self, timeout: Duration) -> Result<WaitOutcome, DetachedError> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let slice = left.min(MAX_CONTROL_WAIT);
            let request = ControlRequest::Wait {
                deadline_millis: u64::try_from(slice.as_millis()).unwrap_or(u64::MAX),
            };
            // The reply deadline is the slice plus the ordinary control
            // timeout: the supervisor is allowed the whole slice to wait *and*
            // the usual allowance to answer.
            let outcome = match self.exchange(&request, slice.saturating_add(CONTROL_TIMEOUT))? {
                ControlReply::Waited { outcome } => outcome,
                other => return Err(unexpected("waited", &other)),
            };
            if matches!(outcome, WaitOutcome::Exit(_)) || Instant::now() >= deadline {
                return Ok(outcome);
            }
        }
    }

    /// End the run now, and report what the death looked like.
    ///
    /// The signal is not the result: this returns only after the supervisor's
    /// `waitpid` observed the death, and the [`SandboxExit`] carries what that
    /// observation said.
    ///
    /// # Errors
    ///
    /// [`DetachedError::Refused`] carrying the [`super::StopError`] the run
    /// produced — a run that already ended is not stoppable — or a transport
    /// failure.
    pub fn stop(&mut self) -> Result<SandboxExit, DetachedError> {
        match self.exchange(&ControlRequest::Stop, CONTROL_TIMEOUT)? {
            ControlReply::Stopped { exit } => Ok(exit),
            other => Err(unexpected("stopped", &other)),
        }
    }

    /// Ask where the run is, with its record and its event ring.
    ///
    /// # Errors
    ///
    /// A transport failure.
    pub fn status(&mut self) -> Result<SessionStatus, DetachedError> {
        match self.exchange(&ControlRequest::Status, CONTROL_TIMEOUT)? {
            ControlReply::Status { status } => Ok(*status),
            other => Err(unexpected("status", &other)),
        }
    }

    /// Prove the run's processes are gone — or hear honestly that they are not.
    ///
    /// The probe runs in the supervisor, which is the process that reaped the
    /// child and therefore the only one that can ask the reaped-and-group-empty
    /// question rather than the weaker identity one.
    ///
    /// # Errors
    ///
    /// [`DetachedError::Refused`] carrying [`ControlRefusal::Cleanup`] when the
    /// run's end has not been observed or its cleanup was already proven, or a
    /// transport failure.
    pub fn verify_cleanup(&mut self) -> Result<CleanupVerification, DetachedError> {
        match self.exchange(&ControlRequest::VerifyCleanup, CONTROL_TIMEOUT)? {
            ControlReply::Cleanup { verdict, .. } => Ok(verdict),
            other => Err(unexpected("cleanup", &other)),
        }
    }

    /// Ask the held child what its installed enforcement does with one
    /// operation.
    ///
    /// The mirror of [`super::PreparedSandbox::probe_enforcement`] for a run
    /// this process does not own. The request crosses the socket, the
    /// supervisor puts it to the child it is holding, the child attempts the
    /// operation with a single real syscall, and the kernel's own `errno` comes
    /// back. **The answer is never derived from the plan's
    /// [`CapabilitySet`][crate::CapabilitySet] and never from a
    /// [`QueryContext`][crate::query::QueryContext]** — a policy that applied
    /// without an error is not evidence that it is enforced, in exactly the way
    /// [`super::cleanup`] says a sent signal is not evidence that a process
    /// died.
    ///
    /// **Nothing is memoised.** Two identical requests are two frames, two
    /// exchanges with the child, and two syscalls; a remembered answer would be
    /// a claim about a moment that has passed. The operation really happens
    /// each time, so a `Create` probe that comes back
    /// [`ProbeOutcome::Permitted`][ok] has created the file twice over — or,
    /// the second time, told you the kernel said `EEXIST`. See
    /// [`super::probe`].
    ///
    /// The observation crosses unchanged. The supervisor does not reinterpret
    /// an outcome: an [`Indeterminate`][ind] stays indeterminate rather than
    /// becoming a refusal or a permission, and
    /// [`denial_observed`][denial] is never upgraded on the way past.
    ///
    /// Legal only while the run is held at the gate. Once it is
    /// [`Running`][run] the child is the customer's program and the scope this
    /// method reports — [`ProbeScope::InstalledChild`][scope] — is unreachable;
    /// the refusal is [`ControlRefusal::ProbeAfterActivation`] and names the
    /// weaker scope a post-activation probe would have to claim, rather than
    /// answering with something re-derived.
    ///
    /// # Errors
    ///
    /// [`DetachedError::Refused`] carrying [`ControlRefusal::Probe`] with the
    /// [`ProbeError`] the run produced, or
    /// [`ControlRefusal::ProbeAfterActivation`] for a released run. A
    /// supervisor that has died or stopped answering is a
    /// [`DetachedError::Frame`] — a transport fact, never an observation this
    /// side invented. A request whose encoded form would exceed
    /// [`MAX_CONTROL_FRAME_BYTES`][limit] — an over-long
    /// [`ProbeId`][id] or path, or a path that is not UTF-8 — is refused by the
    /// framing with nothing written, so the connection survives it and the next
    /// request is answered normally.
    ///
    /// [ok]: super::ProbeOutcome::Permitted
    /// [ind]: super::ProbeOutcome::Indeterminate
    /// [denial]: ProbeObservation::denial_observed
    /// [run]: LifecycleState::Running
    /// [scope]: super::ProbeScope::InstalledChild
    /// [limit]: super::MAX_CONTROL_FRAME_BYTES
    /// [id]: super::ProbeId
    pub fn probe_enforcement(
        &mut self,
        request: &ProbeRequest,
    ) -> Result<ProbeObservation, DetachedError> {
        let frame = ControlRequest::ProbeEnforcement {
            request: request.clone(),
        };
        match self.exchange(&frame, CONTROL_TIMEOUT)? {
            ControlReply::ProbeObservation(observation) => Ok(observation),
            other => Err(unexpected("probe_observation", &other)),
        }
    }

    /// Take over the run's terminal.
    ///
    /// Only an interactive run has one: a headless run's standard streams are
    /// `/dev/null`, and the refusal for one is
    /// [`ControlRefusal::NoTerminal`] rather than an attach to a terminal that
    /// would never say anything.
    ///
    /// `window` is applied to the terminal *before* any output is replayed, so
    /// a program released after this reads the size the viewer actually has.
    /// The returned [`AttachedTerminal`] holds this connection; [`detach`][d]
    /// gives it back.
    ///
    /// Attach occupies the supervisor's single client slot. A second connection
    /// is told [`ControlRefusal::Busy`] exactly as it was before, which is also
    /// why there is no separate "already attached" answer: a second attach
    /// cannot reach the supervisor to be refused.
    ///
    /// # Errors
    ///
    /// [`DetachedError::Refused`] carrying [`ControlRefusal::NoTerminal`] for a
    /// headless run, or a transport failure. Either way this connection is
    /// spent — reconnect with [`super::SessionStore::attach_control`]; the run
    /// itself is untouched.
    ///
    /// [d]: AttachedTerminal::detach
    pub fn attach(mut self, window: WindowSize) -> Result<AttachedTerminal, DetachedError> {
        let ack = self.attach_request(window)?;
        Ok(AttachedTerminal::new(self, ack, window))
    }

    /// Ask for the mode switch and take the ack.
    ///
    /// Shared with [`AttachedTerminal::activate`], which re-enters attach mode
    /// after a control exchange and must ask exactly the same question.
    pub(super) fn attach_request(
        &mut self,
        window: WindowSize,
    ) -> Result<AttachAck, DetachedError> {
        match self.exchange(&ControlRequest::Attach { window }, CONTROL_TIMEOUT)? {
            ControlReply::AttachAck { ack } => Ok(*ack),
            other => Err(unexpected("attach_ack", &other)),
        }
    }

    /// The socket underneath, for the terminal channel that borrows it.
    pub(super) fn stream(&mut self) -> &mut UnixStream {
        &mut self.stream
    }

    /// Leave, politely.
    ///
    /// The run carries on. Saying goodbye rather than simply dropping lets the
    /// supervisor free its single client slot immediately instead of
    /// discovering the close on its next read, which is what makes an
    /// attach-detach-attach sequence deterministic.
    ///
    /// Best effort by construction: a supervisor that has already gone away
    /// cannot be told anything, and there is nothing left for the caller to do
    /// about it.
    pub fn detach(mut self) {
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        if write_frame(&mut self.stream, &ControlRequest::Goodbye, deadline).is_ok() {
            let _: Result<ControlReply, FrameError> = read_frame(&mut self.stream, deadline);
        }
    }

    /// One request, one reply, both bounded.
    fn exchange(
        &mut self,
        request: &ControlRequest,
        timeout: Duration,
    ) -> Result<ControlReply, DetachedError> {
        let deadline = Instant::now() + timeout;
        write_frame(&mut self.stream, request, deadline)?;
        let reply: ControlReply = read_frame(&mut self.stream, deadline)?;
        match reply {
            ControlReply::Refused { refusal } => Err(DetachedError::Refused(refusal)),
            reply => Ok(reply),
        }
    }
}

/// Name a reply that does not answer the question that was asked.
fn unexpected(expected: &'static str, received: &ControlReply) -> DetachedError {
    DetachedError::UnexpectedReply {
        expected,
        // The reply's own tag, not its contents: a mismatched reply is a
        // protocol fact, and its payload is not this error's business.
        received: reply_name(received).to_string(),
    }
}

/// The stable name of a reply variant.
fn reply_name(reply: &ControlReply) -> &'static str {
    match reply {
        ControlReply::Hello { .. } => "hello",
        ControlReply::Activated { .. } => "activated",
        ControlReply::Waited { .. } => "waited",
        ControlReply::Stopped { .. } => "stopped",
        ControlReply::Status { .. } => "status",
        ControlReply::Cleanup { .. } => "cleanup",
        ControlReply::ProbeObservation(_) => "probe_observation",
        ControlReply::AttachAck { .. } => "attach_ack",
        ControlReply::Farewell => "farewell",
        ControlReply::Refused { .. } => "refused",
    }
}

/// Debug that names the conversation without naming what travels on it.
impl std::fmt::Debug for DetachedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachedSession")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("supervisor", &self.supervisor)
            .field("opened_in", &self.opened_in)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_that_answers_a_different_question_is_named_not_panicked_on() {
        let err = unexpected("stopped", &ControlReply::Farewell);
        assert_eq!(
            err,
            DetachedError::UnexpectedReply {
                expected: "stopped",
                received: "farewell".to_string(),
            }
        );
    }

    #[test]
    fn a_refusal_is_reachable_without_matching_on_the_whole_error() {
        let refused = DetachedError::Refused(ControlRefusal::Busy);
        assert_eq!(refused.refusal(), Some(&ControlRefusal::Busy));
        assert_eq!(
            DetachedError::NoSupervisor {
                session_id: Uuid::nil()
            }
            .refusal(),
            None
        );
    }

    #[test]
    fn the_wait_bound_is_shorter_than_the_transport_bound_it_rides_on() {
        // If a single wait slice could outlast the frame deadline wrapped
        // around it, every long wait would time out in transport rather than
        // answering StillRunning.
        assert!(
            MAX_CONTROL_WAIT < MAX_CONTROL_WAIT + CONTROL_TIMEOUT,
            "the reply allowance must be strictly more than the wait itself"
        );
        assert!(CONTROL_TIMEOUT > Duration::from_secs(1));
    }
}
