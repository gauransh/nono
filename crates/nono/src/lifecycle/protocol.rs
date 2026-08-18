//! Control protocol v2: what a caller and a detached supervisor say to each
//! other, and how.
//!
//! A detached run is reached over a Unix socket in the session store's `0700`
//! directory. This module is the whole of that conversation: the framing, the
//! two message vocabularies, the typed refusals, and the deadline-bounded reads
//! and writes both sides use. Contract §11 and ADR-0002 §4 are what it
//! implements.
//!
//! # Framing
//!
//! ```text
//! [u32 little-endian length][length bytes of JSON]
//! ```
//!
//! Length-prefixed rather than delimited, because a delimiter has to be escaped
//! and an escape has to be got right on both sides. The prefix is checked
//! against [`MAX_CONTROL_FRAME_BYTES`] *before* a byte of the body is read, so
//! a peer cannot make either side allocate on the say-so of a number it chose;
//! an oversize prefix is a typed refusal and the end of the connection, because
//! there is no way to resynchronize a stream whose length field cannot be
//! trusted.
//!
//! JSON inside the frame is deliberate. The payloads are the module's own typed
//! results — [`ActivationError`], [`SandboxExit`], [`CleanupVerification`] —
//! and shipping them through `serde` means the client receives *the same value*
//! the supervisor produced rather than a rendering it has to parse back. The
//! cost is a parser on both sides, and the bound above is what keeps that
//! parser from being a resource question.
//!
//! # Hello first, in both directions
//!
//! The first frame each side sends is a hello carrying the protocol version,
//! the session id, and the generation. All three are checked, and any mismatch
//! is a typed [`ControlRefusal`] followed by a close — never a best-effort
//! conversation with a peer that disagrees about what it is talking to. A
//! client that sends anything else first is refused the same way: an operation
//! that arrived before the hello was, by definition, not checked against the
//! session it names.
//!
//! # Nothing here blocks without a deadline
//!
//! Every read and every write on both sides goes through [`read_frame`] and
//! [`write_frame`], which take an [`Instant`] deadline and reach the socket
//! only through `poll`. This is what closes the unbounded-read residual
//! ADR-0001 left behind for the detached path: a peer that connects and then
//! says nothing cannot park the supervisor, and a supervisor that stops
//! answering cannot park the client.
//!
//! # The activation token
//!
//! [`ControlRequest::Activate`] is the one frame that carries secret material.
//! It exists because the token *has* to cross the process boundary somehow, and
//! this socket — in a `0700` directory, peer-uid checked at accept — is the
//! narrowest place to do it. The token is compared supervisor-side by digest,
//! is never written to the session record, and never reaches a log or a
//! `Debug` line: [`ControlRequest`] has a hand-written [`std::fmt::Debug`] that
//! redacts it, for exactly the reason [`super::ActivationHandle`] has one.

use super::cleanup::CleanupVerification;
use super::exit::SandboxExit;
use super::gate::{ACTIVATION_TOKEN_BYTES, ActivationError, StopError};
use super::probe::{ProbeError, ProbeObservation, ProbeRequest, ProbeScope};
use super::state::LifecycleState;
use super::terminal::{AttachAck, WindowSize};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The protocol version this build speaks, and the only one it accepts.
///
/// Two, because [`ControlRequest::ProbeEnforcement`] and its reply were added
/// to the vocabulary. The hello is where the disagreement is settled and it is
/// settled by refusing: a v1 supervisor has no probe verb, so a v2 client that
/// were allowed to talk to one would discover that as a malformed frame — a
/// transport failure standing in for a missing feature. A caller that asks a
/// supervisor for an answer it cannot give deserves to be told which of the two
/// it is.
pub const CONTROL_PROTOCOL_VERSION: u32 = 2;

/// Headroom the wire bound keeps over the record bound, in bytes.
///
/// A status reply is the largest thing this protocol carries and it is *not*
/// just a record: it is a record inside a `SessionStatus` inside a tagged
/// `ControlReply`. Those wrappers cost a few dozen bytes of JSON, so a bound
/// equal to [`super::MAX_RECORD_BYTES`] would refuse a record that had been
/// perfectly legal to write. Four kibibytes is three orders of magnitude more
/// than the envelope actually needs and still nothing next to the frame.
const CONTROL_ENVELOPE_ALLOWANCE: usize = 4 * 1024;

/// Largest control frame either side will send or read, in bytes.
///
/// `MAX_RECORD_BYTES` (65536) + [`CONTROL_ENVELOPE_ALLOWANCE`] (4096) = 69632.
/// The arithmetic is the point: the largest reply the protocol can produce is a
/// status carrying a whole session record, so the wire bound has to be strictly
/// *larger* than the storage bound or a record that fits on disk would not fit
/// on the socket. `a_record_at_its_bound_still_fits_a_frame` locks the
/// inequality.
pub const MAX_CONTROL_FRAME_BYTES: usize =
    super::MAX_RECORD_BYTES.saturating_add(CONTROL_ENVELOPE_ALLOWANCE);

/// Compile-time check that the wire bound leaves room for a whole record.
///
/// At module level rather than in a test, because it is an arithmetic fact
/// about two constants: a build in which a record that fits on disk would not
/// fit on the socket should not link, let alone reach a test run.
const _: () = assert!(MAX_CONTROL_FRAME_BYTES > super::MAX_RECORD_BYTES);

/// Compile-time check that the allowance is real headroom rather than a
/// rounding artefact. An empty status envelope is a few dozen bytes.
const _: () = assert!(CONTROL_ENVELOPE_ALLOWANCE >= 1024);

/// Bytes JSON needs for one byte it has to escape as `\u00XX`.
///
/// The worst case, not the usual one: an ordinary path costs one byte per byte.
const WORST_CASE_JSON_ESCAPE: usize = 6;

/// Compile-time check that the longest path a probe can name still fits a
/// frame, even if every byte of it has to be escaped.
///
/// A path is the largest thing [`ControlRequest::ProbeEnforcement`] carries, and
/// the channel to the held child bounds it at
/// [`PROBE_PATH_BYTES`][super::probe::PROBE_PATH_BYTES]. If the escaped worst
/// case did not fit here, a path the child's own channel would have accepted
/// could not be *asked about* over the socket — and the failure would land on
/// the framing rather than on the bound that caused it. The caller's
/// [`ProbeId`][id] is not in this sum because it is unbounded by design; a
/// request that overruns the frame because of one is refused by
/// [`write_frame`], with nothing written.
///
/// [id]: super::ProbeId
const _: () = assert!(
    super::probe::PROBE_PATH_BYTES * WORST_CASE_JSON_ESCAPE + CONTROL_ENVELOPE_ALLOWANCE
        < MAX_CONTROL_FRAME_BYTES
);

/// Bytes of length prefix in front of every frame.
const LENGTH_PREFIX_BYTES: usize = 4;

/// Everything framing itself can refuse.
///
/// Distinct from [`ControlRefusal`], which is a refusal one side *sends* to the
/// other. These are the failures of the channel underneath that vocabulary: if
/// framing failed, there may be nobody left to tell.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FrameError {
    /// The socket read or write failed.
    #[error("control socket i/o failed: errno {errno}")]
    Io {
        /// Platform error number.
        errno: i32,
    },

    /// The deadline passed with the frame incomplete.
    ///
    /// Not an error about the peer's *intent*: a slow peer and a silent one
    /// look the same from here, which is why the answer is a deadline rather
    /// than a guess.
    #[error("control frame did not complete before its deadline")]
    Timeout,

    /// The peer closed the connection.
    #[error("the control connection was closed by the peer")]
    Closed,

    /// The peer announced a frame larger than [`MAX_CONTROL_FRAME_BYTES`].
    ///
    /// Nothing was read past the prefix, and nothing was allocated.
    #[error("control frame announced {size} bytes (max {limit})")]
    TooLarge {
        /// The size the prefix claimed.
        size: u64,
        /// The bound.
        limit: usize,
    },

    /// The frame's body was not a message this protocol has.
    #[error("control frame could not be understood: {why}")]
    Malformed {
        /// What was wrong with it, without echoing the bytes back.
        why: String,
    },
}

impl FrameError {
    /// The `FrameError` for the last OS error on this thread.
    fn last_os() -> Self {
        Self::Io {
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        }
    }

    /// Whether this failure can be reported back to the peer at all.
    ///
    /// A malformed or oversize frame leaves the connection usable for exactly
    /// one more write — the refusal — and nothing after it. A timeout or a
    /// closed socket leaves nothing.
    #[must_use]
    pub fn is_reportable(&self) -> bool {
        matches!(self, Self::TooLarge { .. } | Self::Malformed { .. })
    }
}

/// What one side is refusing, and why.
///
/// Typed rather than a message, because every one of these is something the
/// other side has to *decide* about: retry with the right generation, give up
/// because the session is not this one, wait because somebody else is
/// connected. Matching on prose is not a contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ControlRefusal {
    /// The peer speaks a different protocol version.
    #[error("control protocol version {supplied} is not {expected}")]
    ProtocolVersion {
        /// The version this supervisor speaks.
        expected: u32,
        /// The version the peer announced.
        supplied: u32,
    },

    /// The hello named a different session.
    #[error("control connection is for session {supplied}, not {expected}")]
    WrongSession {
        /// The session this supervisor owns.
        expected: Uuid,
        /// The session the peer named.
        supplied: Uuid,
    },

    /// The hello named a different generation of this session.
    #[error("control connection is for generation {supplied}, not {expected}")]
    WrongGeneration {
        /// The generation this supervisor is serving.
        expected: u64,
        /// The generation the peer named.
        supplied: u64,
    },

    /// Another client is already connected.
    ///
    /// One client at a time, deliberately: the operations this protocol offers
    /// are not commutative — an activation and a stop racing over one gate is
    /// exactly the situation the gate's single-use claim exists to settle, and
    /// settling it twice, once in the gate and once in the socket, would be two
    /// answers to one question. A second client is told so and closed rather
    /// than queued, so it learns *now* rather than after an unbounded wait.
    #[error("another client is connected to this session")]
    Busy,

    /// The peer's first frame was not a hello.
    #[error("the first control frame must be a hello")]
    HelloExpected,

    /// The peer announced an oversize frame.
    #[error("control frame announced {size} bytes (max {limit})")]
    FrameTooLarge {
        /// The size the prefix claimed.
        size: u64,
        /// The bound.
        limit: usize,
    },

    /// The peer's frame could not be understood.
    #[error("control frame could not be understood: {why}")]
    Malformed {
        /// What was wrong with it.
        why: String,
    },

    /// The activation was refused, with the reason the gate gave.
    #[error(transparent)]
    Activation(ActivationError),

    /// The stop was refused, with the reason the run gave.
    #[error(transparent)]
    Stop(StopError),

    /// Cleanup verification was refused in this state.
    #[error("cleanup verification is not legal in state {state}")]
    Cleanup {
        /// The state that refused.
        state: LifecycleState,
    },

    /// The probe was refused, with the reason the run gave.
    ///
    /// The held child's own typed answer, carried across unchanged — the same
    /// arrangement [`Self::Activation`] and [`Self::Stop`] use. A probe that
    /// *reached* the child is never in here: it produced an observation,
    /// however unhelpful.
    #[error(transparent)]
    Probe(ProbeError),

    /// A probe was asked for once the child had left the gate.
    ///
    /// [`ProbeScope::InstalledChild`] is only reachable while the child is
    /// held. After activation that process is the customer's program and the
    /// gate descriptor is gone, so the only probe still available would be a
    /// fresh sibling with the plan's capabilities re-applied — which is
    /// [`ProbeScope::RederivedSibling`] and proves something strictly weaker:
    /// that the mechanism is still *installable*, not that this child is still
    /// confined. This build does not produce that scope, so the honest answer
    /// is this refusal. A remembered or re-derived result wearing the stronger
    /// label is the one lie the two scopes exist to prevent.
    #[error(
        "a probe after activation would be scope {required_scope}, which this build does not \
         produce; run is {state}"
    )]
    ProbeAfterActivation {
        /// The state that refused.
        state: LifecycleState,
        /// The strongest scope such a probe could honestly claim.
        required_scope: ProbeScope,
    },

    /// The run has no terminal to attach to.
    ///
    /// A headless run's standard streams are `/dev/null` and there is no PTY
    /// anywhere in the picture, so there is nothing an attach could show. The
    /// refusal is typed rather than an empty terminal, because a client that
    /// attached to a run that cannot speak would sit watching silence and
    /// conclude the run had hung.
    #[error("this run is headless: there is no terminal to attach to")]
    NoTerminal,

    /// The operation is one a later slice implements.
    #[error("control operation {op} is not implemented in this build")]
    Unimplemented {
        /// The operation that was asked for.
        op: String,
    },
}

/// What a client asks a detached supervisor to do.
///
/// [`Self::Hello`] must be the first frame; everything else is refused until it
/// has arrived and been checked.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Open the conversation and state what this client believes it is talking
    /// to.
    Hello {
        /// The protocol version the client speaks.
        protocol: u32,
        /// The session the client believes this supervisor owns.
        session_id: Uuid,
        /// The generation the client believes is current.
        generation: u64,
    },

    /// Release the held child, presenting the token that proves the client may.
    Activate {
        /// The activation token, byte for byte. Redacted from `Debug`; never
        /// persisted; compared supervisor-side by digest.
        token: [u8; ACTIVATION_TOKEN_BYTES],
    },

    /// Wait up to this long for the run to end.
    ///
    /// The deadline is the *client's*, and it is bounded supervisor-side as
    /// well: a client that asked for an hour would otherwise be able to park
    /// the one thread that also serves everything else.
    Wait {
        /// How long the client is prepared to wait, in milliseconds.
        deadline_millis: u64,
    },

    /// End the run now and report what the death looked like.
    Stop,

    /// Report where the run is, with the record and the events observed while
    /// nobody was connected.
    Status,

    /// Prove the run's processes are gone, or report honestly that they are
    /// not.
    VerifyCleanup,

    /// Ask the held child what its installed enforcement does with one
    /// operation.
    ///
    /// The request travels, never an answer: the supervisor hands it to the
    /// [`PreparedSandbox`][prepared] it already owns, the held child attempts
    /// the operation with one real syscall, and the kernel's own `errno` comes
    /// back. Nothing on the way reads the plan's capabilities, and nothing is
    /// memoised — two identical frames are two syscalls, and the operation
    /// really happens each time. See [`super::probe`].
    ///
    /// [prepared]: super::PreparedSandbox::probe_enforcement
    ProbeEnforcement {
        /// The operation to attempt, and the tag to return with the answer.
        request: ProbeRequest,
    },

    /// Take over this run's terminal, at this size.
    ///
    /// The last control frame the connection carries: the
    /// [`ControlReply::AttachAck`] that answers it switches both sides to the
    /// terminal framing of [`super::terminal`], and only a
    /// [`AttachTag::Detach`][detach] switches them back.
    ///
    /// [detach]: super::AttachTag::Detach
    Attach {
        /// The size to give the terminal before any output is replayed, so a
        /// program that reads it at startup reads the size the viewer has.
        window: WindowSize,
    },

    /// Leave. The run carries on; this connection does not.
    Goodbye,
}

/// Debug that names the operation without naming the token.
///
/// The same reasoning as [`super::ActivationHandle`]: a request is the kind of
/// value that ends up in a trace line, and one copy of the token is a start
/// button for a held child.
impl std::fmt::Debug for ControlRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hello {
                protocol,
                session_id,
                generation,
            } => f
                .debug_struct("Hello")
                .field("protocol", protocol)
                .field("session_id", session_id)
                .field("generation", generation)
                .finish(),
            Self::Activate { .. } => f
                .debug_struct("Activate")
                .field("token", &"<redacted>")
                .finish(),
            Self::Wait { deadline_millis } => f
                .debug_struct("Wait")
                .field("deadline_millis", deadline_millis)
                .finish(),
            Self::Stop => f.write_str("Stop"),
            Self::Status => f.write_str("Status"),
            Self::VerifyCleanup => f.write_str("VerifyCleanup"),
            Self::ProbeEnforcement { request } => f
                .debug_struct("ProbeEnforcement")
                .field("request", request)
                .finish(),
            Self::Attach { window } => f.debug_struct("Attach").field("window", window).finish(),
            Self::Goodbye => f.write_str("Goodbye"),
        }
    }
}

impl ControlRequest {
    /// The operation's stable name, for refusals that have to name it.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Activate { .. } => "activate",
            Self::Wait { .. } => "wait",
            Self::Stop => "stop",
            Self::Status => "status",
            Self::VerifyCleanup => "verify_cleanup",
            Self::ProbeEnforcement { .. } => "probe_enforcement",
            Self::Attach { .. } => "attach",
            Self::Goodbye => "goodbye",
        }
    }
}

/// What a run was doing when it was asked.
///
/// The record travels whole rather than field by field: it is already the
/// module's durable shape, it is already bounded, and a status that carried a
/// summary would be a second description of the same thing that could drift
/// from the first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStatus {
    /// Where the supervisor's own state machine is *now*.
    state: LifecycleState,
    /// The durable record, including the bounded ring of events observed while
    /// no client was connected.
    record: super::session_store::SessionRecord,
}

impl SessionStatus {
    pub(super) fn new(state: LifecycleState, record: super::session_store::SessionRecord) -> Self {
        Self { state, record }
    }

    /// Where the run is, as the supervisor's live state machine has it.
    ///
    /// Preferred over [`SessionRecord::state`][record] for a connected client:
    /// the record is written after each transition and can lag it by one step,
    /// while this is read from the machine itself.
    ///
    /// [record]: super::SessionRecord::state
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.state
    }

    /// The durable record as it now stands.
    #[must_use]
    pub fn record(&self) -> &super::session_store::SessionRecord {
        &self.record
    }

    /// The events the supervisor kept while nobody was listening.
    ///
    /// Bounded and oldest-dropped — see
    /// [`DETACHED_EVENT_RING_CAPACITY`][cap]. This is *not* live delivery:
    /// [`EventSink`][sink] is caller-side, and a detached supervisor has no
    /// caller to deliver to. What it has is a ring, and what a reconnecting
    /// client gets is that ring.
    ///
    /// [cap]: super::DETACHED_EVENT_RING_CAPACITY
    /// [sink]: super::EventSink
    #[must_use]
    pub fn events(&self) -> &[super::events::LifecycleEvent] {
        self.record.events()
    }

    /// The run's exit facts, once its end was observed.
    #[must_use]
    pub fn exit(&self) -> Option<&SandboxExit> {
        self.record.exit()
    }
}

/// What a detached supervisor answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum ControlReply {
    /// The supervisor's own hello, sent once the client's has been accepted.
    Hello {
        /// The protocol version this supervisor speaks.
        protocol: u32,
        /// The session it owns.
        session_id: Uuid,
        /// The generation it is serving.
        generation: u64,
        /// Where the run was when the connection opened.
        state: LifecycleState,
    },

    /// The gate was released. The run is the customer's program from here.
    Activated {
        /// The state the release moved the run to.
        state: LifecycleState,
    },

    /// The wait finished, one way or the other.
    Waited {
        /// The exit facts, or a statement that the run is still going.
        outcome: WaitOutcome,
    },

    /// The run was stopped, and this is what the death looked like.
    Stopped {
        /// What was observed, never what was requested.
        exit: SandboxExit,
    },

    /// Where the run is, with its record and its event ring.
    Status {
        /// The status.
        ///
        /// Boxed because it is by far the largest thing this enum carries — a
        /// whole session record, including the event ring — and every other
        /// reply would otherwise be as big as it in every buffer either side
        /// allocates.
        status: Box<SessionStatus>,
    },

    /// Cleanup verification produced a verdict.
    Cleanup {
        /// The verdict, with its typed evidence.
        verdict: CleanupVerification,
        /// The state the verdict left the run in.
        state: LifecycleState,
    },

    /// The held child attempted the operation, and this is what the kernel
    /// said.
    ///
    /// Carried whole and unchanged. The supervisor does not reinterpret an
    /// outcome on the way past: an
    /// [`Indeterminate`][super::ProbeOutcome::Indeterminate] stays
    /// indeterminate, and
    /// [`denial_observed`][super::ProbeObservation::denial_observed] stays
    /// whatever the observation said — which on this fork is always `false`,
    /// because no denial record was captured by anyone.
    ProbeObservation(ProbeObservation),

    /// The attach was accepted, and this connection is now a terminal.
    ///
    /// The last control frame this connection carries until a detach. The ack
    /// says where the run is, how much scrollback is about to arrive, how much
    /// the bounded ring could not keep, and — for a run that has already ended
    /// — the exit facts, so a client that attaches to a finished run learns
    /// that from the ack rather than from silence.
    AttachAck {
        /// The terminal's state at the moment of the attach.
        ///
        /// Boxed because it carries a whole [`SandboxExit`] and every other
        /// reply would otherwise be as big as it in every buffer either side
        /// allocates — the same reasoning [`Self::Status`] uses.
        ack: Box<AttachAck>,
    },

    /// The client said goodbye and the supervisor acknowledged it.
    Farewell,

    /// The operation was refused, and this is which check refused it.
    Refused {
        /// The refusal.
        refusal: ControlRefusal,
    },
}

/// What a bounded wait found.
///
/// Two-valued on purpose: a wait that timed out has established that the run
/// had not ended *by then*, which is a different fact from an exit and must not
/// be rounded into one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "wait", rename_all = "snake_case")]
pub enum WaitOutcome {
    /// The run ended, and these are the facts.
    Exit(SandboxExit),
    /// The deadline passed with the run still going.
    StillRunning,
}

impl WaitOutcome {
    /// The exit facts, when the run had ended.
    #[must_use]
    pub fn exit(&self) -> Option<&SandboxExit> {
        match self {
            Self::Exit(exit) => Some(exit),
            Self::StillRunning => None,
        }
    }
}

/// Write one frame, or fail before `deadline`.
///
/// # Errors
///
/// [`FrameError`] naming what stopped it: an OS error, the deadline, a peer
/// that closed, or a value that would not fit the frame bound.
pub(super) fn write_frame<T: Serialize>(
    stream: &mut impl AsRawFd,
    value: &T,
    deadline: Instant,
) -> Result<(), FrameError> {
    // Zeroized rather than merely dropped, on *every* frame: one of the frames
    // this function serializes is `ControlRequest::Activate`, whose body is the
    // activation token in plain bytes. Distinguishing which frame that is at
    // this level would mean a branch that could be got wrong, so the discipline
    // is unconditional — the same reasoning `GateSecrets` uses.
    let body = Zeroizing::new(
        serde_json::to_vec(value).map_err(|err| FrameError::Malformed {
            why: format!("value could not be encoded: {err}"),
        })?,
    );
    if body.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            size: body.len() as u64,
            limit: MAX_CONTROL_FRAME_BYTES,
        });
    }
    let length = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge {
        size: body.len() as u64,
        limit: MAX_CONTROL_FRAME_BYTES,
    })?;

    // The prefix and the body in one buffer, so a short write can never leave a
    // length announced with no body behind it for a peer to wait on. Zeroizing
    // too: it holds a second copy of the same bytes.
    let mut frame = Zeroizing::new(Vec::with_capacity(
        body.len().saturating_add(LENGTH_PREFIX_BYTES),
    ));
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&body);
    write_all_by(stream, &frame, deadline)
}

/// Read one frame, or fail before `deadline`.
///
/// # Errors
///
/// [`FrameError`] naming what stopped it. [`FrameError::TooLarge`] is produced
/// from the length prefix alone: not one byte of the announced body is read.
pub(super) fn read_frame<T: DeserializeOwned>(
    stream: &mut impl AsRawFd,
    deadline: Instant,
) -> Result<T, FrameError> {
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    read_exact_by(stream, &mut prefix, deadline)?;
    let announced = u64::from(u32::from_le_bytes(prefix));
    if announced > MAX_CONTROL_FRAME_BYTES as u64 {
        return Err(FrameError::TooLarge {
            size: announced,
            limit: MAX_CONTROL_FRAME_BYTES,
        });
    }
    let length = usize::try_from(announced).map_err(|_| FrameError::TooLarge {
        size: announced,
        limit: MAX_CONTROL_FRAME_BYTES,
    })?;
    // Allocated only after the bound was checked, so the size the peer
    // announced can never be the size this side reserves. Zeroized on the way
    // out for the same reason [`write_frame`]'s buffer is: the supervisor's
    // side of this call is where an `Activate` frame — the token in plain bytes
    // — is read.
    let mut body = Zeroizing::new(vec![0_u8; length]);
    read_exact_by(stream, &mut body, deadline)?;
    serde_json::from_slice(&body).map_err(|err| FrameError::Malformed {
        why: err.to_string(),
    })
}

/// Fill `buffer`, waiting only through `poll` and only until `deadline`.
///
/// Shared with the launcher's readiness handshake, which is a pipe rather than
/// a socket but needs exactly the same discipline: a supervisor that never
/// wrote must not park the process that launched it.
pub(super) fn read_exact_by(
    stream: &mut impl AsRawFd,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), FrameError> {
    let fd = stream.as_raw_fd();
    let mut filled: usize = 0;
    while filled < buffer.len() {
        wait_for(fd, libc::POLLIN, deadline)?;
        let Some(slice) = buffer.get_mut(filled..) else {
            return Ok(());
        };
        // SAFETY: `slice` is a live, exclusively borrowed sub-slice of the
        // caller's buffer, and its length is exactly what is passed. `read`
        // writes at most that many bytes and returns how many it wrote.
        let count =
            unsafe { libc::read(fd, slice.as_mut_ptr().cast::<libc::c_void>(), slice.len()) };
        match usize::try_from(count) {
            Ok(0) => return Err(FrameError::Closed),
            Ok(count) => filled = filled.saturating_add(count),
            Err(_) => {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR | libc::EAGAIN) => {}
                    _ => return Err(FrameError::last_os()),
                }
            }
        }
    }
    Ok(())
}

/// Write all of `bytes`, waiting only through `poll` and only until `deadline`.
///
/// Shared with the terminal channel, which frames its own messages but needs
/// exactly the same discipline underneath: a client that stopped reading must
/// not be able to park the writer.
pub(super) fn write_all_by(
    stream: &mut impl AsRawFd,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), FrameError> {
    let fd = stream.as_raw_fd();
    let mut written: usize = 0;
    while written < bytes.len() {
        wait_for(fd, libc::POLLOUT, deadline)?;
        let Some(slice) = bytes.get(written..) else {
            return Ok(());
        };
        // SAFETY: `slice` is a live sub-slice of the caller's buffer and its
        // length is exactly what is passed. `write` reads at most that many
        // bytes and returns how many it consumed.
        let count = unsafe { libc::write(fd, slice.as_ptr().cast::<libc::c_void>(), slice.len()) };
        match usize::try_from(count) {
            // A zero-length write to a socket with bytes outstanding means the
            // peer is gone; treating it as progress would spin.
            Ok(0) => return Err(FrameError::Closed),
            Ok(count) => written = written.saturating_add(count),
            Err(_) => {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR | libc::EAGAIN) => {}
                    // A peer that closed mid-write raises EPIPE (and SIGPIPE,
                    // which the supervisor ignores). Named as a close rather
                    // than an i/o error because that is what it is.
                    Some(libc::EPIPE) => return Err(FrameError::Closed),
                    _ => return Err(FrameError::last_os()),
                }
            }
        }
    }
    Ok(())
}

/// Block in `poll` until `fd` is ready for `events`, or `deadline` passes.
fn wait_for(fd: RawFd, events: libc::c_short, deadline: Instant) -> Result<(), FrameError> {
    loop {
        let Some(timeout) = remaining_millis(deadline) else {
            return Err(FrameError::Timeout);
        };
        let mut fds = [libc::pollfd {
            fd,
            events,
            revents: 0,
        }];
        match poll_fds(&mut fds, timeout) {
            PollOutcome::Ready => return Ok(()),
            PollOutcome::TimedOut => return Err(FrameError::Timeout),
            PollOutcome::Interrupted => {}
            PollOutcome::Failed(errno) => return Err(FrameError::Io { errno }),
        }
    }
}

/// What one `poll` call answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PollOutcome {
    /// At least one descriptor has an event; `revents` says which.
    Ready,
    /// The timeout expired with nothing ready.
    TimedOut,
    /// A signal arrived. Not a failure — the caller re-arms with whatever is
    /// left of its deadline.
    Interrupted,
    /// `poll` itself failed.
    Failed(i32),
}

/// `poll` with a millisecond timeout, classified.
///
/// The one place this module reaches the kernel to wait, so it is also the one
/// place a `-1` (wait forever) could be written. It cannot be: the timeout is a
/// `c_int` the caller computed from a deadline, and every caller in this module
/// derives it from [`remaining_millis`], which never yields a negative number.
pub(super) fn poll_fds(fds: &mut [libc::pollfd], timeout_millis: libc::c_int) -> PollOutcome {
    let count = match libc::nfds_t::try_from(fds.len()) {
        Ok(count) => count,
        Err(_) => return PollOutcome::Failed(libc::EINVAL),
    };
    let timeout = timeout_millis.max(0);
    // SAFETY: `fds` is a live, exclusively borrowed slice of `pollfd` and
    // `count` is exactly its length. `poll` writes only the `revents` field of
    // each entry.
    let ready = unsafe { libc::poll(fds.as_mut_ptr(), count, timeout) };
    if ready > 0 {
        return PollOutcome::Ready;
    }
    if ready == 0 {
        return PollOutcome::TimedOut;
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno == libc::EINTR {
        PollOutcome::Interrupted
    } else {
        PollOutcome::Failed(errno)
    }
}

/// Milliseconds left before `deadline`, or `None` once it has passed.
///
/// Saturating rather than wrapping, and capped at `c_int::MAX`, so a deadline a
/// caller set far in the future cannot overflow into "wait forever".
pub(super) fn remaining_millis(deadline: Instant) -> Option<libc::c_int> {
    let now = Instant::now();
    if now >= deadline {
        return None;
    }
    let millis = deadline.saturating_duration_since(now).as_millis();
    // At least 1: a sub-millisecond remainder is still time left, and a zero
    // timeout would turn this into a spin.
    Some(
        libc::c_int::try_from(millis)
            .unwrap_or(libc::c_int::MAX)
            .max(1),
    )
}

/// Put a descriptor into non-blocking mode.
///
/// Every read and write in this module is `poll`-gated, so a blocking
/// descriptor would only ever block in the window between "poll said ready" and
/// the syscall — a window a second reader on the same socket can make real.
/// Non-blocking closes it: the syscall answers `EAGAIN` and the caller goes
/// back to its deadline.
pub(super) fn set_nonblocking(fd: RawFd) -> Result<(), FrameError> {
    // SAFETY: `fd` is a live descriptor for the duration of the call; `F_GETFL`
    // only reads flags and `F_SETFL` only sets them.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(FrameError::last_os());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(FrameError::last_os());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::probe::{
        EnforcementMechanism, ProbeId, ProbeIndeterminate, ProbeOp, ProbeOutcome,
    };
    use super::*;
    use crate::capability_modes::FsMode;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn pair() -> (UnixStream, UnixStream) {
        match UnixStream::pair() {
            Ok(pair) => pair,
            Err(err) => panic!("a socket pair must be creatable: {err}"),
        }
    }

    fn hello() -> ControlRequest {
        ControlRequest::Hello {
            protocol: CONTROL_PROTOCOL_VERSION,
            session_id: Uuid::nil(),
            generation: 1,
        }
    }

    #[test]
    fn a_frame_round_trips_over_a_socket() -> Result<(), FrameError> {
        let (mut left, mut right) = pair();
        set_nonblocking(left.as_raw_fd())?;
        set_nonblocking(right.as_raw_fd())?;
        write_frame(&mut left, &hello(), soon())?;
        let received: ControlRequest = read_frame(&mut right, soon())?;
        assert_eq!(received, hello());
        Ok(())
    }

    #[test]
    fn an_oversize_length_prefix_is_refused_before_a_byte_of_body_is_read() {
        let (mut left, mut right) = pair();
        for stream in [&left, &right] {
            if let Err(err) = set_nonblocking(stream.as_raw_fd()) {
                panic!("the test sockets must go non-blocking: {err}");
            }
        }
        // Announce a gigabyte and send nothing. If the bound were checked after
        // the read rather than before it, this would allocate a gigabyte and
        // then park until the deadline.
        let announced = 1_024_u32 * 1_024 * 1_024;
        if let Err(err) = left.write_all(&announced.to_le_bytes()) {
            panic!("the prefix must be writable: {err}");
        }
        let outcome: Result<ControlRequest, FrameError> = read_frame(&mut right, soon());
        assert_eq!(
            outcome.err(),
            Some(FrameError::TooLarge {
                size: u64::from(announced),
                limit: MAX_CONTROL_FRAME_BYTES,
            })
        );
    }

    #[test]
    fn a_frame_exactly_at_the_bound_is_still_read() -> Result<(), FrameError> {
        // The bound is inclusive, and a test that only proved the refusal would
        // not notice an off-by-one that rejected legal frames.
        let (mut left, mut right) = pair();
        set_nonblocking(left.as_raw_fd())?;
        set_nonblocking(right.as_raw_fd())?;
        let body = vec![b'x'; MAX_CONTROL_FRAME_BYTES];
        let length = MAX_CONTROL_FRAME_BYTES as u32;
        let writer = std::thread::spawn(move || {
            let mut frame = length.to_le_bytes().to_vec();
            frame.extend_from_slice(&body);
            let _ = write_all_by(&mut left, &frame, soon());
        });
        let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
        read_exact_by(&mut right, &mut prefix, soon())?;
        assert_eq!(u32::from_le_bytes(prefix), length);
        let mut body = vec![0_u8; MAX_CONTROL_FRAME_BYTES];
        read_exact_by(&mut right, &mut body, soon())?;
        if writer.join().is_err() {
            panic!("the writing thread must not panic");
        }
        Ok(())
    }

    #[test]
    fn a_record_at_its_bound_still_fits_a_frame() {
        // The inequality the envelope allowance exists for. A status reply is a
        // record wrapped in a `SessionStatus` wrapped in a tagged
        // `ControlReply`, so a wire bound merely *equal* to the storage bound
        // would refuse a record that had been perfectly legal to write, and the
        // failure would land on the reply rather than on the write that caused
        // it.
        // The inequality itself is a `const _: () = assert!(…)` beside the
        // constant, so a build that broke it would not compile. What is left
        // for a test is the arithmetic the doc comment states, so that changing
        // one number without the other is caught here rather than by a reader.
        assert_eq!(
            MAX_CONTROL_FRAME_BYTES,
            super::super::MAX_RECORD_BYTES + CONTROL_ENVELOPE_ALLOWANCE
        );
        assert_eq!(MAX_CONTROL_FRAME_BYTES, 69_632);
    }

    #[test]
    fn a_garbage_body_is_malformed_not_a_guess() {
        let (mut left, mut right) = pair();
        for stream in [&left, &right] {
            if let Err(err) = set_nonblocking(stream.as_raw_fd()) {
                panic!("the test sockets must go non-blocking: {err}");
            }
        }
        let body = b"not json at all";
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(body);
        if let Err(err) = left.write_all(&frame) {
            panic!("the frame must be writable: {err}");
        }
        let outcome: Result<ControlRequest, FrameError> = read_frame(&mut right, soon());
        assert!(
            matches!(outcome, Err(FrameError::Malformed { .. })),
            "expected a malformed frame, got {outcome:?}"
        );
    }

    #[test]
    fn a_read_with_no_writer_times_out_rather_than_parking() {
        let (left, mut right) = pair();
        if let Err(err) = set_nonblocking(right.as_raw_fd()) {
            panic!("the test socket must go non-blocking: {err}");
        }
        let deadline = Instant::now() + Duration::from_millis(80);
        let outcome: Result<ControlRequest, FrameError> = read_frame(&mut right, deadline);
        assert_eq!(outcome.err(), Some(FrameError::Timeout));
        // The peer is still open, which is what makes this a timeout rather
        // than a close: nothing about the descriptor changed.
        drop(left);
    }

    #[test]
    fn a_closed_peer_is_a_close_not_a_timeout() {
        let (left, mut right) = pair();
        if let Err(err) = set_nonblocking(right.as_raw_fd()) {
            panic!("the test socket must go non-blocking: {err}");
        }
        drop(left);
        let outcome: Result<ControlRequest, FrameError> = read_frame(&mut right, soon());
        assert_eq!(outcome.err(), Some(FrameError::Closed));
    }

    #[test]
    fn debug_never_renders_the_activation_token() {
        let request = ControlRequest::Activate {
            token: [0xAB; ACTIVATION_TOKEN_BYTES],
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
        assert!(!rendered.contains("ab"), "{rendered}");
    }

    #[test]
    fn every_refusal_round_trips_through_serde() -> Result<(), serde_json::Error> {
        let refusals = [
            ControlRefusal::ProtocolVersion {
                expected: 1,
                supplied: 2,
            },
            ControlRefusal::WrongSession {
                expected: Uuid::nil(),
                supplied: Uuid::max(),
            },
            ControlRefusal::WrongGeneration {
                expected: 1,
                supplied: 2,
            },
            ControlRefusal::Busy,
            ControlRefusal::HelloExpected,
            ControlRefusal::FrameTooLarge {
                size: 1 << 30,
                limit: MAX_CONTROL_FRAME_BYTES,
            },
            ControlRefusal::Malformed {
                why: "nonsense".to_string(),
            },
            ControlRefusal::Activation(ActivationError::AlreadyActivated),
            ControlRefusal::Stop(StopError::NotStoppable {
                state: LifecycleState::Exited,
            }),
            ControlRefusal::Cleanup {
                state: LifecycleState::Running,
            },
            ControlRefusal::Probe(ProbeError::NotLegalInState {
                state: LifecycleState::Stopped,
            }),
            ControlRefusal::ProbeAfterActivation {
                state: LifecycleState::Running,
                required_scope: ProbeScope::RederivedSibling,
            },
            ControlRefusal::NoTerminal,
            ControlRefusal::Unimplemented {
                op: "reprepare".to_string(),
            },
        ];
        for refusal in refusals {
            let json = serde_json::to_string(&refusal)?;
            assert_eq!(serde_json::from_str::<ControlRefusal>(&json)?, refusal);
        }
        Ok(())
    }

    #[test]
    fn an_attach_and_its_ack_round_trip_over_a_socket() -> Result<(), FrameError> {
        // The mode switch rides on ordinary control framing, so the two frames
        // that perform it must survive the same round trip as everything else.
        let (mut left, mut right) = pair();
        set_nonblocking(left.as_raw_fd())?;
        set_nonblocking(right.as_raw_fd())?;
        let request = ControlRequest::Attach {
            window: WindowSize::new(40, 100),
        };
        write_frame(&mut left, &request, soon())?;
        assert_eq!(read_frame::<ControlRequest>(&mut right, soon())?, request);

        let reply = ControlReply::AttachAck {
            ack: Box::new(AttachAck::new(LifecycleState::Running, 7, 3, None)),
        };
        write_frame(&mut right, &reply, soon())?;
        assert_eq!(read_frame::<ControlReply>(&mut left, soon())?, reply);
        Ok(())
    }

    #[test]
    fn a_deadline_that_has_passed_yields_no_time_rather_than_forever() {
        // The bug this guards is the classic one: a negative timeout is
        // `poll`'s spelling of "wait until something happens", which is exactly
        // what every read in this module must never do.
        assert_eq!(remaining_millis(Instant::now()), None);
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(remaining_millis(past), None);
        let future = Instant::now() + Duration::from_secs(2);
        let left = remaining_millis(future);
        assert!(left.is_some_and(|millis| millis > 0), "{left:?}");
    }

    #[test]
    fn a_request_names_itself_for_a_refusal_that_has_to() {
        assert_eq!(hello().as_str(), "hello");
        assert_eq!(ControlRequest::Stop.as_str(), "stop");
        assert_eq!(ControlRequest::Status.as_str(), "status");
        assert_eq!(ControlRequest::VerifyCleanup.as_str(), "verify_cleanup");
        assert_eq!(ControlRequest::Goodbye.as_str(), "goodbye");
        assert_eq!(
            ControlRequest::Attach {
                window: WindowSize::new(24, 80)
            }
            .as_str(),
            "attach"
        );
        assert_eq!(
            ControlRequest::Wait {
                deadline_millis: 10
            }
            .as_str(),
            "wait"
        );
        assert_eq!(
            ControlRequest::Activate {
                token: [0; ACTIVATION_TOKEN_BYTES]
            }
            .as_str(),
            "activate"
        );
        assert_eq!(
            ControlRequest::ProbeEnforcement {
                request: probe_request(FsMode::ReadContents)
            }
            .as_str(),
            "probe_enforcement"
        );
    }

    /// One probe of `/etc/hosts`, for the frames that carry one.
    fn probe_request(mode: FsMode) -> ProbeRequest {
        ProbeRequest {
            id: ProbeId::new("wire"),
            op: ProbeOp::OpenPath {
                path: PathBuf::from("/etc/hosts"),
                mode,
            },
        }
    }

    #[test]
    fn a_probe_and_its_observation_round_trip_over_a_socket() -> Result<(), FrameError> {
        let (mut left, mut right) = pair();
        set_nonblocking(left.as_raw_fd())?;
        set_nonblocking(right.as_raw_fd())?;

        let request = ControlRequest::ProbeEnforcement {
            request: probe_request(FsMode::Write),
        };
        write_frame(&mut left, &request, soon())?;
        assert_eq!(read_frame::<ControlRequest>(&mut right, soon())?, request);

        // Every outcome, including the two an optimistic implementation would
        // be tempted to round: `Indeterminate` must not arrive as a refusal or
        // a permission, and the errno on a refusal is the kernel's own number
        // rather than a flag.
        for outcome in [
            ProbeOutcome::Permitted,
            ProbeOutcome::Refused {
                errno: libc::EACCES,
            },
            ProbeOutcome::Indeterminate {
                reason: ProbeIndeterminate::ProbeCouldNotRun {
                    errno: libc::ENOENT,
                },
            },
            ProbeOutcome::Indeterminate {
                reason: ProbeIndeterminate::PlatformHasNoInScopeProbe,
            },
            ProbeOutcome::Indeterminate {
                reason: ProbeIndeterminate::MechanismCannotExpress {
                    mechanism: EnforcementMechanism::Landlock,
                },
            },
        ] {
            let sent = ControlReply::ProbeObservation(ProbeObservation {
                id: ProbeId::new("wire"),
                outcome,
                mechanism: EnforcementMechanism::Seatbelt,
                scope: ProbeScope::InstalledChild,
                denial_observed: false,
                observed_at: SystemTime::UNIX_EPOCH + Duration::from_millis(1_755_000_000_123),
            });
            write_frame(&mut right, &sent, soon())?;
            let received: ControlReply = read_frame(&mut left, soon())?;
            assert_eq!(received, sent, "an observation must cross unchanged");
            match received {
                ControlReply::ProbeObservation(observation) => {
                    assert_eq!(observation.outcome, outcome);
                    assert!(
                        !observation.denial_observed,
                        "no denial record was captured by anyone, least of all the wire"
                    );
                    assert_eq!(observation.scope, ProbeScope::InstalledChild);
                }
                other => panic!("expected an observation, got {other:?}"),
            }
        }
        Ok(())
    }

    #[test]
    fn a_path_that_is_not_utf8_is_refused_rather_than_mangled() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        // JSON has no spelling for these bytes. The frame refuses rather than
        // sending a *different* path, which is the same rule the child's own
        // channel applies to an interior NUL.
        let (mut left, _right) = pair();
        if let Err(err) = set_nonblocking(left.as_raw_fd()) {
            panic!("the test socket must go non-blocking: {err}");
        }
        let request = ControlRequest::ProbeEnforcement {
            request: ProbeRequest {
                id: ProbeId::new("not-utf8"),
                op: ProbeOp::OpenPath {
                    path: PathBuf::from(OsString::from_vec(vec![0xFF, 0xFE])),
                    mode: FsMode::ReadContents,
                },
            },
        };
        let outcome = write_frame(&mut left, &request, soon());
        assert!(
            matches!(outcome, Err(FrameError::Malformed { .. })),
            "expected a malformed refusal, got {outcome:?}"
        );
    }

    #[test]
    fn a_probe_request_too_large_for_a_frame_is_refused_with_nothing_written() {
        // The caller's tag is unbounded by design, so this is the shape an
        // over-long request has. Nothing must reach the socket: a truncated
        // frame is a frame the peer would read as a *different* request, and a
        // stream whose framing has slipped cannot be resynchronized.
        let (mut left, mut right) = pair();
        for stream in [&left, &right] {
            if let Err(err) = set_nonblocking(stream.as_raw_fd()) {
                panic!("the test sockets must go non-blocking: {err}");
            }
        }
        let request = ControlRequest::ProbeEnforcement {
            request: ProbeRequest {
                id: ProbeId::new("x".repeat(MAX_CONTROL_FRAME_BYTES)),
                op: ProbeOp::OpenPath {
                    path: PathBuf::from("/etc/hosts"),
                    mode: FsMode::ReadContents,
                },
            },
        };
        let outcome = write_frame(&mut left, &request, soon());
        assert!(
            matches!(outcome, Err(FrameError::TooLarge { .. })),
            "expected an oversize refusal, got {outcome:?}"
        );
        // Not one byte on the wire, which is what makes the connection usable
        // afterwards.
        let after: Result<ControlRequest, FrameError> =
            read_frame(&mut right, Instant::now() + Duration::from_millis(80));
        assert_eq!(after.err(), Some(FrameError::Timeout));
    }

    #[test]
    fn the_longest_probe_path_the_child_accepts_still_fits_a_frame() {
        // The compile-time assertion beside `WORST_CASE_JSON_ESCAPE` covers the
        // escaped worst case; this covers the ordinary one end to end, so that
        // changing either bound without the other is caught here rather than by
        // a caller whose path was legal for the child and too big for the wire.
        let mut path = String::from("/");
        while path.len() < super::super::probe::PROBE_PATH_BYTES.saturating_sub(1) {
            path.push('a');
        }
        let request = ControlRequest::ProbeEnforcement {
            request: ProbeRequest {
                id: ProbeId::new("longest"),
                op: ProbeOp::OpenPath {
                    path: PathBuf::from(path),
                    mode: FsMode::ReadContents,
                },
            },
        };
        let encoded = match serde_json::to_vec(&request) {
            Ok(encoded) => encoded,
            Err(err) => panic!("a request at the path bound must encode: {err}"),
        };
        assert!(
            encoded.len() < MAX_CONTROL_FRAME_BYTES,
            "a path the child would accept must fit a frame: {} bytes",
            encoded.len()
        );
    }
}
