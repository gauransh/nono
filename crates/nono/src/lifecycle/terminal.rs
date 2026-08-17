//! The run's terminal: one PTY, owned by the supervisor, viewed by one client.
//!
//! An interactive run is a run whose standard streams are a pseudo-terminal
//! rather than `/dev/null`. The *master* end of that terminal belongs to the
//! supervisor and to nothing else — not the launcher, which opens it and lets
//! go before the readiness handshake, and not the customer child, which is
//! given the slave and closes every other copy before it reaches the gate. That
//! is what makes the terminal survive the caller: a run whose master lived in
//! the launcher would lose its terminal the moment the launcher exited, which
//! is the failure the whole detached path exists to avoid.
//!
//! # The attach channel
//!
//! A client reaches that terminal over the *same* Unix socket the control
//! protocol uses. [`ControlRequest::Attach`][attach] is an ordinary control
//! frame; the [`AttachAck`] that answers it is the last control frame the
//! connection carries, because after it both sides switch to the framing below
//! and stay there until a [`AttachTag::Detach`] switches them back.
//!
//! ```text
//! [u8 tag][u32 little-endian length][length bytes of payload]
//! ```
//!
//! | Tag | Name | Direction | Payload |
//! |-----|------|-----------|---------|
//! | `0x01` | `Input` | client → supervisor | raw bytes for the terminal master |
//! | `0x02` | `Output` | supervisor → client | raw bytes the run wrote |
//! | `0x03` | `Resize` | client → supervisor | rows `u16` LE, cols `u16` LE |
//! | `0x04` | `Detach` | both | empty; the client asks, the supervisor confirms |
//! | `0x05` | `SessionEnded` | supervisor → client | JSON [`TerminalEnd`] |
//! | `0x06` | `Ping` | client → supervisor | empty |
//! | `0x07` | `Pong` | supervisor → client | empty |
//!
//! **Raw bytes and controls are distinct by framing, not by content.** An
//! `Input` frame's payload reaches the master byte for byte: `0xFF`, a NUL, and
//! a byte sequence that looks exactly like another frame header all travel
//! unchanged, because the length prefix has already said how many bytes belong
//! to this frame. There is no escape to get wrong and no in-band sequence to
//! collide with. `a_frame_payload_that_looks_like_a_frame_is_still_payload`
//! locks that, and the live hostility test proves it end to end through a real
//! `/bin/cat`.
//!
//! Every frame is bounded by [`MAX_ATTACH_PAYLOAD_BYTES`], checked from the
//! length prefix *before* a byte of payload is buffered. A tag this protocol
//! does not have, a tag sent in the wrong direction, or an oversize length is a
//! typed [`AttachViolation`] and the end of the *channel* — never the end of
//! the run, which is exactly what the live test reattaches to prove.
//!
//! # One viewer, and what that costs
//!
//! Attach occupies the supervisor's single client slot: a second connection
//! gets [`ControlRefusal::Busy`][busy] as it always did, and there is no
//! separate "attach is busy" answer because a second attach cannot reach the
//! supervisor to be refused. Control operations are still available to an
//! attached client — [`AttachedTerminal::activate`] leaves attach mode for one
//! exchange and returns to it — and no output is lost across that gap, because
//! output with nobody attached goes to the ring below.
//!
//! # Output with nobody listening
//!
//! [`Scrollback`] is a bounded ring: [`SCROLLBACK_CAPACITY_BYTES`] of the most
//! recent output, oldest dropped, with the dropped bytes *counted* and reported
//! on the next [`AttachAck`]. It is scrollback, not a transcript, and the
//! difference is stated rather than implied — a consumer that needs every byte
//! stays attached, and one that reattaches is told exactly how much it missed.
//!
//! # These bytes are not secrets, and that is a decision
//!
//! The terminal stream is the customer's own data, and this module does not
//! treat it as secret material: the ring holds up to 256 KiB of it in the
//! supervisor's memory and the frames cross the socket unencrypted (a socket in
//! a `0700` directory with the peer's uid checked at accept). A consumer that
//! types a password into an interactive run should know that, which is why it
//! is written here rather than left to be discovered.
//!
//! [attach]: super::ControlRequest::Attach
//! [busy]: super::ControlRefusal::Busy

use super::detached::{CONTROL_TIMEOUT, DetachedError, DetachedSession};
use super::exit::SandboxExit;
use super::gate::ActivationHandle;
use super::prepare::{PrepareError, above_standard_streams};
use super::protocol::{FrameError, PollOutcome, poll_fds, remaining_millis, write_all_by};
use super::state::LifecycleState;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Largest payload one attach frame may carry, in bytes.
///
/// Thirty-two kibibytes: three orders of magnitude more than a keystroke and
/// more than a full screen of output, while still small enough that a peer
/// cannot make either side reserve a meaningful amount of memory on the say-so
/// of a number it chose. Checked from the length prefix before a byte of the
/// payload is buffered, exactly as the control protocol checks its own.
pub const MAX_ATTACH_PAYLOAD_BYTES: usize = 32 * 1024;

/// How much output the supervisor keeps while nobody is attached, in bytes.
///
/// **Bounded scrollback, not a transcript.** A run that writes more than this
/// with no viewer loses its oldest bytes, and the count of what was lost rides
/// on the next [`AttachAck`] rather than being quietly absorbed. Two hundred
/// and fifty-six kibibytes is a few thousand lines of ordinary terminal output
/// — enough to cover a caller's restart, small enough that a forgotten session
/// is not a memory leak with a supervisor around it.
pub const SCROLLBACK_CAPACITY_BYTES: usize = 256 * 1024;

/// How much output may be in flight to an attached client before the supervisor
/// stops reading the terminal, in bytes.
///
/// Backpressure rather than an unbounded buffer: once this much is queued the
/// master is left unread, which is the terminal's own way of telling the run to
/// slow down. [`ATTACH_STALL_DEADLINE`] is what stops that becoming permanent.
const MAX_ATTACH_OUTBOUND_BYTES: usize = 256 * 1024;

/// How long an attached client may make no progress before it is dropped.
///
/// A client that has stopped reading holds the run itself still, because the
/// backpressure above eventually stops the supervisor reading the master. The
/// answer is to drop the *client* and not the *session*: output goes back to
/// the ring, the run carries on, and a caller that comes back is told how much
/// it missed.
const ATTACH_STALL_DEADLINE: Duration = Duration::from_secs(10);

/// Bytes of tag and length in front of every attach frame.
const ATTACH_HEADER_BYTES: usize = 5;

/// Compile-time check that the ring can hold more than one frame.
///
/// At module level rather than in a test, because it is an arithmetic fact
/// about two constants: a build in which a single maximal frame overflowed the
/// scrollback would make every attach report a drop, and should not link.
const _: () = assert!(SCROLLBACK_CAPACITY_BYTES > MAX_ATTACH_PAYLOAD_BYTES);

/// Compile-time check that one read can never overflow one frame.
const _: () = assert!(TERMINAL_READ_CHUNK <= MAX_ATTACH_PAYLOAD_BYTES);

/// Compile-time check that the in-flight bound can hold a maximal frame, so a
/// single large write is never permanently un-queueable.
const _: () = assert!(MAX_ATTACH_OUTBOUND_BYTES > MAX_ATTACH_PAYLOAD_BYTES);

/// How much either side reads from a descriptor in one go, in bytes.
///
/// Small enough to be a stack buffer in a loop that runs between a `poll` and
/// the next one, large enough that ordinary terminal output is one read.
pub(super) const TERMINAL_READ_CHUNK: usize = 8 * 1024;

/// A terminal's size, in character cells.
///
/// Rows and columns, and deliberately not pixels: the pixel fields of a
/// `winsize` are set by almost nothing and honoured by almost nothing, and a
/// value this library cannot fill honestly is a value it does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WindowSize {
    /// Character rows.
    rows: u16,
    /// Character columns.
    cols: u16,
}

impl WindowSize {
    /// A size, in character cells.
    #[must_use]
    pub fn new(rows: u16, cols: u16) -> Self {
        Self { rows, cols }
    }

    /// Character rows.
    #[must_use]
    pub fn rows(self) -> u16 {
        self.rows
    }

    /// Character columns.
    #[must_use]
    pub fn cols(self) -> u16 {
        self.cols
    }
}

/// What an attach frame is.
///
/// The byte values are contract: they cross a socket between two processes that
/// may be different builds of this library, and the version handshake that
/// would have caught a mismatch happened before the mode switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttachTag {
    /// Bytes for the terminal master, verbatim.
    Input,
    /// Bytes the run wrote to its terminal, verbatim.
    Output,
    /// A new window size: rows then cols, each a little-endian `u16`.
    Resize,
    /// Leave attach mode. The client asks; the supervisor confirms with the
    /// same tag, and both sides go back to control framing.
    Detach,
    /// The run ended, and this is the typed summary.
    SessionEnded,
    /// A liveness probe.
    Ping,
    /// The answer to one.
    Pong,
}

impl AttachTag {
    /// The wire byte.
    #[must_use]
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Input => 0x01,
            Self::Output => 0x02,
            Self::Resize => 0x03,
            Self::Detach => 0x04,
            Self::SessionEnded => 0x05,
            Self::Ping => 0x06,
            Self::Pong => 0x07,
        }
    }

    /// Decode a wire byte, or `None` for a tag this protocol does not have.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Input),
            0x02 => Some(Self::Output),
            0x03 => Some(Self::Resize),
            0x04 => Some(Self::Detach),
            0x05 => Some(Self::SessionEnded),
            0x06 => Some(Self::Ping),
            0x07 => Some(Self::Pong),
            _ => None,
        }
    }

    /// Whether this side may send this tag.
    ///
    /// Direction is part of the protocol, not a convention: an `Output` frame
    /// from a client and an `Input` frame from a supervisor are each a peer
    /// doing something it has no business doing, and answering them would mean
    /// the two ends disagree about who owns the terminal.
    #[must_use]
    fn may_be_sent_by(self, peer: Peer) -> bool {
        match peer {
            Peer::Client => matches!(
                self,
                Self::Input | Self::Resize | Self::Detach | Self::Ping | Self::Pong
            ),
            Peer::Supervisor => matches!(
                self,
                Self::Output | Self::Detach | Self::SessionEnded | Self::Ping | Self::Pong
            ),
        }
    }
}

/// Which end of the channel sent a frame.
///
/// Public because [`AttachViolation::WrongDirection`] names it: a consumer that
/// wants to know *which* side broke the rules should be able to read the
/// answer rather than parse it out of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// The process that attached.
    Client,
    /// The process that owns the run.
    Supervisor,
}

/// What a peer did that ends the channel.
///
/// Typed rather than a message, because the *decision* differs: an oversize
/// frame and an unknown tag both end the attach, but only the supervisor's side
/// then has to decide whether the run survives — and it always does.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttachViolation {
    /// A tag byte this protocol does not have.
    #[error("attach frame tag {tag:#04x} is not part of this protocol")]
    UnknownTag {
        /// The byte that arrived.
        tag: u8,
    },

    /// A tag the sending side may not send.
    #[error("attach frame {tag:?} may not be sent by the {peer:?} side")]
    WrongDirection {
        /// The tag that arrived.
        tag: AttachTag,
        /// Who sent it.
        peer: Peer,
    },

    /// A length prefix larger than [`MAX_ATTACH_PAYLOAD_BYTES`].
    ///
    /// Nothing past the prefix was buffered, and nothing was allocated for it.
    #[error("attach frame announced {size} bytes (max {limit})")]
    Oversize {
        /// The size the prefix claimed.
        size: u64,
        /// The bound.
        limit: usize,
    },

    /// A payload that does not decode into what its tag promised.
    #[error("attach frame {tag:?} carried a payload it could not have meant")]
    BadPayload {
        /// The tag whose payload was wrong.
        tag: AttachTag,
    },
}

/// Everything an attached client can fail with.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttachError {
    /// The socket underneath failed, timed out, or was closed by the peer.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// The peer broke the framing rules.
    #[error(transparent)]
    Violation(#[from] AttachViolation),

    /// The value handed in would not fit one frame.
    ///
    /// Refused rather than split: a terminal write that arrived as two frames
    /// with something else between them is not the write the caller made.
    #[error("attach payload is {size} bytes (max {limit})")]
    PayloadTooLarge {
        /// What was offered.
        size: usize,
        /// The bound.
        limit: usize,
    },

    /// A control operation performed through the attach failed.
    #[error(transparent)]
    Control(#[from] DetachedError),

    /// The supervisor answered a frame this operation has no use for.
    #[error("the supervisor sent {received:?} where {expected} was expected")]
    UnexpectedFrame {
        /// What the operation needed.
        expected: &'static str,
        /// What arrived instead.
        received: AttachTag,
    },
}

/// The run's terminal state at the moment a client attached.
///
/// The two counts are the honest half: `buffered` is what the client is about
/// to be sent from the ring, and `dropped` is what the ring could not keep. A
/// consumer that sees a non-zero `dropped` knows its view of the run has a hole
/// in it, and knows how big.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachAck {
    /// Where the run is, as the supervisor's live state machine has it.
    state: LifecycleState,
    /// Bytes of scrollback about to be replayed as `Output` frames.
    buffered: u64,
    /// Bytes the bounded ring dropped since the last attach.
    dropped: u64,
    /// The run's exit facts, once its end has been observed.
    exit: Option<SandboxExit>,
}

impl AttachAck {
    pub(super) fn new(
        state: LifecycleState,
        buffered: u64,
        dropped: u64,
        exit: Option<SandboxExit>,
    ) -> Self {
        Self {
            state,
            buffered,
            dropped,
            exit,
        }
    }

    /// Where the run is.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.state
    }

    /// Bytes of scrollback the supervisor is about to replay.
    #[must_use]
    pub fn buffered(&self) -> u64 {
        self.buffered
    }

    /// Bytes the bounded ring dropped rather than keep.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The run's exit facts, when its end has already been observed.
    #[must_use]
    pub fn exit(&self) -> Option<&SandboxExit> {
        self.exit.as_ref()
    }
}

/// What a `SessionEnded` frame carries.
///
/// `exit` is an `Option` for the same reason every other end-of-run report in
/// this module is honest about it: a run can reach a terminal state whose exit
/// facts were never observed — a reap that failed — and inventing an exit code
/// for one would be the sentinel-as-fact mistake the module exists to avoid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalEnd {
    /// The terminal state the run reached.
    state: LifecycleState,
    /// What the supervisor's `waitpid` saw, when it saw anything.
    exit: Option<SandboxExit>,
}

impl TerminalEnd {
    pub(super) fn new(state: LifecycleState, exit: Option<SandboxExit>) -> Self {
        Self { state, exit }
    }

    /// The terminal state the run reached.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.state
    }

    /// The exit facts, when the run's end was observed.
    #[must_use]
    pub fn exit(&self) -> Option<&SandboxExit> {
        self.exit.as_ref()
    }
}

/// What an attached client heard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalEvent {
    /// Bytes the run wrote to its terminal, verbatim.
    Output(Vec<u8>),
    /// The run ended, and these are the facts.
    Ended(TerminalEnd),
    /// The supervisor answered a liveness probe.
    Pong,
    /// The deadline passed with nothing to report.
    ///
    /// Not an error: a terminal that is quiet is a terminal that is quiet, and
    /// rounding that into a timeout would make every idle read look like a
    /// failure.
    Idle,
}

// ---------------------------------------------------------------------------
// Framing.
// ---------------------------------------------------------------------------

/// Append one framed message to `into`.
///
/// # Errors
///
/// [`AttachError::PayloadTooLarge`] if the payload would not fit one frame.
pub(super) fn encode_frame(
    tag: AttachTag,
    payload: &[u8],
    into: &mut Vec<u8>,
) -> Result<(), AttachError> {
    if payload.len() > MAX_ATTACH_PAYLOAD_BYTES {
        return Err(AttachError::PayloadTooLarge {
            size: payload.len(),
            limit: MAX_ATTACH_PAYLOAD_BYTES,
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_| AttachError::PayloadTooLarge {
        size: payload.len(),
        limit: MAX_ATTACH_PAYLOAD_BYTES,
    })?;
    into.push(tag.as_byte());
    into.extend_from_slice(&length.to_le_bytes());
    into.extend_from_slice(payload);
    Ok(())
}

/// A frame that has been taken whole out of a byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AttachFrame {
    pub(super) tag: AttachTag,
    pub(super) payload: Vec<u8>,
}

/// Turns a byte stream into frames, one at a time, without ever blocking.
///
/// A socket delivers bytes, not messages: a single `read` can return half a
/// frame, three frames, or three and a half. This buffers whatever arrived and
/// hands back only complete frames, which is what lets the supervisor's single
/// thread service a terminal without a read that could park it.
pub(super) struct FrameDecoder {
    /// Who is sending, so direction can be checked.
    peer: Peer,
    /// Bytes that have arrived and not yet formed a frame.
    buffer: Vec<u8>,
}

impl FrameDecoder {
    pub(super) fn new(peer: Peer) -> Self {
        Self {
            peer,
            buffer: Vec::new(),
        }
    }

    /// Take in whatever the socket produced.
    pub(super) fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// How many bytes are held part-way through a frame.
    ///
    /// Bounded by construction: a frame is refused from its prefix, so the most
    /// this can hold is one header plus one maximal payload.
    pub(super) fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// The next complete frame, if one has arrived.
    ///
    /// # Errors
    ///
    /// [`AttachViolation`] for a tag this protocol does not have, a tag the
    /// sending side may not send, or a length prefix past the bound. In every
    /// case nothing past the header was interpreted.
    pub(super) fn next_frame(&mut self) -> Result<Option<AttachFrame>, AttachViolation> {
        if self.buffer.len() < ATTACH_HEADER_BYTES {
            return Ok(None);
        }
        let Some(&raw_tag) = self.buffer.first() else {
            return Ok(None);
        };
        let Some(tag) = AttachTag::from_byte(raw_tag) else {
            return Err(AttachViolation::UnknownTag { tag: raw_tag });
        };
        if !tag.may_be_sent_by(self.peer) {
            return Err(AttachViolation::WrongDirection {
                tag,
                peer: self.peer,
            });
        }
        let Some(header) = self.buffer.get(1..ATTACH_HEADER_BYTES) else {
            return Ok(None);
        };
        let announced = u64::from(u32::from_le_bytes([
            *header.first().unwrap_or(&0),
            *header.get(1).unwrap_or(&0),
            *header.get(2).unwrap_or(&0),
            *header.get(3).unwrap_or(&0),
        ]));
        // Checked before the payload is waited for, let alone copied: a peer
        // that announced a gigabyte must not be able to make this side hold a
        // gigabyte of buffer waiting for it.
        if announced > MAX_ATTACH_PAYLOAD_BYTES as u64 {
            return Err(AttachViolation::Oversize {
                size: announced,
                limit: MAX_ATTACH_PAYLOAD_BYTES,
            });
        }
        let length = usize::try_from(announced).unwrap_or(MAX_ATTACH_PAYLOAD_BYTES);
        let total = ATTACH_HEADER_BYTES.saturating_add(length);
        if self.buffer.len() < total {
            return Ok(None);
        }
        let payload = self
            .buffer
            .get(ATTACH_HEADER_BYTES..total)
            .unwrap_or_default()
            .to_vec();
        self.buffer.drain(..total);
        Ok(Some(AttachFrame { tag, payload }))
    }
}

/// Decode a `Resize` payload.
pub(super) fn decode_window(payload: &[u8]) -> Result<WindowSize, AttachViolation> {
    let bad = || AttachViolation::BadPayload {
        tag: AttachTag::Resize,
    };
    let rows = payload.get(0..2).ok_or_else(bad)?;
    let cols = payload.get(2..4).ok_or_else(bad)?;
    if payload.len() != 4 {
        return Err(bad());
    }
    Ok(WindowSize::new(
        u16::from_le_bytes([*rows.first().unwrap_or(&0), *rows.get(1).unwrap_or(&0)]),
        u16::from_le_bytes([*cols.first().unwrap_or(&0), *cols.get(1).unwrap_or(&0)]),
    ))
}

/// Encode a `Resize` payload.
#[must_use]
pub(super) fn encode_window(window: WindowSize) -> [u8; 4] {
    let rows = window.rows().to_le_bytes();
    let cols = window.cols().to_le_bytes();
    [
        *rows.first().unwrap_or(&0),
        *rows.get(1).unwrap_or(&0),
        *cols.first().unwrap_or(&0),
        *cols.get(1).unwrap_or(&0),
    ]
}

// ---------------------------------------------------------------------------
// The bounded ring.
// ---------------------------------------------------------------------------

/// Output the supervisor kept while nobody was attached.
///
/// Bounded and oldest-dropped, with the drop *counted*. The count is the point:
/// a ring that silently discarded would let a reconnecting client believe it
/// had seen the whole run.
pub(super) struct Scrollback {
    bytes: VecDeque<u8>,
    dropped: u64,
}

impl Scrollback {
    pub(super) fn new() -> Self {
        Self {
            bytes: VecDeque::new(),
            dropped: 0,
        }
    }

    /// Keep `bytes`, dropping whatever no longer fits.
    pub(super) fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes.iter().copied());
        while self.bytes.len() > SCROLLBACK_CAPACITY_BYTES {
            // One byte at a time rather than a bulk drain: the queue is a ring
            // buffer, `pop_front` is O(1), and the loop runs once per byte over
            // the bound rather than once per push.
            if self.bytes.pop_front().is_some() {
                self.dropped = self.dropped.saturating_add(1);
            }
        }
    }

    /// How much is held.
    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    /// How much has been dropped since the ring was created.
    pub(super) fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Take everything, leaving the ring empty and the drop count intact.
    ///
    /// The count survives on purpose: it describes the run's history, not the
    /// ring's current contents, and a client that attaches twice should not be
    /// told the second time that nothing was ever lost.
    pub(super) fn take(&mut self) -> Vec<u8> {
        self.bytes.drain(..).collect()
    }
}

// ---------------------------------------------------------------------------
// The PTY itself.
// ---------------------------------------------------------------------------

/// `TIOCSCTTY`: make this descriptor the calling session's controlling
/// terminal.
///
/// Taken from the platform header rather than from `libc`, which does not
/// declare the `TIOC*` numbers for Apple targets. The values are the BSD
/// `_IO`/`_IOW` encodings and are identical across Darwin and the BSDs;
/// `the_darwin_ioctl_numbers_are_the_documented_encodings` recomputes them from
/// the encoding rule so a typo cannot pass as a constant.
#[cfg(target_os = "macos")]
const TIOCSCTTY: libc::c_ulong = 0x2000_7461;

/// `TIOCSWINSZ`: set a terminal's window size, and signal `SIGWINCH` to its
/// foreground process group if the size changed.
#[cfg(target_os = "macos")]
const TIOCSWINSZ: libc::c_ulong = 0x8008_7467;

/// `TIOCPTYGNAME`: the slave's path, into a 128-byte buffer.
///
/// Darwin's own `ptsname_r`, which `libc` does not declare for Apple targets.
/// The non-reentrant `ptsname` is deliberately not used: it returns a pointer
/// into a static buffer, and this runs in the embedder's process, which may
/// have threads.
#[cfg(target_os = "macos")]
const TIOCPTYGNAME: libc::c_ulong = 0x4080_7453;

/// The slave name buffer `TIOCPTYGNAME` fills.
#[cfg(target_os = "macos")]
const PTY_NAME_BYTES: usize = 128;

#[cfg(target_os = "linux")]
use libc::{TIOCSCTTY, TIOCSWINSZ};

/// A freshly allocated pseudo-terminal, both ends still held here.
pub(super) struct PtyPair {
    /// The master. Ends up in the supervisor and nowhere else.
    pub(super) master: OwnedFd,
    /// The slave. Ends up as the customer child's 0, 1, and 2.
    pub(super) slave: OwnedFd,
}

/// Allocate a pseudo-terminal.
///
/// Runs in the launcher, before any fork, because every call here can allocate,
/// take a lock, or walk the filesystem — none of which a forked child may do.
/// What crosses the fork is two descriptor numbers.
///
/// The slave is opened `O_NOFOLLOW`: the path came from the kernel and names a
/// device node, so a symlink under it would mean something had replaced the
/// terminal between `unlockpt` and this open.
///
/// # Errors
///
/// [`PrepareError::Terminal`] naming the step that failed and its errno.
pub(super) fn open_pty() -> Result<PtyPair, PrepareError> {
    let fail = |stage: &'static str| PrepareError::Terminal {
        stage,
        errno: super::prepare::last_errno(),
    };

    // O_NOCTTY: the master must never become *this* process's controlling
    // terminal. The launcher is an ordinary program with a terminal of its own,
    // and stealing it would be a side effect of preparing a sandbox.
    // SAFETY: `posix_openpt` takes flags and returns a descriptor or -1. No
    // memory is passed.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        return Err(fail("posix_openpt"));
    }
    // SAFETY: `master` is a fresh descriptor with no other owner, so taking
    // sole ownership of it is sound. From here every exit path closes it.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let master = above_standard_streams(master)?;
    set_close_on_exec(master.as_raw_fd())?;

    // SAFETY: both take the master descriptor and touch no memory of ours.
    if unsafe { libc::grantpt(master.as_raw_fd()) } != 0 {
        return Err(fail("grantpt"));
    }
    // SAFETY: as above.
    if unsafe { libc::unlockpt(master.as_raw_fd()) } != 0 {
        return Err(fail("unlockpt"));
    }

    let name = slave_name(master.as_raw_fd())?;
    // SAFETY: `name` is a NUL-terminated buffer owned by this frame and `open`
    // reads it for the length of the call only.
    let slave = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if slave < 0 {
        return Err(fail("open pty slave"));
    }
    // SAFETY: `slave` is a fresh descriptor with no other owner.
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    let slave = above_standard_streams(slave)?;
    Ok(PtyPair { master, slave })
}

/// The slave's path, as the kernel names it.
#[cfg(target_os = "linux")]
fn slave_name(master: RawFd) -> Result<CString, PrepareError> {
    let mut buffer = [0_i8; 128];
    // SAFETY: `buffer` is a live local of exactly the length passed, and
    // `ptsname_r` writes a NUL-terminated name into it or returns non-zero.
    let rc = unsafe { libc::ptsname_r(master, buffer.as_mut_ptr().cast(), buffer.len()) };
    if rc != 0 {
        return Err(PrepareError::Terminal {
            stage: "ptsname_r",
            errno: super::prepare::last_errno(),
        });
    }
    name_from_buffer(&buffer)
}

/// The slave's path, as the kernel names it.
///
/// Darwin has no `ptsname_r` in `libc`'s declarations, and `ptsname` writes
/// into a static buffer that a threaded embedder could be sharing. The ioctl
/// below is what `ptsname_r` calls on this platform anyway.
#[cfg(target_os = "macos")]
fn slave_name(master: RawFd) -> Result<CString, PrepareError> {
    let mut buffer = [0_i8; PTY_NAME_BYTES];
    // SAFETY: `TIOCPTYGNAME` writes at most `PTY_NAME_BYTES` bytes of
    // NUL-terminated name into the pointer, and `buffer` is a live local of
    // exactly that length.
    let rc = unsafe { libc::ioctl(master, TIOCPTYGNAME, buffer.as_mut_ptr()) };
    if rc != 0 {
        return Err(PrepareError::Terminal {
            stage: "TIOCPTYGNAME",
            errno: super::prepare::last_errno(),
        });
    }
    name_from_buffer(&buffer)
}

/// A NUL-terminated C string out of a kernel-filled buffer.
///
/// Bounded by the array rather than by the NUL, so a buffer the kernel did not
/// terminate is truncated at the end of its own storage instead of running off
/// it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn name_from_buffer(buffer: &[i8]) -> Result<CString, PrepareError> {
    let bytes: Vec<u8> = buffer
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect();
    if bytes.is_empty() {
        return Err(PrepareError::Terminal {
            stage: "pty slave name",
            errno: 0,
        });
    }
    CString::new(bytes).map_err(|_| PrepareError::Terminal {
        stage: "pty slave name",
        errno: 0,
    })
}

/// Put the close-on-exec flag on a descriptor.
fn set_close_on_exec(fd: RawFd) -> Result<(), PrepareError> {
    // SAFETY: `fd` is a live descriptor; `F_GETFD` reads flags and `F_SETFD`
    // sets them.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(PrepareError::Terminal {
            stage: "pty close-on-exec",
            errno: super::prepare::last_errno(),
        });
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(PrepareError::Terminal {
            stage: "pty close-on-exec",
            errno: super::prepare::last_errno(),
        });
    }
    Ok(())
}

/// Make `slave` this process's controlling terminal and its standard streams.
///
/// Runs in the forked customer child, so it is syscalls only. Returns `Err`
/// with the errno on the first step that failed; the caller reports it through
/// the status descriptor and exits.
///
/// The caller must already have called `setsid`: `TIOCSCTTY` is refused for a
/// process that is not a session leader, which is exactly why an interactive
/// child leads a *session* rather than only a process group.
pub(super) fn adopt_controlling_terminal(slave: RawFd, master: RawFd) -> Result<(), i32> {
    for stream in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: two integers; `dup2` closes the target if it was open and is
        // async-signal-safe.
        if unsafe { libc::dup2(slave, stream) } < 0 {
            return Err(super::prepare::last_errno());
        }
    }
    // Zero, not one: one *steals* a terminal from the session that already has
    // it, and a sandboxed child has no business doing that.
    // SAFETY: an ioctl on a descriptor this process owns, with an integer
    // argument. `ioctl` is async-signal-safe for a request that touches no
    // memory of ours.
    if unsafe { libc::ioctl(libc::STDIN_FILENO, TIOCSCTTY as _, 0_i32) } != 0 {
        return Err(super::prepare::last_errno());
    }
    // Both spare copies go now rather than being left to the descriptor sweep:
    // the master in particular must not survive into the customer's program,
    // because a program holding the master of its own terminal could read back
    // everything it wrote and everything typed at it.
    if slave > libc::STDERR_FILENO {
        // SAFETY: a descriptor this process owns, closed exactly once.
        unsafe { libc::close(slave) };
    }
    // SAFETY: as above.
    unsafe { libc::close(master) };
    Ok(())
}

/// Set a terminal's window size.
///
/// The kernel signals `SIGWINCH` to the terminal's foreground process group
/// when — and only when — the size actually *changes*. That is a fact this
/// build depends on and proves live: the resize test runs a shell that traps
/// `WINCH` and prints `stty size`, so a platform that stopped delivering the
/// signal would fail that test rather than silently deliver a resize nothing
/// noticed. Setting the size a program already has therefore signals nothing,
/// which is correct and is why the test changes it.
pub(super) fn set_window_size(master: RawFd, window: WindowSize) -> Result<(), i32> {
    let size = libc::winsize {
        ws_row: window.rows(),
        ws_col: window.cols(),
        // Pixels are not carried: see `WindowSize`.
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `size` is a live local of exactly the type the request expects,
    // and the kernel reads it for the length of the call only.
    if unsafe { libc::ioctl(master, TIOCSWINSZ as _, &raw const size) } != 0 {
        return Err(super::prepare::last_errno());
    }
    Ok(())
}

/// What one non-blocking read found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadOutcome {
    /// This many bytes landed in the buffer.
    Read(usize),
    /// Nothing was ready. Not a failure and not an end.
    WouldBlock,
    /// The descriptor has no more to give, ever.
    ///
    /// A terminal master reaches this when the last slave closes, which the
    /// two platforms spell differently — `read` returns 0 on macOS and fails
    /// with `EIO` on Linux — so both are folded into the one fact that matters.
    Ended,
}

/// Read whatever is ready, without waiting.
pub(super) fn read_nonblocking(fd: RawFd, into: &mut [u8]) -> ReadOutcome {
    // SAFETY: `into` is a live, exclusively borrowed buffer and its length is
    // exactly what is passed. `read` writes at most that many bytes.
    let count = unsafe { libc::read(fd, into.as_mut_ptr().cast::<libc::c_void>(), into.len()) };
    match usize::try_from(count) {
        Ok(0) => ReadOutcome::Ended,
        Ok(count) => ReadOutcome::Read(count),
        Err(_) => match super::prepare::last_errno() {
            libc::EAGAIN | libc::EINTR => ReadOutcome::WouldBlock,
            _ => ReadOutcome::Ended,
        },
    }
}

/// What one non-blocking write achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteOutcome {
    /// This many bytes were taken.
    Wrote(usize),
    /// Nothing could be taken right now.
    WouldBlock,
    /// The descriptor is gone.
    Ended,
}

/// Write whatever fits, without waiting.
pub(super) fn write_nonblocking(fd: RawFd, bytes: &[u8]) -> WriteOutcome {
    if bytes.is_empty() {
        return WriteOutcome::Wrote(0);
    }
    // SAFETY: `bytes` is a live buffer and its length is exactly what is
    // passed. `write` reads at most that many bytes.
    let count = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
    match usize::try_from(count) {
        Ok(0) => WriteOutcome::Ended,
        Ok(count) => WriteOutcome::Wrote(count),
        Err(_) => match super::prepare::last_errno() {
            libc::EAGAIN | libc::EINTR => WriteOutcome::WouldBlock,
            _ => WriteOutcome::Ended,
        },
    }
}

/// The in-flight bound for output owed to an attached client.
pub(super) const fn outbound_bound() -> usize {
    MAX_ATTACH_OUTBOUND_BYTES
}

/// How long a client may make no progress before it is dropped.
pub(super) const fn stall_deadline() -> Duration {
    ATTACH_STALL_DEADLINE
}

// ---------------------------------------------------------------------------
// The client's side.
// ---------------------------------------------------------------------------

/// A live view of a detached run's terminal.
///
/// Built by [`DetachedSession::attach`]. Holds the same socket the control
/// conversation used, in the mode the attach switched it to, and gives it back
/// with [`Self::detach`].
///
/// Dropping this closes the socket. The run carries on — it is a *detached*
/// run, and the terminal belongs to the supervisor — but the supervisor learns
/// of the close only when it next polls, which is why `detach` exists as a name
/// for saying so deliberately.
pub struct AttachedTerminal {
    /// The control conversation, suspended for the duration.
    session: DetachedSession,
    /// What the supervisor said when this attach was accepted.
    ack: AttachAck,
    /// The size last asked for, so a re-attach can ask for it again.
    window: WindowSize,
    /// Frames that have arrived and not yet been asked for.
    decoder: FrameDecoder,
    /// Events decoded while waiting for something else.
    pending: VecDeque<TerminalEvent>,
}

impl AttachedTerminal {
    pub(super) fn new(session: DetachedSession, ack: AttachAck, window: WindowSize) -> Self {
        Self {
            session,
            ack,
            window,
            decoder: FrameDecoder::new(Peer::Supervisor),
            pending: VecDeque::new(),
        }
    }

    /// What the supervisor reported when this attach was accepted.
    ///
    /// Refreshed by [`Self::activate`], which re-attaches: the counts describe
    /// the most recent attach, not the first one.
    #[must_use]
    pub fn ack(&self) -> &AttachAck {
        &self.ack
    }

    /// The session this terminal belongs to.
    #[must_use]
    pub fn session_id(&self) -> uuid::Uuid {
        self.session.session_id()
    }

    /// The supervisor on the other end.
    #[must_use]
    pub fn supervisor(&self) -> &super::identity::ProcessIdentity {
        self.session.supervisor()
    }

    /// Send bytes to the terminal, verbatim.
    ///
    /// Every byte arrives at the master exactly as given: `0xFF`, NUL, and a
    /// sequence that happens to look like a frame header are all payload,
    /// because the length prefix already said how many bytes this frame owns.
    ///
    /// # Errors
    ///
    /// [`AttachError::PayloadTooLarge`] for more than
    /// [`MAX_ATTACH_PAYLOAD_BYTES`] at once — refused rather than split,
    /// because a write that arrived as two frames with something else between
    /// them is not the write that was made — or a transport failure.
    pub fn write_input(&mut self, bytes: &[u8]) -> Result<(), AttachError> {
        self.send(AttachTag::Input, bytes)
    }

    /// Tell the terminal it is a different size.
    ///
    /// The kernel signals `SIGWINCH` to the run's foreground process group when
    /// the size changes, so a program that traps it hears about this without
    /// the library sending anything else. A resize to the size it already has
    /// signals nothing.
    ///
    /// # Errors
    ///
    /// A transport failure.
    pub fn resize(&mut self, rows: u16, cols: u16) -> Result<(), AttachError> {
        let window = WindowSize::new(rows, cols);
        self.send(AttachTag::Resize, &encode_window(window))?;
        self.window = window;
        Ok(())
    }

    /// Ask the supervisor whether it is still there.
    ///
    /// The answer arrives as [`TerminalEvent::Pong`] from [`Self::read_event`],
    /// possibly behind output that was already on its way.
    ///
    /// # Errors
    ///
    /// A transport failure.
    pub fn ping(&mut self) -> Result<(), AttachError> {
        self.send(AttachTag::Ping, &[])
    }

    /// Wait for something from the terminal, up to `deadline`.
    ///
    /// [`TerminalEvent::Idle`] means the deadline passed with nothing to
    /// report, which is a fact about the run and not a failure of the call.
    ///
    /// # Errors
    ///
    /// A transport failure, or a supervisor that broke the framing rules.
    pub fn read_event(&mut self, deadline: Instant) -> Result<TerminalEvent, AttachError> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(event);
            }
            match self.decoder.next_frame()? {
                Some(frame) => {
                    if let Some(event) = self.classify(frame)? {
                        return Ok(event);
                    }
                }
                None => match self.fill(deadline)? {
                    Filled::Bytes => {}
                    Filled::Deadline => return Ok(TerminalEvent::Idle),
                },
            }
        }
    }

    /// Release the held child while attached, then carry on watching.
    ///
    /// The attach is left for exactly one control exchange and resumed, because
    /// activation is a control operation and the channel is in terminal mode.
    /// Nothing is lost across the gap: output with nobody attached goes to the
    /// supervisor's bounded ring, and the re-attach replays it — the refreshed
    /// [`Self::ack`] says how much, and how much the ring could not keep.
    ///
    /// # Errors
    ///
    /// [`AttachError::Control`] carrying the gate's own typed refusal, or a
    /// transport failure. A failure between leaving and re-entering attach mode
    /// leaves this value unusable and the run untouched; reconnect with
    /// [`super::SessionStore::attach_control`].
    pub fn activate(&mut self, handle: &ActivationHandle) -> Result<LifecycleState, AttachError> {
        self.leave_attach_mode()?;
        let activated = self.session.activate(handle);
        self.enter_attach_mode()?;
        activated.map_err(AttachError::Control)
    }

    /// Stop watching, and get the control conversation back.
    ///
    /// The run carries on and so does its terminal; output from here goes to
    /// the supervisor's ring until somebody attaches again.
    ///
    /// Output already in flight when this was called is discarded — the caller
    /// asked to stop watching — while everything the supervisor had *not* yet
    /// sent is kept in the ring and replayed on the next attach.
    ///
    /// # Errors
    ///
    /// A transport failure. The session is lost with it: a socket whose framing
    /// state is unknown cannot be handed back as a control connection.
    pub fn detach(mut self) -> Result<DetachedSession, AttachError> {
        self.leave_attach_mode()?;
        Ok(self.session)
    }

    /// Send one frame, bounded.
    fn send(&mut self, tag: AttachTag, payload: &[u8]) -> Result<(), AttachError> {
        let mut frame = Vec::with_capacity(payload.len().saturating_add(ATTACH_HEADER_BYTES));
        encode_frame(tag, payload, &mut frame)?;
        write_all_by(
            self.session.stream(),
            &frame,
            Instant::now() + CONTROL_TIMEOUT,
        )?;
        Ok(())
    }

    /// Turn a frame into an event, or absorb it.
    fn classify(&mut self, frame: AttachFrame) -> Result<Option<TerminalEvent>, AttachError> {
        match frame.tag {
            AttachTag::Output => Ok(Some(TerminalEvent::Output(frame.payload))),
            AttachTag::Pong => Ok(Some(TerminalEvent::Pong)),
            AttachTag::SessionEnded => {
                let end: TerminalEnd = serde_json::from_slice(&frame.payload).map_err(|_| {
                    AttachViolation::BadPayload {
                        tag: AttachTag::SessionEnded,
                    }
                })?;
                Ok(Some(TerminalEvent::Ended(end)))
            }
            // A confirmation for a detach nobody asked for. The channel is in a
            // state neither side agrees about, so it is named rather than
            // guessed at.
            AttachTag::Detach => Err(AttachError::UnexpectedFrame {
                expected: "output",
                received: AttachTag::Detach,
            }),
            // The decoder refuses these by direction before they reach here.
            AttachTag::Input | AttachTag::Resize | AttachTag::Ping => {
                Err(AttachError::UnexpectedFrame {
                    expected: "output",
                    received: frame.tag,
                })
            }
        }
    }

    /// Read once, waiting no longer than `deadline`.
    fn fill(&mut self, deadline: Instant) -> Result<Filled, AttachError> {
        let fd = self.session.stream().as_raw_fd();
        loop {
            let Some(timeout) = remaining_millis(deadline) else {
                return Ok(Filled::Deadline);
            };
            let mut fds = [libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            }];
            match poll_fds(&mut fds, timeout) {
                PollOutcome::Ready => {}
                PollOutcome::TimedOut => return Ok(Filled::Deadline),
                PollOutcome::Interrupted => continue,
                PollOutcome::Failed(errno) => return Err(FrameError::Io { errno }.into()),
            }
            let mut scratch = [0_u8; TERMINAL_READ_CHUNK];
            match read_nonblocking(fd, &mut scratch) {
                ReadOutcome::Read(count) => {
                    self.decoder.feed(scratch.get(..count).unwrap_or_default());
                    return Ok(Filled::Bytes);
                }
                ReadOutcome::WouldBlock => continue,
                ReadOutcome::Ended => return Err(FrameError::Closed.into()),
            }
        }
    }

    /// Ask to leave attach mode and wait for the confirmation.
    ///
    /// Output frames still on the wire are read past rather than left in the
    /// buffer: the next thing this connection carries is a control frame, and a
    /// terminal frame sitting in front of it would be read as one.
    fn leave_attach_mode(&mut self) -> Result<(), AttachError> {
        self.send(AttachTag::Detach, &[])?;
        self.pending.clear();
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        loop {
            match self.decoder.next_frame()? {
                Some(frame) if frame.tag == AttachTag::Detach => return Ok(()),
                // Everything else is output the supervisor had already queued,
                // or a late pong. Both are dropped: the caller has said it is
                // no longer watching.
                Some(_) => {}
                None => match self.fill(deadline)? {
                    Filled::Bytes => {}
                    Filled::Deadline => return Err(FrameError::Timeout.into()),
                },
            }
        }
    }

    /// Ask to re-enter attach mode with the size last asked for.
    fn enter_attach_mode(&mut self) -> Result<(), AttachError> {
        self.ack = self.session.attach_request(self.window)?;
        Ok(())
    }
}

/// What one fill achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filled {
    /// Bytes arrived.
    Bytes,
    /// The deadline passed first.
    Deadline,
}

/// Debug that names the attach without rendering the terminal's contents.
impl std::fmt::Debug for AttachedTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachedTerminal")
            .field("session_id", &self.session.session_id())
            .field("window", &self.window)
            .field("ack", &self.ack)
            .field("buffered", &self.decoder.buffered())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(peer: Peer, bytes: &[u8]) -> Result<Vec<AttachFrame>, AttachViolation> {
        let mut decoder = FrameDecoder::new(peer);
        decoder.feed(bytes);
        let mut frames = Vec::new();
        while let Some(frame) = decoder.next_frame()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    #[test]
    fn a_frame_round_trips_through_the_decoder() -> Result<(), AttachError> {
        let mut wire = Vec::new();
        encode_frame(AttachTag::Input, b"hello", &mut wire)?;
        let frames = decode_all(Peer::Client, &wire)?;
        assert_eq!(
            frames,
            vec![AttachFrame {
                tag: AttachTag::Input,
                payload: b"hello".to_vec(),
            }]
        );
        Ok(())
    }

    #[test]
    fn a_frame_payload_that_looks_like_a_frame_is_still_payload() -> Result<(), AttachError> {
        // The raw-versus-control distinctness claim, at the unit level: a
        // payload containing a perfectly well-formed frame header, a 0xFF, and
        // NULs must come back byte for byte as *one* frame's payload. If the
        // framing were delimiter-based, or if the decoder rescanned the
        // payload, this would split into two.
        let mut hostile = Vec::new();
        hostile.push(AttachTag::Output.as_byte());
        hostile.extend_from_slice(&64_u32.to_le_bytes());
        hostile.extend_from_slice(&[0xFF, 0x00, 0x01, 0xFE, 0x00]);
        hostile.extend_from_slice(&[AttachTag::Detach.as_byte(), 0, 0, 0, 0]);

        let mut wire = Vec::new();
        encode_frame(AttachTag::Input, &hostile, &mut wire)?;
        encode_frame(AttachTag::Ping, &[], &mut wire)?;

        let frames = decode_all(Peer::Client, &wire)?;
        assert_eq!(frames.len(), 2, "{frames:?}");
        assert_eq!(
            frames.first().map(|frame| frame.tag),
            Some(AttachTag::Input)
        );
        assert_eq!(
            frames.first().map(|frame| frame.payload.clone()),
            Some(hostile)
        );
        assert_eq!(frames.get(1).map(|frame| frame.tag), Some(AttachTag::Ping));
        Ok(())
    }

    #[test]
    fn a_frame_delivered_one_byte_at_a_time_still_arrives_whole() -> Result<(), AttachError> {
        // A socket delivers bytes, not messages. A decoder that assumed one
        // read was one frame would work in every test that wrote both halves at
        // once and fail on a loaded machine.
        let mut wire = Vec::new();
        encode_frame(AttachTag::Input, b"abcdef", &mut wire)?;
        let mut decoder = FrameDecoder::new(Peer::Client);
        for byte in wire.iter().copied() {
            assert_eq!(
                decoder.next_frame()?,
                None,
                "a partial frame is not a frame"
            );
            decoder.feed(&[byte]);
        }
        assert_eq!(
            decoder.next_frame()?,
            Some(AttachFrame {
                tag: AttachTag::Input,
                payload: b"abcdef".to_vec(),
            })
        );
        assert_eq!(decoder.next_frame()?, None);
        Ok(())
    }

    #[test]
    fn a_tag_this_protocol_does_not_have_is_named_not_skipped() {
        let wire = [0x7F, 0, 0, 0, 0];
        assert_eq!(
            decode_all(Peer::Client, &wire).err(),
            Some(AttachViolation::UnknownTag { tag: 0x7F })
        );
    }

    #[test]
    fn a_tag_the_sender_may_not_send_is_refused_by_direction() {
        // An `Output` frame from a client and an `Input` frame from a
        // supervisor are each a peer claiming to own the other end of the
        // terminal.
        let mut wire = Vec::new();
        wire.push(AttachTag::Output.as_byte());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            decode_all(Peer::Client, &wire).err(),
            Some(AttachViolation::WrongDirection {
                tag: AttachTag::Output,
                peer: Peer::Client,
            })
        );

        let mut reverse = Vec::new();
        reverse.push(AttachTag::Input.as_byte());
        reverse.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            decode_all(Peer::Supervisor, &reverse).err(),
            Some(AttachViolation::WrongDirection {
                tag: AttachTag::Input,
                peer: Peer::Supervisor,
            })
        );
    }

    #[test]
    fn an_oversize_length_prefix_is_refused_before_the_payload_is_waited_for() {
        let mut wire = Vec::new();
        wire.push(AttachTag::Input.as_byte());
        let announced = 1_024_u32 * 1_024 * 1_024;
        wire.extend_from_slice(&announced.to_le_bytes());
        let mut decoder = FrameDecoder::new(Peer::Client);
        decoder.feed(&wire);
        assert_eq!(
            decoder.next_frame().err(),
            Some(AttachViolation::Oversize {
                size: u64::from(announced),
                limit: MAX_ATTACH_PAYLOAD_BYTES,
            })
        );
        // Nothing was buffered for it: the header is all that is held.
        assert_eq!(decoder.buffered(), ATTACH_HEADER_BYTES);
    }

    #[test]
    fn a_payload_at_the_bound_is_still_a_frame() -> Result<(), AttachError> {
        // The bound is inclusive, and a test that only proved the refusal would
        // not notice an off-by-one that rejected legal frames.
        let payload = vec![0xAB_u8; MAX_ATTACH_PAYLOAD_BYTES];
        let mut wire = Vec::new();
        encode_frame(AttachTag::Input, &payload, &mut wire)?;
        let frames = decode_all(Peer::Client, &wire)?;
        assert_eq!(
            frames.first().map(|frame| frame.payload.len()),
            Some(payload.len())
        );

        let one_more = vec![0_u8; MAX_ATTACH_PAYLOAD_BYTES.saturating_add(1)];
        let mut overflow = Vec::new();
        assert_eq!(
            encode_frame(AttachTag::Input, &one_more, &mut overflow).err(),
            Some(AttachError::PayloadTooLarge {
                size: one_more.len(),
                limit: MAX_ATTACH_PAYLOAD_BYTES,
            })
        );
        Ok(())
    }

    #[test]
    fn a_window_round_trips_through_its_payload() -> Result<(), AttachViolation> {
        let window = WindowSize::new(40, 100);
        assert_eq!(decode_window(&encode_window(window))?, window);
        // Four bytes exactly: a resize with three or five is a peer that means
        // something this protocol does not have.
        assert!(decode_window(&[1, 0, 2]).is_err());
        assert!(decode_window(&[1, 0, 2, 0, 0]).is_err());
        Ok(())
    }

    #[test]
    fn the_ring_stays_bounded_and_counts_what_it_dropped() {
        let mut ring = Scrollback::new();
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..8 {
            ring.push(&chunk);
        }
        assert_eq!(
            ring.len(),
            SCROLLBACK_CAPACITY_BYTES,
            "the ring must never exceed its bound"
        );
        assert_eq!(
            ring.dropped(),
            (8 * 64 * 1024_u64).saturating_sub(SCROLLBACK_CAPACITY_BYTES as u64),
            "every dropped byte must be counted"
        );
        // Taking the contents empties the ring and leaves the history intact: a
        // client that attaches twice must not be told the second time that
        // nothing was ever lost.
        let dropped = ring.dropped();
        assert_eq!(ring.take().len(), SCROLLBACK_CAPACITY_BYTES);
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.dropped(), dropped);
    }

    #[test]
    fn the_ring_keeps_the_tail_not_the_head() {
        // Scrollback, not a transcript: what survives is the most recent
        // output, which is what a reattaching viewer wants to see.
        let mut ring = Scrollback::new();
        ring.push(&vec![b'o'; SCROLLBACK_CAPACITY_BYTES]);
        ring.push(b"newest");
        let kept = ring.take();
        assert_eq!(kept.len(), SCROLLBACK_CAPACITY_BYTES);
        assert!(kept.ends_with(b"newest"), "the tail must survive");
    }

    #[test]
    fn every_tag_round_trips_through_its_byte() {
        for tag in [
            AttachTag::Input,
            AttachTag::Output,
            AttachTag::Resize,
            AttachTag::Detach,
            AttachTag::SessionEnded,
            AttachTag::Ping,
            AttachTag::Pong,
        ] {
            assert_eq!(AttachTag::from_byte(tag.as_byte()), Some(tag));
        }
        // The byte values are contract: they cross a socket between two
        // processes that may be different builds.
        assert_eq!(AttachTag::Input.as_byte(), 0x01);
        assert_eq!(AttachTag::Output.as_byte(), 0x02);
        assert_eq!(AttachTag::Resize.as_byte(), 0x03);
        assert_eq!(AttachTag::Detach.as_byte(), 0x04);
        assert_eq!(AttachTag::SessionEnded.as_byte(), 0x05);
        assert_eq!(AttachTag::Ping.as_byte(), 0x06);
        assert_eq!(AttachTag::Pong.as_byte(), 0x07);
        assert_eq!(AttachTag::from_byte(0x00), None);
        assert_eq!(AttachTag::from_byte(0x08), None);
        assert_eq!(AttachTag::from_byte(0xFF), None);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn the_darwin_ioctl_numbers_are_the_documented_encodings() {
        // `libc` does not declare the `TIOC*` numbers for Apple targets, so
        // this build carries them. Recomputed here from the BSD `_IOC` encoding
        // rule rather than copied, so a transposed digit fails here instead of
        // failing as an `ENOTTY` at the point of use.
        const IOC_VOID: libc::c_ulong = 0x2000_0000;
        const IOC_IN: libc::c_ulong = 0x8000_0000;
        const IOC_OUT: libc::c_ulong = 0x4000_0000;
        const GROUP: libc::c_ulong = (b't' as libc::c_ulong) << 8;
        let encode = |dir: libc::c_ulong, len: libc::c_ulong, num: libc::c_ulong| {
            dir | ((len & 0x1fff) << 16) | GROUP | num
        };
        let winsize = std::mem::size_of::<libc::winsize>() as libc::c_ulong;
        assert_eq!(winsize, 8);
        assert_eq!(TIOCSCTTY, encode(IOC_VOID, 0, 97));
        assert_eq!(TIOCSWINSZ, encode(IOC_IN, winsize, 103));
        assert_eq!(TIOCPTYGNAME, encode(IOC_OUT, PTY_NAME_BYTES as u64, 83));
    }

    #[test]
    fn a_pty_can_be_opened_and_resized_here() -> Result<(), PrepareError> {
        // The live half of the constants above, and of the whole allocation
        // sequence: a build whose `TIOCSWINSZ` were wrong would fail here with
        // an errno rather than silently resizing nothing.
        let pty = open_pty()?;
        assert!(pty.master.as_raw_fd() >= 3);
        assert!(pty.slave.as_raw_fd() >= 3);
        assert_ne!(pty.master.as_raw_fd(), pty.slave.as_raw_fd());
        if let Err(errno) = set_window_size(pty.master.as_raw_fd(), WindowSize::new(40, 100)) {
            panic!("a freshly opened master must take a window size: errno {errno}");
        }
        Ok(())
    }

    #[test]
    fn the_bounds_say_what_the_documentation_says_they_say() {
        // The inequalities themselves are `const _: () = assert!(…)` beside the
        // constants, so a build that broke one would not link. What is left for
        // a test is the arithmetic the doc comments state, so that changing one
        // number without the other is caught here rather than by a reader.
        assert_eq!(MAX_ATTACH_PAYLOAD_BYTES, 32 * 1024);
        assert_eq!(SCROLLBACK_CAPACITY_BYTES, 256 * 1024);
        assert_eq!(outbound_bound(), SCROLLBACK_CAPACITY_BYTES);
        // Long enough that a client on a loaded machine is not dropped for
        // being slow, short enough that a run is not held still by one that
        // has stopped reading altogether.
        assert!(stall_deadline() >= Duration::from_secs(5));
        assert!(stall_deadline() <= Duration::from_secs(60));
    }
}
