//! The activation gate: what a prepared child is held by, and what releases it.
//!
//! A prepared child is sandboxed and blocked before `execve`. The only thing
//! that can start it is the release message on the gate descriptor, and the
//! only thing that can cause that message to be written is presenting the
//! [`ActivationHandle`] that `prepare` returned.
//!
//! Two secrets guard two different things. The [`ActivationHandle`] proves a
//! *caller* may ask for the release; the [`GateSecrets`] pair is what the
//! *child* recognises, so that a stray copy of the gate descriptor cannot
//! start anything on its own.
//!
//! # What the handle is, and is not
//!
//! The handle is a 32-byte random token plus the session and generation it
//! belongs to. It is *not* a capability the library interprets: nono checks
//! that the bytes match and that the gate is still open, and nothing else.
//! Whether the holder *should* have it is the consumer's decision, made before
//! it ever calls `activate`.
//!
//! # Where the token lives
//!
//! Only the handle holds the token. The prepared sandbox keeps a SHA-256
//! digest of it, so a supervisor's memory, a core dump, or a durable session
//! record cannot yield something replayable. The token is never logged, never
//! rendered by `Debug`, never placed in argv, the environment, or a file, and
//! both halves are zeroized: the handle on drop, the digest when the gate
//! closes.
//!
//! # Single use is enforced by state, not by ownership
//!
//! [`super::PreparedSandbox::activate`] takes the handle by reference, so
//! Rust's move semantics deliberately do *not* provide the single-use
//! guarantee. That guarantee lives in the gate: the first activation moves the
//! state machine out of `Prepared`, and every later attempt — with the same
//! handle, a copied one, or a forged one — finds a state from which activation
//! is unreachable. A guarantee that depended on the caller giving up ownership
//! would be no guarantee at all against a caller who kept a copy.

use super::exit::{PreExecStage, SupervisorStage};
use super::state::LifecycleState;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of an activation token, in bytes.
pub const ACTIVATION_TOKEN_BYTES: usize = 32;

/// Length of the stored token digest, in bytes.
pub(crate) const TOKEN_DIGEST_BYTES: usize = 32;

/// Length of a gate message, in bytes.
pub(crate) const GATE_MESSAGE_BYTES: usize = 16;

/// The two messages that can end a child's wait at the gate.
///
/// Not fixed bytes. A constant release byte would mean that *any* writable
/// copy of the gate descriptor releases the child — and a descriptor can be
/// inherited, passed over a socket, or left behind by a fork the supervisor
/// did not intend. These are drawn from the system CSPRNG before the fork, so
/// the only parties that know them are the supervisor and the child forked
/// from it. A leaked descriptor without them can at worst make the child
/// refuse and exit, never start.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct GateSecrets {
    release: [u8; GATE_MESSAGE_BYTES],
    abort: [u8; GATE_MESSAGE_BYTES],
}

impl GateSecrets {
    /// Draw a fresh pair from the system CSPRNG.
    pub(crate) fn generate() -> Result<Self, getrandom::Error> {
        let mut release = [0_u8; GATE_MESSAGE_BYTES];
        let mut abort = [0_u8; GATE_MESSAGE_BYTES];
        getrandom::fill(&mut release)?;
        getrandom::fill(&mut abort)?;
        Ok(Self { release, abort })
    }

    pub(crate) fn release(&self) -> &[u8; GATE_MESSAGE_BYTES] {
        &self.release
    }

    pub(crate) fn abort(&self) -> &[u8; GATE_MESSAGE_BYTES] {
        &self.abort
    }

    /// Decide what a message that arrived on the gate means.
    ///
    /// Allocation-free and free of any syscall, so the child can run it
    /// between its sandbox apply and `execve`. Both comparisons run in
    /// constant time and both always run, so the work does not depend on which
    /// message arrived.
    pub(crate) fn classify(&self, message: &[u8; GATE_MESSAGE_BYTES]) -> GateDecision {
        let is_release = ct_eq(message, &self.release);
        let is_abort = ct_eq(message, &self.abort);
        match (is_release, is_abort) {
            (true, false) => GateDecision::Release,
            (false, true) => GateDecision::Abort,
            // Neither, or (impossibly) both: not a message this gate speaks.
            _ => GateDecision::Unknown,
        }
    }
}

impl std::fmt::Debug for GateSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateSecrets")
            .field("release", &"<redacted>")
            .field("abort", &"<redacted>")
            .finish()
    }
}

/// What a message on the gate descriptor asks the child to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateDecision {
    /// Proceed to `execve`.
    Release,
    /// Stop without running anything.
    Abort,
    /// Refused: whoever wrote this does not hold the gate's secrets.
    Unknown,
}

/// The single-use capability that releases one prepared child.
///
/// Zeroized on drop. `Debug` prints the session and generation but never the
/// token — a handle that reached a log line would be a handle an attacker
/// could replay, and the state machine's single-use check is the last line of
/// defence, not the first.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ActivationHandle {
    #[zeroize(skip)]
    session_id: Uuid,
    #[zeroize(skip)]
    generation: u64,
    token: [u8; ACTIVATION_TOKEN_BYTES],
}

impl ActivationHandle {
    pub(crate) fn new(
        session_id: Uuid,
        generation: u64,
        token: [u8; ACTIVATION_TOKEN_BYTES],
    ) -> Self {
        Self {
            session_id,
            generation,
            token,
        }
    }

    /// The session this handle activates.
    #[must_use]
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// The generation this handle activates.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn token(&self) -> &[u8; ACTIVATION_TOKEN_BYTES] {
        &self.token
    }
}

impl std::fmt::Debug for ActivationHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivationHandle")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// SHA-256 of an activation token: what a prepared sandbox stores instead of
/// the token itself.
pub(crate) fn token_digest(token: &[u8; ACTIVATION_TOKEN_BYTES]) -> [u8; TOKEN_DIGEST_BYTES] {
    Sha256::digest(token).into()
}

/// Compare two byte strings without leaking where they first differ.
///
/// Accumulates the XOR of every byte pair and inspects the result once, so the
/// work done is the same whether the inputs match at byte 0 or byte 31. A
/// short-circuiting `==` would let a caller learn the digest one byte at a time
/// from response timing.
///
/// The length check is not a timing leak here: every call site passes two
/// fixed-length operands ([`TOKEN_DIGEST_BYTES`] or [`GATE_MESSAGE_BYTES`]), so
/// the branch never depends on secret data.
pub(crate) fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut accumulator: u8 = 0;
    for (lhs, rhs) in left.iter().zip(right.iter()) {
        accumulator |= lhs ^ rhs;
    }
    // `black_box` keeps the optimizer from noticing that the accumulator can
    // be tested early and rewriting the loop into a short-circuiting compare.
    std::hint::black_box(accumulator) == 0
}

/// Everything an activation can be refused for.
///
/// Checked in this order: session, generation, gate state, expiry, token. The
/// state check precedes the token compare because a closed gate has already
/// zeroized the digest it would compare against, and because the state machine
/// already knows the better answer. Expiry precedes the token compare too, so
/// presenting a *wrong* token to an expired gate still stops the child.
///
/// The messages name no secret — not the token, not the digest, not a byte of
/// either.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ActivationError {
    /// The handle belongs to a different session.
    #[error("activation handle is for session {supplied}, not {expected}")]
    WrongSession {
        /// The session that owns this gate.
        expected: Uuid,
        /// The session named by the handle.
        supplied: Uuid,
    },

    /// The handle belongs to a different generation of the same session.
    #[error("activation handle is for generation {supplied}, not {expected}")]
    WrongGeneration {
        /// The generation that owns this gate.
        expected: u64,
        /// The generation named by the handle.
        supplied: u64,
    },

    /// The gate's expiry passed before activation was attempted. The gate is
    /// now permanently closed and the child has been stopped.
    #[error("activation expired before it was used")]
    ActivationExpired,

    /// The token did not match. Says nothing about how close it was.
    #[error("activation token does not match")]
    InvalidActivationToken,

    /// The gate was already claimed. Exactly one activation ever wins.
    #[error("this sandbox has already been activated")]
    AlreadyActivated,

    /// The run was stopped before activation, so the gate can never open.
    #[error("this sandbox was stopped before activation")]
    AlreadyStopped,

    /// The gate is closed for a reason with no more specific name.
    #[error("the activation gate is not open in state {state}")]
    GateUnavailable {
        /// The state the machine was in when activation was attempted.
        state: LifecycleState,
    },

    /// The child was released but died before `execve` completed.
    #[error("child failed before exec at stage {stage}: errno {errno}")]
    PreExecFailed {
        /// Where in the pre-exec sequence it stopped.
        stage: PreExecStage,
        /// Platform error number captured at that point.
        errno: i32,
    },

    /// The supervisor's own machinery failed, so the child's fate is unknown.
    #[error("supervisor failed at stage {stage}: errno {errno}")]
    SupervisorFailed {
        /// Which supervisor step failed.
        stage: SupervisorStage,
        /// Platform error number captured at that point.
        errno: i32,
    },
}

impl ActivationError {
    /// Map a refused `BeginActivate` to the reason the gate is shut.
    ///
    /// The state machine is the single-use compare-and-swap: it, not a boolean
    /// beside it, decides whether a second activation wins. This turns its
    /// refusal into the caller-facing name for that refusal.
    pub(crate) fn from_closed_gate(state: LifecycleState) -> Self {
        match state {
            LifecycleState::Activating | LifecycleState::Running | LifecycleState::Exited => {
                Self::AlreadyActivated
            }
            LifecycleState::Stopping | LifecycleState::Stopped => Self::AlreadyStopped,
            other => Self::GateUnavailable { state: other },
        }
    }
}

/// Everything a pre-activation stop can be refused for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StopError {
    /// A stop is not legal from this state — the run already ended, or was
    /// already stopped.
    #[error("stop is not legal in state {state}")]
    NotStoppable {
        /// The state the machine was in.
        state: LifecycleState,
    },

    /// The stop signal could not be delivered, so nothing was killed and
    /// nothing is claimed about the run's processes.
    ///
    /// Reported rather than swallowed: a stop that could not signal is not a
    /// stop, and continuing to the reap would block on a process nothing had
    /// asked to die.
    #[error("stop signal could not be delivered to {target}: errno {errno}")]
    SignalFailed {
        /// The pid or process group the signal was aimed at.
        target: i32,
        /// Platform error number from the signal.
        errno: i32,
    },

    /// The stop was requested but the child's death was never observed. A sent
    /// signal is not proof, so this is a failure, not a stop.
    #[error(transparent)]
    Reap(#[from] super::exit::ReapError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(fill: u8) -> [u8; ACTIVATION_TOKEN_BYTES] {
        [fill; ACTIVATION_TOKEN_BYTES]
    }

    #[test]
    fn debug_never_renders_the_token() {
        // A fixed session id keeps the assertions deterministic: a random uuid
        // is hex, and hex can contain any byte pattern the token might use.
        let secret = token(0xAB);
        let handle = ActivationHandle::new(Uuid::nil(), 1, secret);
        let rendered = format!("{handle:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            !rendered.contains(&format!("{secret:?}")),
            "the token array leaked: {rendered}"
        );
        // Neither the decimal nor the hex spelling of a token byte appears.
        assert!(!rendered.contains("171"), "{rendered}");
        assert!(!rendered.contains("ab"), "{rendered}");
    }

    #[test]
    fn handle_reports_its_session_and_generation() {
        let session_id = Uuid::now_v7();
        let handle = ActivationHandle::new(session_id, 7, token(1));
        assert_eq!(handle.session_id(), session_id);
        assert_eq!(handle.generation(), 7);
    }

    #[test]
    fn the_digest_is_not_the_token() {
        let secret = token(0x5A);
        let digest = token_digest(&secret);
        assert_ne!(digest, secret, "storing the token would defeat the digest");
    }

    #[test]
    fn the_digest_is_stable_and_distinguishes_tokens() {
        assert_eq!(token_digest(&token(1)), token_digest(&token(1)));
        assert_ne!(token_digest(&token(1)), token_digest(&token(2)));
    }

    #[test]
    fn constant_time_compare_accepts_only_exact_matches() {
        let digest = token_digest(&token(9));
        assert!(ct_eq(&digest, &digest));

        // Differing in the first byte and differing in the last byte must both
        // be rejected: an implementation that short-circuits would still pass
        // the first case, so both are required.
        let mut first_byte_differs = digest;
        first_byte_differs[0] ^= 0x01;
        assert!(!ct_eq(&digest, &first_byte_differs));

        let mut last_byte_differs = digest;
        last_byte_differs[TOKEN_DIGEST_BYTES - 1] ^= 0x01;
        assert!(!ct_eq(&digest, &last_byte_differs));
    }

    #[test]
    fn constant_time_compare_rejects_length_mismatches() {
        assert!(!ct_eq(&[1, 2, 3], &[1, 2]));
        assert!(!ct_eq(&[], &[0]));
        assert!(ct_eq(&[], &[]));
    }

    #[test]
    fn a_closed_gate_names_why_it_is_closed() {
        assert_eq!(
            ActivationError::from_closed_gate(LifecycleState::Activating),
            ActivationError::AlreadyActivated
        );
        assert_eq!(
            ActivationError::from_closed_gate(LifecycleState::Running),
            ActivationError::AlreadyActivated
        );
        assert_eq!(
            ActivationError::from_closed_gate(LifecycleState::Exited),
            ActivationError::AlreadyActivated
        );
        assert_eq!(
            ActivationError::from_closed_gate(LifecycleState::Stopping),
            ActivationError::AlreadyStopped
        );
        assert_eq!(
            ActivationError::from_closed_gate(LifecycleState::Stopped),
            ActivationError::AlreadyStopped
        );
        assert_eq!(
            ActivationError::from_closed_gate(LifecycleState::Failed),
            ActivationError::GateUnavailable {
                state: LifecycleState::Failed
            }
        );
    }

    fn secrets() -> GateSecrets {
        match GateSecrets::generate() {
            Ok(secrets) => secrets,
            Err(err) => panic!("the system CSPRNG must answer: {err}"),
        }
    }

    #[test]
    fn the_gate_recognises_its_own_two_messages() {
        let secrets = secrets();
        assert_eq!(
            secrets.classify(secrets.release()),
            GateDecision::Release,
            "the release message must release"
        );
        assert_eq!(
            secrets.classify(secrets.abort()),
            GateDecision::Abort,
            "the abort message must abort"
        );
        assert_ne!(
            secrets.release(),
            secrets.abort(),
            "release and abort must never be the same bytes"
        );
    }

    #[test]
    fn a_message_the_gate_did_not_issue_is_refused() {
        // This is the whole point of the random pair: a party holding a copy
        // of the gate descriptor but not the secret cannot release the child.
        // With a fixed release byte, the all-`R` case below would start it.
        let secrets = secrets();
        for guess in [
            [0x00; GATE_MESSAGE_BYTES],
            [0xFF; GATE_MESSAGE_BYTES],
            [b'R'; GATE_MESSAGE_BYTES],
            [b'A'; GATE_MESSAGE_BYTES],
        ] {
            assert_eq!(
                secrets.classify(&guess),
                GateDecision::Unknown,
                "a guessed message must never release or abort"
            );
        }
    }

    #[test]
    fn a_near_miss_message_is_refused() {
        let secrets = secrets();
        for flipped in [0, GATE_MESSAGE_BYTES / 2, GATE_MESSAGE_BYTES - 1] {
            let mut nearly = *secrets.release();
            nearly[flipped] ^= 0x01;
            assert_eq!(
                secrets.classify(&nearly),
                GateDecision::Unknown,
                "one wrong bit at index {flipped} must still be refused"
            );
        }
    }

    #[test]
    fn two_gates_never_share_a_release_message() {
        // Each prepared child gets its own pair, so a handle-holder for one
        // child cannot release another.
        assert_ne!(secrets().release(), secrets().release());
    }

    #[test]
    fn gate_secrets_debug_never_renders_either_message() {
        let rendered = format!("{:?}", secrets());
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains('['), "{rendered}");
    }

    #[test]
    fn activation_errors_never_render_secret_material() {
        let errors = [
            ActivationError::InvalidActivationToken,
            ActivationError::ActivationExpired,
            ActivationError::AlreadyActivated,
            ActivationError::AlreadyStopped,
        ];
        for error in errors {
            let rendered = error.to_string();
            assert!(!rendered.contains("token: "), "{rendered}");
            assert!(!rendered.contains("digest"), "{rendered}");
        }
    }
}
