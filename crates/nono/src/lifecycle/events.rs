//! Lifecycle events and the consumer-implemented sink.
//!
//! The library emits facts; it never routes them anywhere. A consumer supplies
//! an [`EventSink`] and decides what an event means. Every event carries an
//! [`Observation`] label so a consumer can tell a fact the platform showed us
//! from one we rebuilt after the fact — and events the platform cannot show are
//! **absent**, never synthesized to fill a gap. There is no `KernelDenial`
//! variant in this vocabulary because this library does not observe kernel
//! denials; [`super::SupportReport::event_observation`] says so in the same
//! words, in machine-readable form.
//!
//! # The shape of an event
//!
//! [`LifecycleEvent`] is an envelope — who, when, how faithfully — around a
//! closed [`LifecycleEventKind`]:
//!
//! | Field | What it is |
//! |---|---|
//! | `session_id` | the run this is about. `None` only for a moment before a session exists, which nothing in this slice reaches |
//! | `generation` | which preparation of that session |
//! | `seq` | the run's own counter, described below |
//! | `observed_at` | wall clock read at the moment of observation |
//! | `identity` | the child's pid and the facts that make it non-reusable, once there is a child |
//! | `observation` | witnessed, or reconstructed |
//! | `what` | the fact itself |
//!
//! # What `seq` guarantees, and what it does not
//!
//! `seq` counts from zero per *sandbox instance* — one counter for a run, kept
//! across the handoff from [`super::PreparedSandbox`] to
//! [`super::ActivatedSandbox`], so a consumer sees one unbroken sequence for
//! the whole run. Numbers are allocated by a single atomic, so the allocation
//! order is total: **`seq` is the ordering authority.**
//!
//! `observed_at` is not. It is a wall clock, and a wall clock can step
//! backwards; it is there so a consumer can correlate with its own logs, not so
//! it can sort. Two events emitted from different threads may also *arrive* at
//! a sink out of `seq` order — the counter is what puts them back in order.
//!
//! # Where events are emitted
//!
//! Always after the fact they report, and always outside the shared lifecycle
//! core's lock: a sink is consumer code, it may do anything including calling
//! back in, and the gate's single-use guarantee depends on that lock. The
//! consequence — a supervisor that dies between the fact and the emit reports
//! one event fewer — is stated rather than hidden, and is the same reason
//! [`super::SessionStore::recover`] reconciles instead of believing a record.

use super::cleanup::CleanupVerification;
use super::exit::{ExitOutcome, SupervisorStage};
use super::identity::ProcessIdentity;
use super::state::LifecycleState;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;
use uuid::Uuid;

/// How faithfully an event reflects what the platform showed us.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    /// Observed as it happened, from a syscall result or descriptor state.
    DirectlyObserved,
    /// Rebuilt after the fact, e.g. from a durable session record after a
    /// restart. Ordering and timing are inferred, not witnessed.
    Reconstructed,
}

/// What an activation attempt did.
///
/// Carries **no token material of any kind**: not the token, not its digest,
/// not the gate's release or abort nonce. An event is the thing most likely to
/// be written to a log, forwarded to a collector, or pasted into an issue, and
/// a single copy of the token is a start button for a held child. The refusals
/// name the *check* that refused, which is what a consumer needs, and never the
/// value that failed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ActivationOutcome {
    /// The attempt won the gate's single-use claim. The release write happened
    /// inside that claim; whether the child then reached `execve` is a separate
    /// fact ([`LifecycleEventKind::ExecObserved`]).
    Accepted,
    /// The handle named a different session.
    RefusedWrongSession,
    /// The handle named a different generation of this session.
    RefusedWrongGeneration,
    /// The gate was no longer open — already activated, stopped, failed, or
    /// lost to a concurrent claim.
    RefusedGateClosed {
        /// The state the machine was in when it refused.
        state: LifecycleState,
    },
    /// The gate's deadline had passed. Checked before the token, so a late
    /// attempt with a wrong token is still reported as expiry: the deadline is
    /// a property of the gate, not a judgement about the caller.
    RefusedExpired,
    /// The token did not match. The comparison is constant-time and the value
    /// is not reported.
    RefusedInvalidToken,
}

/// Something the lifecycle observed.
///
/// A closed enum: these are the facts this library can witness, and a consumer
/// that matches all of them today must keep compiling — but must also be made
/// to revisit its handling when the set changes, which a `#[non_exhaustive]`
/// catch-all would silently prevent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LifecycleEventKind {
    /// The state machine moved. Emitted for every transition, after it
    /// happened.
    StateChanged {
        /// State before the transition.
        from: LifecycleState,
        /// State after the transition.
        to: LifecycleState,
    },

    /// A child is about to be forked for this session. The last event with no
    /// identity: there is no child yet.
    PrepareStarted,

    /// The child applied the platform sandbox to itself.
    ///
    /// Rests on the trusted child's own status record, which it writes *after*
    /// the sandbox is applied and never before — so this and
    /// [`Self::GateReady`] are two halves of one observation, and both are
    /// emitted when that record arrives.
    SandboxApplied,

    /// The child is blocked at the activation gate. Nothing of the customer's
    /// program has run.
    GateReady,

    /// An activation was attempted, and this is what happened.
    ActivationAttempted {
        /// Accepted, or the check that refused. Never any token material.
        outcome: ActivationOutcome,
    },

    /// The release message was written to the gate. Emitted only by the
    /// activation that won the single-use claim.
    Released,

    /// The status descriptor reached EOF with no record.
    ///
    /// The strongest statement the descriptor protocol supports, and
    /// deliberately not "the program started": a child killed between the
    /// release and `execve` closes the same descriptor the same way. See
    /// [`super::ActivationObservation`].
    ExecObserved,

    /// The child's death was observed by `waitpid`, on a path that was not a
    /// stop.
    ChildExited {
        /// What `waitpid` — or the child's own status record — reported.
        outcome: ExitOutcome,
    },

    /// A stop was requested. The signal is not the result; [`Self::StopObserved`]
    /// is.
    StopRequested,

    /// The stop could not kill by cgroup, and fell back to the process group
    /// alone.
    ///
    /// Emitted rather than swallowed because it is a downgrade in what the stop
    /// can reach: the process-group kill misses a descendant that called
    /// `setsid`, and the cgroup kill is the thing that does not. A caller that
    /// sees this knows the run was contained by the escapable mechanism.
    StopCgroupFailed {
        /// What went wrong, in an operator's terms.
        detail: String,
    },

    /// The death that a stop asked for was observed.
    StopObserved {
        /// What the reap reported. A `SIGKILL` death is
        /// [`ExitOutcome::Signaled`], and a program that exited on its own
        /// first is reported as the exit it actually had.
        outcome: ExitOutcome,
    },

    /// The gate was closed without releasing the child: a stop, an expiry, a
    /// failed activation, or a dropped handle.
    GateAborted,

    /// The supervisor's own machinery failed, so nothing is claimed about the
    /// child at this point.
    SupervisorFailure {
        /// Which supervisor step failed.
        stage: SupervisorStage,
        /// Platform error number captured at that point.
        errno: i32,
    },

    /// Cleanup verification produced a verdict. Emitted for every verdict, not
    /// only for a proof of absence: "something is still there" is exactly as
    /// much a fact as "nothing is".
    CleanupVerdict {
        /// The verdict, with its typed evidence.
        verdict: CleanupVerification,
    },

    /// A durable session record was written and `fsync`ed.
    RecordPersisted {
        /// The schema the record was written by. See
        /// [`super::CURRENT_SCHEMA_VERSION`].
        schema_version: u32,
    },
}

/// One observed fact, with everything needed to place it.
///
/// Built only by the library. Consumers read it; see the module documentation
/// for the envelope's fields and `docs/lifecycle/lifecycle-event-v1.md` for the
/// field table and a golden example.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvent {
    /// The session this is about.
    ///
    /// `Option` because the type must be able to describe a moment before a
    /// session exists; nothing in this slice emits one, so in practice this is
    /// always `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_id: Option<Uuid>,
    /// Which preparation of that session.
    generation: u64,
    /// This run's own counter. See the module docs: `seq` is the ordering
    /// authority, `observed_at` is not.
    seq: u64,
    /// Wall clock read at the moment of observation.
    observed_at: SystemTime,
    /// The child, once there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<ProcessIdentity>,
    /// Whether the fact was witnessed or reconstructed.
    observation: Observation,
    /// The fact.
    what: LifecycleEventKind,
}

impl LifecycleEvent {
    /// The session this event is about.
    #[must_use]
    pub fn session_id(&self) -> Option<Uuid> {
        self.session_id
    }

    /// Which preparation of the session.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// This run's own event counter.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The wall clock read when the fact was observed.
    #[must_use]
    pub fn observed_at(&self) -> SystemTime {
        self.observed_at
    }

    /// The child's identity, once there is a child.
    #[must_use]
    pub fn identity(&self) -> Option<&ProcessIdentity> {
        self.identity.as_ref()
    }

    /// Whether the fact was witnessed or reconstructed.
    #[must_use]
    pub fn observation(&self) -> Observation {
        self.observation
    }

    /// The fact itself.
    #[must_use]
    pub fn what(&self) -> &LifecycleEventKind {
        &self.what
    }

    /// Build an event from parts, for tests that need a fixed one.
    ///
    /// Test-only and deliberately not public: outside tests an event is always
    /// *emitted*, with its sequence number allocated by the run's own counter
    /// and its clock read at the moment of observation, so that nothing can
    /// claim a position or a time it did not have. The durable record's golden
    /// example needs a value that does not move, which is the one case that
    /// cannot come from an emitter.
    #[cfg(test)]
    pub(crate) fn from_parts(
        session_id: Option<Uuid>,
        generation: u64,
        seq: u64,
        observed_at: SystemTime,
        identity: Option<ProcessIdentity>,
        observation: Observation,
        what: LifecycleEventKind,
    ) -> Self {
        Self {
            session_id,
            generation,
            seq,
            observed_at,
            identity,
            observation,
            what,
        }
    }
}

/// Consumer-supplied event receiver.
///
/// `Send + Sync` because the supervisor emits from whichever thread observed
/// the fact. Implementations must not block or panic: an emit happens on the
/// path that is also driving a child process, and the library has no way to
/// recover a sink's failure.
pub trait EventSink: Send + Sync {
    /// Receive one event. Called by reference so the library keeps ownership
    /// and a sink can cheaply ignore what it does not care about.
    fn emit(&self, event: &LifecycleEvent);
}

/// The emitting side of the vocabulary: one per run, shared by its handles.
///
/// Owns the `seq` counter, which is why it is shared by `Arc` rather than
/// copied: the [`super::PreparedSandbox`] and the
/// [`super::ActivatedSandbox`] it hands off to are two handles onto *one* run,
/// and two counters would restart the sequence in the middle of it.
///
/// A run with no sink emits nothing and allocates no sequence numbers: the
/// counter exists to order what a consumer sees, and a consumer that asked for
/// nothing sees nothing.
pub(crate) struct EventEmitter {
    sink: Option<Arc<dyn EventSink>>,
    session_id: Uuid,
    generation: u64,
    /// Learned once, after the fork. Before that there is no child to name.
    identity: OnceLock<ProcessIdentity>,
    seq: AtomicU64,
}

impl EventEmitter {
    /// A run's emitter. `sink` is whatever the plan carried, which may be
    /// nothing.
    pub(crate) fn new(sink: Option<Arc<dyn EventSink>>, session_id: Uuid, generation: u64) -> Self {
        Self {
            sink,
            session_id,
            generation,
            identity: OnceLock::new(),
            seq: AtomicU64::new(0),
        }
    }

    /// Name the child, once it exists.
    ///
    /// Set once and never replaced: a run has one child, and an identity that
    /// could be overwritten would let a later event relabel an earlier one.
    pub(crate) fn set_identity(&self, identity: ProcessIdentity) {
        let _ = self.identity.set(identity);
    }

    /// Report a directly observed fact.
    pub(crate) fn emit(&self, what: LifecycleEventKind) {
        self.emit_with(what, Observation::DirectlyObserved);
    }

    /// Report a fact with an explicit fidelity label.
    pub(crate) fn emit_with(&self, what: LifecycleEventKind, observation: Observation) {
        let Some(sink) = &self.sink else {
            return;
        };
        // Allocated here, immediately before the hand-off, so the numbers a
        // sink sees have no gaps for events that were never emitted. Relaxed
        // is enough: a single atomic has a total modification order, which is
        // exactly the ordering `seq` promises.
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let event = LifecycleEvent {
            session_id: Some(self.session_id),
            generation: self.generation,
            seq,
            // Read here rather than passed in: "when did we observe it" and
            // "when did we report it" are the same instant for every emit in
            // this module, because every emit is the line after the
            // observation.
            observed_at: SystemTime::now(),
            identity: self.identity.get().cloned(),
            observation,
            what,
        };
        sink.emit(&event);
    }
}

/// How many events a detached supervisor keeps for a caller that is not there.
///
/// Bounded because the ring is written into the durable session record on every
/// transition, and a record that grew with the run would eventually exceed
/// [`super::MAX_RECORD_BYTES`] and stop being written at all. Thirty-two is
/// comfortably more than the longest run this vocabulary can produce end to end
/// (prepare through cleanup verification is under twenty), so in practice a
/// completed detached run keeps all of its events; a run that is activated,
/// stopped, and verified repeatedly is what drops the oldest.
pub const DETACHED_EVENT_RING_CAPACITY: usize = 32;

/// The sink a detached supervisor gives itself, because it has no caller to
/// give it one.
///
/// [`EventSink`] is caller-side by design: the consumer implements it and
/// decides what an event means. A detached supervisor has no consumer in the
/// process — that is what "detached" means — so events observed while nobody is
/// connected **cannot be delivered live**, and this library does not pretend
/// otherwise. What it does instead is keep the last
/// [`DETACHED_EVENT_RING_CAPACITY`] of them in the session record, so a caller
/// that reconnects can read what happened while it was away.
///
/// The fidelity of that is stated rather than implied: the ring is bounded and
/// drops its oldest entry, so a long-running session's early events are gone.
/// A consumer that needs every event needs to stay connected.
pub(crate) struct EventRing {
    events: Mutex<VecDeque<LifecycleEvent>>,
}

impl EventRing {
    /// An empty ring at [`DETACHED_EVENT_RING_CAPACITY`].
    pub(crate) fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(DETACHED_EVENT_RING_CAPACITY)),
        }
    }

    /// The ring's contents, oldest first.
    ///
    /// Copied out rather than borrowed: the caller is the durable record write,
    /// which must not hold this lock while it does filesystem I/O.
    pub(crate) fn snapshot(&self) -> Vec<LifecycleEvent> {
        self.locked().iter().cloned().collect()
    }

    /// Take the ring lock, recovering from a poisoned one.
    ///
    /// Same reasoning as everywhere else in this module: the ring is a plain
    /// value that is always left consistent, and refusing to hand it back would
    /// turn one panic into a supervisor that can no longer record anything.
    fn locked(&self) -> std::sync::MutexGuard<'_, VecDeque<LifecycleEvent>> {
        match self.events.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl EventSink for EventRing {
    fn emit(&self, event: &LifecycleEvent) {
        let mut guard = self.locked();
        if guard.len() >= DETACHED_EVENT_RING_CAPACITY {
            guard.pop_front();
        }
        guard.push_back(event.clone());
    }
}

impl std::fmt::Debug for EventRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventRing")
            .field("len", &self.locked().len())
            .field("capacity", &DETACHED_EVENT_RING_CAPACITY)
            .finish()
    }
}

/// Debug that names the run without pulling in the sink's own `Debug`.
impl std::fmt::Debug for EventEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventEmitter")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("identity", &self.identity.get())
            .field("seq", &self.seq.load(Ordering::Relaxed))
            .field("sink", &self.sink.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{AbsenceBasis, ExitOutcome, PreExecStage};
    use std::sync::Mutex;
    use std::time::Duration;

    /// The golden example locked by the schema doc.
    const GOLDEN_DOC: &str = include_str!("../../../../docs/lifecycle/lifecycle-event-v1.md");
    const GOLDEN_PATH: &str = "docs/lifecycle/lifecycle-event-v1.md";

    /// Test sink that records every event it is handed, in order.
    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<LifecycleEvent>>,
    }

    impl RecordingSink {
        fn recorded(&self) -> Vec<LifecycleEvent> {
            self.events
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or_default()
        }
    }

    impl EventSink for RecordingSink {
        fn emit(&self, event: &LifecycleEvent) {
            if let Ok(mut guard) = self.events.lock() {
                guard.push(event.clone());
            }
        }
    }

    fn emitter(sink: &Arc<RecordingSink>) -> EventEmitter {
        EventEmitter::new(Some(Arc::clone(sink) as Arc<dyn EventSink>), test_id(), 1)
    }

    fn test_id() -> Uuid {
        match Uuid::parse_str("019512f0-0000-7000-8000-000000000001") {
            Ok(id) => id,
            Err(_) => Uuid::nil(),
        }
    }

    fn state_changed(from: LifecycleState, to: LifecycleState) -> LifecycleEventKind {
        LifecycleEventKind::StateChanged { from, to }
    }

    /// No key that names key material, and no sequence, anywhere in a tree.
    fn assert_no_secret_shape(node: &serde_json::Value, whole: &serde_json::Value) {
        match node {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    for forbidden in ["token", "nonce", "secret", "digest"] {
                        assert!(
                            !key.to_lowercase().contains(forbidden),
                            "an activation event must have no {forbidden} field: {whole}"
                        );
                    }
                    assert_no_secret_shape(child, whole);
                }
            }
            serde_json::Value::Array(_) => {
                panic!("an activation event must carry no byte buffer: {whole}")
            }
            _ => {}
        }
    }

    /// The one event the schema doc shows.
    fn golden_event() -> LifecycleEvent {
        LifecycleEvent {
            session_id: Some(test_id()),
            generation: 1,
            seq: 4,
            observed_at: SystemTime::UNIX_EPOCH + Duration::from_millis(1_755_000_000_123),
            identity: Some(ProcessIdentity::from_parts(
                4242,
                Some(1_755_000_000_000_000),
                Some("1754990000.000000".to_string()),
            )),
            observation: Observation::DirectlyObserved,
            what: LifecycleEventKind::ActivationAttempted {
                outcome: ActivationOutcome::Accepted,
            },
        }
    }

    #[test]
    fn recording_sink_receives_events_in_order() {
        let sink = Arc::new(RecordingSink::default());
        let emitter = emitter(&sink);

        emitter.emit(state_changed(
            LifecycleState::Planning,
            LifecycleState::Preparing,
        ));
        emitter.emit(state_changed(
            LifecycleState::Preparing,
            LifecycleState::Prepared,
        ));

        let seen = sink.recorded();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0].what(),
            &state_changed(LifecycleState::Planning, LifecycleState::Preparing)
        );
        assert_eq!(
            seen[1].what(),
            &state_changed(LifecycleState::Preparing, LifecycleState::Prepared)
        );
    }

    #[test]
    fn seq_counts_from_zero_and_never_repeats() {
        let sink = Arc::new(RecordingSink::default());
        let emitter = emitter(&sink);
        for _ in 0..5 {
            emitter.emit(LifecycleEventKind::GateAborted);
        }
        let seen: Vec<u64> = sink.recorded().iter().map(LifecycleEvent::seq).collect();
        assert_eq!(seen, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn one_shared_emitter_keeps_one_sequence_across_a_handoff() {
        // The property the `Arc` exists for: a run that changes hands mid-flight
        // must not restart its own numbering, or a consumer cannot tell a
        // handoff from a second run.
        let sink = Arc::new(RecordingSink::default());
        let first = Arc::new(emitter(&sink));
        let second = Arc::clone(&first);

        first.emit(LifecycleEventKind::GateReady);
        second.emit(LifecycleEventKind::Released);
        first.emit(LifecycleEventKind::ExecObserved);

        let seen: Vec<u64> = sink.recorded().iter().map(LifecycleEvent::seq).collect();
        assert_eq!(seen, vec![0, 1, 2]);
    }

    #[test]
    fn an_emitter_without_a_sink_emits_nothing_and_allocates_nothing() {
        let emitter = EventEmitter::new(None, test_id(), 1);
        emitter.emit(LifecycleEventKind::PrepareStarted);
        emitter.emit(LifecycleEventKind::GateReady);
        assert_eq!(emitter.seq.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn the_identity_appears_from_the_moment_it_is_known() {
        let sink = Arc::new(RecordingSink::default());
        let emitter = emitter(&sink);

        emitter.emit(LifecycleEventKind::PrepareStarted);
        emitter.set_identity(ProcessIdentity::from_parts(7, Some(1), None));
        emitter.emit(LifecycleEventKind::GateReady);

        let seen = sink.recorded();
        assert_eq!(
            seen.first().and_then(LifecycleEvent::identity),
            None,
            "there is no child to name before the fork"
        );
        assert_eq!(
            seen.get(1)
                .and_then(LifecycleEvent::identity)
                .map(ProcessIdentity::pid),
            Some(7)
        );
    }

    #[test]
    fn an_identity_is_never_relabelled() {
        let sink = Arc::new(RecordingSink::default());
        let emitter = emitter(&sink);
        emitter.set_identity(ProcessIdentity::from_parts(7, Some(1), None));
        emitter.set_identity(ProcessIdentity::from_parts(9, Some(2), None));
        emitter.emit(LifecycleEventKind::GateReady);

        assert_eq!(
            sink.recorded()
                .first()
                .and_then(LifecycleEvent::identity)
                .map(ProcessIdentity::pid),
            Some(7)
        );
    }

    #[test]
    fn every_event_carries_the_session_and_a_wall_clock() {
        let sink = Arc::new(RecordingSink::default());
        let emitter = emitter(&sink);
        let before = SystemTime::now();
        emitter.emit(LifecycleEventKind::PrepareStarted);
        let after = SystemTime::now();

        let Some(event) = sink.recorded().into_iter().next() else {
            panic!("the sink recorded nothing");
        };
        assert_eq!(event.session_id(), Some(test_id()));
        assert_eq!(event.generation(), 1);
        assert!(event.observed_at() >= before && event.observed_at() <= after);
        assert_eq!(event.observation(), Observation::DirectlyObserved);
    }

    #[test]
    fn sink_is_usable_behind_a_shared_trait_object() {
        let sink = Arc::new(RecordingSink::default());
        let erased: Arc<dyn EventSink> = sink.clone();
        let emitter = EventEmitter::new(Some(erased), test_id(), 1);

        emitter.emit(state_changed(
            LifecycleState::Activating,
            LifecycleState::Running,
        ));

        assert_eq!(sink.recorded().len(), 1);
    }

    #[test]
    fn reconstructed_events_are_labelled_distinctly() {
        let sink = Arc::new(RecordingSink::default());
        let emitter = emitter(&sink);
        emitter.emit(state_changed(
            LifecycleState::Running,
            LifecycleState::Exited,
        ));
        emitter.emit_with(
            state_changed(LifecycleState::Running, LifecycleState::Exited),
            Observation::Reconstructed,
        );

        let seen = sink.recorded();
        assert_eq!(
            seen.first().map(LifecycleEvent::observation),
            Some(Observation::DirectlyObserved)
        );
        assert_eq!(
            seen.get(1).map(LifecycleEvent::observation),
            Some(Observation::Reconstructed)
        );
        assert_ne!(seen.first(), seen.get(1));
    }

    #[test]
    fn no_activation_outcome_can_carry_token_material() -> Result<(), serde_json::Error> {
        // The structural lock on the one payload that touches the gate's
        // secrets. Every refusal names the *check*; none of them can name the
        // value that failed it, and this fails the moment a field is added
        // that could.
        let outcomes = [
            ActivationOutcome::Accepted,
            ActivationOutcome::RefusedWrongSession,
            ActivationOutcome::RefusedWrongGeneration,
            ActivationOutcome::RefusedGateClosed {
                state: LifecycleState::Stopped,
            },
            ActivationOutcome::RefusedExpired,
            ActivationOutcome::RefusedInvalidToken,
        ];
        for outcome in outcomes {
            let value = serde_json::to_value(LifecycleEventKind::ActivationAttempted { outcome })?;
            // Every *key* in the tree is a fixed name of this vocabulary, and
            // no node is a sequence. A field called token, nonce, digest, or
            // secret is the failure this locks out; so is any array, because
            // every secret in this module is a fixed-size array of `u8` — the
            // activation token, its digest, and the gate's release and abort
            // nonces. Checked on *keys and shapes*, not on values: the variant
            // named `refused_invalid_token` is a value, and forbidding that
            // spelling would be a check on prose.
            assert_no_secret_shape(&value, &value);
            // And nothing that could *be* 16 or 32 bytes rendered as text,
            // whatever it were called: no long hex or base64 run, in the serde
            // form or in the Debug one.
            for rendered in [serde_json::to_string(&value)?, format!("{outcome:?}")] {
                let longest = rendered
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .map(str::len)
                    .max()
                    .unwrap_or(0);
                assert!(
                    longest < 24,
                    "an activation event must carry no opaque blob: {rendered}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn an_event_round_trips_through_serde() -> Result<(), serde_json::Error> {
        let event = golden_event();
        let json = serde_json::to_string(&event)?;
        assert_eq!(serde_json::from_str::<LifecycleEvent>(&json)?, event);
        Ok(())
    }

    #[test]
    fn every_kind_round_trips_through_serde() -> Result<(), serde_json::Error> {
        let kinds = vec![
            state_changed(LifecycleState::Preparing, LifecycleState::Prepared),
            LifecycleEventKind::PrepareStarted,
            LifecycleEventKind::SandboxApplied,
            LifecycleEventKind::GateReady,
            LifecycleEventKind::ActivationAttempted {
                outcome: ActivationOutcome::Accepted,
            },
            LifecycleEventKind::Released,
            LifecycleEventKind::ExecObserved,
            LifecycleEventKind::ChildExited {
                outcome: ExitOutcome::Exited { code: 0 },
            },
            LifecycleEventKind::StopRequested,
            LifecycleEventKind::StopObserved {
                outcome: ExitOutcome::Signaled { signal: 9 },
            },
            LifecycleEventKind::GateAborted,
            LifecycleEventKind::SupervisorFailure {
                stage: SupervisorStage::Release,
                errno: 32,
            },
            LifecycleEventKind::CleanupVerdict {
                verdict: CleanupVerification::ConfirmedAbsent {
                    basis: AbsenceBasis::ReapedAndGroupEmpty { pgid: 4242 },
                },
            },
            LifecycleEventKind::RecordPersisted { schema_version: 1 },
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind)?;
            assert_eq!(
                serde_json::from_str::<LifecycleEventKind>(&json)?,
                kind,
                "{json}"
            );
        }
        Ok(())
    }

    #[test]
    fn event_serde_uses_stable_snake_case_names() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::to_string(&LifecycleEventKind::PrepareStarted)?,
            r#"{"kind":"prepare_started"}"#
        );
        assert_eq!(
            serde_json::to_string(&state_changed(
                LifecycleState::Prepared,
                LifecycleState::Activating
            ))?,
            r#"{"kind":"state_changed","from":"prepared","to":"activating"}"#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleEventKind::ActivationAttempted {
                outcome: ActivationOutcome::RefusedInvalidToken
            })?,
            r#"{"kind":"activation_attempted","outcome":{"outcome":"refused_invalid_token"}}"#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleEventKind::ChildExited {
                outcome: ExitOutcome::PreExecFailure {
                    stage: PreExecStage::Exec,
                    errno: 2
                }
            })?,
            r#"{"kind":"child_exited","outcome":{"kind":"pre_exec_failure","stage":"exec","errno":2}}"#
        );
        Ok(())
    }

    #[test]
    fn observation_serde_names_are_stable() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::to_string(&Observation::DirectlyObserved)?,
            "\"directly_observed\""
        );
        assert_eq!(
            serde_json::to_string(&Observation::Reconstructed)?,
            "\"reconstructed\""
        );
        Ok(())
    }

    #[test]
    fn the_golden_example_in_the_schema_doc_still_matches() -> Result<(), serde_json::Error> {
        let serialized = serde_json::to_string_pretty(&golden_event())?;
        assert_eq!(
            serialized,
            super::super::doc_golden_example(GOLDEN_DOC, GOLDEN_PATH),
            "the golden example in {GOLDEN_PATH} no longer matches a serialized LifecycleEvent; \
             the doc and the type must be updated together"
        );
        let parsed: LifecycleEvent = serde_json::from_str(&serialized)?;
        assert_eq!(parsed, golden_event());
        Ok(())
    }
}
