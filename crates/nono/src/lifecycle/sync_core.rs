//! The lifecycle state and its one-shot gate effect, behind one lock.
//!
//! [`super::state::LifecycleState`] is a pure value: `apply` returns the next
//! state and mutates nothing. That is what makes it testable, and it is also
//! what makes it useless on its own to two parties racing for the same gate —
//! a caller that reads the state, decides, and then writes it back has a
//! read-modify-write with a window in the middle. [`SharedLifecycle`] closes
//! that window. It owns the only copy of the state a run has, and every
//! observation reaches it through a lock, so "which fact arrived first" has an
//! answer rather than a race.
//!
//! # Why the effect lives here and not at the call site
//!
//! Releasing the gate is not just a state change; it is a *write to the
//! child's gate descriptor*, and that write is what actually starts the
//! customer's program. Deciding "I won" under a lock and then performing the
//! write after unlocking would leave exactly the gap this module exists to
//! remove: two parties could each win a different decision — one the
//! activation, one the stop — and both reach for the same descriptor.
//!
//! So the win and the effect are the same critical section.
//! [`SharedLifecycle::try_begin_activate`] takes the release action as a
//! closure and runs it inside the lock, on the winning path only. The effect
//! is therefore executable **at most once for the life of the value**, across
//! any interleaving of activate, stop, expiry, and drop — not once per caller,
//! and not once per handle. A caller that keeps a copy of the
//! [`super::ActivationHandle`] cannot get a second run out of it, because the
//! second attempt never reaches the closure.
//!
//! The three-valued [`GateEffect`] is what makes stop and release exclusive
//! without making them the same thing: a stop *closes the gate to activation*
//! but still owes the child its abort message, so it reserves the write rather
//! than consuming it.
//!
//! # What this module is not
//!
//! It adds no transitions. Every mutation goes through
//! [`super::state::LifecycleState::apply`], so the legal-transition table has
//! exactly one definition and this file cannot quietly widen it. What it adds
//! is atomicity: the read, the decision, the write, and the effect happen with
//! no observable gap.
//!
//! # Loom
//!
//! Under `--cfg nono_loom` the lock is `loom::sync::Mutex` and the type is
//! exported publicly so `tests/loom_lifecycle.rs` can drive it from several
//! threads; under any ordinary build it is `std::sync::Mutex` and the type is
//! crate-internal. Nothing about the public API of the crate changes either
//! way.
//!
//! The cfg is spelled `nono_loom`, not the `loom` the loom README uses,
//! because `RUSTFLAGS` reaches every crate in the build: `--cfg loom` makes
//! `tokio` compile out `tokio::net`, which `hyper-util` — reached from here
//! through `sigstore-verify` — then fails to find. The name is the only
//! difference; the wiring is the one the README prescribes.

use super::state::{LifecycleOp, LifecycleState, TransitionError};
use sync::{Mutex, MutexGuard};

/// The lock, from `loom` when Loom is driving and from `std` otherwise.
///
/// Only the mutex is shimmed because only the mutex is used here; the model
/// harness reaches for `loom::sync::Arc` and `loom::sync::atomic` directly,
/// since those appear in the tests rather than in this file.
mod sync {
    #[cfg(nono_loom)]
    pub(super) use loom::sync::{Mutex, MutexGuard};
    #[cfg(not(nono_loom))]
    pub(super) use std::sync::{Mutex, MutexGuard};
}

/// One run's state, and the single gate write that belongs to it.
///
/// Shared by reference: every operation takes `&self`, so a future supervisor
/// can hold this in an `Arc` across threads without any of the callers below
/// changing shape.
pub struct SharedLifecycle {
    core: Mutex<Core>,
}

/// The two things that must move together, and never separately.
struct Core {
    state: LifecycleState,
    gate: GateEffect,
}

/// What has already happened to the one write the gate descriptor gets.
///
/// Three values, not two, because "the gate can never open again" and "the
/// gate has been written" are different facts. A stop establishes the first
/// and still owes the child the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateEffect {
    /// Nothing has been written and activation may still claim the write.
    Open,
    /// A stop, an expiry, or a supervisor loss has ruled out release; the
    /// abort write is still owed to whoever established that.
    ClosedToActivation,
    /// The one write has happened. Nothing may write again.
    Spent,
}

impl GateEffect {
    /// Rule out release without consuming the write.
    ///
    /// Saturating rather than assigning: a gate that is already `Spent` must
    /// not be walked backwards into a state where something could write again.
    fn close_to_activation(self) -> Self {
        match self {
            Self::Open => Self::ClosedToActivation,
            other => other,
        }
    }
}

/// A state change that actually happened.
///
/// Returned instead of just the new state so the caller can report the pair it
/// observed — the event sink wants both halves, and re-reading `state()` to
/// recover the `from` would be reading a value another thread may already have
/// moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    /// The state the machine was in.
    pub from: LifecycleState,
    /// The state this op moved it to.
    pub to: LifecycleState,
}

impl SharedLifecycle {
    /// Start from a known state.
    ///
    /// The gate write is unclaimed. Callers that start past the gate — an
    /// activated run, say — are held back by the state machine instead:
    /// `BeginActivate` is reachable only from
    /// [`LifecycleState::Prepared`].
    pub fn new(state: LifecycleState) -> Self {
        Self {
            core: Mutex::new(Core {
                state,
                gate: GateEffect::Open,
            }),
        }
    }

    /// Where the run is right now.
    ///
    /// A snapshot, not a reservation: by the time the caller acts on it another
    /// party may have moved the machine. Anything that must be atomic with the
    /// read belongs in one of the operations below.
    pub fn state(&self) -> LifecycleState {
        self.locked().state
    }

    /// Record an observed fact.
    ///
    /// The general case: everything that is not the activation claim or a stop
    /// request. The gate is untouched, because none of these facts decide who
    /// may write to it.
    ///
    /// # Errors
    ///
    /// [`TransitionError`] if `op` is not legal in the state this call found,
    /// naming that state. The machine is left exactly as it was.
    pub fn mark(&self, op: LifecycleOp) -> Result<Transition, TransitionError> {
        self.locked().apply(op)
    }

    /// Request a stop, closing the gate to activation in the same breath.
    ///
    /// The state machine already refuses `BeginActivate` from `Stopping`, so
    /// this could be [`Self::mark`]. It is not, because the state machine
    /// guards *transitions* and this also has to guard the *write*: after a
    /// stop wins, no interleaving may still reach the release effect. The
    /// abort message the stopping caller owes the child is reserved rather
    /// than consumed — [`Self::claim_gate_close`] performs it.
    ///
    /// # Errors
    ///
    /// [`TransitionError`] if a stop is not legal in the state this call
    /// found. A refused stop closes nothing: the gate stays exactly as it was,
    /// because a caller who was not allowed to stop the run has no business
    /// shutting someone else's gate.
    pub fn begin_stop(&self) -> Result<Transition, TransitionError> {
        let mut core = self.locked();
        let change = core.apply(LifecycleOp::BeginStop)?;
        core.gate = core.gate.close_to_activation();
        Ok(change)
    }

    /// Claim the activation, and release the gate if the claim wins.
    ///
    /// The compare-and-swap the whole gate rests on. Exactly one call, for the
    /// life of this value, can leave here with `release` having run: the state
    /// move out of [`LifecycleState::Prepared`] and the gate claim happen
    /// under one lock, before the closure is called and before any other party
    /// can observe either.
    ///
    /// `release` runs *inside* the lock. It must do the gate write and nothing
    /// else — in particular it must not call back into this value, which would
    /// deadlock, and it must not block on the child, which would hold every
    /// other observation up behind it. The status-descriptor read that follows
    /// a release deliberately happens after this returns.
    ///
    /// A panic in `release` poisons the lock, which this type recovers from:
    /// the claim was recorded before the closure ran, so a half-performed
    /// release can never be retried by a later caller.
    ///
    /// # Errors
    ///
    /// [`TransitionError`] naming the state this call found, when activation
    /// is not reachable from it — because someone else already claimed it,
    /// because the run was stopped, or because the gate write was already
    /// committed elsewhere. In every case `release` is not called.
    pub fn try_begin_activate<T>(
        &self,
        release: impl FnOnce() -> T,
    ) -> Result<(Transition, T), TransitionError> {
        let mut core = self.locked();
        if core.gate != GateEffect::Open {
            // Unreachable while `Prepared` and `Open` agree, which they do on
            // every path here; reported rather than asserted because a library
            // does not get to panic on its own invariants. The message the
            // caller renders — the gate is not open in this state — is true
            // whichever half refused.
            return Err(TransitionError {
                from: core.state,
                op: LifecycleOp::BeginActivate,
            });
        }
        let change = core.apply(LifecycleOp::BeginActivate)?;
        core.gate = GateEffect::Spent;
        Ok((change, release()))
    }

    /// Claim the gate write for a close or an abort.
    ///
    /// Returns `true` for the one caller that gets it. Every later caller —
    /// a second stop path, an expiry, the drop that follows either — gets
    /// `false` and must write nothing. Unlike [`Self::begin_stop`] this moves
    /// no state: closing the gate is not an observation about the child.
    pub fn claim_gate_close(&self) -> bool {
        let mut core = self.locked();
        if core.gate == GateEffect::Spent {
            return false;
        }
        core.gate = GateEffect::Spent;
        true
    }

    /// Take the lock, recovering from a poisoned one.
    ///
    /// Poisoning here means a caller's effect closure panicked. The core is
    /// still consistent — the claim and the state move are committed before
    /// any closure runs — and refusing to hand the state back would turn one
    /// caller's panic into a run nobody can stop or reap. Recovering is the
    /// fail-secure choice: the gate stays `Spent`.
    fn locked(&self) -> MutexGuard<'_, Core> {
        match self.core.lock() {
            Ok(core) => core,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Core {
    /// The one place the state moves. Nothing in this module writes
    /// `self.state` except through [`LifecycleState::apply`].
    fn apply(&mut self, op: LifecycleOp) -> Result<Transition, TransitionError> {
        let from = self.state;
        let to = from.apply(op)?;
        self.state = to;
        Ok(Transition { from, to })
    }
}

impl std::fmt::Debug for SharedLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let core = self.locked();
        f.debug_struct("SharedLifecycle")
            .field("state", &core.state)
            .field("gate", &core.gate)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use LifecycleOp as Op;
    use LifecycleState as S;

    /// A shared core at the gate, with the release write unclaimed.
    fn prepared() -> SharedLifecycle {
        SharedLifecycle::new(S::Prepared)
    }

    /// Count how many times an effect closure actually ran.
    #[derive(Default)]
    struct Effects(std::cell::Cell<usize>);

    impl Effects {
        fn run(&self) {
            self.0.set(self.0.get().saturating_add(1));
        }

        fn count(&self) -> usize {
            self.0.get()
        }
    }

    #[test]
    fn the_first_activation_wins_and_runs_the_effect_once() {
        let shared = prepared();
        let effects = Effects::default();

        let first = shared.try_begin_activate(|| effects.run());
        assert_eq!(
            first.map(|(change, ())| change),
            Ok(Transition {
                from: S::Prepared,
                to: S::Activating
            })
        );
        assert_eq!(effects.count(), 1);
        assert_eq!(shared.state(), S::Activating);
    }

    #[test]
    fn a_second_activation_never_reaches_the_effect() {
        let shared = prepared();
        let effects = Effects::default();

        assert!(shared.try_begin_activate(|| effects.run()).is_ok());
        let second = shared.try_begin_activate(|| effects.run());

        assert_eq!(
            second.map(|(change, ())| change),
            Err(TransitionError {
                from: S::Activating,
                op: Op::BeginActivate
            })
        );
        assert_eq!(
            effects.count(),
            1,
            "the release write must be executable at most once"
        );
    }

    #[test]
    fn a_stop_closes_the_gate_before_any_activation_can_reach_it() {
        let shared = prepared();
        let effects = Effects::default();

        assert_eq!(
            shared.begin_stop(),
            Ok(Transition {
                from: S::Prepared,
                to: S::Stopping
            })
        );
        let refused = shared.try_begin_activate(|| effects.run());

        assert_eq!(
            refused.map(|(change, ())| change),
            Err(TransitionError {
                from: S::Stopping,
                op: Op::BeginActivate
            })
        );
        assert_eq!(
            effects.count(),
            0,
            "the release write must never run after a stop"
        );
    }

    #[test]
    fn a_stop_reserves_the_abort_write_rather_than_consuming_it() {
        let shared = prepared();
        assert!(shared.begin_stop().is_ok());
        assert!(
            shared.claim_gate_close(),
            "the stopping caller still owes the child its abort message"
        );
        assert!(
            !shared.claim_gate_close(),
            "and only that caller may write it"
        );
    }

    #[test]
    fn a_refused_stop_leaves_the_gate_alone() {
        // The run already ended; this caller has no claim on anything.
        let shared = SharedLifecycle::new(S::Exited);
        assert_eq!(
            shared.begin_stop(),
            Err(TransitionError {
                from: S::Exited,
                op: Op::BeginStop
            })
        );
        assert!(
            shared.claim_gate_close(),
            "a refused stop must not consume someone else's write"
        );
    }

    #[test]
    fn a_released_gate_is_never_written_again() {
        let shared = prepared();
        let effects = Effects::default();
        assert!(shared.try_begin_activate(|| effects.run()).is_ok());
        assert!(
            !shared.claim_gate_close(),
            "an abort must not follow a release onto the same descriptor"
        );
    }

    #[test]
    fn a_stop_after_a_release_does_not_reopen_the_write() {
        let shared = prepared();
        let effects = Effects::default();
        assert!(shared.try_begin_activate(|| effects.run()).is_ok());
        assert!(shared.mark(Op::ExecObserved).is_ok());
        assert!(
            shared.begin_stop().is_ok(),
            "a running child can be stopped"
        );
        assert!(
            !shared.claim_gate_close(),
            "the gate write was spent at release and cannot come back"
        );
    }

    #[test]
    fn the_gate_write_is_claimed_exactly_once_without_a_stop() {
        // The drop path: no state change, one abort write, and no second one.
        let shared = prepared();
        assert!(shared.claim_gate_close());
        assert!(!shared.claim_gate_close());
        assert_eq!(shared.state(), S::Prepared, "closing is not an observation");
    }

    #[test]
    fn a_claimed_gate_refuses_activation_even_from_prepared() {
        let shared = prepared();
        let effects = Effects::default();
        assert!(shared.claim_gate_close());

        let refused = shared.try_begin_activate(|| effects.run());
        assert_eq!(
            refused.map(|(change, ())| change),
            Err(TransitionError {
                from: S::Prepared,
                op: Op::BeginActivate
            })
        );
        assert_eq!(effects.count(), 0);
        assert_eq!(shared.state(), S::Prepared, "a refused claim moves nothing");
    }

    #[test]
    fn mark_reports_both_halves_of_the_change() {
        let shared = SharedLifecycle::new(S::Running);
        assert_eq!(
            shared.mark(Op::ChildExited),
            Ok(Transition {
                from: S::Running,
                to: S::Exited
            })
        );
        assert_eq!(shared.state(), S::Exited);
    }

    #[test]
    fn a_refused_mark_leaves_the_state_where_it_was() {
        let shared = SharedLifecycle::new(S::Exited);
        assert_eq!(
            shared.mark(Op::ChildExited),
            Err(TransitionError {
                from: S::Exited,
                op: Op::ChildExited
            })
        );
        assert_eq!(shared.state(), S::Exited);
    }

    #[test]
    fn a_second_cleanup_confirmation_is_refused() {
        let shared = SharedLifecycle::new(S::Stopped);
        assert!(shared.mark(Op::CleanupConfirmed).is_ok());
        assert_eq!(
            shared.mark(Op::CleanupConfirmed),
            Err(TransitionError {
                from: S::CleanupVerified,
                op: Op::CleanupConfirmed
            })
        );
    }

    #[test]
    fn debug_names_the_state_and_the_gate() {
        let shared = prepared();
        let rendered = format!("{shared:?}");
        assert!(rendered.contains("Prepared"), "{rendered}");
        assert!(rendered.contains("Open"), "{rendered}");
    }
}
