//! Deterministic concurrency proof for the activation gate.
//!
//! Every model below runs under [`loom::model`], which executes the closure
//! once per legal interleaving of its threads under the C11 memory model. An
//! assertion that holds here holds for *all* of those interleavings, not for
//! the one a stress test happened to hit.
//!
//! The subject is `nono::lifecycle::sync_core::SharedLifecycle`: the state
//! machine plus the one-shot gate write, behind one lock. Today's public API
//! hands out `&mut PreparedSandbox`, so Rust's aliasing rules alone forbid
//! these races — but the durable supervisor shares one run's state between the
//! caller and the thread watching the child, and at that point the guarantees
//! pinned here are the only thing standing between "exactly one activation"
//! and "one activation per thread that asked".
//!
//! Each model keeps to a single pair of racing operations. Loom's state space
//! is the product of the interleavings, so a model that tried to cover
//! activate *and* stop *and* cleanup at once would either exceed the branch
//! limit or quietly stop exploring.
//!
//! ```console
//! RUSTFLAGS='--cfg nono_loom' cargo test -p nono --test loom_lifecycle --release
//! ```
//!
//! The cfg is `nono_loom` rather than loom's own `loom` because `RUSTFLAGS`
//! reaches every crate in the build and `--cfg loom` breaks two of this
//! crate's transitive dependencies; see `lifecycle/sync_core.rs`.
#![cfg(nono_loom)]

use loom::sync::Arc;
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::thread;
use nono::lifecycle::sync_core::{SharedLifecycle, Transition};
use nono::lifecycle::{
    AbsenceBasis, CleanupVerification, LifecycleOp as Op, LifecycleState as S, RecoveryDecision,
    SupervisorPresence, SurvivorEvidence, TransitionError, reconcile,
};

/// What one racing thread came back with.
type Outcome = Result<Transition, TransitionError>;

/// Join a model thread, naming the failure instead of unwrapping it.
fn joined<T>(handle: thread::JoinHandle<T>) -> T {
    match handle.join() {
        Ok(value) => value,
        Err(_) => panic!("a model thread panicked"),
    }
}

/// Claim the gate, counting the release effect if this caller wins it.
///
/// The counter is incremented *inside* the effect closure, so it counts actual
/// executions of the gate write rather than successful claims. That is the
/// distinction the whole design rests on: a claim that won but never ran the
/// effect starts nothing, and an effect that ran twice starts the child twice.
fn activate(shared: &SharedLifecycle, releases: &AtomicUsize) -> Outcome {
    shared
        .try_begin_activate(|| {
            releases.fetch_add(1, Ordering::Relaxed);
        })
        .map(|(change, ())| change)
}

/// How many of these outcomes were the winner.
fn wins(outcomes: &[Outcome]) -> usize {
    outcomes.iter().filter(|outcome| outcome.is_ok()).count()
}

/// The refusal an outcome carries, or a failure naming what it carried instead.
fn refusal(outcome: Outcome) -> TransitionError {
    match outcome {
        Err(err) => err,
        Ok(change) => panic!("expected a typed refusal, got the win {change:?}"),
    }
}

// ---------------------------------------------------------------------------
// a. Two activations race. Exactly one may ever win, and the gate is written
//    exactly once.
// ---------------------------------------------------------------------------

#[test]
fn two_racing_activations_leave_exactly_one_winner_and_one_release() {
    loom::model(|| {
        let shared = Arc::new(SharedLifecycle::new(S::Prepared));
        let releases = Arc::new(AtomicUsize::new(0));

        let racers: Vec<_> = (0..2)
            .map(|_| {
                let shared = Arc::clone(&shared);
                let releases = Arc::clone(&releases);
                thread::spawn(move || activate(&shared, &releases))
            })
            .collect();
        let outcomes: Vec<Outcome> = racers.into_iter().map(joined).collect();

        assert_eq!(wins(&outcomes), 1, "two activations both won: {outcomes:?}");
        assert_eq!(
            releases.load(Ordering::Relaxed),
            1,
            "the gate write must happen exactly once: {outcomes:?}"
        );
        for outcome in outcomes {
            match outcome {
                Ok(change) => assert_eq!(
                    change,
                    Transition {
                        from: S::Prepared,
                        to: S::Activating
                    }
                ),
                // The loser is told which state refused it, not merely that
                // something went wrong.
                Err(err) => assert_eq!(
                    err,
                    TransitionError {
                        from: S::Activating,
                        op: Op::BeginActivate
                    }
                ),
            }
        }
        assert_eq!(shared.state(), S::Activating);
    });
}

// ---------------------------------------------------------------------------
// b. An activation races a stop. Either order is legal; what is not legal is
//    a release after the stop won, or two winners.
// ---------------------------------------------------------------------------

#[test]
fn an_activation_racing_a_stop_never_both_wins_and_releases() {
    loom::model(|| {
        let shared = Arc::new(SharedLifecycle::new(S::Prepared));
        let releases = Arc::new(AtomicUsize::new(0));

        let activating = {
            let shared = Arc::clone(&shared);
            let releases = Arc::clone(&releases);
            thread::spawn(move || activate(&shared, &releases))
        };
        let stopping = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || shared.begin_stop())
        };

        let activated = joined(activating);
        let stopped = joined(stopping);
        let released = releases.load(Ordering::Relaxed);

        assert_eq!(
            wins(&[activated, stopped]),
            1,
            "activate and stop both won: {activated:?} / {stopped:?}"
        );

        if let Ok(change) = activated {
            // The activation got there first: it released, and the stop is
            // refused by the state its win produced.
            assert_eq!(
                change,
                Transition {
                    from: S::Prepared,
                    to: S::Activating
                }
            );
            assert_eq!(released, 1, "the winner must have released the gate");
            assert_eq!(
                refusal(stopped),
                TransitionError {
                    from: S::Activating,
                    op: Op::BeginStop
                }
            );
            assert_eq!(shared.state(), S::Activating);
        } else {
            // The stop got there first. This is the invariant with teeth: no
            // interleaving may still reach the release write.
            assert_eq!(
                stopped,
                Ok(Transition {
                    from: S::Prepared,
                    to: S::Stopping
                })
            );
            assert_eq!(
                released, 0,
                "the gate was released after a stop had already won"
            );
            assert_eq!(
                refusal(activated),
                TransitionError {
                    from: S::Stopping,
                    op: Op::BeginActivate
                }
            );
            assert_eq!(shared.state(), S::Stopping);
        }
    });
}

// ---------------------------------------------------------------------------
// c. The supervisor observes the child die while a stop is requested. One
//    death must record one fact.
// ---------------------------------------------------------------------------

#[test]
fn a_death_and_a_stop_request_never_both_record_the_same_death() {
    loom::model(|| {
        let shared = Arc::new(SharedLifecycle::new(S::Running));

        let waiting = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || shared.mark(Op::ChildExited))
        };
        let stopping = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || shared.begin_stop())
        };

        let exited = joined(waiting);
        let stopped = joined(stopping);

        assert_eq!(
            wins(&[exited, stopped]),
            1,
            "one death recorded two facts: {exited:?} / {stopped:?}"
        );

        if exited.is_ok() {
            assert_eq!(shared.state(), S::Exited);
            assert_eq!(
                refusal(stopped),
                TransitionError {
                    from: S::Exited,
                    op: Op::BeginStop
                }
            );
            // The reaping observation that belongs to a stop cannot be
            // recorded for a death that was already filed as a plain exit.
            assert_eq!(
                shared.mark(Op::StopObserved),
                Err(TransitionError {
                    from: S::Exited,
                    op: Op::StopObserved
                })
            );
        } else {
            assert_eq!(shared.state(), S::Stopping);
            assert_eq!(
                refusal(exited),
                TransitionError {
                    from: S::Stopping,
                    op: Op::ChildExited
                }
            );
            // The mirror image: once a stop is outstanding, the reaping is
            // recorded as the stop's and `ChildExited` stays refused.
            assert_eq!(
                shared.mark(Op::ChildExited),
                Err(TransitionError {
                    from: S::Stopping,
                    op: Op::ChildExited
                })
            );
            assert!(shared.mark(Op::StopObserved).is_ok());
        }
    });
}

// ---------------------------------------------------------------------------
// d. The supervisor is lost while an activation is in flight. A run whose
//    outcome can no longer be observed must not start.
// ---------------------------------------------------------------------------

#[test]
fn a_lost_supervisor_never_lets_a_release_happen_after_it() {
    loom::model(|| {
        let shared = Arc::new(SharedLifecycle::new(S::Prepared));
        let releases = Arc::new(AtomicUsize::new(0));

        let losing = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || shared.mark(Op::SupervisorLost))
        };
        let activating = {
            let shared = Arc::clone(&shared);
            let releases = Arc::clone(&releases);
            thread::spawn(move || activate(&shared, &releases))
        };

        let lost = joined(losing);
        let activated = joined(activating);
        let released = releases.load(Ordering::Relaxed);

        // Supervisor loss is legal from both `Prepared` and `Activating`, so
        // unlike the other models this one always lands.
        assert!(lost.is_ok(), "supervisor loss must always be recordable");
        assert_eq!(shared.state(), S::Failed);

        if activated.is_ok() {
            // The activation got in first: it released while the run was still
            // observable, and the loss then failed the run.
            assert_eq!(released, 1);
            assert_eq!(
                lost,
                Ok(Transition {
                    from: S::Activating,
                    to: S::Failed
                })
            );
        } else {
            // The loss got in first. `Failed` absorbs the activation, and the
            // gate write must never run behind it.
            assert_eq!(
                released, 0,
                "the gate was released after the run had already failed"
            );
            assert_eq!(
                refusal(activated),
                TransitionError {
                    from: S::Failed,
                    op: Op::BeginActivate
                }
            );
        }
        // Either way the write happened at most once.
        assert!(released <= 1, "the gate write ran {released} times");
    });
}

// ---------------------------------------------------------------------------
// e. Two cleanup verifications race. Counting the same verification twice is
//    a refusal, not an idempotent no-op.
// ---------------------------------------------------------------------------

#[test]
fn two_racing_cleanup_confirmations_leave_exactly_one_winner() {
    loom::model(|| {
        let shared = Arc::new(SharedLifecycle::new(S::Stopped));

        let racers: Vec<_> = (0..2)
            .map(|_| {
                let shared = Arc::clone(&shared);
                thread::spawn(move || shared.mark(Op::CleanupConfirmed))
            })
            .collect();
        let outcomes: Vec<Outcome> = racers.into_iter().map(joined).collect();

        assert_eq!(
            wins(&outcomes),
            1,
            "one cleanup was verified twice: {outcomes:?}"
        );
        for outcome in outcomes {
            match outcome {
                Ok(change) => assert_eq!(
                    change,
                    Transition {
                        from: S::Stopped,
                        to: S::CleanupVerified
                    }
                ),
                Err(err) => assert_eq!(
                    err,
                    TransitionError {
                        from: S::CleanupVerified,
                        op: Op::CleanupConfirmed
                    }
                ),
            }
        }
        assert_eq!(shared.state(), S::CleanupVerified);
    });
}

// ---------------------------------------------------------------------------
// f. A session recovered from the durable store reconciles its record while
//    another party confirms the same cleanup. One absence must not be counted
//    twice.
//
//    The recovery's read-decide-record is deliberately *not* one critical
//    section: `reconcile` is a pure function over a state the caller has
//    already read, so there is a real gap between "I saw `failed`" and "I
//    record the confirmation". This model is what says that gap is safe — the
//    state machine, not the reader, decides who wins.
// ---------------------------------------------------------------------------

/// The verdict a probe of a process that is provably gone produces.
fn absent() -> CleanupVerification {
    CleanupVerification::ConfirmedAbsent {
        basis: AbsenceBasis::PidAbsent { pid: 4242 },
    }
}

/// The verdict a probe of a live pid whose start time still matches produces.
fn present() -> CleanupVerification {
    CleanupVerification::StillPresent {
        survivors: SurvivorEvidence::IdentityMatch { pid: 4242 },
    }
}

#[test]
fn a_recovery_and_a_cleanup_never_both_confirm_the_same_absence() {
    loom::model(|| {
        let shared = Arc::new(SharedLifecycle::new(S::Failed));

        let recovering = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let observed = shared.state();
                let decision = reconcile(observed, &absent(), SupervisorPresence::NeverDetached);
                // A recovery that finds the cleanup already proven records
                // nothing. That is the whole of "never adopt after cleanup" on
                // the write side.
                decision
                    .is_process_gone()
                    .then(|| shared.mark(Op::CleanupConfirmed))
            })
        };
        let confirming = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || shared.mark(Op::CleanupConfirmed))
        };

        let recovered = joined(recovering);
        let confirmed = joined(confirming);

        let mut attempts = vec![confirmed];
        if let Some(outcome) = recovered {
            attempts.push(outcome);
        }
        assert_eq!(
            wins(&attempts),
            1,
            "one absence was confirmed twice: {attempts:?}"
        );
        for attempt in attempts {
            match attempt {
                Ok(change) => assert_eq!(
                    change,
                    Transition {
                        from: S::Failed,
                        to: S::CleanupVerified
                    }
                ),
                Err(err) => assert_eq!(
                    err,
                    TransitionError {
                        from: S::CleanupVerified,
                        op: Op::CleanupConfirmed
                    }
                ),
            }
        }
        assert_eq!(shared.state(), S::CleanupVerified);
    });
}

// ---------------------------------------------------------------------------
// g. A recovery reconciles the same record a stop is finishing on. Once the
//    cleanup is proven, no interleaving may still produce an adoption — the pid
//    it would adopt has been proven absent, so anything answering to that
//    number now is a reissue.
// ---------------------------------------------------------------------------

#[test]
fn a_recovery_never_adopts_a_run_whose_cleanup_was_already_proven() {
    loom::model(|| {
        let shared = Arc::new(SharedLifecycle::new(S::Stopping));

        let stopping = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let reaped = shared.mark(Op::StopObserved);
                let confirmed = shared.mark(Op::CleanupConfirmed);
                (reaped, confirmed)
            })
        };
        let recovering = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let observed = shared.state();
                // The probe says the pid is alive. Before the cleanup lands
                // that is a survivor worth reporting; after it, the same
                // observation can only be a number the kernel handed to
                // somebody else.
                (
                    observed,
                    reconcile(observed, &present(), SupervisorPresence::NeverDetached),
                )
            })
        };

        let (reaped, confirmed) = joined(stopping);
        let (seen, decision) = joined(recovering);

        // Nothing else moves this machine, so the stop path always lands.
        assert_eq!(
            reaped,
            Ok(Transition {
                from: S::Stopping,
                to: S::Stopped
            })
        );
        assert_eq!(
            confirmed,
            Ok(Transition {
                from: S::Stopped,
                to: S::CleanupVerified
            })
        );
        assert_eq!(shared.state(), S::CleanupVerified);

        assert!(
            !(seen == S::CleanupVerified && decision.is_still_running()),
            "a run whose cleanup was proven was adopted anyway: {decision:?}"
        );
        if seen == S::CleanupVerified {
            assert_eq!(decision, RecoveryDecision::AlreadyVerified);
        } else {
            assert!(
                decision.is_still_running(),
                "before the cleanup lands, a live pid is a survivor: {decision:?}"
            );
        }
    });
}
