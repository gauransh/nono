//! Typed lifecycle state machine.
//!
//! [`LifecycleState::apply`] is a total pure function over
//! `(state, op) -> Result<state, TransitionError>`: it allocates nothing,
//! touches no OS resource, and never panics, so the supervisor can drive it
//! from inside a CAS loop and Loom can exhaust the interleavings.
//!
//! Ops are named for what was *observed*, not for what the caller intends —
//! [`LifecycleOp::ExecObserved`] is "the status descriptor reached EOF without
//! an error record", not "we asked the child to exec". An op the platform
//! cannot show us has no variant here.
//!
//! # Single-use semantics
//!
//! Repeating an op is a [`TransitionError`], never an idempotent no-op. A
//! second [`LifecycleOp::BeginActivate`] means a second party raced for the
//! gate, and a second [`LifecycleOp::CleanupConfirmed`] means the same
//! verification was counted twice; both are bugs the caller must see, so the
//! machine reports them instead of silently absorbing them.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Where a sandboxed run currently is.
///
/// Serializes to the stable snake_case name reported by
/// [`LifecycleState::as_str`]; the session store persists these, so the wire
/// names are contract and must not be renamed with the variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// A plan exists; nothing has been created.
    Planning,
    /// The child has been forked and is applying its sandbox.
    Preparing,
    /// The child is sandboxed and blocked at the activation gate. This is the
    /// only state from which activation is reachable.
    Prepared,
    /// The gate has been claimed by exactly one activation; the release byte
    /// is in flight and the exec outcome is not yet observed.
    Activating,
    /// Exec was positively observed; the customer program is running.
    Running,
    /// The child was reaped after running to completion on its own.
    Exited,
    /// A stop was requested; the process has not yet been observed gone.
    Stopping,
    /// The child was reaped after a stop request.
    Stopped,
    /// The process was proven absent, identity re-checked. Terminal.
    CleanupVerified,
    /// The run failed. Absorbing: the only way out is cleanup verification.
    Failed,
}

impl LifecycleState {
    /// The stable snake_case name, identical to the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planning => "planning",
            Self::Preparing => "preparing",
            Self::Prepared => "prepared",
            Self::Activating => "activating",
            Self::Running => "running",
            Self::Exited => "exited",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::CleanupVerified => "cleanup_verified",
            Self::Failed => "failed",
        }
    }

    /// Apply an observed fact to this state.
    ///
    /// Total and pure: every `(state, op)` pair either produces the next state
    /// or a [`TransitionError`] naming the pair that was refused. The legal
    /// transitions are:
    ///
    /// | From | Op | To |
    /// |------|----|----|
    /// | `Planning` | `BeginPrepare` | `Preparing` |
    /// | `Preparing` | `PrepareSucceeded` | `Prepared` |
    /// | `Preparing` | `PrepareFailed` | `Failed` |
    /// | `Prepared` | `BeginActivate` | `Activating` |
    /// | `Prepared` | `BeginStop` | `Stopping` |
    /// | `Activating` | `ExecObserved` | `Running` |
    /// | `Activating` | `ActivateFailed` | `Failed` |
    /// | `Running` | `ChildExited` | `Exited` |
    /// | `Running` | `BeginStop` | `Stopping` |
    /// | `Stopping` | `StopObserved` | `Stopped` |
    /// | `Exited`, `Stopped`, `Failed` | `CleanupConfirmed` | `CleanupVerified` |
    /// | `Preparing`, `Prepared`, `Activating`, `Running`, `Stopping` | `SupervisorLost` | `Failed` |
    ///
    /// Everything else is refused. Three refusals carry the security weight:
    /// activation is unreachable except from `Prepared`; a stop taken before
    /// activation moves to `Stopping`/`Stopped`, from which activation can
    /// never be re-entered; and `Failed` absorbs every op but cleanup.
    ///
    /// # Errors
    ///
    /// [`TransitionError`] when `op` is not legal in `self`.
    #[must_use = "the next state must be stored; apply() does not mutate self"]
    pub fn apply(self, op: LifecycleOp) -> Result<Self, TransitionError> {
        use LifecycleOp as Op;

        let next = match (self, op) {
            (Self::Planning, Op::BeginPrepare) => Self::Preparing,
            (Self::Preparing, Op::PrepareSucceeded) => Self::Prepared,
            (Self::Preparing, Op::PrepareFailed) => Self::Failed,
            (Self::Prepared, Op::BeginActivate) => Self::Activating,
            (Self::Prepared | Self::Running, Op::BeginStop) => Self::Stopping,
            (Self::Activating, Op::ExecObserved) => Self::Running,
            (Self::Activating, Op::ActivateFailed) => Self::Failed,
            (Self::Running, Op::ChildExited) => Self::Exited,
            (Self::Stopping, Op::StopObserved) => Self::Stopped,
            (Self::Exited | Self::Stopped | Self::Failed, Op::CleanupConfirmed) => {
                Self::CleanupVerified
            }
            (
                Self::Preparing
                | Self::Prepared
                | Self::Activating
                | Self::Running
                | Self::Stopping,
                Op::SupervisorLost,
            ) => Self::Failed,
            _ => return Err(TransitionError { from: self, op }),
        };
        Ok(next)
    }
}

impl std::fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A directly observable fact that drives the machine.
///
/// Each variant is something the library can *see*: a syscall returning, a
/// descriptor reaching EOF, a supervisor handle going away. Nothing here
/// encodes intent or product meaning.
///
/// Serializes to the stable snake_case name reported by
/// [`LifecycleOp::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleOp {
    /// The fork that creates the prepared child has been issued.
    BeginPrepare,
    /// The child reported reaching the gate with its sandbox applied.
    PrepareSucceeded,
    /// The child reported a typed pre-gate failure, or the fork itself failed.
    PrepareFailed,
    /// One activation claimed the gate. A second claim is a
    /// [`TransitionError`], which is how the single-use guarantee is anchored.
    BeginActivate,
    /// The status descriptor reached EOF with no error record: exec happened.
    ExecObserved,
    /// A typed pre-exec failure record arrived, or the release could not be
    /// delivered. Exec did not happen.
    ActivateFailed,
    /// `waitpid` reaped the child with no stop outstanding.
    ChildExited,
    /// A stop was issued. Sending a signal is not proof of anything; this only
    /// records that the request went out.
    BeginStop,
    /// `waitpid` reaped the child with a stop outstanding. Once a stop is
    /// requested this is the reaping observation regardless of why the process
    /// actually died — [`Self::ChildExited`] is refused in `Stopping` so the
    /// two facts can never both be recorded for one death.
    StopObserved,
    /// Cleanup verification proved the process absent, with the recorded
    /// identity re-checked so a reused pid cannot pass.
    CleanupConfirmed,
    /// The supervisor is gone, so the run can no longer be observed. The gate
    /// closes and a held child exits; the session moves to `Failed` because
    /// its outcome is now unobservable, and cleanup verification is the only
    /// remaining step.
    SupervisorLost,
}

impl LifecycleOp {
    /// The stable snake_case name, identical to the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeginPrepare => "begin_prepare",
            Self::PrepareSucceeded => "prepare_succeeded",
            Self::PrepareFailed => "prepare_failed",
            Self::BeginActivate => "begin_activate",
            Self::ExecObserved => "exec_observed",
            Self::ActivateFailed => "activate_failed",
            Self::ChildExited => "child_exited",
            Self::BeginStop => "begin_stop",
            Self::StopObserved => "stop_observed",
            Self::CleanupConfirmed => "cleanup_confirmed",
            Self::SupervisorLost => "supervisor_lost",
        }
    }
}

impl std::fmt::Display for LifecycleOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An op that was refused, with the exact pair that was refused.
///
/// Carrying both halves means a caller (or a log line) can say which fact
/// arrived in which state without re-deriving it from context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Error)]
#[error("illegal lifecycle transition: op {op} is not legal in state {from}")]
pub struct TransitionError {
    /// The state the machine was in.
    pub from: LifecycleState,
    /// The op that was refused.
    pub op: LifecycleOp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use LifecycleOp as Op;
    use LifecycleState as S;

    /// Every state, in declaration order. The exhaustive-match guard below
    /// fails to compile if a variant is added without extending this list.
    const ALL_STATES: [LifecycleState; 10] = [
        S::Planning,
        S::Preparing,
        S::Prepared,
        S::Activating,
        S::Running,
        S::Exited,
        S::Stopping,
        S::Stopped,
        S::CleanupVerified,
        S::Failed,
    ];

    /// Every op, in declaration order. Same compile-time guard applies.
    const ALL_OPS: [LifecycleOp; 11] = [
        Op::BeginPrepare,
        Op::PrepareSucceeded,
        Op::PrepareFailed,
        Op::BeginActivate,
        Op::ExecObserved,
        Op::ActivateFailed,
        Op::ChildExited,
        Op::BeginStop,
        Op::StopObserved,
        Op::CleanupConfirmed,
        Op::SupervisorLost,
    ];

    /// The expected-outcome table: for each state, the complete list of ops
    /// that are legal there and the state each produces. Every (state, op)
    /// pair absent from a row must be rejected with a [`TransitionError`].
    ///
    /// This table is written independently of `apply`'s match so that any
    /// future edit to the machine has to be made twice, deliberately.
    const TABLE: [(LifecycleState, &[(LifecycleOp, LifecycleState)]); 10] = [
        (S::Planning, &[(Op::BeginPrepare, S::Preparing)]),
        (
            S::Preparing,
            &[
                (Op::PrepareSucceeded, S::Prepared),
                (Op::PrepareFailed, S::Failed),
                (Op::SupervisorLost, S::Failed),
            ],
        ),
        (
            S::Prepared,
            &[
                (Op::BeginActivate, S::Activating),
                (Op::BeginStop, S::Stopping),
                (Op::SupervisorLost, S::Failed),
            ],
        ),
        (
            S::Activating,
            &[
                (Op::ExecObserved, S::Running),
                (Op::ActivateFailed, S::Failed),
                (Op::SupervisorLost, S::Failed),
            ],
        ),
        (
            S::Running,
            &[
                (Op::ChildExited, S::Exited),
                (Op::BeginStop, S::Stopping),
                (Op::SupervisorLost, S::Failed),
            ],
        ),
        (S::Exited, &[(Op::CleanupConfirmed, S::CleanupVerified)]),
        (
            S::Stopping,
            &[
                (Op::StopObserved, S::Stopped),
                (Op::SupervisorLost, S::Failed),
            ],
        ),
        (S::Stopped, &[(Op::CleanupConfirmed, S::CleanupVerified)]),
        (S::CleanupVerified, &[]),
        (S::Failed, &[(Op::CleanupConfirmed, S::CleanupVerified)]),
    ];

    fn expected(from: LifecycleState, op: LifecycleOp) -> Option<LifecycleState> {
        TABLE
            .iter()
            .find(|(state, _)| *state == from)
            .and_then(|(_, legal)| legal.iter().find(|(legal_op, _)| *legal_op == op))
            .map(|(_, to)| *to)
    }

    #[test]
    fn every_state_and_op_is_enumerated() {
        // Exhaustive matches: adding a variant breaks compilation here, which
        // forces ALL_STATES / ALL_OPS / TABLE to be revisited.
        for state in ALL_STATES {
            match state {
                S::Planning
                | S::Preparing
                | S::Prepared
                | S::Activating
                | S::Running
                | S::Exited
                | S::Stopping
                | S::Stopped
                | S::CleanupVerified
                | S::Failed => {}
            }
        }
        for op in ALL_OPS {
            match op {
                Op::BeginPrepare
                | Op::PrepareSucceeded
                | Op::PrepareFailed
                | Op::BeginActivate
                | Op::ExecObserved
                | Op::ActivateFailed
                | Op::ChildExited
                | Op::BeginStop
                | Op::StopObserved
                | Op::CleanupConfirmed
                | Op::SupervisorLost => {}
            }
        }

        // The table covers each state exactly once.
        assert_eq!(TABLE.len(), ALL_STATES.len());
        for state in ALL_STATES {
            let rows = TABLE.iter().filter(|(s, _)| *s == state).count();
            assert_eq!(rows, 1, "state {state} must appear exactly once in TABLE");
        }
    }

    #[test]
    fn transition_matrix_matches_expected_table() {
        for from in ALL_STATES {
            for op in ALL_OPS {
                let actual = from.apply(op);
                match expected(from, op) {
                    Some(to) => assert_eq!(
                        actual,
                        Ok(to),
                        "expected {from} + {op} -> {to}, got {actual:?}"
                    ),
                    None => assert_eq!(
                        actual,
                        Err(TransitionError { from, op }),
                        "expected {from} + {op} to be rejected, got {actual:?}"
                    ),
                }
            }
        }
    }

    #[test]
    fn happy_path_runs_from_planning_to_cleanup_verified() -> Result<(), TransitionError> {
        let state = S::Planning
            .apply(Op::BeginPrepare)?
            .apply(Op::PrepareSucceeded)?
            .apply(Op::BeginActivate)?
            .apply(Op::ExecObserved)?
            .apply(Op::ChildExited)?
            .apply(Op::CleanupConfirmed)?;
        assert_eq!(state, S::CleanupVerified);
        Ok(())
    }

    #[test]
    fn activation_is_only_reachable_from_prepared() -> Result<(), TransitionError> {
        assert_eq!(S::Prepared.apply(Op::BeginActivate)?, S::Activating);
        for from in ALL_STATES.into_iter().filter(|s| *s != S::Prepared) {
            assert_eq!(
                from.apply(Op::BeginActivate),
                Err(TransitionError {
                    from,
                    op: Op::BeginActivate
                }),
                "activation must not be reachable from {from}"
            );
        }
        Ok(())
    }

    #[test]
    fn running_is_only_reachable_through_activating() {
        for from in ALL_STATES {
            for op in ALL_OPS {
                if from.apply(op) == Ok(S::Running) {
                    assert_eq!(
                        from,
                        S::Activating,
                        "Running must only be entered from Activating, not {from}"
                    );
                    assert_eq!(op, Op::ExecObserved);
                }
            }
        }
    }

    #[test]
    fn stop_before_activation_permanently_blocks_activation() -> Result<(), TransitionError> {
        let stopping = S::Prepared.apply(Op::BeginStop)?;
        assert_eq!(stopping, S::Stopping);
        assert!(stopping.apply(Op::BeginActivate).is_err());

        let stopped = stopping.apply(Op::StopObserved)?;
        assert_eq!(stopped, S::Stopped);
        assert!(stopped.apply(Op::BeginActivate).is_err());

        let verified = stopped.apply(Op::CleanupConfirmed)?;
        assert_eq!(verified, S::CleanupVerified);
        assert!(verified.apply(Op::BeginActivate).is_err());
        Ok(())
    }

    #[test]
    fn double_begin_activate_is_rejected_not_idempotent() -> Result<(), TransitionError> {
        let activating = S::Prepared.apply(Op::BeginActivate)?;
        assert_eq!(
            activating.apply(Op::BeginActivate),
            Err(TransitionError {
                from: S::Activating,
                op: Op::BeginActivate
            })
        );
        Ok(())
    }

    #[test]
    fn double_cleanup_confirmed_is_rejected_not_idempotent() -> Result<(), TransitionError> {
        let verified = S::Exited.apply(Op::CleanupConfirmed)?;
        assert_eq!(
            verified.apply(Op::CleanupConfirmed),
            Err(TransitionError {
                from: S::CleanupVerified,
                op: Op::CleanupConfirmed
            })
        );
        Ok(())
    }

    #[test]
    fn failed_is_absorbing_except_cleanup_verification() -> Result<(), TransitionError> {
        assert_eq!(S::Failed.apply(Op::CleanupConfirmed)?, S::CleanupVerified);
        for op in ALL_OPS.into_iter().filter(|o| *o != Op::CleanupConfirmed) {
            assert_eq!(
                S::Failed.apply(op),
                Err(TransitionError {
                    from: S::Failed,
                    op
                }),
                "Failed must absorb {op}"
            );
        }
        Ok(())
    }

    #[test]
    fn cleanup_verification_is_reachable_from_exited_stopped_and_failed()
    -> Result<(), TransitionError> {
        for from in [S::Exited, S::Stopped, S::Failed] {
            assert_eq!(from.apply(Op::CleanupConfirmed)?, S::CleanupVerified);
        }
        Ok(())
    }

    #[test]
    fn cleanup_verified_is_terminal() {
        for op in ALL_OPS {
            assert!(
                S::CleanupVerified.apply(op).is_err(),
                "CleanupVerified must reject {op}"
            );
        }
    }

    #[test]
    fn supervisor_loss_fails_every_live_state_and_nothing_else() -> Result<(), TransitionError> {
        let live = [
            S::Preparing,
            S::Prepared,
            S::Activating,
            S::Running,
            S::Stopping,
        ];
        for from in live {
            assert_eq!(from.apply(Op::SupervisorLost)?, S::Failed);
        }
        for from in ALL_STATES.into_iter().filter(|s| !live.contains(s)) {
            assert!(
                from.apply(Op::SupervisorLost).is_err(),
                "SupervisorLost must be rejected in {from}"
            );
        }
        Ok(())
    }

    #[test]
    fn transition_error_carries_the_observed_from_and_op() {
        let err = match S::Planning.apply(Op::BeginActivate) {
            Err(err) => err,
            Ok(state) => panic!("expected rejection, got {state}"),
        };
        assert_eq!(err.from, S::Planning);
        assert_eq!(err.op, Op::BeginActivate);
        let rendered = err.to_string();
        assert!(rendered.contains("planning"), "{rendered}");
        assert!(rendered.contains("begin_activate"), "{rendered}");
    }

    #[test]
    fn state_serde_names_are_stable_snake_case() -> Result<(), serde_json::Error> {
        let expected_names = [
            (S::Planning, "planning"),
            (S::Preparing, "preparing"),
            (S::Prepared, "prepared"),
            (S::Activating, "activating"),
            (S::Running, "running"),
            (S::Exited, "exited"),
            (S::Stopping, "stopping"),
            (S::Stopped, "stopped"),
            (S::CleanupVerified, "cleanup_verified"),
            (S::Failed, "failed"),
        ];
        for (state, name) in expected_names {
            assert_eq!(serde_json::to_string(&state)?, format!("\"{name}\""));
            assert_eq!(state.as_str(), name);
            let parsed: LifecycleState = serde_json::from_str(&format!("\"{name}\""))?;
            assert_eq!(parsed, state);
        }
        Ok(())
    }

    #[test]
    fn op_serde_names_are_stable_snake_case() -> Result<(), serde_json::Error> {
        let expected_names = [
            (Op::BeginPrepare, "begin_prepare"),
            (Op::PrepareSucceeded, "prepare_succeeded"),
            (Op::PrepareFailed, "prepare_failed"),
            (Op::BeginActivate, "begin_activate"),
            (Op::ExecObserved, "exec_observed"),
            (Op::ActivateFailed, "activate_failed"),
            (Op::ChildExited, "child_exited"),
            (Op::BeginStop, "begin_stop"),
            (Op::StopObserved, "stop_observed"),
            (Op::CleanupConfirmed, "cleanup_confirmed"),
            (Op::SupervisorLost, "supervisor_lost"),
        ];
        for (op, name) in expected_names {
            assert_eq!(serde_json::to_string(&op)?, format!("\"{name}\""));
            assert_eq!(op.as_str(), name);
            let parsed: LifecycleOp = serde_json::from_str(&format!("\"{name}\""))?;
            assert_eq!(parsed, op);
        }
        Ok(())
    }

    #[test]
    fn display_matches_the_serde_name() {
        for state in ALL_STATES {
            assert_eq!(state.to_string(), state.as_str());
        }
        for op in ALL_OPS {
            assert_eq!(op.to_string(), op.as_str());
        }
    }
}
