//! Generic prepared-process lifecycle.
//!
//! A sandboxed run moves through five stages:
//!
//! ```text
//! plan -> prepared -> activated -> exit -> cleanup-verify
//! ```
//!
//! A [`SandboxPlan`] describes the run; `prepare()` forks a child that applies
//! the sandbox to itself and then *holds* before `execve`; `activate()` releases
//! that hold exactly once against an unforgeable token; the run ends with typed
//! exit facts; and cleanup verification proves the process is gone rather than
//! assuming a signal worked. Every stage boundary is a directly observed fact,
//! never an inference — see `docs/adr/0001-generic-lifecycle.md`.
//!
//! # What this slice contains
//!
//! This is the pure, no-OS-interaction layer only:
//!
//! - [`state`][self]: the typed state machine ([`LifecycleState`],
//!   [`LifecycleOp`], [`TransitionError`]) as a total pure function.
//! - [`plan`][self]: [`SandboxPlan`] and its typestate output [`ValidatedPlan`],
//!   with pre-launch validation that touches no filesystem.
//! - [`events`][self]: [`EventSink`] and the fidelity-labelled
//!   [`LifecycleEvent`].
//!
//! # What it does not contain yet
//!
//! No process is created, no descriptor is opened, and no sandbox is applied by
//! anything in this module. The activation gate (`gate.rs`), the forking
//! prepare step (`prepare.rs`), the durable supervisor and session store, exit
//! facts, process identity, and cleanup verification all arrive in later
//! slices. Until then the state machine is driven by callers in tests only, and
//! [`SandboxPlan::validate`] deliberately performs no existence or
//! canonicalization checks — those belong to `prepare()`, at the point where
//! the result can be acted on without a time-of-check/time-of-use gap.
//!
//! # Example
//!
//! ```
//! use nono::lifecycle::{LifecycleOp, LifecycleState, SandboxPlan};
//!
//! let plan = SandboxPlan::new("/bin/echo")
//!     .arg("hello")
//!     .env("LANG", "C")
//!     .validate()?;
//! assert_eq!(plan.program(), "/bin/echo");
//!
//! // Activation is reachable only from `Prepared`.
//! let prepared = LifecycleState::Planning
//!     .apply(LifecycleOp::BeginPrepare)?
//!     .apply(LifecycleOp::PrepareSucceeded)?;
//! assert!(prepared.apply(LifecycleOp::BeginActivate).is_ok());
//! # Ok::<(), nono::NonoError>(())
//! ```

mod events;
mod plan;
mod state;

pub use events::{EventSink, LifecycleEvent, Observation};
pub use plan::{
    GateConfig, MAX_PLAN_METADATA_BYTES, PlanError, ResourceLimits, SandboxPlan, SessionMode,
    ValidatedPlan,
};
pub use state::{LifecycleOp, LifecycleState, TransitionError};

use crate::error::NonoError;
use thiserror::Error;

/// Everything the lifecycle can refuse to do, as one type.
///
/// The single aggregate that [`NonoError::Lifecycle`] wraps, so the module can
/// grow variants without widening [`NonoError`] again. Callers who want the
/// precise failure match on the inner [`PlanError`] or [`TransitionError`];
/// callers who only propagate use `?`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LifecycleError {
    /// A [`SandboxPlan`] failed pre-launch validation.
    #[error(transparent)]
    Plan(#[from] PlanError),

    /// An op was applied in a state where it is not legal.
    #[error(transparent)]
    Transition(#[from] TransitionError),
}

impl From<PlanError> for NonoError {
    fn from(err: PlanError) -> Self {
        Self::Lifecycle(LifecycleError::Plan(err))
    }
}

impl From<TransitionError> for NonoError {
    fn from(err: TransitionError) -> Self {
        Self::Lifecycle(LifecycleError::Transition(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::NonoDiagnosticCode;

    #[test]
    fn plan_errors_convert_to_nono_error_in_one_hop() {
        let err: NonoError = PlanError::EmptyProgram.into();
        assert!(matches!(
            err,
            NonoError::Lifecycle(LifecycleError::Plan(PlanError::EmptyProgram))
        ));
        assert_eq!(
            err.diagnostic_code(),
            NonoDiagnosticCode::ConfigurationError
        );
    }

    #[test]
    fn transition_errors_convert_to_nono_error_in_one_hop() {
        let transition = TransitionError {
            from: LifecycleState::Planning,
            op: LifecycleOp::BeginActivate,
        };
        let err: NonoError = transition.into();
        assert!(matches!(
            err,
            NonoError::Lifecycle(LifecycleError::Transition(_))
        ));
        assert_eq!(err.diagnostic_code(), NonoDiagnosticCode::Other);
    }

    #[test]
    fn lifecycle_error_display_is_transparent() {
        let inner = PlanError::EmptyProgram;
        let wrapped = LifecycleError::from(inner.clone());
        assert_eq!(wrapped.to_string(), inner.to_string());
    }
}
