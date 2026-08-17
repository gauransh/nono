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
//! The pure layer, plus a working prepare/activate/wait path:
//!
//! - [`state`][self]: the typed state machine ([`LifecycleState`],
//!   [`LifecycleOp`], [`TransitionError`]) as a total pure function.
//! - [`plan`][self]: [`SandboxPlan`] and its typestate output [`ValidatedPlan`],
//!   with pre-launch validation that touches no filesystem.
//! - [`events`][self]: [`EventSink`] and the fidelity-labelled
//!   [`LifecycleEvent`], whose closed [`LifecycleEventKind`] is the whole
//!   vocabulary this library can witness — events the platform cannot show are
//!   absent from it, never synthesized.
//! - [`support`][self]: [`SupportReport`], what this build can actually
//!   enforce, per capability, with how each answer was established.
//! - [`prepare`][self]: [`PreparedSandbox`], which forks a child, sandboxes it,
//!   and holds it before `execve`.
//! - [`gate`][self]: [`ActivationHandle`] and the single-use release check.
//! - `sync_core`: the state and the one-shot gate write behind a single lock,
//!   so the activation compare-and-swap has an answer under concurrency rather
//!   than a race. Crate-internal; proven by `tests/loom_lifecycle.rs`.
//! - [`exit`][self]: [`ActivatedSandbox`], the typed [`SandboxExit`] facts, and
//!   the group-wide [`ActivatedSandbox::stop`].
//! - [`identity`][self]: [`ProcessIdentity`], pid plus what makes it unique.
//! - [`cleanup`][self]: [`CleanupVerification`], which probes after the fact
//!   rather than treating a sent signal as proof.
//! - [`session_store`][self]: [`SessionStore`], the schema-versioned durable
//!   record and the identity-reconciled [`SessionStore::recover`] that reads it
//!   back after the caller restarts.
//!
//! # What it does not contain yet
//!
//! The recoverable supervisor and attach arrive in later slices. Nothing yet
//! survives its supervisor *by design*: dropping a [`PreparedSandbox`] or an
//! [`ActivatedSandbox`] kills and reaps the run rather than leaving it running,
//! and every prepared session is generation 1 because nothing re-prepares into
//! an existing session's slot. What the durable store adds is the ability to
//! reason honestly about a run whose supervisor died *anyway* — a crash, a
//! `SIGKILL`, a machine that went away — rather than a supported way to detach.
//!
//! One consequence of that is worth stating here rather than only in
//! [`session_store`][self]: a recovered process is not this process's child, so
//! `waitpid` cannot reach it and its exit code or signal is not observable
//! after a restart. Recovery reports presence and absence, and never
//! manufactures a [`SandboxExit`] it did not witness.
//!
//! [`SandboxPlan::validate`] still performs no existence or canonicalization
//! checks — those belong to [`PreparedSandbox::prepare`], at the point where
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

mod cleanup;
mod events;
mod exit;
mod gate;
mod identity;
mod plan;
mod prepare;
mod session_store;
mod state;
mod support;

// The shared core is crate-internal in every ordinary build. Under `--cfg
// nono_loom` it is exported so `tests/loom_lifecycle.rs`, which is an
// out-of-crate consumer, can drive it from several threads; that cfg is never
// set for a released build, so the public API is the same either way.
#[cfg(nono_loom)]
pub mod sync_core;
#[cfg(not(nono_loom))]
mod sync_core;

pub use cleanup::{
    AbsenceBasis, CleanupError, CleanupVerification, IndeterminateReason, SurvivorEvidence,
    UnsupportedReason,
};
pub use events::{ActivationOutcome, EventSink, LifecycleEvent, LifecycleEventKind, Observation};
pub use exit::{
    ActivatedSandbox, ActivationObservation, ExitOutcome, PRE_EXEC_EXIT_CODE, PreExecStage,
    ReapError, SandboxExit, SupervisorStage,
};
pub use gate::{ACTIVATION_TOKEN_BYTES, ActivationError, ActivationHandle, StopError};
pub use identity::ProcessIdentity;
pub use plan::{
    GateConfig, MAX_PLAN_METADATA_BYTES, PlanError, ResourceLimits, SandboxPlan, SessionMode,
    ValidatedPlan,
};
pub use prepare::{PrepareError, PreparedSandbox};
pub use session_store::{
    CURRENT_SCHEMA_VERSION, MAX_RECORD_BYTES, RecoveredSession, RecoveryDecision, SessionRecord,
    SessionStore, SessionStoreError, SessionSummary, Sessions, reconcile,
};
pub use state::{LifecycleOp, LifecycleState, TransitionError};
pub use support::{
    Capability, CleanupFacts, DarkSpot, DarkSpotEntry, Determination, EventFamily, EventFidelity,
    EventObservationSupport, HostFacts, IdentityFacts, KernelFacts, LandlockFacts, LandlockRight,
    LandlockRightSupport, NetworkFilteringFacts, NetworkMechanism, NetworkMechanismSupport,
    SUPPORT_REPORT_SCHEMA_VERSION, SupportReason, SupportReport, SupportStatus,
};

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

    /// A child could not be prepared, or died before reaching the gate.
    #[error(transparent)]
    Prepare(#[from] PrepareError),

    /// An activation was refused.
    #[error(transparent)]
    Activation(#[from] ActivationError),

    /// A pre-activation stop was refused.
    #[error(transparent)]
    Stop(#[from] StopError),

    /// A child's death was never observed.
    #[error(transparent)]
    Reap(#[from] ReapError),

    /// Cleanup verification was attempted where it has no meaning: before the
    /// run's end was observed, or a second time after it was already proven.
    #[error(transparent)]
    Cleanup(#[from] CleanupError),

    /// The durable session store refused an operation, or a record could not
    /// be trusted.
    #[error(transparent)]
    Session(#[from] SessionStoreError),
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

impl From<PrepareError> for NonoError {
    fn from(err: PrepareError) -> Self {
        Self::Lifecycle(LifecycleError::Prepare(err))
    }
}

impl From<ActivationError> for NonoError {
    fn from(err: ActivationError) -> Self {
        Self::Lifecycle(LifecycleError::Activation(err))
    }
}

impl From<StopError> for NonoError {
    fn from(err: StopError) -> Self {
        Self::Lifecycle(LifecycleError::Stop(err))
    }
}

impl From<ReapError> for NonoError {
    fn from(err: ReapError) -> Self {
        Self::Lifecycle(LifecycleError::Reap(err))
    }
}

impl From<CleanupError> for NonoError {
    fn from(err: CleanupError) -> Self {
        Self::Lifecycle(LifecycleError::Cleanup(err))
    }
}

impl From<SessionStoreError> for NonoError {
    fn from(err: SessionStoreError) -> Self {
        Self::Lifecycle(LifecycleError::Session(err))
    }
}

/// The JSON example a schema doc locks, extracted from the doc itself.
///
/// The three `docs/lifecycle/*-v1.md` schema documents each show one example
/// under a `## Golden example` heading, and each has a test that serializes a
/// constructed value and compares it against that block. Reading the doc rather
/// than duplicating the example in the test is what makes the doc the thing
/// under test: a type that changes shape fails at the doc, with the doc's path
/// in the message.
///
/// Panics rather than returns, because every caller is a test and a doc that
/// has lost its example is a failure of exactly the kind this exists to catch.
#[cfg(test)]
pub(crate) fn doc_golden_example(doc: &str, path: &str) -> String {
    const HEADING: &str = "## Golden example";
    let Some((_, section)) = doc.split_once(HEADING) else {
        panic!("{path} must contain a '{HEADING}' section");
    };
    let Some((_, fenced)) = section.split_once("```json\n") else {
        panic!("{path}: '{HEADING}' must be followed by a ```json block");
    };
    let Some((body, _)) = fenced.split_once("```") else {
        panic!("{path}: the golden ```json block is never closed");
    };
    body.trim_end().to_string()
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
    fn a_child_that_could_not_sandbox_itself_reports_a_sandbox_failure_code() {
        // Same failure class as a policy that could not be built at all — the
        // confinement was not established — so it must not be filed under
        // "your configuration is malformed".
        let exit = SandboxExit::new(
            ExitOutcome::SandboxApplicationFailure {
                stage: PreExecStage::SandboxApply,
                errno: 1,
            },
            ActivationObservation::NotActivated,
            ProcessIdentity::capture(0),
        );
        let err: NonoError = PrepareError::ChildFailed { exit }.into();
        assert_eq!(err.diagnostic_code(), NonoDiagnosticCode::SandboxDeniedPath);

        let spec: NonoError = PrepareError::SandboxSpec {
            reason: "unsupported".to_string(),
        }
        .into();
        assert_eq!(
            spec.diagnostic_code(),
            NonoDiagnosticCode::SandboxDeniedPath,
            "the two must agree; they are the same failure at different moments"
        );
    }

    #[test]
    fn a_child_that_died_after_the_sandbox_applied_is_not_a_sandbox_failure() {
        let exit = SandboxExit::new(
            ExitOutcome::PreExecFailure {
                stage: PreExecStage::Exec,
                errno: 2,
            },
            ActivationObservation::NotActivated,
            ProcessIdentity::capture(0),
        );
        let err: NonoError = PrepareError::ChildFailed { exit }.into();
        assert_eq!(
            err.diagnostic_code(),
            NonoDiagnosticCode::ConfigurationError
        );
    }

    #[test]
    fn lifecycle_error_display_is_transparent() {
        let inner = PlanError::EmptyProgram;
        let wrapped = LifecycleError::from(inner.clone());
        assert_eq!(wrapped.to_string(), inner.to_string());
    }
}
