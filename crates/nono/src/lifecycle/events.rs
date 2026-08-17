//! Lifecycle events and the consumer-implemented sink.
//!
//! The library emits facts; it never routes them anywhere. A consumer supplies
//! an [`EventSink`] and decides what an event means. Every event carries an
//! [`Observation`] label so a consumer can tell a fact the platform showed us
//! from one we rebuilt after the fact — events the platform cannot show are
//! absent, never synthesized to fill a gap.

use super::state::LifecycleState;
use serde::{Deserialize, Serialize};

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

/// Something the lifecycle observed.
///
/// Deliberately small: one variant covering the state machine. Later slices add
/// variants as they gain facts worth reporting, and each addition is a
/// conscious API change rather than an open extension point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LifecycleEvent {
    /// The state machine moved.
    StateChanged {
        /// State before the transition.
        from: LifecycleState,
        /// State after the transition.
        to: LifecycleState,
        /// Whether the transition was witnessed or reconstructed.
        observation: Observation,
    },
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

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
                guard.push(*event);
            }
        }
    }

    fn state_changed(from: LifecycleState, to: LifecycleState) -> LifecycleEvent {
        LifecycleEvent::StateChanged {
            from,
            to,
            observation: Observation::DirectlyObserved,
        }
    }

    #[test]
    fn recording_sink_receives_events_in_order() {
        let sink = RecordingSink::default();
        let first = state_changed(LifecycleState::Planning, LifecycleState::Preparing);
        let second = state_changed(LifecycleState::Preparing, LifecycleState::Prepared);

        sink.emit(&first);
        sink.emit(&second);

        assert_eq!(sink.recorded(), vec![first, second]);
    }

    #[test]
    fn sink_is_usable_behind_a_shared_trait_object() {
        let sink = Arc::new(RecordingSink::default());
        let erased: Arc<dyn EventSink> = sink.clone();

        erased.emit(&state_changed(
            LifecycleState::Activating,
            LifecycleState::Running,
        ));

        assert_eq!(sink.recorded().len(), 1);
    }

    #[test]
    fn reconstructed_events_are_labelled_distinctly() {
        let direct = LifecycleEvent::StateChanged {
            from: LifecycleState::Running,
            to: LifecycleState::Exited,
            observation: Observation::DirectlyObserved,
        };
        let reconstructed = LifecycleEvent::StateChanged {
            from: LifecycleState::Running,
            to: LifecycleState::Exited,
            observation: Observation::Reconstructed,
        };
        assert_ne!(direct, reconstructed);
    }

    #[test]
    fn event_serde_uses_stable_snake_case_names() -> Result<(), serde_json::Error> {
        let event = LifecycleEvent::StateChanged {
            from: LifecycleState::Prepared,
            to: LifecycleState::Activating,
            observation: Observation::Reconstructed,
        };
        let json = serde_json::to_string(&event)?;
        assert_eq!(
            json,
            r#"{"kind":"state_changed","from":"prepared","to":"activating","observation":"reconstructed"}"#
        );
        let parsed: LifecycleEvent = serde_json::from_str(&json)?;
        assert_eq!(parsed, event);
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
}
