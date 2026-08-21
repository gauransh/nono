//! Live lifecycle tests: real forks, real sandboxes, real `execve`.
//!
//! Every test here creates an actual sandboxed child. They exist because the
//! guarantees under test — that nothing runs before activation, that no shell
//! ever sees an argument, that a replayed handle is refused, that a dropped
//! supervisor leaves nothing behind — are properties of the running system,
//! not of a type signature. A mock cannot fail these tests in the way a real
//! kernel can.
//!
//! No test reads or writes an ambient environment variable, so none of them
//! serialises against the others; each owns a private temporary directory.
//!
//! # Capabilities used here
//!
//! The plans grant read on `/` and read-write on the test's own temporary
//! directory. That is deliberately broad: these tests exercise the *lifecycle*
//! mechanism, and a narrower policy would make them fail for reasons that have
//! nothing to do with the gate. The sandbox is still applied and still
//! enforced — writes outside the temporary directory are denied — which is what
//! keeps the R03 hold proof meaningful.

use nono::lifecycle::{
    AbsenceBasis, ActivationError, ActivationObservation, CleanupError, CleanupVerification,
    EventSink, ExitOutcome, GateConfig, LifecycleEvent, LifecycleEventKind, LifecycleState,
    Observation, PreExecStage, PrepareError, PreparedSandbox, ProcessIdentity, RecoveryDecision,
    SandboxPlan, SessionRecord, SessionStore, StopError, SurvivorEvidence, ValidatedPlan,
};
use nono::{AccessMode, CapabilitySet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// How long a test waits for a process to disappear before giving up.
const GONE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the R03 proof waits before checking that nothing has run.
const HOLD_OBSERVATION: Duration = Duration::from_millis(300);

fn temp_dir() -> TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(err) => panic!("test needs a temporary directory: {err}"),
    }
}

/// Read everything, write only inside this test's own directory.
fn capabilities(writable: &Path) -> CapabilitySet {
    let caps = CapabilitySet::new()
        .allow_path("/", AccessMode::Read)
        .and_then(|caps| caps.allow_path(writable, AccessMode::ReadWrite));
    match caps {
        Ok(caps) => caps,
        Err(err) => panic!("test capabilities must build: {err}"),
    }
}

fn plan(writable: &Path, program: &str, args: &[&str]) -> ValidatedPlan {
    let plan = SandboxPlan::new(program)
        .args(args.iter().copied())
        .capabilities(capabilities(writable));
    match plan.validate() {
        Ok(plan) => plan,
        Err(err) => panic!("test plan must validate: {err}"),
    }
}

fn prepared(plan: ValidatedPlan) -> (PreparedSandbox, nono::ActivationHandle) {
    match PreparedSandbox::prepare(plan) {
        Ok(pair) => pair,
        Err(err) => panic!("prepare must succeed: {err}"),
    }
}

/// Whether `pid` is gone, polled until the timeout.
///
/// `kill(pid, 0)` returning `ESRCH` is the observation; a sent signal on its
/// own would prove nothing.
fn wait_until_gone(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: signal 0 performs the permission and existence check without
        // delivering anything. `pid` is a plain integer; no memory is touched.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        if !alive && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Whether every member of `pgid` is gone, polled until the timeout.
///
/// `kill(-pgid, 0)` returning `ESRCH` is the observation. A process that has
/// died but not yet been reaped by its new parent still answers, which is why
/// this polls rather than asking once.
fn wait_until_group_gone(pgid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: signal 0 performs the existence and permission check without
        // delivering anything. `pgid` is a plain integer; no memory is touched.
        let alive = unsafe { libc::killpg(pgid, 0) } == 0;
        if !alive && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ---------------------------------------------------------------------------
// 1. The happy path.
// ---------------------------------------------------------------------------

#[test]
fn prepare_activate_wait_runs_the_program_and_reports_its_exit() {
    let dir = temp_dir();
    let (mut held, handle) = prepared(plan(dir.path(), "/bin/echo", &["hello"]));
    assert_eq!(held.state(), LifecycleState::Prepared);

    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    assert_eq!(held.state(), LifecycleState::Running);

    let exit = match running.wait() {
        Ok(exit) => exit,
        Err(err) => panic!("wait must observe the exit: {err}"),
    };
    // A normal exit is what settles the activation question: a child that
    // never reached `execve` writes a record before it exits, and no record
    // arrived.
    assert_eq!(exit.activation(), ActivationObservation::Observed);
    assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 });
    assert_eq!(running.state(), LifecycleState::Exited);
}

// ---------------------------------------------------------------------------
// 2. R03: a prepared child has not run.
// ---------------------------------------------------------------------------

#[test]
fn a_prepared_child_does_not_run_until_it_is_activated() {
    let dir = temp_dir();
    let marker = dir.path().join("r03-marker");
    let marker_arg = marker.to_string_lossy().into_owned();

    let (mut held, handle) = prepared(plan(dir.path(), "/usr/bin/touch", &[&marker_arg]));

    // The hold is real time, not a scheduling accident: wait long enough that
    // an unheld `touch` would certainly have run.
    std::thread::sleep(HOLD_OBSERVATION);
    assert!(
        !marker.exists(),
        "the program ran before it was activated: {}",
        marker.display()
    );
    assert_eq!(held.state(), LifecycleState::Prepared);

    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    match running.wait() {
        Ok(exit) => assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 }),
        Err(err) => panic!("wait must observe the exit: {err}"),
    }
    assert!(
        marker.exists(),
        "the program did not run after activation: {}",
        marker.display()
    );
}

// ---------------------------------------------------------------------------
// 3. No shell is ever involved.
// ---------------------------------------------------------------------------

#[test]
fn arguments_reach_the_program_literally_with_no_shell_expansion() {
    let dir = temp_dir();
    // Every metacharacter a shell would act on, in one filename. Only `/` and
    // NUL are illegal in a filename, and neither is needed to make the point.
    let hostile_name = "$(touch pwned)-`id`-;rm -rf .-&|<>*?";
    let target = dir.path().join(hostile_name);
    let target_arg = target.to_string_lossy().into_owned();

    let (mut held, handle) = prepared(plan(dir.path(), "/usr/bin/touch", &[&target_arg]));
    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    match running.wait() {
        Ok(exit) => assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 }),
        Err(err) => panic!("wait must observe the exit: {err}"),
    }

    assert!(
        target.exists(),
        "the literal argument did not reach the program: {}",
        target.display()
    );
    let entries: Vec<String> = match std::fs::read_dir(dir.path()) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(err) => panic!("test directory must be readable: {err}"),
    };
    // Exactly one file, named exactly what was asked for: no substitution ran,
    // no `pwned` appeared, no glob matched anything.
    assert_eq!(entries, vec![hostile_name.to_string()]);
}

// ---------------------------------------------------------------------------
// 4. A handle is single use, even when the caller still holds it.
// ---------------------------------------------------------------------------

#[test]
fn a_replayed_handle_is_refused_by_the_gate_not_by_ownership() {
    let dir = temp_dir();
    let (mut held, handle) = prepared(plan(dir.path(), "/bin/echo", &["once"]));

    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("first activation must succeed: {err}"),
    };

    // The caller still owns a perfectly valid handle. It must not work again.
    assert_eq!(
        held.activate(&handle).err(),
        Some(ActivationError::AlreadyActivated)
    );
    assert_eq!(
        held.activate(&handle).err(),
        Some(ActivationError::AlreadyActivated),
        "the refusal must be permanent, not a one-time race loss"
    );

    if let Err(err) = running.wait() {
        panic!("wait must observe the exit: {err}");
    }
}

// ---------------------------------------------------------------------------
// 5. A handle only opens its own gate.
// ---------------------------------------------------------------------------

#[test]
fn a_handle_from_another_session_is_refused() {
    let first_dir = temp_dir();
    let second_dir = temp_dir();
    let marker = second_dir.path().join("cross-session-marker");
    let marker_arg = marker.to_string_lossy().into_owned();

    let (first, first_handle) = prepared(plan(first_dir.path(), "/bin/echo", &["first"]));
    let (mut second, second_handle) =
        prepared(plan(second_dir.path(), "/usr/bin/touch", &[&marker_arg]));

    let error = second.activate(&first_handle).err();
    assert_eq!(
        error,
        Some(ActivationError::WrongSession {
            expected: second.session_id(),
            supplied: first.session_id(),
        })
    );
    assert_eq!(
        second.state(),
        LifecycleState::Prepared,
        "a refused activation must not move the gate"
    );
    assert!(
        !marker.exists(),
        "a mismatched handle released the wrong child"
    );

    // The rightful handle still works afterwards.
    let mut running = match second.activate(&second_handle) {
        Ok(running) => running,
        Err(err) => panic!("the matching handle must still work: {err}"),
    };
    if let Err(err) = running.wait() {
        panic!("wait must observe the exit: {err}");
    }
    assert!(marker.exists());

    drop(first_handle);
    drop(first);
}

// ---------------------------------------------------------------------------
// 6. Stopping before activation is permanent.
// ---------------------------------------------------------------------------

#[test]
fn a_stopped_child_can_never_be_activated() {
    let dir = temp_dir();
    let marker = dir.path().join("stopped-marker");
    let marker_arg = marker.to_string_lossy().into_owned();

    let (mut held, handle) = prepared(plan(dir.path(), "/usr/bin/touch", &[&marker_arg]));
    let pid = held.identity().pid();

    let exit = match held.stop_before_activation() {
        Ok(exit) => exit,
        Err(err) => panic!("stop must succeed on a held child: {err}"),
    };
    assert_eq!(exit.activation(), ActivationObservation::NotActivated);
    // The abort record, not the child's exit code. Reporting a deliberate stop
    // as `Exited { code: 1 }` would be indistinguishable from a customer
    // program that exited 1 — the sentinel-as-fact mistake.
    assert_eq!(
        exit.outcome(),
        ExitOutcome::PreExecFailure {
            stage: PreExecStage::GateAborted,
            errno: 0,
        }
    );
    assert_eq!(held.state(), LifecycleState::Stopped);
    assert!(
        wait_until_gone(pid, GONE_TIMEOUT),
        "the child was not reaped"
    );

    assert_eq!(
        held.activate(&handle).err(),
        Some(ActivationError::AlreadyStopped)
    );
    assert_eq!(
        held.stop_before_activation().err(),
        Some(StopError::NotStoppable {
            state: LifecycleState::Stopped
        })
    );
    assert!(
        !marker.exists(),
        "a stopped child must never have run its program"
    );
}

// ---------------------------------------------------------------------------
// 7. An expired gate refuses a correct token.
// ---------------------------------------------------------------------------

#[test]
fn an_expired_gate_refuses_the_right_token_and_stops_the_child() {
    let dir = temp_dir();
    let marker = dir.path().join("expired-marker");
    let marker_arg = marker.to_string_lossy().into_owned();

    let plan = SandboxPlan::new("/usr/bin/touch")
        .arg(&marker_arg)
        .capabilities(capabilities(dir.path()))
        .gate(GateConfig {
            activation_expiry: Some(Duration::from_millis(50)),
        });
    let plan = match plan.validate() {
        Ok(plan) => plan,
        Err(err) => panic!("test plan must validate: {err}"),
    };

    let (mut held, handle) = prepared(plan);
    let pid = held.identity().pid();
    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(
        held.activate(&handle).err(),
        Some(ActivationError::ActivationExpired)
    );
    assert!(
        wait_until_gone(pid, GONE_TIMEOUT),
        "an expired gate must stop its child"
    );
    assert!(!marker.exists(), "an expired gate must not run anything");

    // Same typed fact as a deliberate stop: the child took the abort, and that
    // is reported as such rather than as an exit code.
    match held.exit() {
        Some(exit) => {
            assert_eq!(exit.activation(), ActivationObservation::NotActivated);
            assert_eq!(
                exit.outcome(),
                ExitOutcome::PreExecFailure {
                    stage: PreExecStage::GateAborted,
                    errno: 0,
                }
            );
        }
        None => panic!("an expired gate must record how the child ended"),
    }

    // Expiry is permanent. The second refusal names the stop the expiry
    // performed rather than repeating the deadline: the gate is closed, and
    // the state machine is what says so.
    assert_eq!(held.state(), LifecycleState::Stopped);
    assert_eq!(
        held.activate(&handle).err(),
        Some(ActivationError::AlreadyStopped)
    );
    assert!(!marker.exists());
}

// ---------------------------------------------------------------------------
// 8. Exit facts, both shapes.
// ---------------------------------------------------------------------------

#[test]
fn a_nonzero_exit_is_reported_verbatim() {
    let dir = temp_dir();
    let (mut held, handle) = prepared(plan(dir.path(), "/usr/bin/false", &[]));
    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    match running.wait() {
        Ok(exit) => assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 1 }),
        Err(err) => panic!("wait must observe the exit: {err}"),
    }
}

#[test]
fn a_signal_death_is_reported_as_a_signal_not_an_exit_code() {
    let dir = temp_dir();
    let (mut held, handle) = prepared(plan(dir.path(), "/bin/sleep", &["30"]));
    let pid = held.identity().pid();
    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };

    // SAFETY: `pid` is this process's own child, still unreaped, so the number
    // cannot yet have been reissued.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);

    match running.wait() {
        Ok(exit) => {
            assert_eq!(exit.outcome(), ExitOutcome::Signaled { signal: 9 });
            // A signal can land on either side of `execve`, so the library
            // cannot claim the program started — even though this test knows
            // it did. Reporting `Observed` here would be a guess dressed as an
            // observation.
            assert_eq!(
                exit.activation(),
                ActivationObservation::ExecOrKilledPreExec
            );
        }
        Err(err) => panic!("wait must observe the death: {err}"),
    }
}

// ---------------------------------------------------------------------------
// 9. A failure after the release is a typed fact, not an exit code.
// ---------------------------------------------------------------------------

#[test]
fn an_exec_failure_after_release_is_reported_with_its_stage_and_errno() {
    let dir = temp_dir();
    let program = dir.path().join("doomed");
    if let Err(err) = std::fs::copy("/bin/echo", &program) {
        panic!("test needs a copy of a real binary: {err}");
    }
    let program_arg = program.to_string_lossy().into_owned();

    let (mut held, handle) = prepared(plan(dir.path(), &program_arg, &["never printed"]));
    let pid = held.identity().pid();

    // The program existed at prepare time and does not exist at exec time.
    // That window is exactly the one prepare's advisory check cannot close,
    // which is why the exec record — not the check — is the binding fact.
    if let Err(err) = std::fs::remove_file(&program) {
        panic!("test setup must be able to remove its own file: {err}");
    }

    let error = held.activate(&handle).err();
    assert_eq!(
        error,
        Some(ActivationError::PreExecFailed {
            stage: PreExecStage::Exec,
            errno: libc::ENOENT,
        })
    );
    assert_eq!(held.state(), LifecycleState::Failed);
    assert!(
        wait_until_gone(pid, GONE_TIMEOUT),
        "the child was not reaped"
    );

    match held.exit() {
        Some(exit) => {
            assert_eq!(
                exit.activation(),
                ActivationObservation::NotActivated,
                "the child said where it stopped, so this is a fact not a guess"
            );
            assert_eq!(
                exit.outcome(),
                ExitOutcome::PreExecFailure {
                    stage: PreExecStage::Exec,
                    errno: libc::ENOENT,
                }
            );
        }
        None => panic!("a failed activation must record its exit facts"),
    }
}

// ---------------------------------------------------------------------------
// 10. A dropped supervisor leaves nothing behind.
// ---------------------------------------------------------------------------

#[test]
fn dropping_a_prepared_sandbox_kills_and_reaps_the_held_child() {
    let dir = temp_dir();
    let marker = dir.path().join("dropped-marker");
    let marker_arg = marker.to_string_lossy().into_owned();

    let pid = {
        let (held, _handle) = prepared(plan(dir.path(), "/usr/bin/touch", &[&marker_arg]));
        let pid = held.identity().pid();
        // SAFETY: the child is alive and held at the gate; signal 0 only
        // checks.
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            0,
            "the held child must be alive before the drop"
        );
        pid
    };

    assert!(
        wait_until_gone(pid, GONE_TIMEOUT),
        "a dropped supervisor left a process behind"
    );
    assert!(
        !marker.exists(),
        "a dropped supervisor must never release the gate"
    );
}

// ---------------------------------------------------------------------------
// 11. The child really is confined, not merely forked.
// ---------------------------------------------------------------------------

#[test]
fn the_activated_program_runs_inside_the_sandbox_it_was_prepared_with() {
    // Without this test every other test here could pass with the sandbox
    // never applied at all: they all write inside the one directory the plan
    // grants. This one writes outside it.
    let granted = temp_dir();
    let ungranted = temp_dir();
    let escape = ungranted.path().join("escape");
    let escape_arg = escape.to_string_lossy().into_owned();

    let (mut held, handle) = prepared(plan(granted.path(), "/usr/bin/touch", &[&escape_arg]));
    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    let exit = match running.wait() {
        Ok(exit) => exit,
        Err(err) => panic!("wait must observe the exit: {err}"),
    };

    assert_eq!(
        exit.activation(),
        ActivationObservation::Observed,
        "the program ran; it was the write that had to fail"
    );
    assert_ne!(
        exit.outcome(),
        ExitOutcome::Exited { code: 0 },
        "a write outside the granted paths must not succeed"
    );
    assert!(
        !escape.exists(),
        "the sandbox was not applied: {}",
        escape.display()
    );
}

// ---------------------------------------------------------------------------
// 12. The customer's program inherits no descriptor it was not given.
// ---------------------------------------------------------------------------

#[test]
fn the_activated_program_inherits_no_descriptor_beyond_the_standard_streams() {
    let dir = temp_dir();
    let bystander = dir.path().join("bystander");
    if let Err(err) = std::fs::write(&bystander, b"open me") {
        panic!("test setup must be able to write its own file: {err}");
    }
    let bystander_c = match std::ffi::CString::new(bystander.to_string_lossy().into_owned()) {
        Ok(path) => path,
        Err(err) => panic!("test path must be a C string: {err}"),
    };

    // Deliberately inheritable: no O_CLOEXEC. This is what an embedding
    // process's own open files look like, and without the child's sweep it
    // would ride through fork and execve into the customer's program.
    // SAFETY: a plain `open` of a path this test just created; the returned
    // descriptor is closed below.
    let leaked = unsafe { libc::open(bystander_c.as_ptr(), libc::O_RDONLY) };
    assert!(leaked >= 3, "test needs a descriptor above the streams");

    // `test -e /dev/fd/N` exits 0 if the program can see descriptor N and 1 if
    // it cannot. Descriptor numbers survive fork and execve, so N is the same
    // number on both sides.
    let probe = format!("/dev/fd/{leaked}");
    let (mut held, handle) = prepared(plan(dir.path(), "/bin/test", &["-e", &probe]));
    let outcome = match held.activate(&handle) {
        Ok(mut running) => match running.wait() {
            Ok(exit) => exit.outcome(),
            Err(err) => panic!("wait must observe the exit: {err}"),
        },
        Err(err) => panic!("activation must succeed: {err}"),
    };

    // SAFETY: `leaked` is a descriptor this test opened and has not closed.
    unsafe { libc::close(leaked) };

    assert_eq!(
        outcome,
        ExitOutcome::Exited { code: 1 },
        "the program could still see descriptor {leaked}: the child's \
         close-everything sweep did not run"
    );
}

// ---------------------------------------------------------------------------
// 13. Two prepared children coexist without holding each other's channels.
// ---------------------------------------------------------------------------

#[test]
fn two_overlapping_prepares_do_not_capture_each_others_channels() {
    // The second `prepare` forks while the first child is alive and while the
    // first gate's write end is still open in this process. Without the
    // child's close-everything sweep, each child would hold a copy of the
    // other's channel ends, and neither could ever see its own supervisor
    // disappear. Both must still run and both must be reaped.
    let first_dir = temp_dir();
    let second_dir = temp_dir();

    let (mut first, first_handle) = prepared(plan(first_dir.path(), "/bin/echo", &["first"]));
    let (mut second, second_handle) = prepared(plan(second_dir.path(), "/bin/echo", &["second"]));

    let mut first_running = match first.activate(&first_handle) {
        Ok(running) => running,
        Err(err) => panic!("first activation must succeed: {err}"),
    };
    let mut second_running = match second.activate(&second_handle) {
        Ok(running) => running,
        Err(err) => panic!("second activation must succeed: {err}"),
    };

    for running in [&mut first_running, &mut second_running] {
        match running.wait() {
            Ok(exit) => assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 }),
            Err(err) => panic!("wait must observe the exit: {err}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 14. The consumer's event sink sees the whole run, in the whole vocabulary.
// ---------------------------------------------------------------------------

/// A sink that keeps every event, for the sequence assertions below.
#[derive(Default)]
struct RecordingSink {
    seen: Mutex<Vec<LifecycleEvent>>,
}

impl EventSink for RecordingSink {
    fn emit(&self, event: &LifecycleEvent) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(event.clone());
        }
    }
}

impl RecordingSink {
    fn recorded(&self) -> Vec<LifecycleEvent> {
        match self.seen.lock() {
            Ok(seen) => seen.clone(),
            Err(err) => panic!("the sink's records must be readable: {err}"),
        }
    }
}

/// A watched plan for `program args…`, writable only inside `dir`.
fn watched_plan(
    dir: &Path,
    program: &str,
    args: &[&str],
    sink: &Arc<RecordingSink>,
) -> ValidatedPlan {
    let plan = SandboxPlan::new(program)
        .args(args.iter().copied())
        .capabilities(capabilities(dir))
        .event_sink(sink.clone() as Arc<dyn EventSink>);
    match plan.validate() {
        Ok(plan) => plan,
        Err(err) => panic!("test plan must validate: {err}"),
    }
}

/// The event kinds, in order, reduced to something an assertion can read.
fn shapes(events: &[LifecycleEvent]) -> Vec<String> {
    events
        .iter()
        .map(|event| match event.what() {
            LifecycleEventKind::StateChanged { from, to } => format!("state_changed:{from}->{to}"),
            LifecycleEventKind::PrepareStarted => "prepare_started".to_string(),
            LifecycleEventKind::SandboxApplied => "sandbox_applied".to_string(),
            LifecycleEventKind::GateReady => "gate_ready".to_string(),
            LifecycleEventKind::ActivationAttempted { outcome } => {
                format!("activation_attempted:{outcome:?}")
            }
            LifecycleEventKind::Released => "released".to_string(),
            LifecycleEventKind::ExecObserved => "exec_observed".to_string(),
            LifecycleEventKind::ChildExited { outcome } => format!("child_exited:{outcome:?}"),
            LifecycleEventKind::StopRequested => "stop_requested".to_string(),
            LifecycleEventKind::StopCgroupFailed { .. } => "stop_cgroup_failed".to_string(),
            LifecycleEventKind::StopObserved { .. } => "stop_observed".to_string(),
            LifecycleEventKind::GateAborted => "gate_aborted".to_string(),
            LifecycleEventKind::SupervisorFailure { stage, errno } => {
                format!("supervisor_failure:{stage}:{errno}")
            }
            LifecycleEventKind::CleanupVerdict { verdict } => {
                format!("cleanup_verdict:{verdict}")
            }
            LifecycleEventKind::RecordPersisted { schema_version } => {
                format!("record_persisted:{schema_version}")
            }
        })
        .collect()
}

/// The envelope invariants every run's stream must satisfy.
fn assert_envelope_is_sound(events: &[LifecycleEvent], session_id: uuid::Uuid, pid: i32) {
    let mut expected_seq = 0_u64;
    let mut previous_time = None;
    for event in events {
        // Strictly increasing *and* gapless: a gap would mean an event was
        // allocated a number and then never handed over, which is the one thing
        // the counter's placement immediately before the sink call rules out.
        assert_eq!(
            event.seq(),
            expected_seq,
            "seq must count this run's events from zero without gaps: {:?}",
            shapes(events)
        );
        expected_seq = expected_seq.saturating_add(1);

        // Advisory, not an ordering key — but a stream whose wall clock ran
        // backwards inside one run would mean the clock was read somewhere
        // other than at the observation.
        if let Some(previous) = previous_time {
            assert!(
                event.observed_at() >= previous,
                "observed_at must not run backwards within a run"
            );
        }
        previous_time = Some(event.observed_at());

        assert_eq!(event.session_id(), Some(session_id));
        assert_eq!(event.generation(), 1);
        assert_eq!(event.observation(), Observation::DirectlyObserved);
        // Only the pre-fork event has no child to name.
        match event.what() {
            LifecycleEventKind::PrepareStarted => assert_eq!(event.identity(), None),
            _ => assert_eq!(
                event.identity().map(ProcessIdentity::pid),
                Some(pid),
                "every event after the fork names the child"
            ),
        }
    }
}

#[test]
fn the_event_sink_observes_the_whole_vocabulary_of_a_happy_run() {
    let dir = temp_dir();
    let sink = Arc::new(RecordingSink::default());
    let (mut held, handle) = prepared(watched_plan(dir.path(), "/bin/echo", &["watched"], &sink));
    let session_id = held.session_id();
    let pid = held.identity().pid();

    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    if let Err(err) = running.wait() {
        panic!("wait must observe the exit: {err}");
    }
    match running.verify_cleanup() {
        Ok(verdict) => assert!(verdict.is_confirmed_absent(), "{verdict:?}"),
        Err(err) => panic!("cleanup verification must be legal after an exit: {err}"),
    }

    let seen = sink.recorded();
    // The whole run, in order. Two properties are load-bearing here: the fact
    // always precedes the state change it caused, and the last events come from
    // the *activated* handle — a sink that stopped hearing about the run at the
    // handoff would go quiet exactly when the program was doing something.
    assert_eq!(
        shapes(&seen),
        vec![
            "prepare_started",
            "sandbox_applied",
            "gate_ready",
            "state_changed:preparing->prepared",
            "activation_attempted:Accepted",
            "state_changed:prepared->activating",
            "released",
            "exec_observed",
            "state_changed:activating->running",
            "child_exited:Exited { code: 0 }",
            "state_changed:running->exited",
            "cleanup_verdict:confirmed_absent",
            "state_changed:exited->cleanup_verified",
        ]
    );
    assert_envelope_is_sound(&seen, session_id, pid);
}

// ---------------------------------------------------------------------------
// 14b. The same, for a run that is stopped rather than allowed to finish.
// ---------------------------------------------------------------------------

#[test]
fn the_event_sink_observes_a_stopped_run_as_a_stop_not_an_exit() {
    let dir = temp_dir();
    let sink = Arc::new(RecordingSink::default());
    let (mut held, handle) = prepared(watched_plan(dir.path(), "/bin/sleep", &["30"], &sink));
    let session_id = held.session_id();
    let pid = held.identity().pid();

    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    match running.stop() {
        Ok(exit) => assert_eq!(
            exit.outcome(),
            ExitOutcome::Signaled {
                signal: libc::SIGKILL
            }
        ),
        Err(err) => panic!("stop must observe the death: {err}"),
    }
    match running.verify_cleanup() {
        Ok(verdict) => assert!(verdict.is_confirmed_absent(), "{verdict:?}"),
        Err(err) => panic!("cleanup verification must be legal after a stop: {err}"),
    }

    let seen = sink.recorded();
    // A stop reports `stop_requested` / `stop_observed`, never `child_exited`:
    // the two are different facts about the same death, and collapsing them
    // would lose which one the consumer asked for.
    assert_eq!(
        shapes(&seen),
        vec![
            "prepare_started",
            "sandbox_applied",
            "gate_ready",
            "state_changed:preparing->prepared",
            "activation_attempted:Accepted",
            "state_changed:prepared->activating",
            "released",
            "exec_observed",
            "state_changed:activating->running",
            "stop_requested",
            "state_changed:running->stopping",
            "stop_observed",
            "state_changed:stopping->stopped",
            "cleanup_verdict:confirmed_absent",
            "state_changed:stopped->cleanup_verified",
        ]
    );
    assert_envelope_is_sound(&seen, session_id, pid);
}

// ---------------------------------------------------------------------------
// 14c. A refused activation is reported, and carries nothing that could
//      release a child.
// ---------------------------------------------------------------------------

#[test]
fn a_refused_activation_is_reported_without_any_token_material() {
    let dir = temp_dir();
    let sink = Arc::new(RecordingSink::default());
    let (mut held, _handle) = prepared(watched_plan(dir.path(), "/bin/echo", &["refused"], &sink));

    // A real handle, from a real second run: the token in it is genuine, and
    // this is the path where a careless implementation would report it.
    let other = temp_dir();
    let (_second, foreign) = prepared(plan(other.path(), "/bin/echo", &["other"]));
    assert!(
        held.activate(&foreign).is_err(),
        "a foreign handle must be refused"
    );

    let seen = sink.recorded();
    let attempts: Vec<&LifecycleEvent> = seen
        .iter()
        .filter(|event| matches!(event.what(), LifecycleEventKind::ActivationAttempted { .. }))
        .collect();
    assert_eq!(attempts.len(), 1, "one attempt, one event");
    assert_eq!(
        shapes(&seen).last().map(String::as_str),
        Some("activation_attempted:RefusedWrongSession")
    );

    // Serialized, because that is the form a consumer forwards or logs.
    let json = match serde_json::to_string(attempts[0]) {
        Ok(json) => json,
        Err(err) => panic!("an event must serialize: {err}"),
    };
    assert_eq!(
        json.matches("token").count(),
        0,
        "no field of a refusal may name the token: {json}"
    );
}

// ---------------------------------------------------------------------------
// 15. R11: the child leads its own process group.
// ---------------------------------------------------------------------------

#[test]
fn a_prepared_child_leads_a_process_group_of_its_own() {
    // Everything R11 rests on. Without the child's `setpgid(0, 0)` there is no
    // group to signal on a stop and nothing to probe after the pid is reaped —
    // the child would simply stay in the supervisor's own group, and the
    // assertions below would see that.
    let dir = temp_dir();
    let (held, _handle) = prepared(plan(dir.path(), "/bin/echo", &["grouped"]));
    let pid = held.identity().pid();

    // SAFETY: `pid` is this process's live, unreaped child; `getpgid` only
    // reads its process group.
    let child_group = unsafe { libc::getpgid(pid) };
    // SAFETY: `getpgrp` takes no arguments, touches no memory, and cannot fail.
    let supervisor_group = unsafe { libc::getpgrp() };

    assert_eq!(
        child_group, pid,
        "the held child must be its own group leader, so its group id is its pid"
    );
    assert_ne!(
        child_group, supervisor_group,
        "a child left in the supervisor's group would make a stop signal the supervisor"
    );
}

// ---------------------------------------------------------------------------
// 16. R11: an observed exit is verified absent, exactly once.
// ---------------------------------------------------------------------------

#[test]
fn an_observed_exit_verifies_absent_and_refuses_a_second_verification() {
    let dir = temp_dir();
    let (mut held, handle) = prepared(plan(dir.path(), "/bin/echo", &["verified"]));
    // The group id is the child's pid: the child made itself the leader.
    let pgid = held.identity().pid();

    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };

    // Before the exit is observed there is nothing to verify, and the library
    // says so instead of probing a live run.
    assert_eq!(
        running.verify_cleanup().err(),
        Some(CleanupError {
            state: LifecycleState::Running
        })
    );

    match running.wait() {
        Ok(exit) => assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 }),
        Err(err) => panic!("wait must observe the exit: {err}"),
    }

    assert_eq!(
        running.verify_cleanup(),
        Ok(CleanupVerification::ConfirmedAbsent {
            basis: AbsenceBasis::ReapedAndGroupEmpty { pgid }
        })
    );
    assert_eq!(running.state(), LifecycleState::CleanupVerified);

    // A second verification is refused rather than absorbed: counting one proof
    // twice is a caller bug worth seeing.
    assert_eq!(
        running.verify_cleanup().err(),
        Some(CleanupError {
            state: LifecycleState::CleanupVerified
        })
    );

    // The prepared handle froze at the handoff and does not own this run's end,
    // so it refuses too rather than answering about a run it stopped following.
    assert_eq!(
        held.verify_cleanup().err(),
        Some(CleanupError {
            state: LifecycleState::Running
        })
    );
}

// ---------------------------------------------------------------------------
// 17. R11: a survivor is reported, not killed and not rounded down.
// ---------------------------------------------------------------------------

#[test]
fn a_survivor_in_the_group_is_reported_until_it_is_really_gone() {
    let dir = temp_dir();
    // A shell, because the caller asked for one by name — nono runs the program
    // it was given and still passes the arguments literally. This one exits
    // immediately and leaves a child behind, which is the whole point: the
    // process nono waited for is gone while the run is not.
    let (mut held, handle) = prepared(plan(
        dir.path(),
        "/bin/sh",
        &["-c", "/bin/sleep 30 & exit 0"],
    ));
    let pgid = held.identity().pid();

    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    match running.wait() {
        Ok(exit) => assert_eq!(
            exit.outcome(),
            ExitOutcome::Exited { code: 0 },
            "the shell itself exited cleanly"
        ),
        Err(err) => panic!("wait must observe the exit: {err}"),
    }

    // The direct child was reaped, so a pid-only check would report "gone".
    // The group probe is what makes the answer honest.
    assert_eq!(
        running.verify_cleanup(),
        Ok(CleanupVerification::StillPresent {
            survivors: SurvivorEvidence::ProcessGroupMember { pgid }
        })
    );
    assert_eq!(
        running.state(),
        LifecycleState::Exited,
        "a survivor must never be recorded as verified cleanup"
    );

    // Verification observes; acting on what it found is the consumer's move.
    // SAFETY: `pgid` is the group nono recorded for this run and the run's own
    // leader is already reaped, so the signal reaches the run's leftovers.
    assert_eq!(unsafe { libc::killpg(pgid, libc::SIGKILL) }, 0);
    assert!(
        wait_until_group_gone(pgid, GONE_TIMEOUT),
        "the group survived a SIGKILL"
    );

    // Same call, different fact — because the world changed, not because the
    // library gave up.
    assert_eq!(
        running.verify_cleanup(),
        Ok(CleanupVerification::ConfirmedAbsent {
            basis: AbsenceBasis::ReapedAndGroupEmpty { pgid }
        })
    );
    assert_eq!(running.state(), LifecycleState::CleanupVerified);
}

// ---------------------------------------------------------------------------
// 18. R11: stopping a running program ends the whole group.
// ---------------------------------------------------------------------------

#[test]
fn stopping_a_running_program_kills_its_group_and_verifies_absent() {
    let dir = temp_dir();
    let (mut held, handle) = prepared(plan(dir.path(), "/bin/sleep", &["30"]));
    let pgid = held.identity().pid();

    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };

    let exit = match running.stop() {
        Ok(exit) => exit,
        Err(err) => panic!("stop must end a running program: {err}"),
    };
    // The observed death, not the request: `SIGKILL` is reported as a signal
    // and never as `Exited { code: 137 }`.
    assert_eq!(exit.outcome(), ExitOutcome::Signaled { signal: 9 });
    // A signal can land on either side of `execve`, so the activation question
    // stays where activation left it rather than being sharpened by a kill.
    assert_eq!(
        exit.activation(),
        ActivationObservation::ExecOrKilledPreExec
    );
    assert_eq!(running.state(), LifecycleState::Stopped);
    assert!(
        wait_until_group_gone(pgid, GONE_TIMEOUT),
        "a stop must leave nothing in the run's process group"
    );

    // The run already ended, so a second stop is refused by the state machine
    // rather than sending a signal at a reaped pid.
    assert_eq!(
        running.stop().err(),
        Some(StopError::NotStoppable {
            state: LifecycleState::Stopped
        })
    );

    assert_eq!(
        running.verify_cleanup(),
        Ok(CleanupVerification::ConfirmedAbsent {
            basis: AbsenceBasis::ReapedAndGroupEmpty { pgid }
        })
    );
    assert_eq!(running.state(), LifecycleState::CleanupVerified);
}

// ---------------------------------------------------------------------------
// 19. R11: a child stopped before activation is verifiable too.
// ---------------------------------------------------------------------------

#[test]
fn a_child_stopped_before_activation_verifies_absent() {
    let dir = temp_dir();
    let marker = dir.path().join("never-run-marker");
    let marker_arg = marker.to_string_lossy().into_owned();

    let (mut held, _handle) = prepared(plan(dir.path(), "/usr/bin/touch", &[&marker_arg]));
    let pgid = held.identity().pid();

    // Nothing may be claimed while the child is still held at the gate.
    assert_eq!(
        held.verify_cleanup().err(),
        Some(CleanupError {
            state: LifecycleState::Prepared
        })
    );

    if let Err(err) = held.stop_before_activation() {
        panic!("stop must succeed on a held child: {err}");
    }
    assert_eq!(held.state(), LifecycleState::Stopped);

    assert_eq!(
        held.verify_cleanup(),
        Ok(CleanupVerification::ConfirmedAbsent {
            basis: AbsenceBasis::ReapedAndGroupEmpty { pgid }
        })
    );
    assert_eq!(held.state(), LifecycleState::CleanupVerified);
    assert!(!marker.exists(), "a stopped child must never have run");
}

// ---------------------------------------------------------------------------
// 20. F7: dropping a running handle ends the whole group, not just the pid.
// ---------------------------------------------------------------------------

#[test]
fn dropping_an_activated_sandbox_kills_the_whole_process_group() {
    // The shell exits immediately and leaves a `sleep` behind in the run's
    // process group. A drop that signalled only the pid `waitpid` knows about
    // would reap the shell, report the run over, and leave the sleep running —
    // which is exactly what `stop()` refuses to do, and a drop must not be a
    // quietly weaker guarantee than a stop.
    let dir = temp_dir();
    let pgid = {
        let (mut held, handle) = prepared(plan(
            dir.path(),
            "/bin/sh",
            &["-c", "/bin/sleep 30 & exec /bin/sleep 30"],
        ));
        let pgid = held.identity().pid();
        let running = match held.activate(&handle) {
            Ok(running) => running,
            Err(err) => panic!("activation must succeed: {err}"),
        };
        // Give the shell time to fork its child and exec, so the group really
        // has two members when the drop below happens.
        std::thread::sleep(HOLD_OBSERVATION);
        // SAFETY: signal 0 checks existence and permission without delivering
        // anything; `pgid` is the group this run was prepared into.
        assert_eq!(
            unsafe { libc::killpg(pgid, 0) },
            0,
            "the run's group must be alive before the drop"
        );
        drop(running);
        pgid
    };

    assert!(
        wait_until_group_gone(pgid, GONE_TIMEOUT),
        "a dropped activated sandbox left a descendant running"
    );
}

// ---------------------------------------------------------------------------
// 21. R09: a durable session follows the whole run, on disk.
// ---------------------------------------------------------------------------

#[test]
fn a_durable_session_records_every_state_the_run_passes_through() {
    let dir = temp_dir();
    let store = match SessionStore::open(&dir.path().join("sessions")) {
        Ok(store) => store,
        Err(err) => panic!("store must open: {err}"),
    };

    let (mut held, handle) = match store.prepare(plan(dir.path(), "/bin/echo", &["durable"])) {
        Ok(pair) => pair,
        Err(err) => panic!("durable prepare must succeed: {err}"),
    };
    let session_id = held.session_id();
    let pid = held.identity().pid();

    // Reading through a *separate* store handle throughout: what a recovering
    // process would see, not what this one remembers.
    let reader = match SessionStore::open(&dir.path().join("sessions")) {
        Ok(store) => store,
        Err(err) => panic!("store must reopen: {err}"),
    };
    let read = |what: &str| -> SessionRecord {
        let mut found = None;
        let sessions = match reader.sessions() {
            Ok(sessions) => sessions,
            Err(err) => panic!("enumeration must start ({what}): {err}"),
        };
        for summary in sessions {
            match summary {
                Ok(summary) if summary.session_id() == session_id => {
                    found = Some(summary.record().clone());
                }
                Ok(_) => {}
                Err(err) => panic!("record must load ({what}): {err}"),
            }
        }
        match found {
            Some(record) => record,
            None => panic!("the session must be enumerable ({what})"),
        }
    };

    let at_prepare = read("prepared");
    assert_eq!(at_prepare.state(), LifecycleState::Prepared);
    assert_eq!(at_prepare.identity().pid(), pid);
    assert_eq!(at_prepare.process_group(), pid);
    assert_eq!(at_prepare.generation(), 1);
    assert_eq!(at_prepare.activation(), None, "nothing has run yet");

    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    let at_activate = read("running");
    assert_eq!(at_activate.state(), LifecycleState::Running);
    assert_eq!(
        at_activate.activation(),
        Some(ActivationObservation::ExecOrKilledPreExec),
        "the honest answer until the exit status sharpens it"
    );

    match running.wait() {
        Ok(exit) => assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 }),
        Err(err) => panic!("wait must observe the exit: {err}"),
    }
    let at_exit = read("exited");
    assert_eq!(at_exit.state(), LifecycleState::Exited);
    assert_eq!(
        at_exit.activation(),
        Some(ActivationObservation::Observed),
        "a normal exit is what settles the activation question"
    );

    match running.verify_cleanup() {
        Ok(verdict) => assert!(verdict.is_confirmed_absent(), "{verdict:?}"),
        Err(err) => panic!("cleanup verification must be legal after an exit: {err}"),
    }
    let at_cleanup = read("cleanup-verified");
    assert_eq!(at_cleanup.state(), LifecycleState::CleanupVerified);
    assert!(
        at_cleanup.updated_unix_millis() >= at_prepare.created_unix_millis(),
        "the record's own timeline must not run backwards"
    );

    // The run is over and proven over, so a recovery adopts nothing.
    match reader.recover(session_id) {
        Ok(recovered) => assert_eq!(recovered.decision(), RecoveryDecision::AlreadyVerified),
        Err(err) => panic!("recovery must succeed: {err}"),
    }
}

// ---------------------------------------------------------------------------
// Refusals that never reach a fork.
// ---------------------------------------------------------------------------

#[test]
fn a_program_that_is_not_an_absolute_path_is_refused_before_forking() {
    let dir = temp_dir();
    let plan = plan(dir.path(), "echo", &["hello"]);
    assert_eq!(
        PreparedSandbox::prepare(plan).err(),
        Some(PrepareError::ProgramNotAbsolute {
            program: "echo".to_string()
        }),
        "the library must never search PATH"
    );
}

/// A run placed under a caller-named parent lands *there*, not at the root.
///
/// This is what makes an out-of-process enforcement attachment reachable. A
/// cgroup created at the cgroup2 root shares no ancestor with one created
/// anywhere else, so a BPF program attached to a cgroup by another process
/// governs nothing a root-placed run does. The caller names the cgroup it
/// attached to; the run has to land underneath it.
///
/// The observation is the kernel's, not the library's: the child's pid is read
/// back out of `cgroup.procs` under the parent. Asserting only on the path the
/// library reports would pass on a build that computed a nice-looking path and
/// placed the child somewhere else.
///
/// Mutation check: delete the `cgroup_parent` plumbing and the run lands at
/// `/sys/fs/cgroup/nono-<uuid>`, the directory under the parent never exists,
/// and the read fails. The test cannot pass on a build that ignores the field.
///
/// Compiled on every platform and skipped at runtime, rather than `#[cfg]`d
/// out. A test that only compiles on Linux is a test whose types are only
/// checked by CI, and this one shipped a `held` that was not `mut` past a green
/// macOS run because of exactly that.
#[test]
fn a_run_lands_under_the_cgroup_parent_its_plan_named() {
    if !cfg!(target_os = "linux") {
        println!(
            "NOT_APPLICABLE: no cgroups on this platform. The refusal is what this \
             platform promises, and \
             a_cgroup_parent_is_refused_on_a_platform_without_cgroups asserts it."
        );
        return;
    }
    let dir = temp_dir();
    let parent = std::path::PathBuf::from(format!(
        "/sys/fs/cgroup/nono-parent-test-{}",
        std::process::id()
    ));

    // A host that will not give this process a cgroup cannot answer the
    // question. That is reported, never treated as a pass: a test that is
    // silently skipped is a test that stopped being evidence.
    if let Err(err) = std::fs::create_dir(&parent) {
        println!(
            "INCONCLUSIVE: cannot create {}: {err}. \
             This test needs write access to the cgroup2 root; it proves nothing here.",
            parent.display()
        );
        return;
    }

    let validated = match SandboxPlan::new("/bin/sleep")
        .args(["30"])
        .capabilities(capabilities(dir.path()))
        .cgroup_parent(&parent)
        .validate()
    {
        Ok(validated) => validated,
        Err(err) => {
            let _ = std::fs::remove_dir(&parent);
            panic!("plan must validate: {err}");
        }
    };

    let (mut held, handle) = prepared(validated);
    assert_eq!(
        held.cgroup_parent(),
        Some(parent.as_path()),
        "the prepared run must carry the parent its plan named"
    );

    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => {
            let _ = std::fs::remove_dir(&parent);
            panic!("activation must succeed: {err}");
        }
    };

    let placed = running.cgroup_path().map(std::path::Path::to_path_buf);
    let pid = running.identity().pid();
    let members = placed
        .as_ref()
        .and_then(|path| std::fs::read_to_string(path.join("cgroup.procs")).ok());

    // Stop the run before asserting, so a failed assertion does not leave a
    // sleeping child and a cgroup that cannot be removed.
    let _ = running.stop();
    let _ = wait_until_gone(pid, GONE_TIMEOUT);
    if let Some(path) = &placed {
        let _ = std::fs::remove_dir(path);
    }
    let _ = std::fs::remove_dir(&parent);

    let Some(placed) = placed else {
        panic!(
            "the run asked for a cgroup under {} and got none",
            parent.display()
        );
    };
    assert!(
        placed.starts_with(&parent),
        "run landed at {}, which is not under {}",
        placed.display(),
        parent.display()
    );

    // The kernel's answer, not the library's. `cgroup.procs` lists the pids the
    // kernel considers members; the child's pid being in it is the placement.
    let Some(members) = members else {
        panic!("could not read cgroup.procs under {}", placed.display());
    };
    assert!(
        members.lines().any(|line| line.trim() == pid.to_string()),
        "pid {pid} is not a member of {}; cgroup.procs held {members:?}",
        placed.display()
    );
}

/// A relative cgroup parent is refused, not resolved against the caller's
/// working directory.
#[test]
fn a_relative_cgroup_parent_is_refused_by_validation() {
    let dir = temp_dir();
    let err = SandboxPlan::new("/bin/true")
        .capabilities(capabilities(dir.path()))
        .cgroup_parent("relative/cgroup")
        .validate()
        .err();
    assert!(
        matches!(
            err,
            Some(nono::lifecycle::PlanError::RelativeCgroupParent { .. })
        ),
        "a relative cgroup parent must be refused, got {err:?}"
    );
}

/// On a platform with no cgroups, asking for a parent is refused at
/// preparation rather than accepted and quietly ignored.
///
/// The caller asked for the run to land under an attachment. Running it
/// somewhere else and saying nothing is the silent downgrade this crate
/// refuses to make.
///
/// Compiled everywhere and skipped at runtime for the same reason as
/// `a_run_lands_under_the_cgroup_parent_its_plan_named`: a `#[cfg]`d-out test
/// is one whose types only one CI lane ever checks.
#[test]
fn a_cgroup_parent_is_refused_on_a_platform_without_cgroups() {
    if cfg!(target_os = "linux") {
        println!("NOT_APPLICABLE: this platform has cgroups, so it honours the request.");
        return;
    }
    let dir = temp_dir();
    let validated = match SandboxPlan::new("/bin/true")
        .capabilities(capabilities(dir.path()))
        .cgroup_parent("/sys/fs/cgroup/somewhere")
        .validate()
    {
        Ok(validated) => validated,
        Err(err) => panic!("plan must validate: {err}"),
    };
    let err = PreparedSandbox::prepare(validated).err();
    assert!(
        matches!(
            err,
            Some(PrepareError::UnsupportedPlanFeature {
                feature: "cgroup parent"
            })
        ),
        "expected a refusal naming the feature, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 13. A workload uid drop changes the identity the program runs as.
// ---------------------------------------------------------------------------

/// The uid the workload should run as, distinct from the daemon uid (0 here)
/// that owns its cgroup. `nobody` conventionally, and `setresuid` takes a
/// numeric id, so the account need not exist for the drop to take.
const WORKLOAD_UID: u32 = 65534;

/// A run given a `workload_uid` execs as that uid, not as the forking process.
///
/// This is what closes the cgroup self-migration escape: the workload's euid
/// differs from the daemon uid that owns its cgroup, so it cannot write its own
/// pid into a sibling `cgroup.procs` and walk out of the placement. The proof
/// is the kernel's, not the library's — the program reports `id -u`/`id -g`,
/// and the numbers it wrote are read back here. Asserting only that activation
/// reached `Observed` would pass on a build that never dropped, because the
/// child's own readback (which gates the `execve`) would be the only witness.
///
/// Mutation check: delete the drop block in `child_main` and the program runs
/// as uid 0, the file holds `0`, and the assertion fails. Reorder it to set the
/// uid before the gid and a non-root run would half-drop; here it is exercised
/// under root, where the readback guard is what a partial drop trips on.
///
/// Compiled on every platform and skipped at runtime, for the reason the cgroup
/// placement test spells out: a `#[cfg]`d-out test is one whose types only the
/// Linux CI lane ever checks. Needs `CAP_SETUID`, so it is INCONCLUSIVE for an
/// unprivileged runner and runs for real on the root Linux rig.
#[test]
fn a_workload_uid_drop_makes_the_program_run_as_that_uid() {
    if !cfg!(target_os = "linux") {
        println!(
            "NOT_APPLICABLE: the drop is setresuid/setresgid, which this platform's \
             libc does not have; a_workload_uid_is_refused_without_the_syscalls_to_make_it \
             asserts the refusal instead."
        );
        return;
    }
    // SAFETY: `geteuid` reads a per-process id and touches no memory.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        println!(
            "INCONCLUSIVE: dropping to another uid needs CAP_SETUID, which a process \
             running as {euid} does not hold; this test proves nothing here."
        );
        return;
    }
    // The invariant the drop exists to create: a target that is neither the
    // daemon uid (0) nor the identity we start with.
    assert_ne!(
        WORKLOAD_UID, euid,
        "the drop target must differ from our uid"
    );

    let dir = temp_dir();
    // The workload writes as `WORKLOAD_UID`, so the directory it writes into has
    // to admit that identity: the temp dir is created 0700 for the runner, and a
    // dropped `nobody` could not create a file under it otherwise. The Landlock
    // read-write grant is orthogonal — it still applies after the drop — so both
    // the DAC bits and the policy have to permit the write.
    if let Err(err) = std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o777),
    ) {
        println!("INCONCLUSIVE: could not widen the temp dir for the dropped uid: {err}");
        return;
    }

    let out = dir.path().join("ids");
    // `id -u`/`id -g` report the *effective* ids, which the full r/e/s drop sets
    // together; the file carries the uid then the gid, one per line.
    let script = format!("id -u > {out}; id -g >> {out}", out = out.display());
    let validated = match SandboxPlan::new("/bin/sh")
        .args(["-c", script.as_str()])
        .capabilities(capabilities(dir.path()))
        // Nothing is inherited, so `id` is only found if a search path is
        // granted; the drop does not change where a binary lives.
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .workload_uid(WORKLOAD_UID)
        .validate()
    {
        Ok(validated) => validated,
        Err(err) => panic!("plan must validate: {err}"),
    };

    let (mut held, handle) = prepared(validated);
    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    let exit = match running.wait() {
        Ok(exit) => exit,
        Err(err) => panic!("wait must observe the exit: {err}"),
    };
    // A clean exit means the child reached `execve` — which it only does after
    // its own readback confirmed the drop to `WORKLOAD_UID` took hold.
    assert_eq!(exit.activation(), ActivationObservation::Observed);
    assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 });

    let written = match std::fs::read_to_string(&out) {
        Ok(written) => written,
        Err(err) => panic!("the workload should have written its ids: {err}"),
    };
    let mut lines = written.lines();
    assert_eq!(
        lines.next(),
        Some(WORKLOAD_UID.to_string().as_str()),
        "the program's effective uid was not the one the plan named; file held {written:?}"
    );
    assert_eq!(
        lines.next(),
        Some(WORKLOAD_UID.to_string().as_str()),
        "the program's effective gid was not the one the plan named; file held {written:?}"
    );
}

/// Without the privilege to make the drop, the run refuses before `execve`.
///
/// The whole point is fail-closed: a `workload_uid` that cannot be reached must
/// stop the run, never exec the workload with the wrong identity still on it. An
/// unprivileged process has no `CAP_SETGID`/`CAP_SETUID`, so the very first
/// syscall of the drop — `setgroups` — returns `EPERM`, and the child dies at
/// [`PreExecStage::DropPrivileges`] rather than running the program.
///
/// Only observable without the capability, so this is the mirror of the
/// positive test: exactly one of the two runs for real in a given environment,
/// and the other reports why it could not. Under a root runner the drop always
/// succeeds, so the refusal cannot be provoked and the test is INCONCLUSIVE.
#[test]
fn a_workload_uid_is_refused_without_the_privilege_to_make_it() {
    if !cfg!(target_os = "linux") {
        println!(
            "NOT_APPLICABLE: the drop is a Linux-only syscall sequence; a_workload_uid \
             plan is refused at preparation here, not at the gate."
        );
        return;
    }
    // SAFETY: `geteuid` reads a per-process id and touches no memory.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        println!(
            "INCONCLUSIVE: root can always make the drop, so its refusal cannot be \
             provoked; this case is only observable without CAP_SETUID."
        );
        return;
    }
    // A target that is not the identity we already hold, so the drop is a real
    // change the kernel must authorise rather than a no-op it waves through.
    let target = if euid == WORKLOAD_UID {
        WORKLOAD_UID.saturating_sub(1)
    } else {
        WORKLOAD_UID
    };

    let dir = temp_dir();
    // `/bin/echo` need only exist for prepare's advisory check; the drop fails
    // before the working directory or the `execve`, so it never runs.
    let validated = match SandboxPlan::new("/bin/echo")
        .args(["never printed"])
        .capabilities(capabilities(dir.path()))
        .workload_uid(target)
        .validate()
    {
        Ok(validated) => validated,
        Err(err) => panic!("plan must validate: {err}"),
    };

    let (mut held, handle) = prepared(validated);
    let pid = held.identity().pid();

    let error = held.activate(&handle).err();
    assert_eq!(
        error,
        Some(ActivationError::PreExecFailed {
            stage: PreExecStage::DropPrivileges,
            errno: libc::EPERM,
        }),
        "an unprivileged drop must fail closed at the drop stage"
    );
    assert_eq!(held.state(), LifecycleState::Failed);
    assert!(
        wait_until_gone(pid, GONE_TIMEOUT),
        "the child was not reaped"
    );

    match held.exit() {
        Some(exit) => {
            assert_eq!(
                exit.activation(),
                ActivationObservation::NotActivated,
                "the child said where it stopped, so this is a fact not a guess"
            );
            assert_eq!(
                exit.outcome(),
                ExitOutcome::PreExecFailure {
                    stage: PreExecStage::DropPrivileges,
                    errno: libc::EPERM,
                }
            );
        }
        None => panic!("a failed activation must record its exit facts"),
    }
}
