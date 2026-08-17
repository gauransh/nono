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
    ActivationError, ActivationObservation, EventSink, ExitOutcome, GateConfig, LifecycleEvent,
    LifecycleState, PreExecStage, PrepareError, PreparedSandbox, SandboxPlan, StopError,
    ValidatedPlan,
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
// 14. The consumer's event sink sees the whole run.
// ---------------------------------------------------------------------------

#[test]
fn the_event_sink_observes_every_state_change_including_the_exit() {
    #[derive(Default)]
    struct RecordingSink {
        seen: Mutex<Vec<(LifecycleState, LifecycleState)>>,
    }

    impl EventSink for RecordingSink {
        fn emit(&self, event: &LifecycleEvent) {
            let LifecycleEvent::StateChanged { from, to, .. } = event;
            if let Ok(mut seen) = self.seen.lock() {
                seen.push((*from, *to));
            }
        }
    }

    let dir = temp_dir();
    let sink = Arc::new(RecordingSink::default());
    let plan = SandboxPlan::new("/bin/echo")
        .arg("watched")
        .capabilities(capabilities(dir.path()))
        .event_sink(sink.clone() as Arc<dyn EventSink>);
    let plan = match plan.validate() {
        Ok(plan) => plan,
        Err(err) => panic!("test plan must validate: {err}"),
    };

    let (mut held, handle) = prepared(plan);
    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    if let Err(err) = running.wait() {
        panic!("wait must observe the exit: {err}");
    }

    let seen = match sink.seen.lock() {
        Ok(seen) => seen.clone(),
        Err(err) => panic!("the sink's records must be readable: {err}"),
    };
    // The last transition is emitted by the activated handle, not the prepared
    // one: a sink that stopped hearing about the run at the handoff would go
    // quiet exactly when the program was doing something.
    assert_eq!(
        seen,
        vec![
            (LifecycleState::Preparing, LifecycleState::Prepared),
            (LifecycleState::Prepared, LifecycleState::Activating),
            (LifecycleState::Activating, LifecycleState::Running),
            (LifecycleState::Running, LifecycleState::Exited),
        ]
    );
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
