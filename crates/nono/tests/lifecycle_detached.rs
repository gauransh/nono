//! Live detached-supervisor tests: real re-execs, real sockets, real deaths.
//!
//! # Why this target has no libtest harness
//!
//! A detached prepare re-executes `current_exe()` and expects the new image to
//! become a supervisor. It does that only if
//! [`nono::lifecycle::supervisor_entry`] is called at the top of `main` — that
//! is ADR-0002's one line of embedder cooperation, and it is deliberately not
//! something the library can arrange for itself. libtest owns `main` and offers
//! no pre-main hook, so this target sets `harness = false` in `Cargo.toml` and
//! brings its own `main`, which installs the hook on its first line.
//!
//! The same `main` is what makes the R09 core proof possible. Test (b) needs a
//! process that prepares a detached session and then *dies*, so it re-runs this
//! very binary with a private environment flag, has it print the session id and
//! the activation token, and lets it exit. Everything after that happens in a
//! process that never forked anything involved.
//!
//! # Timeouts
//!
//! Every wait here is bounded. A detached-supervisor bug that parks a caller is
//! exactly the failure this slice exists to prevent, so a test that hung would
//! be reporting success in the least useful way available.

use nono::lifecycle::{
    ActivationError, ActivationHandle, ActivationObservation, CleanupVerification, ControlRefusal,
    ControlReply, ControlRequest, DetachedError, ExitOutcome, LifecycleError, LifecycleState,
    MAX_CONTROL_FRAME_BYTES, PrepareError, RecoveryDecision, SandboxPlan, SessionStore,
    SupervisorPresence, ValidatedPlan, WaitOutcome,
};
use nono::{AccessMode, CapabilitySet};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// The private flag that turns this binary into the launcher of test (b).
///
/// Test scaffolding, not library protocol: the library's own marker is
/// `NONO_LIFECYCLE_SUPERVISOR` and is set only by the launcher inside `nono`.
const LAUNCHER_FLAG: &str = "NONO_DETACHED_TEST_LAUNCHER";

/// How long any test waits for a process or a fact before giving up.
const PATIENCE: Duration = Duration::from_secs(10);

/// How long a test waits when it expects *nothing* to happen.
const BRIEF: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

fn main() {
    // First line, before anything else — including the launcher branch below.
    // This is the call every embedder makes, and the reason a detached prepare
    // from this binary works at all.
    nono::lifecycle::supervisor_entry();

    if let Some(store) = std::env::var_os(LAUNCHER_FLAG) {
        run_as_launcher(Path::new(&store));
        return;
    }

    let tests: Vec<(&str, fn())> = vec![
        (
            "a_detached_run_activates_waits_and_reports_a_real_exit",
            a_detached_run_activates_waits_and_reports_a_real_exit,
        ),
        (
            "a_session_outlives_the_process_that_prepared_it",
            a_session_outlives_the_process_that_prepared_it,
        ),
        (
            "an_exit_that_happened_while_detached_is_there_on_reconnect",
            an_exit_that_happened_while_detached_is_there_on_reconnect,
        ),
        (
            "a_stop_before_activation_makes_activation_impossible_forever",
            a_stop_before_activation_makes_activation_impossible_forever,
        ),
        (
            "a_replayed_activation_is_refused_by_the_gate_over_the_socket",
            a_replayed_activation_is_refused_by_the_gate_over_the_socket,
        ),
        (
            "a_hello_from_another_protocol_version_is_refused",
            a_hello_from_another_protocol_version_is_refused,
        ),
        (
            "a_hello_for_another_session_or_generation_is_refused",
            a_hello_for_another_session_or_generation_is_refused,
        ),
        (
            "an_oversize_frame_is_refused_without_being_read",
            an_oversize_frame_is_refused_without_being_read,
        ),
        (
            "a_garbage_frame_is_refused_as_malformed",
            a_garbage_frame_is_refused_as_malformed,
        ),
        (
            "an_operation_before_the_hello_is_refused",
            an_operation_before_the_hello_is_refused,
        ),
        (
            "a_second_concurrent_client_is_told_it_is_busy",
            a_second_concurrent_client_is_told_it_is_busy,
        ),
        (
            "a_killed_supervisor_leaves_a_stale_socket_that_recovery_removes",
            a_killed_supervisor_leaves_a_stale_socket_that_recovery_removes,
        ),
        (
            "an_undetached_plan_is_refused_by_the_detaching_entry_point",
            an_undetached_plan_is_refused_by_the_detaching_entry_point,
        ),
        (
            "a_detached_plan_is_refused_by_the_entry_points_that_cannot_supervise",
            a_detached_plan_is_refused_by_the_entry_points_that_cannot_supervise,
        ),
        (
            "the_event_ring_survives_a_disconnect",
            the_event_ring_survives_a_disconnect,
        ),
    ];

    // What stays unproven is only the *kernel's* half: a test process cannot
    // conjure a second uid, so `SO_PEERCRED`/`getpeereid` reporting a foreign
    // one has never been observed here. Everything above that is covered, and
    // removal-detected, in `lifecycle/supervisor.rs`: the decision table
    // (`a_peer_of_another_uid_is_closed_without_a_word`) and — since the
    // credential source has a test-only injection seam — the *live* accept path
    // itself (`the_live_accept_path_consults_the_peer_credential`, which fails
    // if the `peer_uid` call or the decision consult is removed). Named here
    // per the R18 convention rather than left implicit.
    let ignored: &[(&str, &str)] = &[(
        "a_connection_from_another_uid_is_closed_end_to_end",
        "requires a second uid; the accept path's own guard is removal-detected in \
         lifecycle/supervisor.rs",
    )];

    let filter: Option<String> = std::env::args().skip(1).find(|arg| !arg.starts_with('-'));
    let mut failures = Vec::new();
    let mut ran = 0_usize;

    for (name, test) in tests {
        if filter
            .as_ref()
            .is_some_and(|needle| !name.contains(needle.as_str()))
        {
            continue;
        }
        ran = ran.saturating_add(1);
        print!("test {name} ... ");
        let _ = std::io::stdout().flush();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(test)) {
            Ok(()) => println!("ok"),
            Err(_) => {
                println!("FAILED");
                failures.push(name);
            }
        }
    }
    for (name, why) in ignored {
        println!("test {name} ... ignored, {why}");
    }

    println!(
        "\ntest result: {}. {} passed; {} failed; {} ignored",
        if failures.is_empty() { "ok" } else { "FAILED" },
        ran.saturating_sub(failures.len()),
        failures.len(),
        ignored.len()
    );
    if !failures.is_empty() {
        for name in &failures {
            println!("  failed: {name}");
        }
        std::process::exit(1);
    }
}

/// This binary, acting as the doomed launcher of test (b).
///
/// Prepares a detached session, prints what the *next* process needs to reach
/// it, and exits. Nothing is activated and nothing is waited for here — that is
/// the point.
fn run_as_launcher(store_path: &Path) {
    let store = match SessionStore::open(store_path) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("launcher: store: {err}");
            std::process::exit(2);
        }
    };
    let (session, handle) =
        match store.prepare_detached(detached_plan(store_path, "/usr/bin/true", &[])) {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("launcher: prepare_detached: {err}");
                std::process::exit(3);
            }
        };
    // The session id and the token, because the process that activates a
    // detached run is whichever one holds the token — and here that is
    // deliberately not this one.
    println!("{} {}", session.session_id(), hex(handle.token()));
    let _ = std::io::stdout().flush();
    // Dropped, not detached: a caller that crashes does not say goodbye, and
    // the run must survive that too.
    std::mem::forget(session);
    std::process::exit(0);
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// A private store directory with a path short enough for a Unix socket.
///
/// `tempfile`'s default root on macOS is `/var/folders/<random>/<random>/T`,
/// which leaves fewer than the 41 bytes a `<uuid>.sock` name needs inside the
/// 104-byte `sun_path`. This keeps the whole path under thirty characters, so
/// the socket-path bound is exercised by its own unit test rather than by every
/// test in this file failing on macOS.
struct TempStore {
    path: PathBuf,
}

impl TempStore {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let path = PathBuf::from(format!(
            "/tmp/nono-d{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        // Not `create_dir_all`: a name already there is a name something else
        // chose, and the store's own owner and mode checks should never be the
        // first thing to notice that.
        if let Err(err) = std::fs::DirBuilder::new().mode(0o700).create(&path) {
            panic!("test store {} must be creatable: {err}", path.display());
        }
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn open(&self) -> SessionStore {
        match SessionStore::open(&self.path) {
            Ok(store) => store,
            Err(err) => panic!("store must open: {err}"),
        }
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        // Retried, because the thing being removed is shared with a *process*
        // this test does not wait for: a supervisor that has just been told to
        // verify cleanup still has one record write and one socket unlink to
        // make, and a `remove_dir_all` that listed the directory before that
        // rename lands leaves the recreated record behind. Not a race in the
        // library — the supervisor is doing exactly what it promised — but one
        // this fixture has to outlast rather than ignore.
        let deadline = Instant::now() + PATIENCE;
        loop {
            if std::fs::remove_dir_all(&self.path).is_ok() || !self.path.exists() {
                return;
            }
            if Instant::now() >= deadline {
                eprintln!("warning: {} could not be removed", self.path.display());
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
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

fn detached_plan(writable: &Path, program: &str, args: &[&str]) -> ValidatedPlan {
    let plan = SandboxPlan::new(program)
        .args(args.iter().copied())
        .detached(true)
        .capabilities(capabilities(writable));
    match plan.validate() {
        Ok(plan) => plan,
        Err(err) => panic!("test plan must validate: {err}"),
    }
}

/// A detached `/usr/bin/true`, prepared and connected.
fn detached_true(
    store: &SessionStore,
    writable: &Path,
) -> (nono::lifecycle::DetachedSession, ActivationHandle) {
    match store.prepare_detached(detached_plan(writable, "/usr/bin/true", &[])) {
        Ok(pair) => pair,
        Err(err) => panic!("detached prepare must succeed: {err}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(rendered, "{byte:02x}");
    }
    rendered
}

fn unhex(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index: usize = 0;
    while index.saturating_add(1) < bytes.len() {
        let pair = match std::str::from_utf8(&bytes[index..index.saturating_add(2)]) {
            Ok(pair) => pair,
            Err(_) => panic!("token must be hex"),
        };
        match u8::from_str_radix(pair, 16) {
            Ok(byte) => out.push(byte),
            Err(_) => panic!("token must be hex"),
        }
        index = index.saturating_add(2);
    }
    out
}

/// Whether `pid` is gone, polled until the timeout.
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
// Raw protocol helpers: what a client that is not `DetachedSession` can send.
// ---------------------------------------------------------------------------

/// A hand-driven connection, for the frames the typed client would never send.
struct RawClient {
    stream: UnixStream,
}

impl RawClient {
    /// Connect, retrying while the supervisor is still letting go of the last
    /// connection.
    ///
    /// Not papering over a race in the library: the supervisor frees its client
    /// slot when it *notices* the close, which is one poll slice away, and a
    /// test that connected in that window would be testing scheduling.
    fn connect_free(socket: &Path) -> Self {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let mut client = Self::connect(socket);
            if !client.peek_busy() {
                // The same connection, kept: making a second one here would be
                // the very thing the check just ruled out.
                if let Err(err) = client.stream.set_read_timeout(Some(PATIENCE)) {
                    panic!("a test socket must take a read timeout: {err}");
                }
                return client;
            }
            drop(client);
            if Instant::now() >= deadline {
                panic!("the supervisor never freed its client slot");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn connect(socket: &Path) -> Self {
        match UnixStream::connect(socket) {
            Ok(stream) => {
                if let Err(err) = stream.set_read_timeout(Some(PATIENCE)) {
                    panic!("a test socket must take a read timeout: {err}");
                }
                if let Err(err) = stream.set_write_timeout(Some(PATIENCE)) {
                    panic!("a test socket must take a write timeout: {err}");
                }
                Self { stream }
            }
            Err(err) => panic!("connect to {} must succeed: {err}", socket.display()),
        }
    }

    /// Whether the supervisor refused this connection as busy.
    fn peek_busy(&mut self) -> bool {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .is_ok()
            && matches!(
                self.try_read_reply(),
                Some(ControlReply::Refused {
                    refusal: ControlRefusal::Busy
                })
            )
    }

    fn send(&mut self, request: &ControlRequest) {
        let body = match serde_json::to_vec(request) {
            Ok(body) => body,
            Err(err) => panic!("a request must encode: {err}"),
        };
        self.send_raw(&body);
    }

    /// A frame with a body this test chose, prefixed with its real length.
    fn send_raw(&mut self, body: &[u8]) {
        let length = u32::try_from(body.len()).unwrap_or(u32::MAX);
        let mut frame = length.to_le_bytes().to_vec();
        frame.extend_from_slice(body);
        if let Err(err) = self.stream.write_all(&frame) {
            panic!("a frame must be writable: {err}");
        }
    }

    /// A length prefix that lies, with no body behind it.
    fn send_oversize_prefix(&mut self, announced: u32) {
        if let Err(err) = self.stream.write_all(&announced.to_le_bytes()) {
            panic!("a prefix must be writable: {err}");
        }
    }

    fn read_reply(&mut self) -> ControlReply {
        match self.try_read_reply() {
            Some(reply) => reply,
            None => panic!("the supervisor must answer"),
        }
    }

    fn try_read_reply(&mut self) -> Option<ControlReply> {
        let mut prefix = [0_u8; 4];
        self.stream.read_exact(&mut prefix).ok()?;
        let length = usize::try_from(u32::from_le_bytes(prefix)).ok()?;
        if length > MAX_CONTROL_FRAME_BYTES {
            panic!("the supervisor announced {length} bytes");
        }
        let mut body = vec![0_u8; length];
        self.stream.read_exact(&mut body).ok()?;
        serde_json::from_slice(&body).ok()
    }

    /// Whether the supervisor has closed this connection.
    fn is_closed(&mut self) -> bool {
        let mut scratch = [0_u8; 1];
        matches!(self.stream.read(&mut scratch), Ok(0))
    }

    fn hello(session_id: Uuid, generation: u64, protocol: u32) -> ControlRequest {
        ControlRequest::Hello {
            protocol,
            session_id,
            generation,
        }
    }
}

/// Take the refusal out of a reply, naming what arrived if it is not one.
fn refusal(reply: ControlReply) -> ControlRefusal {
    match reply {
        ControlReply::Refused { refusal } => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// (a) The happy path, end to end, over the socket.
// ---------------------------------------------------------------------------

fn a_detached_run_activates_waits_and_reports_a_real_exit() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let (mut session, handle) = detached_true(&store, store_dir.path());

    // The supervisor is a different process, and it is alive.
    assert_ne!(
        session.supervisor().pid(),
        std::process::id() as i32,
        "the supervisor must not be this process"
    );
    assert!(session.supervisor().is_same_process());
    assert_eq!(session.opened_in(), LifecycleState::Prepared);

    // Nothing has run: the child is held at the gate in another process's
    // session, and the record on disk says so.
    let status = match session.status() {
        Ok(status) => status,
        Err(err) => panic!("status must answer: {err}"),
    };
    assert_eq!(status.state(), LifecycleState::Prepared);
    assert_eq!(status.exit(), None);
    assert_eq!(
        status
            .record()
            .supervisor()
            .map(nono::lifecycle::ProcessIdentity::pid),
        Some(session.supervisor().pid()),
        "the record must name the supervisor that wrote it"
    );

    match session.activate(&handle) {
        Ok(state) => assert_eq!(state, LifecycleState::Running),
        Err(err) => panic!("activation must succeed: {err}"),
    }

    let outcome = match session.wait(PATIENCE) {
        Ok(outcome) => outcome,
        Err(err) => panic!("wait must answer: {err}"),
    };
    let exit = match &outcome {
        WaitOutcome::Exit(exit) => exit,
        WaitOutcome::StillRunning => panic!("/usr/bin/true must have ended"),
    };
    // The facts a supervisor witnessed with `waitpid`, in a process that never
    // forked this child.
    assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 });
    assert_eq!(exit.activation(), ActivationObservation::Observed);

    match session.verify_cleanup() {
        Ok(CleanupVerification::ConfirmedAbsent { .. }) => {}
        Ok(other) => panic!("cleanup must be confirmed, got {other:?}"),
        Err(err) => panic!("cleanup must answer: {err}"),
    }
    session.detach();
}

// ---------------------------------------------------------------------------
// (b) The R09 core proof: the launcher dies, the run does not.
// ---------------------------------------------------------------------------

fn a_session_outlives_the_process_that_prepared_it() {
    let store_dir = TempStore::new();

    // A *different process* prepares the session and then exits. Nothing that
    // happens after this line has any relationship to the process that forked
    // anything.
    let launcher = match Command::new(match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => panic!("the test binary must know its own path: {err}"),
    })
    .env(LAUNCHER_FLAG, store_dir.path())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output()
    {
        Ok(output) => output,
        Err(err) => panic!("the launcher must run: {err}"),
    };
    assert!(
        launcher.status.success(),
        "launcher failed: {}",
        String::from_utf8_lossy(&launcher.stderr)
    );

    let printed = String::from_utf8_lossy(&launcher.stdout).trim().to_string();
    let (id, token) = match printed.split_once(' ') {
        Some(split) => split,
        None => panic!("the launcher must print an id and a token, got {printed:?}"),
    };
    let session_id = match Uuid::parse_str(id) {
        Ok(id) => id,
        Err(err) => panic!("the launcher must print a uuid: {err}"),
    };
    let mut bytes = [0_u8; 32];
    let decoded = unhex(token);
    assert_eq!(decoded.len(), 32, "the token must be 32 bytes");
    bytes.copy_from_slice(&decoded);
    let handle = ActivationHandle::from_parts(session_id, 1, bytes);

    // The launcher is gone: `output()` returned, which means it exited *and*
    // its stdout reached EOF — so nothing it started is holding that pipe
    // either. The supervisor's standard streams are /dev/null, which is what
    // makes that true.
    assert_eq!(launcher.status.code(), Some(0));

    // A store opened fresh, in a process that has never seen this session.
    let store = store_dir.open();
    let recovered = match store.recover(session_id) {
        Ok(recovered) => recovered,
        Err(err) => panic!("recovery must read the record: {err}"),
    };
    assert_eq!(
        recovered.decision(),
        RecoveryDecision::Attachable,
        "a live supervisor must be attachable, not reported gone or running"
    );
    assert!(
        recovered
            .supervisor()
            .is_some_and(nono::lifecycle::ProcessIdentity::is_same_process),
        "the recovered supervisor must still be the process the record named"
    );
    // The record must not have been rewritten as `failed`: the supervisor is
    // alive and owns it.
    assert_eq!(recovered.record().state(), LifecycleState::Prepared);

    let mut session = match recovered.attach() {
        Ok(session) => session,
        Err(err) => panic!("attach must succeed: {err}"),
    };
    match session.activate(&handle) {
        Ok(state) => assert_eq!(state, LifecycleState::Running),
        Err(err) => panic!("activation from a fresh process must succeed: {err}"),
    }
    let outcome = match session.wait(PATIENCE) {
        Ok(outcome) => outcome,
        Err(err) => panic!("wait must answer: {err}"),
    };
    match outcome {
        WaitOutcome::Exit(exit) => {
            assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 });
            assert_eq!(exit.activation(), ActivationObservation::Observed);
        }
        WaitOutcome::StillRunning => panic!("/usr/bin/true must have ended"),
    }
    session.detach();
}

// ---------------------------------------------------------------------------
// (c) An exit observed while nobody was connected.
// ---------------------------------------------------------------------------

fn an_exit_that_happened_while_detached_is_there_on_reconnect() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let session_id = {
        let (mut session, handle) = detached_true(&store, store_dir.path());
        if let Err(err) = session.activate(&handle) {
            panic!("activation must succeed: {err}");
        }
        let id = session.session_id();
        // Disconnected *before* the child could plausibly have been reaped, so
        // the death is observed by a supervisor with no client at all.
        session.detach();
        id
    };

    std::thread::sleep(BRIEF);

    let mut reconnected = match store.attach_control(session_id) {
        Ok(session) => session,
        Err(err) => panic!("reconnection must succeed: {err}"),
    };
    let status = match reconnected.status() {
        Ok(status) => status,
        Err(err) => panic!("status must answer: {err}"),
    };
    let exit = match status.exit() {
        Some(exit) => exit,
        None => panic!("the exit observed while detached must be in the record"),
    };
    assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 });
    assert_eq!(exit.activation(), ActivationObservation::Observed);
    assert_eq!(status.state(), LifecycleState::Exited);

    // And the same facts through `wait`, which must not re-observe anything.
    match reconnected.wait(PATIENCE) {
        Ok(WaitOutcome::Exit(exit)) => {
            assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 });
        }
        Ok(WaitOutcome::StillRunning) => panic!("the run had already ended"),
        Err(err) => panic!("wait must answer: {err}"),
    }
    reconnected.detach();
}

// ---------------------------------------------------------------------------
// (d) A stop before activation, over the socket.
// ---------------------------------------------------------------------------

fn a_stop_before_activation_makes_activation_impossible_forever() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    // A marker file the program would create if it ever ran.
    let marker = store_dir.path().join("d-marker");
    let marker_arg = marker.to_string_lossy().into_owned();
    let (mut session, handle) = match store.prepare_detached(detached_plan(
        store_dir.path(),
        "/usr/bin/touch",
        &[&marker_arg],
    )) {
        Ok(pair) => pair,
        Err(err) => panic!("detached prepare must succeed: {err}"),
    };

    let exit = match session.stop() {
        Ok(exit) => exit,
        Err(err) => panic!("stop must succeed: {err}"),
    };
    assert_eq!(
        exit.activation(),
        ActivationObservation::NotActivated,
        "a stopped-at-the-gate child never ran"
    );

    // The refusal must be the gate's own typed answer, carried over the wire.
    match session.activate(&handle) {
        Ok(state) => panic!("activation after a stop must be refused, got {state}"),
        Err(err) => match err.refusal() {
            Some(ControlRefusal::Activation(ActivationError::AlreadyStopped)) => {}
            other => panic!("expected a typed already-stopped refusal, got {other:?}"),
        },
    }

    std::thread::sleep(BRIEF);
    assert!(
        !marker.exists(),
        "the program ran despite never being activated: {}",
        marker.display()
    );
    session.detach();
}

// ---------------------------------------------------------------------------
// (f) A replayed activation.
// ---------------------------------------------------------------------------

fn a_replayed_activation_is_refused_by_the_gate_over_the_socket() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let (mut session, handle) = detached_true(&store, store_dir.path());

    if let Err(err) = session.activate(&handle) {
        panic!("the first activation must succeed: {err}");
    }
    // The same handle, the same bytes, a second time. Single use lives in the
    // gate's state machine, not in Rust's move semantics and not in the
    // protocol — so it holds against a caller that kept a copy.
    match session.activate(&handle) {
        Ok(state) => panic!("a replayed activation must be refused, got {state}"),
        Err(err) => match err.refusal() {
            Some(ControlRefusal::Activation(ActivationError::AlreadyActivated)) => {}
            other => panic!("expected a typed already-activated refusal, got {other:?}"),
        },
    }
    session.detach();
}

// ---------------------------------------------------------------------------
// (e) Protocol refusals, live.
// ---------------------------------------------------------------------------

/// A prepared session plus its socket path, for the raw-protocol tests.
fn raw_fixture(store_dir: &TempStore) -> (SessionStore, Uuid, PathBuf) {
    let store = store_dir.open();
    let (session, handle) = detached_true(&store, store_dir.path());
    let id = session.session_id();
    let socket = store.control_socket_path(id);
    // The typed client goes away so the single client slot is free; the run
    // stays held at the gate, which is exactly the state these tests want.
    session.detach();
    drop(handle);
    (store, id, socket)
}

fn a_hello_from_another_protocol_version_is_refused() {
    let store_dir = TempStore::new();
    let (_store, id, socket) = raw_fixture(&store_dir);

    let mut client = RawClient::connect_free(&socket);
    client.send(&RawClient::hello(id, 1, 99));
    assert_eq!(
        refusal(client.read_reply()),
        ControlRefusal::ProtocolVersion {
            expected: 1,
            supplied: 99
        }
    );
    assert!(
        client.is_closed(),
        "a version mismatch must end the connection, not continue it"
    );
}

fn a_hello_for_another_session_or_generation_is_refused() {
    let store_dir = TempStore::new();
    let (_store, id, socket) = raw_fixture(&store_dir);

    let mut wrong_session = RawClient::connect_free(&socket);
    let stranger = Uuid::now_v7();
    wrong_session.send(&RawClient::hello(stranger, 1, 1));
    assert_eq!(
        refusal(wrong_session.read_reply()),
        ControlRefusal::WrongSession {
            expected: id,
            supplied: stranger
        }
    );
    assert!(wrong_session.is_closed());

    let mut wrong_generation = RawClient::connect_free(&socket);
    wrong_generation.send(&RawClient::hello(id, 999, 1));
    assert_eq!(
        refusal(wrong_generation.read_reply()),
        ControlRefusal::WrongGeneration {
            expected: 1,
            supplied: 999
        }
    );
    assert!(wrong_generation.is_closed());
}

fn an_oversize_frame_is_refused_without_being_read() {
    let store_dir = TempStore::new();
    let (_store, _id, socket) = raw_fixture(&store_dir);

    let mut client = RawClient::connect_free(&socket);
    // A gigabyte announced and nothing sent. If the bound were checked after
    // the body rather than before it, the supervisor would allocate a gigabyte
    // and then park on a body that never comes.
    let announced = 1_024_u32 * 1_024 * 1_024;
    client.send_oversize_prefix(announced);
    assert_eq!(
        refusal(client.read_reply()),
        ControlRefusal::FrameTooLarge {
            size: u64::from(announced),
            limit: MAX_CONTROL_FRAME_BYTES,
        }
    );
    assert!(
        client.is_closed(),
        "a stream whose length field cannot be trusted cannot be resynchronized"
    );
}

fn a_garbage_frame_is_refused_as_malformed() {
    let store_dir = TempStore::new();
    let (_store, _id, socket) = raw_fixture(&store_dir);

    let mut client = RawClient::connect_free(&socket);
    client.send_raw(b"\x00\xff not json at all \xfe");
    match refusal(client.read_reply()) {
        ControlRefusal::Malformed { .. } => {}
        other => panic!("expected a malformed refusal, got {other:?}"),
    }
    assert!(client.is_closed());
}

fn an_operation_before_the_hello_is_refused() {
    let store_dir = TempStore::new();
    let (_store, _id, socket) = raw_fixture(&store_dir);

    let mut client = RawClient::connect_free(&socket);
    // A well-formed frame for a real operation, sent before the hello that
    // would have said which session it is for.
    client.send(&ControlRequest::Status);
    assert_eq!(refusal(client.read_reply()), ControlRefusal::HelloExpected);
    assert!(client.is_closed());
}

fn a_second_concurrent_client_is_told_it_is_busy() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let (mut session, _handle) = detached_true(&store, store_dir.path());
    // The first client is definitely established: a completed round trip is
    // what proves the supervisor has taken the slot.
    if let Err(err) = session.status() {
        panic!("the first client must be served: {err}");
    }

    let socket = store.control_socket_path(session.session_id());
    let mut second = RawClient::connect(&socket);
    assert_eq!(
        refusal(second.read_reply()),
        ControlRefusal::Busy,
        "a second client must be told, not queued"
    );
    assert!(second.is_closed());

    // The first client is untouched by the refusal.
    match session.status() {
        Ok(status) => assert_eq!(status.state(), LifecycleState::Prepared),
        Err(err) => panic!("the first client must still be served: {err}"),
    }
    session.detach();
}

// ---------------------------------------------------------------------------
// (g) A killed supervisor, and the stale socket it leaves.
// ---------------------------------------------------------------------------

fn a_killed_supervisor_leaves_a_stale_socket_that_recovery_removes() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let (session, _handle) = detached_true(&store, store_dir.path());
    let session_id = session.session_id();
    let supervisor = session.supervisor().pid();
    let socket = store.control_socket_path(session_id);
    assert!(
        socket.exists(),
        "the control socket must exist while serving"
    );
    drop(session);

    // SIGKILL: no unlink, no goodbye, no chance to clean up after itself.
    // SAFETY: `kill` takes two integers and touches no memory. The pid is the
    // supervisor this test just launched.
    assert_eq!(unsafe { libc::kill(supervisor, libc::SIGKILL) }, 0);
    assert!(
        wait_until_gone(supervisor, PATIENCE),
        "the supervisor must die"
    );

    // The record still names it, and the name is now a lie the identity check
    // catches: the socket is there, and connecting to it would answer
    // ECONNREFUSED forever.
    assert!(socket.exists(), "the stale socket must still be on disk");
    let attach = store.attach_control(session_id);
    assert!(
        matches!(attach, Err(DetachedError::NoSupervisor { .. })),
        "a dead supervisor must be named as absent, not connected to: {attach:?}"
    );

    let mut recovered = match store.recover(session_id) {
        Ok(recovered) => recovered,
        Err(err) => panic!("recovery must read the record: {err}"),
    };
    assert!(
        !recovered.decision().is_attachable(),
        "a dead supervisor must not be attachable: {:?}",
        recovered.decision()
    );
    assert!(
        !socket.exists(),
        "recovery must remove the stale socket it just proved dead"
    );
    assert!(
        recovered.attach().is_err(),
        "there is nothing left to attach to"
    );

    // And the slice-A path still works on the record itself.
    match recovered.verify_cleanup_by(Instant::now() + PATIENCE) {
        Ok(CleanupVerification::ConfirmedAbsent { .. }) => {}
        Ok(other) => panic!("the run must be provably gone, got {other:?}"),
        Err(err) => panic!("cleanup verification must answer: {err}"),
    }
    assert_eq!(recovered.state(), LifecycleState::CleanupVerified);
}

// ---------------------------------------------------------------------------
// The two refusals that keep the entry points honest.
// ---------------------------------------------------------------------------

fn an_undetached_plan_is_refused_by_the_detaching_entry_point() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let plan = match SandboxPlan::new("/usr/bin/true")
        .capabilities(capabilities(store_dir.path()))
        .validate()
    {
        Ok(plan) => plan,
        Err(err) => panic!("the plan must validate: {err}"),
    };
    let refused = store.prepare_detached(plan);
    assert!(
        matches!(
            refused,
            Err(LifecycleError::Prepare(PrepareError::DetachedNotRequested))
        ),
        "a plan that did not ask to be detached must not be detached: {:?}",
        refused.err()
    );
}

fn a_detached_plan_is_refused_by_the_entry_points_that_cannot_supervise() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let refused = store.prepare(detached_plan(store_dir.path(), "/usr/bin/true", &[]));
    assert!(
        matches!(
            refused,
            Err(LifecycleError::Prepare(
                PrepareError::DetachedNeedsSupervisor
            ))
        ),
        "an attached prepare must refuse a detached plan rather than run it attached: {:?}",
        refused.err()
    );
    // And the presence table agrees that an attached record was never detached.
    assert_eq!(
        SupervisorPresence::of(None),
        SupervisorPresence::NeverDetached
    );
}

// ---------------------------------------------------------------------------
// The event ring: honest about what a detached supervisor can deliver.
// ---------------------------------------------------------------------------

fn the_event_ring_survives_a_disconnect() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let session_id = {
        let (mut session, handle) = detached_true(&store, store_dir.path());
        if let Err(err) = session.activate(&handle) {
            panic!("activation must succeed: {err}");
        }
        let id = session.session_id();
        session.detach();
        id
    };
    std::thread::sleep(BRIEF);

    let mut reconnected = match store.attach_control(session_id) {
        Ok(session) => session,
        Err(err) => panic!("reconnection must succeed: {err}"),
    };
    let status = match reconnected.status() {
        Ok(status) => status,
        Err(err) => panic!("status must answer: {err}"),
    };
    let events = status.events();
    assert!(
        !events.is_empty(),
        "a detached supervisor must keep what it observed while nobody listened"
    );
    assert!(
        events.len() <= nono::lifecycle::DETACHED_EVENT_RING_CAPACITY,
        "the ring must stay bounded: {} events",
        events.len()
    );
    // The sequence is the ordering authority and must be strictly increasing
    // across the whole ring, disconnect or no disconnect.
    let mut previous: Option<u64> = None;
    for event in events {
        if let Some(previous) = previous {
            assert!(
                event.seq() > previous,
                "the ring must stay in sequence order: {} after {previous}",
                event.seq()
            );
        }
        previous = Some(event.seq());
    }
    // And the run's end is in it, which is the fact no attached run could have
    // delivered to a caller that was not there.
    assert!(
        events.iter().any(|event| matches!(
            event.what(),
            nono::lifecycle::LifecycleEventKind::ChildExited { .. }
        )),
        "the child's death must be in the ring"
    );
    reconnected.detach();
}
