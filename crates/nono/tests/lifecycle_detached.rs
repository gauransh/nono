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
    ActivationError, ActivationHandle, ActivationObservation, AttachAck, AttachTag,
    AttachedTerminal, CleanupVerification, ControlRefusal, ControlReply, ControlRequest,
    DetachedError, ExitOutcome, LifecycleError, LifecycleState, MAX_ATTACH_PAYLOAD_BYTES,
    MAX_CONTROL_FRAME_BYTES, PrepareError, RecoveryDecision, SCROLLBACK_CAPACITY_BYTES,
    SandboxPlan, SessionMode, SessionStore, StopError, SupervisorPresence, TerminalEvent,
    ValidatedPlan, WaitOutcome, WindowSize,
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

/// The same idea for the interactive caller-restart proof.
///
/// A separate flag rather than an argument, because the two launchers do
/// different things: this one *activates* the run and detaches from its
/// terminal, so what the next process inherits is a session already producing
/// output.
const PTY_LAUNCHER_FLAG: &str = "NONO_DETACHED_TEST_PTY_LAUNCHER";

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
    if let Some(store) = std::env::var_os(PTY_LAUNCHER_FLAG) {
        run_as_terminal_launcher(Path::new(&store));
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
            "a_client_that_died_without_a_goodbye_does_not_hold_the_slot",
            a_client_that_died_without_a_goodbye_does_not_hold_the_slot,
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
        // R09 slice C: the terminal.
        (
            "an_interactive_run_gets_a_real_terminal_at_the_size_the_viewer_asked_for",
            an_interactive_run_gets_a_real_terminal_at_the_size_the_viewer_asked_for,
        ),
        (
            "a_resize_reaches_the_run_as_a_signal",
            a_resize_reaches_the_run_as_a_signal,
        ),
        (
            "a_detach_and_reattach_is_the_same_session_with_its_output_resumed",
            a_detach_and_reattach_is_the_same_session_with_its_output_resumed,
        ),
        (
            "an_interactive_session_outlives_the_process_that_prepared_it",
            an_interactive_session_outlives_the_process_that_prepared_it,
        ),
        (
            "a_run_that_ended_while_detached_yields_its_tail_and_then_its_end",
            a_run_that_ended_while_detached_yields_its_tail_and_then_its_end,
        ),
        (
            "a_finished_session_stops_costing_cpu_and_still_serves_its_scrollback",
            a_finished_session_stops_costing_cpu_and_still_serves_its_scrollback,
        ),
        (
            "input_bytes_reach_the_terminal_verbatim_however_hostile",
            input_bytes_reach_the_terminal_verbatim_however_hostile,
        ),
        (
            "a_frame_tag_this_protocol_does_not_have_ends_the_channel_not_the_run",
            a_frame_tag_this_protocol_does_not_have_ends_the_channel_not_the_run,
        ),
        (
            "an_oversize_input_frame_ends_the_channel_not_the_run",
            an_oversize_input_frame_ends_the_channel_not_the_run,
        ),
        (
            "an_attach_occupies_the_one_client_slot",
            an_attach_occupies_the_one_client_slot,
        ),
        (
            "the_scrollback_ring_stays_bounded_and_says_what_it_dropped",
            the_scrollback_ring_stays_bounded_and_says_what_it_dropped,
        ),
        (
            "a_headless_run_refuses_an_attach_with_a_reason",
            a_headless_run_refuses_an_attach_with_a_reason,
        ),
        (
            "an_interactive_plan_is_refused_where_nothing_can_own_a_terminal",
            an_interactive_plan_is_refused_where_nothing_can_own_a_terminal,
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

/// This binary, acting as the doomed launcher of the interactive proof.
///
/// Prepares an interactive detached session, attaches, *activates*, detaches
/// cleanly, prints the session id and exits. What the next process inherits is
/// a run that is already producing output on a terminal nobody is watching.
fn run_as_terminal_launcher(store_path: &Path) {
    let store = match SessionStore::open(store_path) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("pty launcher: store: {err}");
            std::process::exit(2);
        }
    };
    let plan = interactive_plan(store_path, "/bin/sh", &["-c", COUNTER_SCRIPT]);
    let (session, handle) = match store.prepare_detached(plan) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("pty launcher: prepare_detached: {err}");
            std::process::exit(3);
        }
    };
    let id = session.session_id();
    let mut terminal = match session.attach(WindowSize::new(24, 80)) {
        Ok(terminal) => terminal,
        Err(err) => {
            eprintln!("pty launcher: attach: {err}");
            std::process::exit(4);
        }
    };
    if let Err(err) = terminal.activate(&handle) {
        eprintln!("pty launcher: activate: {err}");
        std::process::exit(5);
    }
    // Detached deliberately and completely — terminal first, then the control
    // connection — so the supervisor's one client slot is free before this
    // process is gone and the next one does not have to wait for a close to be
    // noticed.
    match terminal.detach() {
        Ok(session) => session.detach(),
        Err(err) => {
            eprintln!("pty launcher: detach: {err}");
            std::process::exit(6);
        }
    }
    println!("{id}");
    let _ = std::io::stdout().flush();
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

// ---------------------------------------------------------------------------
// Terminal fixtures.
// ---------------------------------------------------------------------------

/// A shell that prints a numbered tick ten times a second, forever enough.
///
/// An explicit `/bin/sh -c` is deliberate: what is under test is a *terminal*,
/// and the programs that need one are shells. The library still never invokes a
/// shell on its own — this plan names `/bin/sh` the way a caller would.
const COUNTER_SCRIPT: &str =
    "i=0; while [ $i -lt 600 ]; do echo tick$i; i=$((i+1)); sleep 0.1; done";

fn interactive_plan(writable: &Path, program: &str, args: &[&str]) -> ValidatedPlan {
    let plan = SandboxPlan::new(program)
        .args(args.iter().copied())
        .detached(true)
        .session_mode(SessionMode::Interactive)
        .capabilities(capabilities(writable));
    match plan.validate() {
        Ok(plan) => plan,
        Err(err) => panic!("interactive plan must validate: {err}"),
    }
}

/// Prepare an interactive run, attach at `window`, and release it.
fn interactive_attached(
    store: &SessionStore,
    writable: &Path,
    program: &str,
    args: &[&str],
    window: WindowSize,
) -> AttachedTerminal {
    let (session, handle) = match store.prepare_detached(interactive_plan(writable, program, args))
    {
        Ok(pair) => pair,
        Err(err) => panic!("interactive detached prepare must succeed: {err}"),
    };
    let mut terminal = match session.attach(window) {
        Ok(terminal) => terminal,
        Err(err) => panic!("attach must succeed: {err}"),
    };
    // Attached *before* activation on purpose: the window size has to reach the
    // terminal before the customer's program starts, or a program that reads
    // its size at startup reads the zeroes a fresh PTY carries.
    match terminal.activate(&handle) {
        Ok(state) => assert_eq!(state, LifecycleState::Running),
        Err(err) => panic!("activation while attached must succeed: {err}"),
    }
    terminal
}

/// Everything the terminal said, until `needle` appears in it.
fn read_until(terminal: &mut AttachedTerminal, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut seen: Vec<u8> = Vec::new();
    loop {
        let event = match terminal.read_event(deadline) {
            Ok(event) => event,
            Err(err) => panic!("the terminal must answer: {err}"),
        };
        match event {
            TerminalEvent::Output(bytes) => seen.extend_from_slice(&bytes),
            TerminalEvent::Ended(end) => {
                let text = String::from_utf8_lossy(&seen).into_owned();
                if text.contains(needle) {
                    return text;
                }
                panic!(
                    "the run ended in {} before {needle:?}: {text:?}",
                    end.state()
                );
            }
            TerminalEvent::Pong => {}
            TerminalEvent::Idle => {
                let text = String::from_utf8_lossy(&seen).into_owned();
                panic!("{needle:?} never arrived; the terminal said {text:?}");
            }
        }
        let text = String::from_utf8_lossy(&seen);
        if text.contains(needle) {
            return text.into_owned();
        }
    }
}

/// Exactly `count` bytes of output, however many frames they arrive in.
fn read_bytes(terminal: &mut AttachedTerminal, count: usize, timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout;
    let mut seen: Vec<u8> = Vec::new();
    while seen.len() < count {
        let event = match terminal.read_event(deadline) {
            Ok(event) => event,
            Err(err) => panic!("the terminal must answer: {err}"),
        };
        match event {
            TerminalEvent::Output(bytes) => seen.extend_from_slice(&bytes),
            TerminalEvent::Pong => {}
            other => panic!(
                "expected {count} bytes, got {other:?} after {} bytes",
                seen.len()
            ),
        }
    }
    seen
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

    /// Whether the supervisor closes, once whatever it had already sent is
    /// read past.
    ///
    /// A terminal channel is not silent: a run that is talking has output on
    /// the wire, and a close that arrives behind it is still a close. Reading
    /// past that is not papering over anything — it is the difference between
    /// "the peer closed" and "the peer had already said something".
    fn closes_after_draining(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        if self
            .stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .is_err()
        {
            return false;
        }
        loop {
            let mut scratch = [0_u8; 4096];
            match self.stream.read(&mut scratch) {
                Ok(0) => return true,
                Ok(_) => {}
                // A read timeout: nothing more has arrived *yet*. Keep waiting
                // until the caller's own deadline rather than concluding.
                Err(_) if Instant::now() < deadline => {}
                Err(_) => return false,
            }
            if Instant::now() >= deadline {
                return false;
            }
        }
    }

    fn hello(session_id: Uuid, generation: u64, protocol: u32) -> ControlRequest {
        ControlRequest::Hello {
            protocol,
            session_id,
            generation,
        }
    }

    /// Greet, then switch this connection into terminal framing.
    fn attach(&mut self, session_id: Uuid, window: WindowSize) -> AttachAck {
        self.send(&Self::hello(session_id, 1, 1));
        match self.read_reply() {
            ControlReply::Hello { .. } => {}
            other => panic!("the hello must be accepted, got {other:?}"),
        }
        self.send(&ControlRequest::Attach { window });
        match self.read_reply() {
            ControlReply::AttachAck { ack } => *ack,
            other => panic!("the attach must be accepted, got {other:?}"),
        }
    }

    /// A terminal frame with a tag and a length this test chose.
    fn send_attach_frame(&mut self, tag: u8, payload: &[u8]) {
        let mut frame = vec![tag];
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        if let Err(err) = self.stream.write_all(&frame) {
            panic!("a terminal frame must be writable: {err}");
        }
    }

    /// A terminal frame header whose length prefix lies, with no body behind it.
    fn send_attach_prefix(&mut self, tag: u8, announced: u32) {
        let mut header = vec![tag];
        header.extend_from_slice(&announced.to_le_bytes());
        if let Err(err) = self.stream.write_all(&header) {
            panic!("a terminal frame header must be writable: {err}");
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

/// R20 defect 3: the slot is held by a client, not by its ghost.
///
/// `Busy` is the right answer for a second *live* client and the wrong answer
/// for a dead one — and a dead one is the ordinary case, not the exotic one:
/// the process that prepares a detached session is meant to be able to exit,
/// and when it does, the kernel closes its control socket with no `Goodbye`
/// sent. A supervisor that read its slot before noticing the close refuses the
/// very process the session exists for. That is what broke
/// `a_session_outlives_the_process_that_prepared_it` on Linux, where the death
/// and the next connection arrive in one `poll` wakeup; macOS reached the same
/// state and got away with it on scheduling.
fn a_client_that_died_without_a_goodbye_does_not_hold_the_slot() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let (mut session, _handle) = detached_true(&store, store_dir.path());
    let session_id = session.session_id();
    // A completed round trip, so the slot is provably taken before it is
    // abandoned.
    if let Err(err) = session.status() {
        panic!("the first client must be served: {err}");
    }

    // Gone the way a crash goes: the descriptor is closed and nothing is said.
    // `detach` would say `Goodbye` — which is the case that already worked.
    drop(session);

    // No retry, deliberately. A bounded retry here would hide exactly the
    // defect: the supervisor must free the slot as part of deciding about this
    // connection, not one poll slice later.
    match store.attach_control(session_id) {
        Ok(session) => {
            let mut session = session;
            match session.status() {
                Ok(status) => assert_eq!(status.state(), LifecycleState::Prepared),
                Err(err) => panic!("the adopting client must be served: {err}"),
            }
            session.detach();
        }
        Err(err) => panic!(
            "a session must be adoptable after its first client died without a goodbye, \
             got {err}"
        ),
    }
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

// ---------------------------------------------------------------------------
// R09 slice C (a): a real terminal, at the size the viewer asked for.
// ---------------------------------------------------------------------------

fn an_interactive_run_gets_a_real_terminal_at_the_size_the_viewer_asked_for() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    // `stty size` answers only from a real terminal: on anything else it fails
    // with "Not a tty". So the assertion below is simultaneously a proof that
    // the child has a controlling terminal and that the window size the client
    // asked for at attach reached it before the program started.
    let mut terminal = interactive_attached(
        &store,
        store_dir.path(),
        "/bin/sh",
        &["-c", "stty size; printf marker; read line; echo got:$line"],
        WindowSize::new(40, 100),
    );

    let seen = read_until(&mut terminal, "marker", PATIENCE);
    assert!(
        seen.contains("40 100"),
        "the run must see the window size the viewer asked for, saw {seen:?}"
    );

    if let Err(err) = terminal.write_input(b"hello\n") {
        panic!("input must reach the terminal: {err}");
    }
    let answered = read_until(&mut terminal, "got:hello", PATIENCE);
    assert!(answered.contains("got:hello"), "{answered:?}");

    let session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    session.detach();
}

// ---------------------------------------------------------------------------
// (b) A resize, and the signal it becomes.
// ---------------------------------------------------------------------------

fn a_resize_reaches_the_run_as_a_signal() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    // The trap is the proof. `TIOCSWINSZ` is documented to signal `SIGWINCH` to
    // the terminal's foreground process group when the size *changes*; a
    // platform that stopped doing it, or a resize that never reached the
    // master, would leave the second `stty size` unprinted.
    let mut terminal = interactive_attached(
        &store,
        store_dir.path(),
        "/bin/sh",
        // A *loop* of short sleeps, not one long one, and the difference is the
        // whole test. A shell runs a trap when the foreground command it is
        // waiting on completes, so `sleep 5` meant the second `stty size` was
        // printed five seconds later — the run was proving that the sleep
        // expired, not that the resize was signalled — and the run then ended
        // on its own, which is what made the stop below fail on a loaded Linux
        // runner. With a tenth-second body the trap is observed promptly and
        // the run is still alive to be stopped. Bounded like `COUNTER_SCRIPT`
        // so a supervisor that somehow lost the stop leaves nothing behind.
        &[
            "-c",
            "trap 'stty size' WINCH; stty size; i=0; \
             while [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done",
        ],
        WindowSize::new(40, 100),
    );

    let first = read_until(&mut terminal, "40 100", PATIENCE);
    assert!(first.contains("40 100"), "{first:?}");

    if let Err(err) = terminal.resize(50, 120) {
        panic!("a resize must reach the supervisor: {err}");
    }
    let second = read_until(&mut terminal, "50 120", PATIENCE);
    assert!(
        second.contains("50 120"),
        "the run must be signalled about the new size, saw {second:?}"
    );

    let mut session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    match session.stop() {
        Ok(_) => {}
        // A run that reached its own end before the stop arrived is a
        // legitimate outcome, and refusing the stop is the *library* being
        // right: a stop is a transition, not a wish, and one asked for from
        // `Exited` has nothing left to do. This test is about the resize above,
        // so it accepts that answer and nothing else — a stop that failed for
        // any other reason is still a failure here.
        Err(DetachedError::Refused(ControlRefusal::Stop(StopError::NotStoppable { state }))) => {
            assert_eq!(
                state,
                LifecycleState::Exited,
                "only an already-finished run may refuse a stop here"
            );
        }
        Err(err) => panic!("the sleeping run must be stoppable: {err}"),
    }
    session.detach();
}

// ---------------------------------------------------------------------------
// (c) Detach, wait, reattach: the same session, still talking.
// ---------------------------------------------------------------------------

fn a_detach_and_reattach_is_the_same_session_with_its_output_resumed() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let mut terminal = interactive_attached(
        &store,
        store_dir.path(),
        "/bin/sh",
        &["-c", COUNTER_SCRIPT],
        WindowSize::new(24, 80),
    );
    let session_id = terminal.session_id();
    let supervisor = terminal.supervisor().pid();
    read_until(&mut terminal, "tick0", PATIENCE);

    let session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    assert_eq!(session.session_id(), session_id);
    session.detach();

    // Half a second with nobody watching. The run does not stop and the
    // supervisor does not exit; the output goes to the bounded ring.
    std::thread::sleep(Duration::from_millis(500));

    let reconnected = match store.attach_control(session_id) {
        Ok(session) => session,
        Err(err) => panic!("reattaching to the control socket must succeed: {err}"),
    };
    assert_eq!(
        reconnected.supervisor().pid(),
        supervisor,
        "a reattach must reach the same supervisor process"
    );
    let mut resumed = match reconnected.attach(WindowSize::new(24, 80)) {
        Ok(terminal) => terminal,
        Err(err) => panic!("reattach must succeed: {err}"),
    };
    assert_eq!(
        resumed.session_id(),
        session_id,
        "the session is the same one"
    );
    assert_eq!(
        resumed.ack().state(),
        LifecycleState::Running,
        "the run must still be running"
    );
    assert!(
        resumed.ack().buffered() > 0,
        "the ring must have kept what the run said while nobody was attached"
    );
    assert_eq!(
        resumed.ack().dropped(),
        0,
        "half a second of ticks is nothing next to a 256 KiB ring"
    );

    // The scrollback is there, and then the run carries on saying more.
    let backlog = read_until(&mut resumed, "tick1", PATIENCE);
    assert!(backlog.contains("tick1"), "{backlog:?}");
    let later = read_until(&mut resumed, "tick12", PATIENCE);
    assert!(
        later.contains("tick12"),
        "output must resume, not merely replay: {later:?}"
    );

    let mut session = match resumed.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    if let Err(err) = session.stop() {
        panic!("the run must be stoppable: {err}");
    }
    session.detach();
}

// ---------------------------------------------------------------------------
// (d) The caller dies; the terminal does not.
// ---------------------------------------------------------------------------

fn an_interactive_session_outlives_the_process_that_prepared_it() {
    let store_dir = TempStore::new();

    let launcher = match Command::new(match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => panic!("the test binary must know its own path: {err}"),
    })
    .env(PTY_LAUNCHER_FLAG, store_dir.path())
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
    let session_id = match Uuid::parse_str(&printed) {
        Ok(id) => id,
        Err(err) => panic!("the launcher must print a uuid, got {printed:?}: {err}"),
    };

    // A store opened fresh, in a process that has never seen this session and
    // never forked anything involved in it.
    let store = store_dir.open();
    let recovered = match store.recover(session_id) {
        Ok(recovered) => recovered,
        Err(err) => panic!("recovery must read the record: {err}"),
    };
    assert_eq!(
        recovered.decision(),
        RecoveryDecision::Attachable,
        "a live supervisor must be attachable"
    );
    let session = match recovered.attach() {
        Ok(session) => session,
        Err(err) => panic!("attach must succeed: {err}"),
    };
    let mut terminal = match session.attach(WindowSize::new(30, 90)) {
        Ok(terminal) => terminal,
        Err(err) => panic!("attaching to the terminal must succeed: {err}"),
    };
    assert_eq!(terminal.ack().state(), LifecycleState::Running);

    // The run has been talking to a terminal nobody held since before this
    // process started, and it is still talking now.
    let seen = read_until(&mut terminal, "tick", PATIENCE);
    assert!(seen.contains("tick"), "{seen:?}");
    let later = read_until(&mut terminal, "tick", PATIENCE);
    assert!(later.contains("tick"), "output must keep coming: {later:?}");

    let mut session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    if let Err(err) = session.stop() {
        panic!("the run must be stoppable: {err}");
    }
    session.detach();
}

// ---------------------------------------------------------------------------
// (e) The run finishes while nobody is watching.
// ---------------------------------------------------------------------------

fn a_run_that_ended_while_detached_yields_its_tail_and_then_its_end() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let terminal = interactive_attached(
        &store,
        store_dir.path(),
        "/bin/sh",
        // The pause is what makes this test the one it claims to be: the output
        // has to happen *while nobody is attached*, so that what a reattaching
        // client sees came out of the supervisor's ring rather than off the
        // wire. Without it the bytes race the detach.
        &["-c", "sleep 0.4; echo done-and-gone"],
        WindowSize::new(24, 80),
    );
    let session_id = terminal.session_id();
    // Detached from the *terminal* before the run could plausibly have spoken,
    // so everything it says is observed by a supervisor with nobody watching.
    let mut session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    // Waited for rather than slept through: a fixed sleep in front of a state
    // assertion is a flake waiting for a loaded machine, and the property under
    // test is "the output happened with nobody attached", which the detach
    // above has already established.
    match session.wait(PATIENCE) {
        Ok(WaitOutcome::Exit(exit)) => assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 }),
        Ok(WaitOutcome::StillRunning) => panic!("the run must finish"),
        Err(err) => panic!("wait must answer: {err}"),
    }
    // And then away entirely, so the reattach below is a fresh connection.
    session.detach();

    let reconnected = match store.attach_control(session_id) {
        Ok(session) => session,
        Err(err) => panic!("reconnection must succeed: {err}"),
    };
    let mut terminal = match reconnected.attach(WindowSize::new(24, 80)) {
        Ok(terminal) => terminal,
        Err(err) => panic!("attaching to a finished run must succeed: {err}"),
    };
    assert_eq!(
        terminal.ack().state(),
        LifecycleState::Exited,
        "the ack must say the run is over"
    );
    let exit = match terminal.ack().exit() {
        Some(exit) => exit.clone(),
        None => panic!("the ack for a finished run must carry the exit facts"),
    };
    assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 });
    assert_eq!(exit.activation(), ActivationObservation::Observed);

    // The tail the ring kept, and then the end — promptly, not at a timeout.
    let tail = read_until(&mut terminal, "done-and-gone", PATIENCE);
    assert!(tail.contains("done-and-gone"), "{tail:?}");
    let ended = loop {
        match terminal.read_event(Instant::now() + PATIENCE) {
            Ok(TerminalEvent::Ended(end)) => break end,
            Ok(TerminalEvent::Output(_) | TerminalEvent::Pong) => {}
            Ok(TerminalEvent::Idle) => panic!("the end must arrive promptly, not at a timeout"),
            Err(err) => panic!("the terminal must answer: {err}"),
        }
    };
    assert_eq!(ended.state(), LifecycleState::Exited);
    assert_eq!(
        ended.exit().map(nono::lifecycle::SandboxExit::outcome),
        Some(ExitOutcome::Exited { code: 0 }),
        "the end frame must carry the facts the supervisor witnessed"
    );

    let session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    session.detach();
}

/// How long an idle supervisor is watched for a spin.
///
/// Long enough that a supervisor burning a core has to show it at the one
/// second `ps` resolves on Linux, short enough not to pad the suite.
const SPIN_WINDOW: Duration = Duration::from_secs(2);

/// The CPU an idle supervisor may use in that window.
///
/// A correct one wakes four times a second to re-check the child and the grace
/// period and does nothing else, so its real figure is a rounding error; a
/// spinning one burns the whole window. The bound sits between two numbers that
/// are three orders of magnitude apart, so it is not delicate.
const SPIN_BUDGET_MILLIS: u64 = 500;

/// The CPU time a process has accumulated, in milliseconds.
///
/// `ps` rather than a platform-specific read, because the two platforms keep
/// this in entirely different places — `/proc/<pid>/stat` fields 14 and 15 in
/// clock ticks on Linux, `PROC_PIDTASKINFO` through `proc_pidinfo` on macOS —
/// and neither belongs in a test that is about a poll set.
fn cpu_millis(pid: i32) -> u64 {
    let output = match Command::new("ps")
        .args(["-o", "time=", "-p"])
        .arg(pid.to_string())
        .output()
    {
        Ok(output) => output,
        Err(err) => panic!("ps must run: {err}"),
    };
    let raw = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() {
        panic!("ps must report on the supervisor (pid {pid}): {raw:?}");
    }
    match parse_cpu_time(&raw) {
        Some(millis) => millis,
        None => panic!("ps printed a cpu time this test cannot read: {raw:?}"),
    }
}

/// `[DD-]HH:MM:SS[.ss]`, which is what both platforms' `ps` prints.
///
/// Linux resolves to the second and macOS to the hundredth; the fraction is
/// read when it is there and the whole seconds are the answer when it is not.
fn parse_cpu_time(raw: &str) -> Option<u64> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    // A day count is separated by '-'. It cannot happen here, but a parse that
    // ignored it would read "1-00:00:00" as zero, which is the one wrong answer
    // that would make this test pass for the wrong reason.
    let (days, rest) = match text.split_once('-') {
        Some((days, rest)) => (days.trim().parse::<u64>().ok()?, rest),
        None => (0_u64, text),
    };
    let mut seconds = days.checked_mul(86_400)?;
    let mut millis = 0_u64;
    for field in rest.split(':') {
        let (whole, fraction) = match field.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (field, None),
        };
        seconds = seconds
            .checked_mul(60)?
            .checked_add(whole.trim().parse::<u64>().ok()?)?;
        if let Some(fraction) = fraction {
            // Hundredths of a second, so two digits scale by ten.
            millis = fraction.trim().parse::<u64>().ok()?.checked_mul(10)?;
        }
    }
    seconds.checked_mul(1_000)?.checked_add(millis)
}

/// R20 defect 1: a run that is over must stop costing anything.
///
/// The bug this pins: the supervisor watched the terminal master for
/// `POLLIN | POLLOUT | POLLHUP` and, once the run had ended, asked for nothing
/// at all. Linux's `poll` reports `POLLHUP` for a zero-`events` entry anyway,
/// and a pty master whose last slave has closed carries `POLLHUP` for good — so
/// every `poll` returned immediately and the supervisor spun at 100% of a core
/// for the whole five-minute idle grace. The same code on macOS is quiet,
/// because kqueue synthesises nothing for an entry that asked for nothing.
///
/// Measured rather than reasoned about, and paired with the two things the fix
/// must not cost: the scrollback a later attach reads, and the end frame.
fn a_finished_session_stops_costing_cpu_and_still_serves_its_scrollback() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let terminal = interactive_attached(
        &store,
        store_dir.path(),
        "/bin/sh",
        &["-c", "sleep 0.2; echo done-and-gone"],
        WindowSize::new(24, 80),
    );
    let session_id = terminal.session_id();
    // Detached before the run speaks, so its output lands in the supervisor's
    // ring — which is where the reattach below has to find it after the master
    // has been let go of.
    let mut session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    let supervisor = session.supervisor().pid();
    match session.wait(PATIENCE) {
        Ok(WaitOutcome::Exit(exit)) => assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 }),
        Ok(WaitOutcome::StillRunning) => panic!("the run must finish"),
        Err(err) => panic!("wait must answer: {err}"),
    }
    // Away entirely: no client, a finished run, and nobody has said stop. This
    // is the state the supervisor sits in for the whole idle grace, and the
    // state the spin was in.
    session.detach();

    let before = cpu_millis(supervisor);
    std::thread::sleep(SPIN_WINDOW);
    let after = cpu_millis(supervisor);
    let burned = after.saturating_sub(before);
    assert!(
        burned <= SPIN_BUDGET_MILLIS,
        "a finished supervisor used {burned}ms of cpu in {}ms of doing nothing; \
         it is spinning on a descriptor it has nothing to ask about",
        SPIN_WINDOW.as_millis()
    );

    // And it is still a supervisor: the ring it kept after unplugging the
    // terminal, and the end frame it owes an attaching client.
    let reconnected = match store.attach_control(session_id) {
        Ok(session) => session,
        Err(err) => panic!("reconnection must succeed: {err}"),
    };
    let mut terminal = match reconnected.attach(WindowSize::new(24, 80)) {
        Ok(terminal) => terminal,
        Err(err) => panic!("attaching to a finished run must succeed: {err}"),
    };
    assert_eq!(terminal.ack().state(), LifecycleState::Exited);
    let tail = read_until(&mut terminal, "done-and-gone", PATIENCE);
    assert!(
        tail.contains("done-and-gone"),
        "the scrollback must outlive the master this run no longer needs: {tail:?}"
    );
    let ended = loop {
        match terminal.read_event(Instant::now() + PATIENCE) {
            Ok(TerminalEvent::Ended(end)) => break end,
            Ok(TerminalEvent::Output(_) | TerminalEvent::Pong) => {}
            Ok(TerminalEvent::Idle) => panic!("the end must still arrive promptly"),
            Err(err) => panic!("the terminal must answer: {err}"),
        }
    };
    assert_eq!(ended.state(), LifecycleState::Exited);

    let session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    session.detach();
}

// ---------------------------------------------------------------------------
// (f) Hostility: raw bytes are raw, and a broken frame breaks only the channel.
// ---------------------------------------------------------------------------

/// A payload chosen to be indistinguishable from framing, if framing were
/// content-based.
///
/// `0xFF`, NULs, and — the load-bearing part — a byte sequence that *is* a
/// well-formed frame header for a 64-byte `Output` frame. A protocol that
/// escaped or scanned its payload would split this; a length-prefixed one
/// carries it.
fn hostile_payload() -> Vec<u8> {
    let mut bytes = vec![0xFF_u8, 0x00, 0x00, 0xFE];
    bytes.push(AttachTag::Output.as_byte());
    bytes.extend_from_slice(&64_u32.to_le_bytes());
    bytes.extend_from_slice(&[0x00, 0xFF, 0x00, AttachTag::Detach.as_byte(), 0, 0, 0, 0]);
    bytes.extend_from_slice(b"tail");
    bytes
}

/// A `cat` behind a terminal in raw mode, so what comes back is what went in.
fn raw_mode_cat(store: &SessionStore, writable: &Path) -> AttachedTerminal {
    let mut terminal = interactive_attached(
        store,
        writable,
        "/bin/sh",
        // Raw mode with echo off: the line discipline neither translates
        // newlines, interprets control characters, nor echoes, so every byte
        // that comes back came back from `cat` and not from the terminal.
        &["-c", "stty raw -echo; printf ready; exec /bin/cat"],
        WindowSize::new(24, 80),
    );
    read_until(&mut terminal, "ready", PATIENCE);
    terminal
}

fn input_bytes_reach_the_terminal_verbatim_however_hostile() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let mut terminal = raw_mode_cat(&store, store_dir.path());

    let hostile = hostile_payload();
    if let Err(err) = terminal.write_input(&hostile) {
        panic!("a hostile payload is still a payload: {err}");
    }
    let echoed = read_bytes(&mut terminal, hostile.len(), PATIENCE);
    assert_eq!(
        echoed, hostile,
        "every byte must survive the round trip through the terminal unchanged"
    );

    // And the client-side bound is enforced before anything is written.
    let too_big = vec![b'x'; MAX_ATTACH_PAYLOAD_BYTES.saturating_add(1)];
    assert!(
        terminal.write_input(&too_big).is_err(),
        "a payload past the frame bound must be refused, not split"
    );

    let mut session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    if let Err(err) = session.stop() {
        panic!("the run must be stoppable: {err}");
    }
    session.detach();
}

/// Prepare an interactive run, activate it, and give the client slot back.
///
/// The raw-protocol tests below drive the socket by hand, so they need the run
/// going and nobody holding the one connection.
fn interactive_running(store: &SessionStore, writable: &Path) -> (Uuid, PathBuf) {
    let terminal = interactive_attached(
        store,
        writable,
        "/bin/sh",
        &["-c", COUNTER_SCRIPT],
        WindowSize::new(24, 80),
    );
    let id = terminal.session_id();
    let session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    session.detach();
    (id, store.control_socket_path(id))
}

/// Attach again and require the run to still be there and still talking.
fn require_still_running(store: &SessionStore, session_id: Uuid) {
    let session = match store.attach_control(session_id) {
        Ok(session) => session,
        Err(err) => panic!("the session must survive a broken channel: {err}"),
    };
    let mut terminal = match session.attach(WindowSize::new(24, 80)) {
        Ok(terminal) => terminal,
        Err(err) => panic!("the session must still be attachable: {err}"),
    };
    assert_eq!(terminal.ack().state(), LifecycleState::Running);
    let seen = read_until(&mut terminal, "tick", PATIENCE);
    assert!(
        seen.contains("tick"),
        "the run must still be talking: {seen:?}"
    );
    let mut session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    if let Err(err) = session.stop() {
        panic!("the run must be stoppable: {err}");
    }
    session.detach();
}

fn a_frame_tag_this_protocol_does_not_have_ends_the_channel_not_the_run() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let (session_id, socket) = interactive_running(&store, store_dir.path());

    let mut client = RawClient::connect_free(&socket);
    let ack = client.attach(session_id, WindowSize::new(24, 80));
    assert_eq!(ack.state(), LifecycleState::Running);
    // A tag no version of this protocol has. The channel is over — a stream
    // whose framing cannot be trusted cannot be resynchronized — and the close
    // is the whole of the answer.
    client.send_attach_frame(0x7F, b"nonsense");
    assert!(
        client.closes_after_draining(PATIENCE),
        "an unknown terminal frame tag must end the channel"
    );
    drop(client);

    require_still_running(&store, session_id);
}

fn an_oversize_input_frame_ends_the_channel_not_the_run() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let (session_id, socket) = interactive_running(&store, store_dir.path());

    let mut client = RawClient::connect_free(&socket);
    client.attach(session_id, WindowSize::new(24, 80));
    // A gigabyte announced and nothing sent. If the bound were checked after
    // the payload rather than before it, the supervisor would buffer a gigabyte
    // waiting for a body that never comes.
    client.send_attach_prefix(AttachTag::Input.as_byte(), 1_024 * 1_024 * 1_024);
    assert!(
        client.closes_after_draining(PATIENCE),
        "an oversize terminal frame must end the channel"
    );
    drop(client);

    require_still_running(&store, session_id);
}

// ---------------------------------------------------------------------------
// (g) The slot discipline attach inherits.
// ---------------------------------------------------------------------------

fn an_attach_occupies_the_one_client_slot() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let mut terminal = interactive_attached(
        &store,
        store_dir.path(),
        "/bin/sh",
        &["-c", COUNTER_SCRIPT],
        WindowSize::new(24, 80),
    );
    read_until(&mut terminal, "tick0", PATIENCE);

    let socket = store.control_socket_path(terminal.session_id());
    let mut second = RawClient::connect(&socket);
    assert_eq!(
        refusal(second.read_reply()),
        ControlRefusal::Busy,
        "attach holds the one client slot, so a second connection is told so"
    );
    assert!(second.is_closed());

    // And the attached client is untouched by the refusal.
    let after = read_until(&mut terminal, "tick", PATIENCE);
    assert!(after.contains("tick"), "{after:?}");

    let mut session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    if let Err(err) = session.stop() {
        panic!("the run must be stoppable: {err}");
    }
    session.detach();
}

// ---------------------------------------------------------------------------
// The ring's bound, and the honesty about it.
// ---------------------------------------------------------------------------

fn the_scrollback_ring_stays_bounded_and_says_what_it_dropped() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    // Roughly 400 KiB, comfortably past the 256 KiB ring, produced with nobody
    // attached. The removal-detection target: without the bound in
    // `Scrollback::push` the ack would report every byte buffered and nothing
    // dropped, and both assertions below fail.
    let terminal = interactive_attached(
        &store,
        store_dir.path(),
        "/bin/sh",
        &[
            "-c",
            "i=0; while [ $i -lt 400 ]; do printf '%01023d\\n' $i; i=$((i+1)); done",
        ],
        WindowSize::new(24, 80),
    );
    let session_id = terminal.session_id();
    let mut session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    match session.wait(PATIENCE) {
        Ok(WaitOutcome::Exit(exit)) => assert_eq!(exit.outcome(), ExitOutcome::Exited { code: 0 }),
        Ok(WaitOutcome::StillRunning) => panic!("the flood must finish"),
        Err(err) => panic!("wait must answer: {err}"),
    }

    let terminal = match session.attach(WindowSize::new(24, 80)) {
        Ok(terminal) => terminal,
        Err(err) => panic!("attach must succeed: {err}"),
    };
    let ack = terminal.ack();
    assert!(
        ack.buffered() <= SCROLLBACK_CAPACITY_BYTES as u64,
        "the ring must stay bounded: {} bytes buffered, bound is {}",
        ack.buffered(),
        SCROLLBACK_CAPACITY_BYTES
    );
    assert!(
        ack.dropped() > 0,
        "a run that outran the ring must be told how much it lost, got {}",
        ack.dropped()
    );
    assert_eq!(ack.state(), LifecycleState::Exited);
    assert_eq!(
        session_id,
        terminal.session_id(),
        "still the same session throughout"
    );

    let session = match terminal.detach() {
        Ok(session) => session,
        Err(err) => panic!("detach must succeed: {err}"),
    };
    session.detach();
}

// ---------------------------------------------------------------------------
// The two refusals that keep the terminal honest.
// ---------------------------------------------------------------------------

fn a_headless_run_refuses_an_attach_with_a_reason() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    let (session, _handle) = detached_true(&store, store_dir.path());
    // A headless run's standard streams are /dev/null. An attach to one would
    // be a client watching a terminal that can never say anything, so it is
    // refused with the reason rather than accepted into silence.
    let refused = session.attach(WindowSize::new(24, 80));
    match refused {
        Ok(_) => panic!("a headless run has no terminal to attach to"),
        Err(err) => assert_eq!(
            err.refusal(),
            Some(&ControlRefusal::NoTerminal),
            "expected a typed no-terminal refusal, got {err:?}"
        ),
    }
}

fn an_interactive_plan_is_refused_where_nothing_can_own_a_terminal() {
    let store_dir = TempStore::new();
    let store = store_dir.open();
    // The ephemeral paths have no process that outlives the call, so there is
    // nowhere for a terminal master to live. Refused with the method that does
    // implement it named, rather than run headless behind the caller's back.
    let plan = || {
        let plan = SandboxPlan::new("/bin/echo")
            .session_mode(SessionMode::Interactive)
            .capabilities(capabilities(store_dir.path()));
        match plan.validate() {
            Ok(plan) => plan,
            Err(err) => panic!("the plan must validate: {err}"),
        }
    };
    let refused = store.prepare(plan());
    assert!(
        matches!(
            refused,
            Err(LifecycleError::Prepare(
                PrepareError::InteractiveNeedsSupervisor
            ))
        ),
        "a store prepare must refuse an interactive plan: {:?}",
        refused.err()
    );
    let refused = nono::lifecycle::PreparedSandbox::prepare(plan());
    assert!(
        matches!(refused, Err(PrepareError::InteractiveNeedsSupervisor)),
        "an ephemeral prepare must refuse it too"
    );
}
