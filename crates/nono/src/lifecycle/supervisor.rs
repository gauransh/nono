//! The detached supervisor: a re-execution of this binary that owns the run.
//!
//! Everything else in this module dies with its caller. A detached run does
//! not, and this file is how. See `docs/adr/0002-detached-supervisor.md` for
//! the decision; what follows is the mechanism.
//!
//! # Why a re-exec, and not a fork
//!
//! A library cannot re-exec "the nono binary": it has no binary of its own. It
//! also cannot fork a *long-running* supervisor out of a threaded caller —
//! after `fork` only async-signal-safe calls are defined, the allocator's locks
//! may be held by threads that no longer exist, and on macOS the Objective-C
//! runtime aborts a forked child that touches it. The gate child of ADR-0001
//! survives that because it is syscall-only until `execve`; a supervisor that
//! runs Rust indefinitely has no such discipline available.
//!
//! So the supervisor is *this binary*, re-executed. It becomes a supervisor
//! rather than the embedder's own program because [`supervisor_entry`] is
//! called at the top of `main` and recognises a private marker in its
//! environment. That is one line of embedder cooperation, and it is the price
//! of fork-safety.
//!
//! # The three processes
//!
//! ```text
//! launcher            first intermediate      supervisor-to-be
//! --------            ------------------      ----------------
//! build image+policy
//! bind control socket
//! open 4 pipes
//! fork --------------> fork ----------------->  setsid
//!                      write SPAWNED pid       stdio -> /dev/null
//! reap the first <---- _exit(0)                fork ------------> (customer child:
//!                                              close its ends      child_main,
//!                                              write bootstrap     ADR-0001)
//!                                              un-CLOEXEC survivors
//!                                              sweep every other fd
//!                                              execve(current_exe)
//!                                                    |
//! wait for readiness <-------------------------------+--> supervisor_entry():
//! connect to socket                                       adopt, persist, ready
//! ```
//!
//! Both middle columns are the ADR-0001 child discipline: syscalls only, over
//! buffers the launcher built, ending in `execve` or `_exit`.
//!
//! **Why two forks and not one.** The second one is what makes the supervisor
//! work: `execve` replaces an image, not a process, so the customer child
//! forked before the exec is still the child of the *same pid* afterwards. The
//! supervisor can therefore `waitpid` it, which is the entire reason a detached
//! run's exit facts are observable at all.
//!
//! The first one is what makes it *detached*. Without it the supervisor would
//! be the launcher's own child, and a launcher that outlived it would collect a
//! zombie it never asked for and cannot be expected to reap — a process that is
//! meant to survive its caller must not leave the caller holding a wait. The
//! first intermediate forks the supervisor, tells the launcher its pid, and
//! exits; the launcher reaps *that*, in a wait it knows will return, and the
//! supervisor is reparented to init.
//!
//! Nothing about the plan crosses the exec: the sandbox policy, the argv, and
//! the environment were all built and used on the launcher's side of it, so a
//! capability set never has to be serialized and re-trusted.
//!
//! # What the supervisor inherits, and what it is told
//!
//! Descriptors cross the exec (the intermediate clears their close-on-exec
//! flag); their *numbers* and the facts that go with them arrive on a private
//! bootstrap pipe. The environment the supervisor is given contains exactly one
//! variable — the marker — and [`supervisor_entry`] removes even that before
//! any customer-related work, so it can never leak into a customer environment.
//! A plan's environment is explicit-only in any case; this is belt and braces.
//!
//! The gate's release/abort pair travels on the bootstrap pipe because the
//! customer child was forked holding it and there is nowhere else for it to
//! come from. The *activation token* travels the other way: it is drawn in the
//! supervisor, after the exec, and handed back to the launcher on the readiness
//! handshake — so it never exists in the customer child's address space at all,
//! not even for the microseconds between fork and exec.
//!
//! # Standard streams
//!
//! The intermediate points 0, 1, and 2 at `/dev/null` before it forks the
//! customer. A detached supervisor that held its launcher's terminal or its
//! launcher's pipes would keep them open after the launcher exited, which is
//! exactly the thing "detached" is supposed to stop. The consequence is stated
//! rather than hidden: **a headless detached run's output goes nowhere.**
//!
//! An *interactive* run is the answer to that, and it is why a plan that asks
//! for a terminal has to ask to be detached as well. The launcher allocates a
//! pseudo-terminal before any fork — [`open_pty`], because `posix_openpt`,
//! `grantpt` and the slave `open` can each allocate, take a lock, or walk the
//! filesystem, none of which a forked child may do — and then lets go of both
//! ends. The slave becomes the customer child's 0, 1 and 2; the master crosses
//! the exec and is held by the supervisor, and by nothing else anywhere. See
//! [`super::terminal`] for the channel a client reaches it through.
//!
//! ```text
//! descriptor   launcher                intermediate            customer child      supervisor
//! ----------   --------                ------------            --------------      ----------
//! pty master   opens, closes at fork   inherits, un-CLOEXEC    closes explicitly   owns, sole holder
//! pty slave    opens, closes at fork   closes after the fork   dup2 -> 0,1,2       never has it
//! ```
//!
//! Three closes matter and each is load-bearing. The launcher's slave, because
//! a copy left there would keep the terminal open after the run ended and the
//! supervisor's master would never see the end of output. The intermediate's
//! slave, for the same reason. The customer child's master, because a program
//! holding the master of its own terminal could read back everything it wrote
//! and everything typed at it.

use super::LifecycleError;
use super::detached::{CONTROL_TIMEOUT, DetachedSession};
use super::events::{EventEmitter, EventRing, EventSink, LifecycleEventKind};
use super::exit::SandboxExit;
use super::gate::{ACTIVATION_TOKEN_BYTES, ActivationHandle, GATE_MESSAGE_BYTES, GateSecrets};
use super::identity::ProcessIdentity;
use super::plan::SessionMode;
use super::plan::ValidatedPlan;
use super::prepare::{
    AdoptedChild, ChildContext, ChildTerminal, ExecImage, PlatformSandbox, PrepareError,
    PreparedSandbox, child_main, close_inherited_descriptors, last_errno, open_channel,
    refuse_unsupported, resolve_program, write_record,
};
use super::protocol::{
    CONTROL_PROTOCOL_VERSION, ControlRefusal, ControlReply, ControlRequest, FrameError,
    MAX_CONTROL_FRAME_BYTES, PollOutcome, SessionStatus, WaitOutcome, poll_fds, read_exact_by,
    read_frame, remaining_millis, set_nonblocking, write_frame,
};
use super::session_store::{SessionHandle, SessionRecord, SessionStore};
use super::state::LifecycleState;
use super::terminal::{
    AttachAck, AttachFrame, AttachTag, FrameDecoder, MAX_ATTACH_PAYLOAD_BYTES, Peer, ReadOutcome,
    Scrollback, TERMINAL_READ_CHUNK, TerminalEnd, WindowSize, WriteOutcome, decode_window,
    encode_frame, open_pty, outbound_bound, read_nonblocking, set_window_size, stall_deadline,
    write_nonblocking,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::ffi::{CString, c_char};
use std::io::{PipeReader, PipeWriter};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// The private marker that turns a re-executed image into a supervisor.
///
/// **Protocol, not configuration.** Nothing outside this file may set it, read
/// it, or document it as a knob: it names inherited descriptor numbers that are
/// meaningless in any other process, and [`supervisor_entry`] removes it from
/// the environment before anything else happens. It is spelled with the
/// library's own prefix so that an environment which happens to contain it did
/// so because this code put it there.
const SUPERVISOR_MARKER: &str = "NONO_LIFECYCLE_SUPERVISOR";

/// Handshake tag: the supervisor is ready, and a JSON frame follows.
const HANDSHAKE_READY: u8 = 0x01;

/// Handshake tag: the intermediate or the supervisor failed, and an errno
/// follows.
const HANDSHAKE_FAILED: u8 = 0x02;

/// Handshake tag: the supervisor has been forked, and its pid follows.
///
/// Written by the first intermediate immediately before it exits, so the
/// launcher knows which process to end if the readiness report never comes.
/// Without it, a supervisor that started but never reported would be a process
/// the launcher could neither wait for nor name.
const HANDSHAKE_SPAWNED: u8 = 0x03;

/// How long the launcher waits for the readiness handshake.
///
/// Long enough for a fork, an exec, a sandbox apply, and an `fsync`ed record on
/// a loaded machine; short enough that a binary whose `main` never calls
/// [`supervisor_entry`] fails in seconds rather than hanging. The failure names
/// the hook, because that is overwhelmingly what it means.
const READINESS_DEADLINE: Duration = Duration::from_secs(20);

/// How long the supervisor waits for its bootstrap blob.
///
/// The writer is the process it was just forked from, which has nothing to do
/// but write it. A deadline this generous only matters if that process was
/// stopped or killed between the fork and the write, in which case there is
/// nothing to supervise and exiting is correct.
const BOOTSTRAP_DEADLINE: Duration = Duration::from_secs(20);

/// How long a supervisor keeps serving a finished run with nobody connected.
///
/// A detached run's whole point is that its facts outlive the caller, so the
/// supervisor does not exit the moment the child does: a caller that restarts
/// has this long to reconnect and read the exit facts from the process that
/// witnessed them. After that the facts are still in the record — they were
/// written when they were observed, not when the supervisor exited — so what
/// is lost by exiting is only the ability to answer questions live.
///
/// Five minutes: long enough to cover a caller's restart, short enough that a
/// forgotten session does not hold a process for a day. A connected client
/// resets it, and a verified cleanup skips it entirely (there is nothing left
/// to verify, so there is nothing left to serve).
const IDLE_AFTER_TERMINAL_GRACE: Duration = Duration::from_secs(300);

/// How long the supervisor will wait for a client's request frame to arrive
/// whole.
///
/// Short on purpose, and much shorter than [`CONTROL_TIMEOUT`]. A request is a
/// few hundred bytes that the client assembled and wrote in a single call, so
/// two seconds is already several orders of magnitude of slack — while a peer
/// that sends three bytes and then nothing would otherwise hold the supervisor's
/// only thread for the full reply allowance on every cycle, and would keep doing
/// it. That thread is also what accepts connections and watches the child, so
/// the bound is not a politeness: it is what stops one slow client from being a
/// denial of service against the run itself.
const REQUEST_DEADLINE: Duration = Duration::from_secs(2);

/// How often the loop wakes up when nothing has happened.
///
/// The `SIGCHLD` self-pipe is what makes a child's death prompt; this is the
/// backstop that makes it *certain*, for the window between adopting the child
/// and installing the handler, and for the grace-period bookkeeping that has no
/// descriptor to wait on.
const POLL_SLICE: Duration = Duration::from_millis(250);

/// The write end of the `SIGCHLD` self-pipe, for the signal handler.
///
/// A raw descriptor number in an atomic, because that is the whole of what a
/// signal handler may touch: no allocation, no lock, no `Option<T>` behind a
/// mutex. `-1` means no supervisor loop is running in this process.
static SIGCHLD_PIPE: AtomicI32 = AtomicI32::new(-1);

/// Become a detached supervisor, if this process was launched as one.
///
/// **Call this first thing in `main`.** It returns immediately — and does
/// nothing at all — in every ordinary run of the program: without the private
/// environment marker and the descriptors it names, there is nothing for it to
/// do. When the marker *is* present, this function never returns. It takes over
/// the process: `setsid` if it is not already a session leader, adopt the child
/// the launcher forked, write the session record, report readiness, serve the
/// control socket until the run is over, and exit.
///
/// Without this call, [`SessionStore::prepare_detached`] cannot work: the
/// re-executed image runs the embedder's own `main` instead, never reports
/// readiness, and the launcher fails at its deadline with
/// [`PrepareError::SupervisorUnresponsive`], which names this function.
///
/// # Example
///
/// The first statement of the embedder's `main`, and nothing else:
///
/// ```no_run
/// // Nothing happens here unless this process *is* a supervisor launch;
/// // in every ordinary run it returns immediately and `main` carries on.
/// nono::lifecycle::supervisor_entry();
/// ```
///
/// # Safety of the environment read
///
/// The marker is removed from this process's environment before any other work,
/// so it can never reach a customer's environment through inheritance. Removing
/// an environment variable is only sound while the process is single-threaded,
/// which is exactly what "first thing in `main`" means — and is why the
/// documentation says it in those words rather than "somewhere early".
pub fn supervisor_entry() {
    let Some(marker) = Marker::take_from_environment() else {
        return;
    };
    let code = run(&marker);
    // Never returns to the embedder's `main`: this process is a supervisor and
    // has just finished being one.
    std::process::exit(code);
}

/// What the environment marker carries.
///
/// Three descriptor numbers and a protocol version, and nothing else: every
/// other fact arrives on the bootstrap pipe, where it can be bytes rather than
/// a string, can be bounded, and cannot be read out of `/proc` by anything that
/// can read this process's environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Marker {
    /// The pipe the launcher's bootstrap blob arrives on.
    bootstrap: RawFd,
    /// The pipe the readiness handshake is written to.
    handshake: RawFd,
    /// The already-bound, already-listening control socket.
    listener: RawFd,
}

impl Marker {
    /// Read the marker and remove it, or answer `None` for an ordinary run.
    fn take_from_environment() -> Option<Self> {
        let raw = std::env::var_os(SUPERVISOR_MARKER)?;
        // Removed before the value is even parsed. A malformed marker is still
        // a marker, and leaving it in place would mean a program that carried
        // on running normally did so with a private protocol variable in its
        // environment, ready to be inherited by anything it started.
        //
        // SAFETY: `remove_var` is sound while the process is single-threaded.
        // The contract of `supervisor_entry` is that it is called first thing
        // in `main`, before any thread exists; that requirement is documented
        // on the public function for exactly this line.
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint exists because env mutation races other threads in tests. \
                      This is not a test and there are no other threads: `supervisor_entry` \
                      is contracted to run as the first statement of `main`, and the \
                      alternative — leaving a private protocol marker in the environment of \
                      a process that then goes on to start other things — is the leak the \
                      removal exists to prevent."
        )]
        unsafe {
            std::env::remove_var(SUPERVISOR_MARKER);
        }

        let parsed = raw.to_str().and_then(Self::parse);
        if parsed.is_none() {
            // Not fatal: a program whose environment contained something under
            // this name must still run. Nothing is assumed about the
            // descriptors a malformed marker named, so nothing is touched.
            tracing::warn!(
                "{SUPERVISOR_MARKER} was set but could not be understood; \
                 continuing as an ordinary process"
            );
        }
        parsed
    }

    /// `<version>:<bootstrap>:<handshake>:<listener>`.
    fn parse(raw: &str) -> Option<Self> {
        let mut fields = raw.split(':');
        let version: u32 = fields.next()?.parse().ok()?;
        if version != CONTROL_PROTOCOL_VERSION {
            return None;
        }
        let bootstrap: RawFd = fields.next()?.parse().ok()?;
        let handshake: RawFd = fields.next()?.parse().ok()?;
        let listener: RawFd = fields.next()?.parse().ok()?;
        if fields.next().is_some() {
            return None;
        }
        // Descriptor numbers below 3 would name a standard stream, which the
        // intermediate has just pointed at `/dev/null`; a marker claiming one
        // is a marker this build did not write.
        if bootstrap < 3 || handshake < 3 || listener < 3 {
            return None;
        }
        Some(Self {
            bootstrap,
            handshake,
            listener,
        })
    }

    /// Render the marker as one `NAME=value` environment entry.
    fn render(self) -> String {
        format!(
            "{}={}:{}:{}:{}",
            SUPERVISOR_MARKER,
            CONTROL_PROTOCOL_VERSION,
            self.bootstrap,
            self.handshake,
            self.listener
        )
    }
}

/// Everything the supervisor is told that is not a descriptor number.
///
/// Carried on a private pipe rather than the environment or the command line:
/// an environment is readable from `/proc/<pid>/environ` and a command line is
/// readable by anyone at all, and this structure contains the gate's secrets.
#[derive(Serialize, Deserialize)]
struct Bootstrap {
    /// The session the launcher chose. It names the record and the socket, so
    /// the launcher has to choose it before it can bind either.
    session_id: Uuid,
    /// Which preparation of that session this is.
    generation: u64,
    /// The store directory, as bytes: a path is not necessarily UTF-8, and a
    /// store that could not be named would be a store that could not be
    /// written.
    store: Vec<u8>,
    /// The caller's opaque metadata, copied into the record verbatim.
    metadata: Vec<u8>,
    /// The gate's write end, as the intermediate left it.
    gate_fd: RawFd,
    /// The status descriptor's read end, likewise.
    status_fd: RawFd,
    /// The terminal master's descriptor number, for an interactive run.
    ///
    /// `None` is a headless run, whose standard streams are `/dev/null` and
    /// which therefore has nothing for an attach to show.
    pty_fd: Option<RawFd>,
    /// The plan's activation expiry, in milliseconds.
    expiry_millis: Option<u64>,
    /// The message that releases the held child.
    release: [u8; GATE_MESSAGE_BYTES],
    /// The message that tells it to give up.
    abort: [u8; GATE_MESSAGE_BYTES],
}

/// Forget the gate's secrets when the bootstrap value goes out of scope.
///
/// The parsed copy is as much a start button as the original, so it dies with
/// the buffer it was parsed from.
impl Drop for Bootstrap {
    fn drop(&mut self) {
        self.release.zeroize();
        self.abort.zeroize();
    }
}

/// What the supervisor tells the launcher once it is serving.
///
/// Carries the activation token, which is why the handshake is a private pipe
/// between exactly two processes and why both sides zeroize their copy of the
/// buffer it arrived in.
#[derive(Serialize, Deserialize)]
struct Readiness {
    /// The supervisor's own identity, captured by the supervisor.
    supervisor: ProcessIdentity,
    /// The customer child, as the supervisor adopted it.
    child: ProcessIdentity,
    /// The group the child leads.
    process_group: i32,
    /// The generation being served.
    generation: u64,
    /// The token that releases the child, drawn on this side of the exec.
    token: [u8; ACTIVATION_TOKEN_BYTES],
}

impl Drop for Readiness {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

// ---------------------------------------------------------------------------
// The launcher's side.
// ---------------------------------------------------------------------------

/// Launch a supervisor for `plan` and return a connection to it.
///
/// See [`SessionStore::prepare_detached`], which is the public name for this.
pub(super) fn launch(
    store: &SessionStore,
    plan: ValidatedPlan,
) -> Result<(DetachedSession, ActivationHandle), LifecycleError> {
    refuse_unsupported(&plan, true)?;
    if !plan.is_detached() {
        return Err(PrepareError::DetachedNotRequested.into());
    }

    let program = resolve_program(plan.program())?;
    let image = ExecImage::build(&program, &plan)?;
    let sandbox = PlatformSandbox::build(&plan)?;
    let (argv_ptrs, envp_ptrs) = image.pointers();

    // Canonicalized here, once, in the launcher: `argv[0]` is whatever started
    // this process and a relative path would resolve against a working
    // directory that the supervisor does not keep.
    let supervisor_image = current_image()?;

    let session_id = Uuid::now_v7();
    let generation = FIRST_DETACHED_GENERATION;
    let socket_path = store.control_socket_path(session_id);
    // Bound *before* the fork, deliberately. The alternative — the supervisor
    // binds, the launcher retries a connect until it appears — is a race with
    // no upper bound and no way to tell "not yet" from "never". Passing the
    // listening descriptor through the exec removes the race outright: by the
    // time readiness is reported, the socket has been listening since before
    // the supervisor existed.
    let listener = bind_control_socket(store, session_id, &socket_path)?;

    let launched = launch_inner(
        store,
        &plan,
        &image,
        &sandbox,
        &argv_ptrs,
        &envp_ptrs,
        &supervisor_image,
        &listener,
        session_id,
        generation,
    );
    // The launcher's copy of the listening socket goes now, whatever happened:
    // the supervisor owns it, and a second holder would keep the address alive
    // after the supervisor died.
    drop(listener);

    let ready = match launched {
        Ok(ready) => ready,
        Err(err) => {
            // Nothing is listening and nothing will; leaving the name behind
            // would leave a socket that answers ECONNREFUSED forever.
            store.inner().remove_socket(session_id);
            return Err(err);
        }
    };

    let session = DetachedSession::connect(
        &socket_path,
        session_id,
        generation,
        ready.supervisor.clone(),
    )
    .map_err(LifecycleError::from)?;
    Ok((
        session,
        ActivationHandle::new(session_id, generation, ready.token),
    ))
}

/// The generation a freshly detached session starts at.
///
/// One, like every other session: re-preparing into an existing session's slot
/// is what increments a generation, and nothing in this slice does that.
const FIRST_DETACHED_GENERATION: u64 = 1;

/// The fork, the exec, and the wait for readiness.
///
/// Split out so the socket cleanup above has exactly one place to happen.
#[expect(
    clippy::too_many_arguments,
    reason = "every argument is a buffer that must outlive the fork, so passing \
              them by reference from one frame is the point"
)]
fn launch_inner(
    store: &SessionStore,
    plan: &ValidatedPlan,
    image: &ExecImage,
    sandbox: &PlatformSandbox,
    argv_ptrs: &[*const c_char],
    envp_ptrs: &[*const c_char],
    supervisor_image: &Path,
    listener: &UnixListener,
    session_id: Uuid,
    generation: u64,
) -> Result<Readiness, LifecycleError> {
    let (gate_read, gate_write) = open_channel()?;
    let (status_read, status_write) = open_channel()?;
    let (handshake_read, handshake_write) = open_channel()?;
    let (bootstrap_read, bootstrap_write) = open_channel()?;

    // Allocated here, in the launcher, and for the same reason everything else
    // is: `posix_openpt`, `grantpt` and the slave open can each allocate, take
    // a lock, or walk the filesystem, and a forked child may do none of those.
    // What crosses the fork is two descriptor numbers.
    let pty = match plan.session_mode() {
        SessionMode::Interactive => Some(open_pty()?),
        SessionMode::Headless => None,
    };
    let terminal = pty.as_ref().map(|pty| ChildTerminal {
        slave: pty.slave.as_raw_fd(),
        master: pty.master.as_raw_fd(),
    });

    let secrets = GateSecrets::generate().map_err(|_| PrepareError::TokenGeneration)?;

    // Built before the fork, because the intermediate may not allocate. The
    // buffer holds the gate's secrets, so it is zeroized when this frame ends
    // rather than left in a freed page.
    let bootstrap = Bootstrap {
        session_id,
        generation,
        store: store.path().as_os_str().as_bytes().to_vec(),
        metadata: plan.metadata().to_vec(),
        gate_fd: gate_write.as_raw_fd(),
        status_fd: status_read.as_raw_fd(),
        pty_fd: terminal.map(|terminal| terminal.master),
        expiry_millis: plan
            .gate()
            .activation_expiry
            .map(|expiry| u64::try_from(expiry.as_millis()).unwrap_or(u64::MAX)),
        release: *secrets.release(),
        abort: *secrets.abort(),
    };
    let blob = Zeroizing::new(serde_json::to_vec(&bootstrap).map_err(|_| {
        PrepareError::SupervisorHandshake {
            stage: "bootstrap encode",
            errno: 0,
        }
    })?);
    let mut framed = Zeroizing::new(Vec::with_capacity(blob.len().saturating_add(4)));
    let blob_length = u32::try_from(blob.len()).map_err(|_| PrepareError::SupervisorHandshake {
        stage: "bootstrap encode",
        errno: 0,
    })?;
    framed.extend_from_slice(&blob_length.to_le_bytes());
    framed.extend_from_slice(&blob);

    let marker = Marker {
        bootstrap: bootstrap_read.as_raw_fd(),
        handshake: handshake_write.as_raw_fd(),
        listener: listener.as_raw_fd(),
    };
    let supervisor_argv = supervisor_command(supervisor_image, marker)?;
    let (supervisor_argv_ptrs, supervisor_envp_ptrs) = supervisor_argv.pointers();

    let child = ChildContext {
        gate_read: gate_read.as_raw_fd(),
        gate_write: gate_write.as_raw_fd(),
        status_read: status_read.as_raw_fd(),
        status_write: status_write.as_raw_fd(),
        terminal,
        program: image.program.as_ptr(),
        argv: argv_ptrs.as_ptr(),
        envp: envp_ptrs.as_ptr(),
        working_dir: image
            .working_dir
            .as_ref()
            .map_or(std::ptr::null(), |dir| dir.as_ptr()),
        sandbox,
        secrets: &secrets,
    };
    let context = LaunchContext {
        child,
        handshake_write: handshake_write.as_raw_fd(),
        bootstrap_read: bootstrap_read.as_raw_fd(),
        bootstrap_write: bootstrap_write.as_raw_fd(),
        listener: listener.as_raw_fd(),
        blob: &framed,
        image: supervisor_argv.program.as_ptr(),
        argv: supervisor_argv_ptrs.as_ptr(),
        envp: supervisor_envp_ptrs.as_ptr(),
    };

    // SAFETY: `fork` duplicates this process. The child branch runs only
    // async-signal-safe syscalls over buffers built above and then `_exit`s or
    // `execve`s, so it never returns into Rust code, never unwinds, and never
    // runs a destructor. The one exception is the macOS sandbox apply inside
    // the customer child, which is documented on `PlatformSandbox`.
    let forked = unsafe { nix::unistd::fork() }.map_err(|errno| PrepareError::Fork {
        errno: errno as i32,
    })?;

    let first = match forked {
        nix::unistd::ForkResult::Child => intermediate_main(&context),
        nix::unistd::ForkResult::Parent { child } => child,
    };

    // Every descriptor the supervisor now owns. The gate's write end in
    // particular: while this process held a copy, a dead supervisor would not
    // make the held child's `read` return 0, and the ADR-0001 property that a
    // held child never outlives every writer of its gate would be broken.
    //
    // The pseudo-terminal is the same argument twice over. The launcher's copy
    // of the *slave* would keep the terminal open after the run ended, so the
    // supervisor's master would never see the end of output — and a launcher
    // that lived for hours would hold a terminal for a run that finished in
    // seconds. The launcher's copy of the *master* would mean two processes
    // could read the run's output, one of which is not the one that owns it.
    drop(gate_read);
    drop(gate_write);
    drop(status_read);
    drop(status_write);
    drop(handshake_write);
    drop(bootstrap_read);
    drop(bootstrap_write);
    drop(pty);

    let mut handshake_read = handshake_read;
    if let Err(err) = set_nonblocking(handshake_read.as_raw_fd()) {
        super::exit::kill_and_reap(first.as_raw());
        return Err(handshake_error(err, supervisor_image, "handshake setup").into());
    }

    let handshake = await_handshake(&mut handshake_read, supervisor_image);

    // The first intermediate has named the supervisor and is on its way out;
    // reaping it is the only wait a detached launch ever makes, and it is
    // bounded by the `SIGKILL` in front of it rather than by trust in a process
    // that has already done its job. The supervisor itself is nobody's child but
    // init's from this moment, which is what stops a long-lived launcher
    // accumulating zombies it never asked for.
    super::exit::kill_and_reap(first.as_raw());

    if handshake.readiness.is_err() {
        // The supervisor never reported serving. Killing it closes the last
        // writer of the held child's gate, so the child leaves too — no orphan,
        // no held process, and no reliance on the supervisor having managed to
        // clean up after itself. It is not this process's child any more, so
        // there is nothing to reap: init does that. If no `SPAWNED` record ever
        // arrived there is no supervisor to end.
        if let Some(pid) = handshake.spawned {
            let _ = super::exit::kill_pid(pid);
        }
    }
    handshake.readiness.map_err(LifecycleError::from)
}

/// The supervisor's own `execve` arguments: its path, one argument, one
/// environment variable.
///
/// The environment is *only* the marker. A supervisor is a long-lived process
/// that may outlive the shell that started its launcher, and inheriting that
/// shell's environment would mean inheriting its secrets into a process that
/// nobody is watching. The plan's environment is explicit-only and belongs to
/// the customer child, which was forked before any of this and carries its own.
fn supervisor_command(image: &Path, marker: Marker) -> Result<ExecCommand, PrepareError> {
    let nul = || PrepareError::SupervisorImageUnreadable { errno: 0 };
    let program = CString::new(image.as_os_str().as_bytes()).map_err(|_| nul())?;
    let marker = CString::new(marker.render()).map_err(|_| nul())?;
    Ok(ExecCommand {
        argv: vec![program.clone()],
        envp: vec![marker],
        program,
    })
}

/// A program, an argv, and an envp, as C buffers owned by the launcher.
struct ExecCommand {
    program: CString,
    argv: Vec<CString>,
    envp: Vec<CString>,
}

impl ExecCommand {
    /// NULL-terminated pointer arrays for `execve`.
    fn pointers(&self) -> (Vec<*const c_char>, Vec<*const c_char>) {
        let argv = self
            .argv
            .iter()
            .map(|entry| entry.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp = self
            .envp
            .iter()
            .map(|entry| entry.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        (argv, envp)
    }
}

/// This process's own executable, canonicalized.
fn current_image() -> Result<PathBuf, PrepareError> {
    let exe = std::env::current_exe().map_err(|err| PrepareError::SupervisorImageUnreadable {
        errno: err.raw_os_error().unwrap_or(0),
    })?;
    exe.canonicalize()
        .map_err(|err| PrepareError::SupervisorImageUnreadable {
            errno: err.raw_os_error().unwrap_or(0),
        })
}

/// Bind and listen on a session's control socket.
///
/// Unlink-guarded: a name left behind by a supervisor that died without
/// cleaning up would make `bind` answer `EADDRINUSE`, and the name is derived
/// from a session id this process has just drawn, so nothing that could still
/// be in use can be under it.
fn bind_control_socket(
    store: &SessionStore,
    session_id: Uuid,
    path: &Path,
) -> Result<UnixListener, PrepareError> {
    refuse_long_socket_path(store.path(), path)?;
    store.inner().remove_socket(session_id);
    let listener = UnixListener::bind(path).map_err(|err| PrepareError::ControlSocket {
        path: path.to_path_buf(),
        errno: err.raw_os_error().unwrap_or(0),
    })?;
    // The directory is already 0700 and owner-checked, so this is the second
    // fence rather than the first — and the peer-uid check at accept is the
    // third. A socket's own mode is not honoured by every kernel, which is
    // exactly why it is not the only one.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, mode).map_err(|err| PrepareError::ControlSocket {
        path: path.to_path_buf(),
        errno: err.raw_os_error().unwrap_or(0),
    })?;
    Ok(listener)
}

/// Refuse a socket path that would not fit a `sockaddr_un`.
///
/// The kernel would otherwise truncate it, and a truncated path is a socket at
/// a *different* address — one the launcher would then fail to connect to for a
/// reason that looks nothing like the cause.
fn refuse_long_socket_path(store: &Path, path: &Path) -> Result<(), PrepareError> {
    // SAFETY: `sockaddr_un` is plain old data; a zeroed one is a valid value
    // and is read only for the length of its `sun_path` array.
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let limit = address.sun_path.len();
    let needed = path.as_os_str().as_bytes().len().saturating_add(1);
    if needed > limit {
        return Err(PrepareError::ControlSocketPathTooLong {
            path: store.to_path_buf(),
            needed,
            limit,
        });
    }
    Ok(())
}

/// Everything the intermediate needs, as values it can use without allocating.
struct LaunchContext<'a> {
    /// The customer child's context, exactly as the attached path builds it.
    child: ChildContext<'a>,
    handshake_write: RawFd,
    bootstrap_read: RawFd,
    bootstrap_write: RawFd,
    listener: RawFd,
    /// The length-prefixed bootstrap blob, built by the launcher.
    blob: &'a [u8],
    image: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
}

/// The whole of the intermediate's life before `execve`.
///
/// Runs only async-signal-safe syscalls over buffers the launcher built, never
/// returns, and never unwinds. It forks the customer child — which is a
/// syscall, and the reason the supervisor can `waitpid` — and then replaces its
/// own image.
fn intermediate_main(context: &LaunchContext<'_>) -> ! {
    // The first fork: this process exists only to produce a supervisor that is
    // nobody's child but init's. See the module docs.
    // SAFETY: `fork` in a process that has run only syscalls since its own
    // fork. Both branches below run syscalls only and end in `_exit` or
    // `execve`.
    let supervisor = unsafe { libc::fork() };
    if supervisor < 0 {
        intermediate_fail(context.handshake_write, last_errno());
    }
    if supervisor > 0 {
        // Still the first intermediate. Name the supervisor for the launcher —
        // which otherwise could not end a supervisor that started but never
        // reported — and then leave, so that the launcher's wait is on a
        // process that is already exiting.
        write_record(context.handshake_write, HANDSHAKE_SPAWNED, supervisor);
        // SAFETY: `_exit` is async-signal-safe, skips every destructor, and
        // does not return. Every descriptor this process holds closes with it;
        // the supervisor has its own copies.
        unsafe { libc::_exit(0) }
    }

    // A session of its own, before the customer child exists, so that the whole
    // detached run leaves the launcher's session and controlling terminal
    // rather than only the supervisor doing so. A fresh fork is never a process
    // group leader, so this cannot fail for the reason `setsid` usually does;
    // if it fails anyway the run is still correct, only less isolated, and
    // there is no channel to report it on yet.
    // SAFETY: `setsid` takes no arguments, touches no memory, and is
    // async-signal-safe.
    unsafe { libc::setsid() };

    // Before the fork, so the customer child gets `/dev/null` too. A detached
    // run that held its launcher's stdout would keep that pipe open after the
    // launcher exited, and a caller waiting for its own child's output would
    // wait forever.
    redirect_standard_streams();

    // SAFETY: `fork` in a process that has run only syscalls since its own
    // fork. The child branch calls `child_main`, which is the ADR-0001
    // discipline and never returns.
    let forked = unsafe { libc::fork() };
    if forked < 0 {
        intermediate_fail(context.handshake_write, last_errno());
    }
    if forked == 0 {
        child_main(&context.child);
    }

    // The customer's ends. Closing the gate's read end here is hygiene; closing
    // the status descriptor's write end is what makes EOF on it meaningful.
    // SAFETY: both are descriptors this process owns, closed exactly once.
    unsafe {
        libc::close(context.child.gate_read);
        libc::close(context.child.status_write);
    }

    // And the terminal's slave, for the same reason as the status descriptor:
    // the supervisor's master reaches end-of-file only when the *last* slave
    // closes, so a copy left here would mean a run whose output never ended.
    // The customer child has its own copy on 0, 1, and 2.
    if let Some(terminal) = context.child.terminal {
        // SAFETY: a descriptor this process owns, closed exactly once.
        unsafe { libc::close(terminal.slave) };
    }

    // The customer child's pid, then the launcher's prebuilt blob. The pid is
    // the one fact the launcher could not know before the fork, so it is the
    // one thing written here rather than prepared there.
    if !write_i32(context.bootstrap_write, forked)
        || !write_bytes(context.bootstrap_write, context.blob)
    {
        intermediate_fail(context.handshake_write, last_errno());
    }

    // Deliberately inheritable across the exec: these are the supervisor's
    // whole inheritance, and every one of them was created close-on-exec so
    // that no *other* exec in this process's history could have leaked it.
    //
    // The terminal master is the sixth when there is one. `-1` stands in for
    // "no terminal" rather than a shorter array, because this runs between a
    // fork and an exec and may not allocate: `fcntl` and `close` on `-1` are
    // `EBADF` and change nothing.
    let survivors = [
        context.child.gate_write,
        context.child.status_read,
        context.listener,
        context.handshake_write,
        context.bootstrap_read,
        context
            .child
            .terminal
            .map_or(-1, |terminal| terminal.master),
    ];
    for fd in survivors {
        if fd >= 0 && !clear_close_on_exec(fd) {
            intermediate_fail(context.handshake_write, last_errno());
        }
    }

    // Everything else this process inherited goes now — including the
    // launcher's own descriptors and the bootstrap write end, which has done
    // its work and whose closure is what lets the supervisor's read see EOF.
    let mut keep = survivors;
    close_inherited_descriptors(&mut keep);

    // SAFETY: all three pointers address NUL-terminated buffers built by the
    // launcher, and the two vectors are NULL-terminated.
    unsafe { libc::execve(context.image, context.argv, context.envp) };
    intermediate_fail(context.handshake_write, last_errno())
}

/// Report a pre-exec failure to the launcher and leave.
fn intermediate_fail(handshake: RawFd, errno: i32) -> ! {
    write_record(handshake, HANDSHAKE_FAILED, errno);
    // SAFETY: `_exit` is async-signal-safe, skips every destructor, and does
    // not return.
    unsafe { libc::_exit(1) }
}

/// Point 0, 1, and 2 at `/dev/null`.
///
/// Best effort per stream: a supervisor with no standard output is correct, and
/// a supervisor that refused to start because `/dev/null` was missing would be
/// refusing over something it does not need.
fn redirect_standard_streams() {
    // SAFETY: a literal NUL-terminated path and a flags integer; `open` is
    // async-signal-safe and allocates nothing.
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
    if null < 0 {
        return;
    }
    for stream in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: two integers; `dup2` closes the target if it was open and is
        // async-signal-safe.
        unsafe { libc::dup2(null, stream) };
    }
    if null > libc::STDERR_FILENO {
        // SAFETY: a descriptor this process owns, closed exactly once.
        unsafe { libc::close(null) };
    }
}

/// Put a descriptor's close-on-exec flag back.
///
/// The mirror of [`clear_close_on_exec`], run in the supervisor once the exec
/// that needed the flag cleared has happened. Best effort per descriptor: this
/// is defence in depth over a flag that was cleared deliberately and for one
/// exec only, so failing to re-arm one is not a reason to refuse a session that
/// is otherwise ready.
fn set_close_on_exec(fd: RawFd) {
    // SAFETY: `fd` is a live descriptor this process owns; `F_GETFD` reads
    // flags and `F_SETFD` sets them.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return;
    }
    // SAFETY: as above.
    unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
}

/// Clear a descriptor's close-on-exec flag. Returns whether it worked.
fn clear_close_on_exec(fd: RawFd) -> bool {
    // SAFETY: `fd` is a live descriptor; `F_GETFD` reads flags and `F_SETFD`
    // sets them. Both are async-signal-safe.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return false;
    }
    // SAFETY: as above.
    unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) >= 0 }
}

/// Write a little-endian `i32`. Returns whether all four bytes landed.
fn write_i32(fd: RawFd, value: i32) -> bool {
    write_bytes(fd, &value.to_le_bytes())
}

/// Write every byte, retrying through interruption. Returns whether it worked.
fn write_bytes(fd: RawFd, bytes: &[u8]) -> bool {
    let mut written: usize = 0;
    while written < bytes.len() {
        let Some(slice) = bytes.get(written..) else {
            return true;
        };
        // SAFETY: `slice` is a live sub-slice of the caller's buffer and its
        // length is exactly what is passed. `write` is async-signal-safe.
        let count = unsafe { libc::write(fd, slice.as_ptr().cast::<libc::c_void>(), slice.len()) };
        match usize::try_from(count) {
            Ok(0) => return false,
            Ok(count) => written = written.saturating_add(count),
            Err(_) if last_errno() == libc::EINTR => {}
            Err(_) => return false,
        }
    }
    true
}

/// Everything the launcher learns from the handshake pipe.
///
/// Two writers share that pipe — the first intermediate, which names the
/// supervisor it forked, and the supervisor itself, which reports readiness —
/// and **their order is not synchronized**. The supervisor is forked before the
/// `HANDSHAKE_SPAWNED` record is written, so in principle it can `execve`, adopt
/// the child and report ready before the intermediate's five bytes land. In
/// practice the intermediate wins by milliseconds every time, which is exactly
/// what makes assuming it dangerous: a launcher that required `SPAWNED` first
/// would fail with a *typed* error on a race that shows up once in a very long
/// while and reproduces never. So the reader tolerates either order.
struct Handshake {
    /// The supervisor's pid, if the intermediate's record was seen.
    ///
    /// Only ever needed on the failure path — a successful readiness report
    /// carries the supervisor's whole identity — so `None` is not itself a
    /// failure.
    spawned: Option<i32>,
    /// What the supervisor reported, or why it did not.
    readiness: Result<Readiness, PrepareError>,
}

/// Read the handshake pipe until it has an answer, in whatever order it arrives.
///
/// Bounded twice: by the readiness deadline, and by the number of records it
/// will consider before giving up — a peer that only ever sent `SPAWNED` records
/// must not be able to keep the launcher reading.
fn await_handshake(handshake: &mut PipeReader, image: &Path) -> Handshake {
    /// `SPAWNED`, then one terminal record. Anything beyond that is a writer
    /// this build does not have.
    const MAX_RECORDS: usize = 4;

    let deadline = Instant::now() + READINESS_DEADLINE;
    let mut spawned = None;
    for _ in 0..MAX_RECORDS {
        let record = read_handshake_record(handshake, deadline, image, "handshake header");
        let (tag, number) = match record {
            Ok(record) => record,
            Err(err) => {
                return Handshake {
                    spawned,
                    readiness: Err(err),
                };
            }
        };
        match tag {
            // Not terminal: keep reading for the readiness report, which may
            // already have been written.
            HANDSHAKE_SPAWNED if number > 0 => spawned = Some(number),
            HANDSHAKE_FAILED => {
                return Handshake {
                    spawned,
                    readiness: Err(PrepareError::SupervisorHandshake {
                        stage: "supervisor start",
                        errno: number,
                    }),
                };
            }
            HANDSHAKE_READY => {
                return Handshake {
                    spawned,
                    readiness: read_readiness_frame(handshake, deadline, image, number),
                };
            }
            _ => {
                return Handshake {
                    spawned,
                    readiness: Err(PrepareError::SupervisorHandshake {
                        stage: "handshake header",
                        errno: 0,
                    }),
                };
            }
        }
    }
    Handshake {
        spawned,
        readiness: Err(PrepareError::SupervisorHandshake {
            stage: "handshake header",
            errno: 0,
        }),
    }
}

/// Read the body of a `HANDSHAKE_READY` record, whose length the header gave.
fn read_readiness_frame(
    handshake: &mut PipeReader,
    deadline: Instant,
    image: &Path,
    length: i32,
) -> Result<Readiness, PrepareError> {
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    if length > MAX_CONTROL_FRAME_BYTES {
        return Err(PrepareError::SupervisorHandshake {
            stage: "readiness frame",
            errno: 0,
        });
    }
    // Zeroized: this is the buffer the activation token arrives in.
    let mut body = Zeroizing::new(vec![0_u8; length]);
    read_exact_by(handshake, &mut body, deadline)
        .map_err(|err| handshake_error(err, image, "readiness frame"))?;
    serde_json::from_slice(&body).map_err(|_| PrepareError::SupervisorHandshake {
        stage: "readiness frame",
        errno: 0,
    })
}

/// Read one five-byte handshake record: a tag and a little-endian `i32`.
fn read_handshake_record(
    handshake: &mut PipeReader,
    deadline: Instant,
    image: &Path,
    stage: &'static str,
) -> Result<(u8, i32), PrepareError> {
    let mut header = [0_u8; 5];
    read_exact_by(handshake, &mut header, deadline)
        .map_err(|err| handshake_error(err, image, stage))?;
    let Some((tag, rest)) = header.split_first() else {
        return Err(PrepareError::SupervisorHandshake { stage, errno: 0 });
    };
    let number = i32::from_le_bytes([
        *rest.first().unwrap_or(&0),
        *rest.get(1).unwrap_or(&0),
        *rest.get(2).unwrap_or(&0),
        *rest.get(3).unwrap_or(&0),
    ]);
    Ok((*tag, number))
}

/// Turn a handshake framing failure into the error a caller can act on.
///
/// A timeout gets the message that names [`supervisor_entry`], because a
/// re-executed image that reports nothing at all is overwhelmingly a binary
/// whose `main` never called it.
fn handshake_error(err: FrameError, image: &Path, stage: &'static str) -> PrepareError {
    match err {
        FrameError::Timeout => PrepareError::SupervisorUnresponsive {
            image: image.to_path_buf(),
            waited: READINESS_DEADLINE,
        },
        FrameError::Closed => PrepareError::SupervisorHandshake { stage, errno: 0 },
        FrameError::Io { errno } => PrepareError::SupervisorHandshake { stage, errno },
        FrameError::TooLarge { .. } | FrameError::Malformed { .. } => {
            PrepareError::SupervisorHandshake { stage, errno: 0 }
        }
    }
}

// ---------------------------------------------------------------------------
// The supervisor's side.
// ---------------------------------------------------------------------------

/// Become the supervisor. Returns the process exit code.
fn run(marker: &Marker) -> i32 {
    // A write to a client that has gone away must be an `EPIPE` this loop can
    // handle, not a signal that ends a process holding somebody's run.
    ignore_sigpipe();

    // SAFETY: the descriptor was inherited across `execve` from the
    // intermediate, which cleared its close-on-exec flag and then swept every
    // other descriptor. Nothing else in this process owns it.
    let bootstrap = PipeReader::from(unsafe { OwnedFd::from_raw_fd(marker.bootstrap) });
    // SAFETY: as above.
    let mut handshake = PipeWriter::from(unsafe { OwnedFd::from_raw_fd(marker.handshake) });
    match serve(marker, bootstrap, &mut handshake) {
        Ok(()) => 0,
        Err(errno) => {
            // The launcher is still waiting on the handshake; telling it why is
            // the difference between a typed error and a deadline.
            write_record(handshake.as_raw_fd(), HANDSHAKE_FAILED, errno);
            1
        }
    }
}

/// Everything between the exec and the exit, with failures as errnos.
fn serve(
    marker: &Marker,
    mut bootstrap: PipeReader,
    handshake: &mut PipeWriter,
) -> Result<(), i32> {
    let bootstrap = read_bootstrap(&mut bootstrap)?;
    become_session_leader();

    // Every descriptor that crossed the exec, put back to close-on-exec now
    // that it has. The intermediate had to clear the flag to pass them here,
    // and the customer child was forked before that — so nothing is left that
    // needs to inherit any of them, and re-arming closes the window before this
    // process ever execs anything again. That is not hypothetical work for its
    // own sake: a supervisor that leaked its own control socket, its own gate
    // descriptor, or the master of the run's terminal into whatever it started
    // would hand that program the run.
    for fd in [
        marker.bootstrap,
        marker.handshake,
        marker.listener,
        bootstrap.blob.gate_fd,
        bootstrap.blob.status_fd,
        bootstrap.blob.pty_fd.unwrap_or(-1),
    ] {
        if fd >= 0 {
            set_close_on_exec(fd);
        }
    }

    let identity = ProcessIdentity::capture(own_pid());
    let store_path = PathBuf::from(os_string_from_bytes(&bootstrap.blob.store));
    let store = SessionStore::open(&store_path).map_err(|_| libc::EIO)?;

    // The supervisor's own sink, because it has no caller to take one from.
    let ring = Arc::new(EventRing::new());
    let events = Arc::new(EventEmitter::new(
        Some(Arc::clone(&ring) as Arc<dyn EventSink>),
        bootstrap.blob.session_id,
        bootstrap.blob.generation,
    ));

    // SAFETY: both descriptors were inherited across `execve` and named by the
    // bootstrap blob the intermediate wrote; nothing else in this process owns
    // either of them.
    let gate = PipeWriter::from(unsafe { OwnedFd::from_raw_fd(bootstrap.blob.gate_fd) });
    // SAFETY: as above.
    let status = PipeReader::from(unsafe { OwnedFd::from_raw_fd(bootstrap.blob.status_fd) });

    let adopted = AdoptedChild {
        session_id: bootstrap.blob.session_id,
        generation: bootstrap.blob.generation,
        identity: ProcessIdentity::capture(bootstrap.child_pid),
        process_group: bootstrap.child_pid,
        gate,
        status,
        secrets: GateSecrets::from_parts(bootstrap.blob.release, bootstrap.blob.abort),
        expiry: bootstrap.blob.expiry_millis.map(Duration::from_millis),
        events: Arc::clone(&events),
    };
    let child_identity = adopted.identity.clone();
    let process_group = adopted.process_group;
    let (mut prepared, handle) = PreparedSandbox::adopt(adopted).map_err(|_| libc::ECHILD)?;

    let mut record = SessionRecord::new(
        bootstrap.blob.session_id,
        bootstrap.blob.generation,
        child_identity.clone(),
        process_group,
        prepared.state(),
        bootstrap.blob.metadata.clone(),
    );
    // Named by the supervisor itself, so the identity a later reader probes for
    // liveness is one this process captured about itself rather than one the
    // launcher guessed about a pid it had just forked.
    record.set_supervisor(identity.clone());
    store
        .inner()
        .create_record(&record)
        .map_err(|_| libc::EIO)?;
    events.emit(LifecycleEventKind::RecordPersisted {
        schema_version: record.schema_version(),
    });
    let session = Arc::new(SessionHandle::detached(
        Arc::clone(store.inner()),
        record,
        Arc::clone(&events),
        Arc::clone(&ring),
    ));
    prepared.attach_session(Arc::clone(&session));

    // The terminal, if this run has one. Non-blocking, because it joins the one
    // poll set that also accepts connections and watches the child: a master
    // whose customer had stopped reading would otherwise park the whole
    // supervisor inside a single `write`.
    let terminal = match bootstrap.blob.pty_fd {
        Some(fd) => {
            // SAFETY: inherited across `execve`, named by the bootstrap blob
            // the intermediate wrote, and owned by nothing else in this
            // process — the launcher dropped its copies after the fork and the
            // customer child closed its own before the sandbox applied.
            let master = unsafe { OwnedFd::from_raw_fd(fd) };
            set_nonblocking(master.as_raw_fd()).map_err(|_| libc::EIO)?;
            Some(Terminal::new(master))
        }
        None => None,
    };

    // Installed *before* readiness is announced, so that the byte the launcher
    // reads means what it says. A supervisor that reported ready and then
    // installed its `SIGCHLD` handler would have a window in which a child that
    // died immediately after activation was noticed only by the 250 ms poll
    // backstop — or, if the handler install failed, not promptly at all, while
    // a caller had already been told the session was serving.
    let signals = SignalPipe::install()?;

    // Ready: the child is adopted, confined, and at the gate; the record is on
    // disk; the death of that child is already watched for; and the socket has
    // been listening since before this process existed.
    let readiness = Readiness {
        supervisor: identity,
        child: child_identity,
        process_group,
        generation: bootstrap.blob.generation,
        token: *handle.token(),
    };
    write_readiness(handshake, &readiness)?;
    drop(readiness);
    drop(handle);

    // SAFETY: inherited across `execve`, named by the marker, and owned by
    // nothing else in this process.
    let listener = unsafe { UnixListener::from_raw_fd(marker.listener) };
    let mut supervisor = Supervisor {
        session_id: bootstrap.blob.session_id,
        generation: bootstrap.blob.generation,
        store,
        session,
        prepared,
        activated: None,
        client: None,
        serving_client: false,
        listener,
        signals,
        terminal,
        idle_since: None,
    };
    supervisor.serve_until_done();
    supervisor
        .store
        .inner()
        .remove_socket(supervisor.session_id);
    Ok(())
}

/// The bootstrap blob plus the pid the intermediate wrote in front of it.
struct BootstrapMessage {
    child_pid: i32,
    blob: Bootstrap,
}

/// Read the intermediate's bootstrap message, bounded.
fn read_bootstrap(reader: &mut PipeReader) -> Result<BootstrapMessage, i32> {
    let deadline = Instant::now() + BOOTSTRAP_DEADLINE;
    set_nonblocking(reader.as_raw_fd()).map_err(|_| libc::EIO)?;

    let mut pid = [0_u8; 4];
    read_exact_by(reader, &mut pid, deadline).map_err(|_| libc::EIO)?;
    let child_pid = i32::from_le_bytes(pid);

    let mut length = [0_u8; 4];
    read_exact_by(reader, &mut length, deadline).map_err(|_| libc::EIO)?;
    let announced = usize::try_from(u32::from_le_bytes(length)).unwrap_or(usize::MAX);
    if announced > MAX_CONTROL_FRAME_BYTES {
        return Err(libc::EMSGSIZE);
    }
    let mut body = Zeroizing::new(vec![0_u8; announced]);
    read_exact_by(reader, &mut body, deadline).map_err(|_| libc::EIO)?;
    let blob: Bootstrap = serde_json::from_slice(&body).map_err(|_| libc::EINVAL)?;
    Ok(BootstrapMessage { child_pid, blob })
}

/// Write the readiness frame and close the handshake.
fn write_readiness(handshake: &mut PipeWriter, readiness: &Readiness) -> Result<(), i32> {
    let body = Zeroizing::new(serde_json::to_vec(readiness).map_err(|_| libc::EINVAL)?);
    let length = i32::try_from(body.len()).map_err(|_| libc::EMSGSIZE)?;
    if !write_record(handshake.as_raw_fd(), HANDSHAKE_READY, length)
        || !write_bytes(handshake.as_raw_fd(), &body)
    {
        return Err(last_errno());
    }
    Ok(())
}

/// `setsid` unless this process already leads its session.
///
/// The intermediate normally does this before the exec, so the check is what
/// keeps the call idempotent rather than a guaranteed `EPERM`.
fn become_session_leader() {
    // SAFETY: both take a single integer, touch no memory, and cannot fail in
    // a way that matters here.
    let (session, pid) = unsafe { (libc::getsid(0), libc::getpid()) };
    if session != pid {
        // SAFETY: as above. A failure leaves the process in its launcher's
        // session, which is less isolated but still correct.
        unsafe { libc::setsid() };
    }
}

/// This process's pid as an `i32`.
fn own_pid() -> i32 {
    // SAFETY: `getpid` takes no arguments, touches no memory, and cannot fail.
    unsafe { libc::getpid() }
}

/// Make `SIGPIPE` an error rather than a death.
fn ignore_sigpipe() {
    // SAFETY: `signal` with `SIG_IGN` for `SIGPIPE` is the standard way to turn
    // a write to a closed peer into an `EPIPE` return. No handler function is
    // installed, so nothing runs in signal context.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
}

/// The `SIGCHLD` self-pipe.
///
/// A signal handler may not take a lock, allocate, or touch a `Waker`; what it
/// may do is `write` one byte to a descriptor. That byte is what makes the
/// supervisor's `poll` return promptly when the customer's program ends,
/// instead of waiting out its next timeout slice.
struct SignalPipe {
    reader: PipeReader,
    /// Kept so the write end outlives the handler that uses its number.
    _writer: PipeWriter,
}

impl SignalPipe {
    /// Create the pipe and install the handler.
    fn install() -> Result<Self, i32> {
        let (reader, writer) = open_channel().map_err(|_| libc::EMFILE)?;
        set_nonblocking(reader.as_raw_fd()).map_err(|_| libc::EIO)?;
        // Non-blocking too: a handler that blocked on a full pipe would block
        // in signal context, and a dropped notification is harmless — the byte
        // means "look at the child", not "here is what happened".
        set_nonblocking(writer.as_raw_fd()).map_err(|_| libc::EIO)?;
        SIGCHLD_PIPE.store(writer.as_raw_fd(), Ordering::Relaxed);

        // SAFETY: `sigaction` installs `on_sigchld`, which is written to be
        // async-signal-safe: it saves and restores `errno`, reads one atomic,
        // and calls `write`. The mask is empty and no flags beyond restart are
        // set, so nothing else about the process's signal handling changes.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = on_sigchld as *const () as usize;
        action.sa_flags = libc::SA_RESTART | libc::SA_NOCLDSTOP;
        // SAFETY: `action` is a live, fully initialised `sigaction`; the old
        // action is discarded with a null pointer, which is documented.
        let installed =
            unsafe { libc::sigaction(libc::SIGCHLD, &raw const action, std::ptr::null_mut()) };
        if installed != 0 {
            return Err(last_errno());
        }
        Ok(Self {
            reader,
            _writer: writer,
        })
    }

    /// Drain whatever the handler wrote. The count is not information.
    fn drain(&mut self) {
        let mut scratch = [0_u8; 64];
        loop {
            // SAFETY: `scratch` is a live local and its length is exactly what
            // is passed; the descriptor is non-blocking, so this returns
            // `EAGAIN` rather than parking.
            let count = unsafe {
                libc::read(
                    self.reader.as_raw_fd(),
                    scratch.as_mut_ptr().cast::<libc::c_void>(),
                    scratch.len(),
                )
            };
            if count <= 0 {
                return;
            }
        }
    }
}

impl Drop for SignalPipe {
    fn drop(&mut self) {
        SIGCHLD_PIPE.store(-1, Ordering::Relaxed);
    }
}

/// The `SIGCHLD` handler: one byte, and nothing else.
extern "C" fn on_sigchld(_signal: libc::c_int) {
    // A handler that clobbered `errno` would turn an interrupted syscall in the
    // main loop into an entirely different failure.
    // SAFETY: the per-thread `errno` location; reading and restoring it is what
    // makes this handler safe to run between any two instructions.
    let location = unsafe { errno_location() };
    // SAFETY: a valid, aligned pointer to this thread's `errno`.
    let saved = unsafe { *location };

    let fd = SIGCHLD_PIPE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = b'c';
        // SAFETY: a one-byte write to a non-blocking descriptor. `write` is
        // async-signal-safe and the pointer addresses a live local.
        unsafe {
            libc::write(fd, std::ptr::from_ref(&byte).cast::<libc::c_void>(), 1);
        }
    }

    // SAFETY: as above.
    unsafe { *location = saved };
}

/// This thread's `errno` location.
#[cfg(target_os = "linux")]
unsafe fn errno_location() -> *mut i32 {
    // SAFETY: the libc entry point for the per-thread errno; always valid.
    unsafe { libc::__errno_location() }
}

/// This thread's `errno` location.
#[cfg(target_os = "macos")]
unsafe fn errno_location() -> *mut i32 {
    // SAFETY: the libc entry point for the per-thread errno; always valid.
    unsafe { libc::__error() }
}

/// The running supervisor.
struct Supervisor {
    session_id: Uuid,
    generation: u64,
    store: SessionStore,
    session: Arc<SessionHandle>,
    /// The held child. Kept after activation too, because it is the value that
    /// refuses a second activation with the gate's own typed answer.
    prepared: PreparedSandbox,
    /// The run, once released.
    activated: Option<super::exit::ActivatedSandbox>,
    /// The one client, if there is one.
    ///
    /// `None` does **not** mean the slot is free — see [`Self::serving_client`].
    /// Ask [`Self::slot_is_taken`], never this field, before deciding about a
    /// connection.
    client: Option<Client>,
    /// Whether an exchange with the client is in flight.
    ///
    /// [`Self::serve_client`] takes the client *out* of its slot for the
    /// duration of one exchange, so that every path which ends a conversation
    /// ends it by simply not returning the stream. That leaves `client` reading
    /// as `None` while a request is being answered — and one request,
    /// [`ControlRequest::Wait`], runs a poll loop of its own that accepts
    /// connections. Without this marker that accept reads a free slot, hands the
    /// session to a second client, and then loses it the moment the first is put
    /// back: the second connection is closed with **nothing written on it**,
    /// which is strictly worse than the refusal the protocol promises.
    serving_client: bool,
    listener: UnixListener,
    signals: SignalPipe,
    /// The run's terminal, when it has one. This process is its only holder.
    terminal: Option<Terminal>,
    /// When the run reached a terminal state with nobody connected.
    idle_since: Option<Instant>,
}

impl Supervisor {
    /// Serve until the run is over and nobody is coming back.
    fn serve_until_done(&mut self) {
        loop {
            self.observe_child();
            self.service_terminal();
            if self.should_exit() {
                // Unplugged before anything else is dropped. Every remaining
                // handle's `Drop` kills and reaps, and a reap of a session
                // leader that still holds an undrained controlling terminal
                // never returns — see `Terminal::hang_up`.
                if let Some(terminal) = self.terminal.as_mut() {
                    terminal.hang_up();
                }
                return;
            }
            self.poll_once();
        }
    }

    /// Where the run is, from whichever handle currently owns it.
    fn state(&self) -> LifecycleState {
        self.activated.as_ref().map_or_else(
            || self.prepared.state(),
            super::exit::ActivatedSandbox::state,
        )
    }

    /// The run's exit facts, if its end has been observed here.
    fn exit(&self) -> Option<SandboxExit> {
        self.session.snapshot().exit().cloned()
    }

    /// Whether the run has reached a state nothing else will move it from.
    fn is_terminal(&self) -> bool {
        matches!(
            self.state(),
            LifecycleState::Exited
                | LifecycleState::Stopped
                | LifecycleState::Failed
                | LifecycleState::CleanupVerified
        )
    }

    /// Whether it is time to stop being a supervisor.
    ///
    /// Two rules, both documented on [`IDLE_AFTER_TERMINAL_GRACE`]: a verified
    /// cleanup ends the session outright, and any other terminal state waits
    /// out the grace period in case a caller is restarting.
    fn should_exit(&mut self) -> bool {
        if self.state() == LifecycleState::CleanupVerified && self.client.is_none() {
            return true;
        }
        if !self.is_terminal() || self.client.is_some() {
            self.idle_since = None;
            return false;
        }
        let since = *self.idle_since.get_or_insert_with(Instant::now);
        since.elapsed() >= IDLE_AFTER_TERMINAL_GRACE
    }

    /// Wait for something to happen, then handle exactly what did.
    fn poll_once(&mut self) {
        // A client that is no longer there does not get to hold the one slot.
        // Checked at the top of every pass — including the passes a timeout
        // ends — so that the idle clock starts when the last client left rather
        // than when this process next happened to read from it.
        self.reap_lost_client();

        let mut watch = WatchSet::new();
        watch.add(Watched::Listener, self.listener.as_raw_fd(), libc::POLLIN);
        watch.add(
            Watched::Signals,
            self.signals.reader.as_raw_fd(),
            libc::POLLIN,
        );
        if let Some(client) = &self.client {
            watch.add(
                Watched::Client,
                client.stream.as_raw_fd(),
                self.client_interest(client),
            );
        }
        if let Some(terminal) = &self.terminal
            && let Some((master, interest)) = terminal_watch(terminal, self.terminal_has_room())
        {
            watch.add(Watched::Terminal, master, interest);
        }
        // Before activation the status descriptor is how a child that died at
        // the gate announces itself; after it, the descriptor is gone and
        // `SIGCHLD` is the only report.
        if let Some(status) = self.prepared.status_fd() {
            watch.add(Watched::Status, status, libc::POLLIN);
        }

        let slice = libc::c_int::try_from(POLL_SLICE.as_millis()).unwrap_or(250);
        match poll_fds(&mut watch.descriptors, slice) {
            PollOutcome::Ready => {}
            // A timeout and an interruption both mean "go round again": the
            // loop re-checks the child, the terminal, and the grace period on
            // every pass.
            PollOutcome::TimedOut | PollOutcome::Interrupted => return,
            PollOutcome::Failed(_) => return,
        }

        if watch.ready(Watched::Signals, libc::POLLIN) {
            self.signals.drain();
        }
        if watch.ready(Watched::Listener, libc::POLLIN) {
            self.accept_one();
        }
        // The terminal before the client, so output that arrived in the same
        // wakeup as a request is already queued when the request is answered.
        // In particular a detach then carries everything the run had said.
        if watch.ready(
            Watched::Terminal,
            libc::POLLIN | libc::POLLOUT | libc::POLLHUP,
        ) {
            self.service_terminal();
        }
        if watch.ready(
            Watched::Client,
            libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        ) {
            self.serve_client();
        }
        if watch.ready(Watched::Client, libc::POLLOUT) {
            self.flush_client();
        }
    }

    /// What the connected client's descriptor is watched for.
    ///
    /// Two pieces of backpressure live here. Output owed to the client makes
    /// this watch for writability; bytes owed to the *terminal* stop it
    /// watching for readability, so a client that types faster than the run
    /// reads fills its own socket buffer instead of this process's memory.
    fn client_interest(&self, client: &Client) -> libc::c_short {
        let terminal_busy = self
            .terminal
            .as_ref()
            .is_some_and(|terminal| !terminal.to_master.is_empty());
        let mut events = if terminal_busy { 0 } else { libc::POLLIN };
        if client
            .attached
            .as_ref()
            .is_some_and(|channel| !channel.outbound.is_empty())
        {
            events |= libc::POLLOUT;
        }
        events
    }

    /// Whether there is anywhere for more terminal output to go.
    fn terminal_has_room(&self) -> bool {
        match self.attached() {
            // The ring always has room: it is bounded and drops its oldest,
            // which is why a detached run can never be stalled by the fact
            // that nobody is listening.
            None => true,
            Some(channel) => channel.outbound.len() < outbound_bound(),
        }
    }

    /// The attach channel, when the connected client is watching the terminal.
    fn attached(&self) -> Option<&AttachChannel> {
        self.client
            .as_ref()
            .and_then(|client| client.attached.as_ref())
    }

    /// Accept a connection, deciding what to do with it before reading a byte.
    ///
    /// The slot is re-checked here and not only at the top of the loop, because
    /// this is the one place its occupancy *decides* anything. A connection and
    /// its predecessor's death routinely arrive in the same `poll` wakeup — the
    /// process that prepared a detached session exits, its control socket is
    /// closed by the kernel, and the process that comes to adopt the session
    /// connects microseconds later — and a supervisor that read the slot before
    /// noticing the death would answer [`ControlRefusal::Busy`] on behalf of a
    /// client that no longer exists. That is not a race in the caller: it is
    /// this process refusing the whole point of a detached session.
    fn accept_one(&mut self) {
        self.reap_lost_client();
        if let Some(stream) = accept_or_refuse(&self.listener, self.slot_is_taken()) {
            self.client = Some(Client {
                stream,
                greeted: false,
                attached: None,
            });
            self.idle_since = None;
        }
    }

    /// Drop the connected client if there is nobody on the other end of it.
    ///
    /// A control connection is *usually* ended with a `Goodbye`, and a crash is
    /// exactly the case where it is not. The kernel closes the descriptor of a
    /// process that exits however it exited, so the connection's end is a fact
    /// available here at once — and a supervisor that waited to notice it by
    /// trying to read would keep the slot occupied for as long as it had
    /// nothing to read *for*.
    fn reap_lost_client(&mut self) {
        let gone = self
            .client
            .as_ref()
            .is_some_and(|client| client_is_gone(client.stream.as_raw_fd()));
        if gone {
            self.client = None;
        }
    }

    /// Whether the one client slot is spoken for.
    ///
    /// Two ways it can be, and only one of them is visible in `client`: a
    /// connection sitting in the slot, and a connection that has been taken
    /// *out* of the slot for the length of one exchange. The second is not a
    /// detail — a `Wait` can hold it for [`MAX_CONTROL_WAIT`][wait], and the
    /// loop that runs inside that wait accepts connections.
    ///
    /// This is the only thing the accept path may ask. Reading `client` there
    /// directly is the bug it exists to prevent.
    ///
    /// [wait]: super::detached::MAX_CONTROL_WAIT
    fn slot_is_taken(&self) -> bool {
        self.client.is_some() || self.serving_client
    }

    /// Read from the client, in whichever mode the connection is in.
    ///
    /// The slot is marked as taken for the whole of this, not merely while the
    /// stream happens to be sitting in it: both arms below take the client out
    /// and put it back, and an accept that ran in between — which a `Wait`
    /// makes routine — would otherwise see a session with no client at all.
    fn serve_client(&mut self) {
        self.serving_client = true;
        if self.attached().is_some() {
            self.serve_attached();
        } else {
            self.serve_one_request();
        }
        self.serving_client = false;
    }

    /// Read one request from the client and answer it.
    ///
    /// The client is taken out of its slot for the duration and put back only
    /// if the exchange leaves the connection usable, so every path that ends a
    /// conversation ends it by simply not returning the stream.
    fn serve_one_request(&mut self) {
        let Some(mut client) = self.client.take() else {
            return;
        };
        // The *read* deadline, and deliberately much shorter than the reply
        // allowance. A request is a handful of bytes that the client has
        // already assembled and written in one call, so a peer that has sent
        // three of them and stopped is not slow, it is holding the one thread
        // that also accepts connections and watches the child. A reply, by
        // contrast, can legitimately follow a `wait` — so it gets a fresh
        // [`CONTROL_TIMEOUT`] of its own in [`Client::reply`].
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let stream = &mut client.stream;
        let request: ControlRequest = match read_frame(stream, deadline) {
            Ok(request) => request,
            Err(err) => {
                if err.is_reportable() {
                    let refusal = match err {
                        FrameError::TooLarge { size, limit } => {
                            ControlRefusal::FrameTooLarge { size, limit }
                        }
                        other => ControlRefusal::Malformed {
                            why: other.to_string(),
                        },
                    };
                    let _ = write_frame(
                        stream,
                        &ControlReply::Refused { refusal },
                        Instant::now() + CONTROL_TIMEOUT,
                    );
                }
                // Either way the connection is over: a stream whose framing
                // failed cannot be resynchronized.
                return;
            }
        };

        if self.answer(&mut client, request) {
            self.client = Some(client);
        }
    }

    /// Answer one request. Returns whether the connection survives it.
    fn answer(&mut self, client: &mut Client, request: ControlRequest) -> bool {
        // The hello is the only frame legal before the hello, and the only
        // frame that carries the three facts the rest of the conversation is
        // checked against. An operation that arrives first was, by definition,
        // not checked against the session it names.
        if let ControlRequest::Hello {
            protocol,
            session_id,
            generation,
        } = request
        {
            let refusal = self.check_hello(protocol, session_id, generation);
            let reply = match refusal {
                Some(refusal) => ControlReply::Refused { refusal },
                None => ControlReply::Hello {
                    protocol: CONTROL_PROTOCOL_VERSION,
                    session_id: self.session_id,
                    generation: self.generation,
                    state: self.state(),
                },
            };
            let accepted = matches!(reply, ControlReply::Hello { .. });
            client.greeted = accepted;
            return client.reply(&reply) && accepted;
        }
        if !client.greeted {
            client.reply(&ControlReply::Refused {
                refusal: ControlRefusal::HelloExpected,
            });
            return false;
        }

        let reply = match request {
            ControlRequest::Hello { .. } => unreachable_hello(),
            ControlRequest::Activate { token } => self.activate(token),
            ControlRequest::Wait { deadline_millis } => self.wait(deadline_millis),
            ControlRequest::Stop => self.stop(),
            ControlRequest::Status => ControlReply::Status {
                status: Box::new(self.status()),
            },
            ControlRequest::VerifyCleanup => self.verify_cleanup(),
            ControlRequest::Attach { window } => self.attach(window),
            ControlRequest::Goodbye => ControlReply::Farewell,
        };
        let farewell = matches!(reply, ControlReply::Farewell);
        let attached = matches!(reply, ControlReply::AttachAck { .. });
        if !client.reply(&reply) {
            return false;
        }
        if attached {
            // The ack was the last control frame this connection carries. The
            // switch happens *after* the write, so a failed ack leaves the
            // connection in the mode both sides still agree about.
            client.attached = Some(AttachChannel::new());
            self.seed_attach(client);
        }
        !farewell
    }

    /// Accept an attach, or say why the run has nothing to attach to.
    ///
    /// The window is applied before the reply, so a program released after this
    /// reads the size the viewer has rather than the zeroes a fresh terminal
    /// carries.
    fn attach(&mut self, window: WindowSize) -> ControlReply {
        let state = self.state();
        let exit = self.exit();
        let Some(terminal) = self.terminal.as_mut() else {
            return ControlReply::Refused {
                refusal: ControlRefusal::NoTerminal,
            };
        };
        // Best effort, and absent entirely once the terminal has been hung up:
        // a master that refuses a window size is still a master, and refusing
        // the attach over it would trade a working terminal for a cosmetic
        // failure. There is no channel to report it on yet either — this is the
        // frame that creates one.
        if let Some(master) = terminal.fd() {
            let _ = set_window_size(master, window);
        }
        ControlReply::AttachAck {
            ack: Box::new(AttachAck::new(
                state,
                terminal.ring.len() as u64,
                terminal.ring.dropped(),
                exit,
            )),
        }
    }

    /// Hand the fresh channel everything the ring was holding.
    ///
    /// The count in the ack has already said how much this is, so a client that
    /// wants to distinguish scrollback from live output can.
    fn seed_attach(&mut self, client: &mut Client) {
        let Some(terminal) = self.terminal.as_mut() else {
            return;
        };
        let Some(channel) = client.attached.as_mut() else {
            return;
        };
        let backlog = terminal.ring.take();
        channel.queue_output(&backlog);
    }

    /// Check the three facts a hello carries.
    fn check_hello(
        &self,
        protocol: u32,
        session_id: Uuid,
        generation: u64,
    ) -> Option<ControlRefusal> {
        if protocol != CONTROL_PROTOCOL_VERSION {
            return Some(ControlRefusal::ProtocolVersion {
                expected: CONTROL_PROTOCOL_VERSION,
                supplied: protocol,
            });
        }
        if session_id != self.session_id {
            return Some(ControlRefusal::WrongSession {
                expected: self.session_id,
                supplied: session_id,
            });
        }
        if generation != self.generation {
            return Some(ControlRefusal::WrongGeneration {
                expected: self.generation,
                supplied: generation,
            });
        }
        None
    }

    /// Release the child, or report which check refused.
    fn activate(&mut self, mut token: [u8; ACTIVATION_TOKEN_BYTES]) -> ControlReply {
        // Rebuilt here and dropped at the end of this function, so the token
        // exists in this process for exactly the length of one comparison.
        // Every check — session, generation, gate state, expiry, digest — is
        // the gate's own, not a second copy of it living in the protocol.
        let handle = ActivationHandle::new(self.session_id, self.generation, token);
        // The argument is a *copy*: `[u8; 32]` is `Copy`, so building the handle
        // above duplicated the bytes rather than moving them. The handle's own
        // copy dies with it (`ZeroizeOnDrop`); this one has to be told to. Done
        // before the comparison rather than after it, because every path out of
        // this function below is a `return` of some shape.
        token.zeroize();

        let reply = match self.prepared.activate(&handle) {
            Ok(activated) => {
                self.activated = Some(activated);
                ControlReply::Activated {
                    state: self.state(),
                }
            }
            Err(err) => ControlReply::Refused {
                refusal: ControlRefusal::Activation(err),
            },
        };
        drop(handle);
        reply
    }

    /// Wait for the run to end, up to the client's bound and this build's.
    fn wait(&mut self, deadline_millis: u64) -> ControlReply {
        if let Some(exit) = self.exit() {
            return ControlReply::Waited {
                outcome: WaitOutcome::Exit(exit),
            };
        }
        let requested = Duration::from_millis(deadline_millis);
        let deadline = Instant::now() + requested.min(super::detached::MAX_CONTROL_WAIT);
        loop {
            self.observe_child();
            // A wait must not stop the terminal being read. Without this the
            // run's own output would fill the terminal's buffer, the program
            // would block writing, and a caller waiting for it to finish would
            // be waiting for something it had itself prevented.
            self.service_terminal();
            if let Some(exit) = self.exit() {
                return ControlReply::Waited {
                    outcome: WaitOutcome::Exit(exit),
                };
            }
            if remaining_millis(deadline).is_none() {
                return ControlReply::Waited {
                    outcome: WaitOutcome::StillRunning,
                };
            }
            // A wait must not stop this supervisor being a supervisor: a second
            // client that connects during one still gets its typed refusal
            // rather than an unexplained silence.
            self.wait_slice(deadline);
        }
    }

    /// One slice of a wait: sleep on the descriptors, service the listener.
    fn wait_slice(&mut self, deadline: Instant) {
        let mut watch = WatchSet::new();
        watch.add(Watched::Listener, self.listener.as_raw_fd(), libc::POLLIN);
        watch.add(
            Watched::Signals,
            self.signals.reader.as_raw_fd(),
            libc::POLLIN,
        );
        // Watched for output only, and only while there is output to come: an
        // ended master reports `POLLHUP` to every `poll` on Linux whatever it
        // was asked about, so a wait that kept it here would burn its whole
        // allowance in a spin. See [`terminal_watch`].
        if let Some(terminal) = self.terminal.as_ref()
            && let Some((master, interest)) = terminal_watch(terminal, self.terminal_has_room())
            && interest & libc::POLLIN != 0
        {
            watch.add(Watched::Terminal, master, libc::POLLIN);
        }
        let slice = remaining_millis(deadline)
            .unwrap_or(0)
            .min(libc::c_int::try_from(POLL_SLICE.as_millis()).unwrap_or(250));
        match poll_fds(&mut watch.descriptors, slice) {
            PollOutcome::Ready => {}
            _ => return,
        }
        if watch.ready(Watched::Signals, libc::POLLIN) {
            self.signals.drain();
        }
        if watch.ready(Watched::Listener, libc::POLLIN) {
            // This can only ever refuse — and the reason is not that `client`
            // holds the waiting connection, because it does not: the exchange
            // this wait belongs to took it out of the slot. It is
            // [`Supervisor::serving_client`] that keeps the slot taken across
            // the whole exchange, which is what makes the refusal here a
            // *written* `Busy` rather than a second client being accepted and
            // then silently dropped when the waiter is put back.
            self.accept_one();
        }
        // The terminal is serviced by the caller's loop on the next pass; the
        // descriptor is here so that the wait wakes for it rather than sitting
        // out a whole poll slice with output ready.
    }

    /// End the run, through whichever handle owns it.
    fn stop(&mut self) -> ControlReply {
        // Read everything the run has said, then unplug its terminal, *before*
        // the kill. A stop reaps, and a reap blocks — and a session leader
        // holding a controlling terminal cannot finish exiting until that
        // terminal has drained. Draining is this thread's job, and this thread
        // is the one about to block, so the terminal has to go first or the
        // wait is for a death that can never complete. Proven: without the
        // hang-up the reap never returns.
        self.service_terminal();
        if let Some(terminal) = self.terminal.as_mut() {
            terminal.hang_up();
        }
        let stopped = match self.activated.as_mut() {
            Some(activated) => activated.stop(),
            None => self.prepared.stop_before_activation(),
        };
        match stopped {
            Ok(exit) => {
                self.session.persist_exit(self.state(), &exit);
                ControlReply::Stopped { exit }
            }
            Err(err) => ControlReply::Refused {
                refusal: ControlRefusal::Stop(err),
            },
        }
    }

    /// Report where the run is, with the record and the ring.
    fn status(&self) -> SessionStatus {
        SessionStatus::new(self.state(), self.session.snapshot_with_ring())
    }

    /// Probe for survivors, through whichever handle owns the run.
    fn verify_cleanup(&mut self) -> ControlReply {
        let verified = match self.activated.as_mut() {
            Some(activated) => activated.verify_cleanup(),
            None => self.prepared.verify_cleanup(),
        };
        match verified {
            Ok(verdict) => ControlReply::Cleanup {
                verdict,
                state: self.state(),
            },
            Err(err) => ControlReply::Refused {
                refusal: ControlRefusal::Cleanup { state: err.state },
            },
        }
    }

    /// Look at the child, and write down anything new.
    ///
    /// Called on every pass of the loop and at every step of a wait, so a
    /// child's death is recorded whether it was announced by `SIGCHLD`, by the
    /// status descriptor, or by nothing at all.
    fn observe_child(&mut self) {
        if let Some(activated) = self.activated.as_mut() {
            // `Ok(None)` is a run that is still going and `Err` is a
            // `waitpid` that failed, which says nothing about the child; both
            // mean there is nothing new to write down.
            if let Ok(Some(exit)) = activated.try_wait() {
                let state = activated.state();
                self.session.persist_exit(state, &exit);
            }
            return;
        }
        // Before activation there is no `ActivatedSandbox` to ask, and the only
        // reap available is the stop path's — which is honest about what it
        // finds: the `ExitOutcome` it records is what the child actually did,
        // not a claim that somebody asked for it.
        if self.prepared.state() == LifecycleState::Prepared
            && self.child_left_the_gate()
            && let Ok(exit) = self.prepared.stop_before_activation()
        {
            self.events_note_unrequested_end();
            let state = self.prepared.state();
            self.session.persist_exit(state, &exit);
        }
    }

    /// Whether the held child has written to, or closed, the status descriptor.
    fn child_left_the_gate(&self) -> bool {
        let Some(fd) = self.prepared.status_fd() else {
            return false;
        };
        let mut descriptors = [libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        match poll_fds(&mut descriptors, 0) {
            PollOutcome::Ready => descriptors.first().is_some_and(|entry| entry.revents != 0),
            _ => false,
        }
    }

    /// Note that the run ended without anybody asking it to.
    ///
    /// The stop path above records the *outcome* faithfully but reports it
    /// through stop-shaped events, because a pre-activation reap is the only
    /// one this module has. This is the event that says so, so a reader of the
    /// ring is not left to infer a stop nobody requested.
    fn events_note_unrequested_end(&self) {
        self.session
            .emit_reconstructed(LifecycleEventKind::GateAborted);
    }

    // -----------------------------------------------------------------------
    // The terminal.
    // -----------------------------------------------------------------------

    /// Move every byte that can move, in the order that keeps them in order.
    ///
    /// Called on every pass of the loop rather than only when `poll` said so,
    /// because two of the five steps have no descriptor to wait on: the
    /// end-of-run frame is owed to a fact about the *child*, and the stall
    /// deadline is owed to the absence of an event.
    fn service_terminal(&mut self) {
        self.pump_to_terminal();
        self.pump_from_terminal();
        self.announce_end();
        self.flush_client();
        self.drop_stalled_client();
        self.retire_terminal();
    }

    /// Let go of a master that has nothing left to carry.
    ///
    /// Last, so that everything the pass could move has moved: the run's output
    /// is in the ring or on its way to a client, the end frame is queued, and
    /// whatever the client typed has either reached the terminal or been
    /// dropped by the write that found it gone.
    ///
    /// Two conditions, and both are load-bearing. [`Terminal::retire`] checks
    /// that no more output can arrive and no input is still owed. This checks
    /// that the *run* is over, which is what makes the close harmless: closing a
    /// master hangs the terminal up and signals the session, and a program that
    /// had merely closed its own standard streams and carried on is not a
    /// program to hang up on. Until it ends, its master simply stops being
    /// watched — see [`terminal_watch`] — which is all the spin needed.
    fn retire_terminal(&mut self) {
        if !self.is_terminal() {
            return;
        }
        if let Some(terminal) = self.terminal.as_mut() {
            terminal.retire();
        }
    }

    /// Hand the terminal whatever the client typed.
    fn pump_to_terminal(&mut self) {
        let Some(terminal) = self.terminal.as_mut() else {
            return;
        };
        let Some(master) = terminal.fd() else {
            terminal.to_master.clear();
            return;
        };
        while let Some(chunk) = front_slice(&terminal.to_master) {
            match write_nonblocking(master, chunk) {
                WriteOutcome::Wrote(count) => {
                    terminal.to_master.drain(..count);
                }
                WriteOutcome::WouldBlock => return,
                // The terminal is gone. Input for a run that has ended is
                // dropped rather than held: there is nothing left to type at.
                WriteOutcome::Ended => {
                    terminal.to_master.clear();
                    return;
                }
            }
        }
    }

    /// Take whatever the run said, and put it wherever it goes.
    fn pump_from_terminal(&mut self) {
        let Self {
            terminal, client, ..
        } = self;
        let Some(terminal) = terminal.as_mut() else {
            return;
        };
        let Some(master) = terminal.fd().filter(|_| !terminal.ended) else {
            return;
        };
        let mut channel = client
            .as_mut()
            .and_then(|client| client.attached.as_mut())
            .filter(|channel| !channel.detaching);
        loop {
            // Room first: with a client attached this is the backpressure that
            // reaches all the way to the run, because an unread master stops
            // the program writing. With nobody attached the ring always has
            // room, so a detached run is never stalled by not being watched.
            let room = channel
                .as_ref()
                .is_none_or(|channel| channel.outbound.len() < outbound_bound());
            if !room {
                return;
            }
            let mut chunk = [0_u8; TERMINAL_READ_CHUNK];
            match read_nonblocking(master, &mut chunk) {
                ReadOutcome::Read(count) => {
                    let bytes = chunk.get(..count).unwrap_or_default();
                    match channel.as_mut() {
                        Some(channel) => channel.queue_output(bytes),
                        None => terminal.ring.push(bytes),
                    }
                }
                ReadOutcome::WouldBlock => return,
                ReadOutcome::Ended => {
                    // The last slave closed, which is what a run whose program
                    // has finished looks like from here. Recorded rather than
                    // acted on: the *exit* facts come from `waitpid`, and this
                    // is only the statement that no more output can arrive.
                    terminal.ended = true;
                    return;
                }
            }
        }
    }

    /// Tell an attached client that the run is over, exactly once.
    ///
    /// Sent only once the run has reached a terminal state, and only after the
    /// pass that drained the master — so everything the program wrote is
    /// already queued in front of it.
    fn announce_end(&mut self) {
        if !self.is_terminal() {
            return;
        }
        let end = TerminalEnd::new(self.state(), self.exit());
        let Some(channel) = self
            .client
            .as_mut()
            .and_then(|client| client.attached.as_mut())
        else {
            return;
        };
        if channel.announced || channel.detaching {
            return;
        }
        channel.announced = true;
        let payload = serde_json::to_vec(&end).unwrap_or_default();
        channel.queue_control(AttachTag::SessionEnded, &payload);
    }

    /// Write whatever is owed to the client, without waiting for it.
    fn flush_client(&mut self) {
        let Some(client) = self.client.as_mut() else {
            return;
        };
        let fd = client.stream.as_raw_fd();
        let Some(channel) = client.attached.as_mut() else {
            return;
        };
        let before = channel.outbound.len();
        while let Some(chunk) = front_slice(&channel.outbound) {
            match write_nonblocking(fd, chunk) {
                WriteOutcome::Wrote(count) => {
                    channel.outbound.drain(..count);
                }
                WriteOutcome::WouldBlock => break,
                WriteOutcome::Ended => {
                    // The client is gone. Dropping it here rather than waiting
                    // for the read to notice keeps the ring collecting output
                    // from this moment instead of the next poll slice.
                    self.client = None;
                    return;
                }
            }
        }
        channel.note_progress(before);
        if channel.detaching && channel.outbound.is_empty() {
            // Everything the client was owed has landed, including the detach
            // confirmation. The connection goes back to control framing with
            // both sides agreeing about when.
            client.attached = None;
        }
    }

    /// Drop a client that has stopped reading.
    ///
    /// The run is not the thing to sacrifice here. A client that stalls holds
    /// the terminal still — the backpressure above eventually stops the master
    /// being read — so after the deadline the *client* goes, output returns to
    /// the ring, and the next attach is told how much it missed.
    fn drop_stalled_client(&mut self) {
        let stalled = self
            .attached()
            .and_then(AttachChannel::stalled_since)
            .is_some_and(|since| since.elapsed() >= stall_deadline());
        if stalled {
            self.client = None;
        }
    }

    /// Read one batch of terminal frames from the client and act on them.
    ///
    /// Incremental by construction: a socket delivers bytes, not messages, and
    /// a read that waited for a whole frame would let one client hold the
    /// thread that also watches the run.
    fn serve_attached(&mut self) {
        let Some(mut client) = self.client.take() else {
            return;
        };
        let fd = client.stream.as_raw_fd();
        let mut chunk = [0_u8; TERMINAL_READ_CHUNK];
        match read_nonblocking(fd, &mut chunk) {
            ReadOutcome::Read(count) => {
                if let Some(channel) = client.attached.as_mut() {
                    channel.decoder.feed(chunk.get(..count).unwrap_or_default());
                }
            }
            ReadOutcome::WouldBlock => {
                self.client = Some(client);
                return;
            }
            // The client closed. The run carries on; that is what detached
            // means.
            ReadOutcome::Ended => return,
        }

        loop {
            let frame = match client
                .attached
                .as_mut()
                .map(|channel| channel.decoder.next_frame())
            {
                Some(Ok(Some(frame))) => frame,
                Some(Ok(None)) | None => break,
                // A tag this protocol does not have, a tag the client may not
                // send, or an oversize length. The channel is over — a stream
                // whose framing cannot be trusted cannot be resynchronized —
                // and the *session* is untouched, which is what a reattach
                // proves.
                Some(Err(_)) => return,
            };
            if !self.handle_attach_frame(&mut client, frame) {
                return;
            }
        }
        self.client = Some(client);
        self.service_terminal();
    }

    /// Act on one terminal frame. Returns whether the channel survives it.
    fn handle_attach_frame(&mut self, client: &mut Client, frame: AttachFrame) -> bool {
        match frame.tag {
            AttachTag::Input => {
                // Verbatim, and that is the whole point: the length prefix has
                // already said how many bytes belong to this frame, so a
                // payload containing 0xFF, a NUL, or something that looks
                // exactly like a frame header is payload and nothing else.
                if let Some(terminal) = self.terminal.as_mut() {
                    terminal.to_master.extend(frame.payload.iter().copied());
                }
                true
            }
            AttachTag::Resize => {
                let Ok(window) = decode_window(&frame.payload) else {
                    // A resize that is not a resize is the same class of fault
                    // as an unknown tag: the client and this side disagree
                    // about the protocol.
                    return false;
                };
                if let Some(master) = self.terminal.as_ref().and_then(Terminal::fd) {
                    // Best effort, and deliberately not reported: the kernel
                    // signals `SIGWINCH` to the foreground group when the size
                    // changes, so the run hears about a successful resize
                    // without this side saying anything, and a failed one on a
                    // live master means the terminal is going away anyway.
                    let _ = set_window_size(master, window);
                }
                true
            }
            AttachTag::Detach => {
                if let Some(channel) = client.attached.as_mut() {
                    channel.detaching = true;
                    channel.queue_control(AttachTag::Detach, &[]);
                }
                true
            }
            AttachTag::Ping => {
                if let Some(channel) = client.attached.as_mut() {
                    channel.queue_control(AttachTag::Pong, &[]);
                }
                true
            }
            // The answer to a ping this build does not send. Accepted and
            // ignored rather than refused: a peer that answers a question
            // nobody asked has broken nothing.
            AttachTag::Pong => true,
            // Refused by direction in the decoder before they reach here.
            AttachTag::Output | AttachTag::SessionEnded => false,
        }
    }
}

/// The run's terminal, and everything this process keeps for it.
struct Terminal {
    /// The master, while the terminal is plugged in. This process is its only
    /// holder, anywhere.
    ///
    /// `None` after [`Self::hang_up`], which is what a stop does. The ring
    /// survives it: a client that attaches to a stopped run still gets
    /// everything the run said.
    master: Option<OwnedFd>,
    /// Output nobody was connected to hear.
    ring: Scrollback,
    /// Bytes a client typed that the terminal has not taken yet.
    ///
    /// Bounded without a constant: the client's descriptor stops being watched
    /// for readability while this is non-empty, so it can only ever hold what
    /// one read produced.
    to_master: VecDeque<u8>,
    /// Whether the master has said there will be no more output.
    ended: bool,
}

impl Terminal {
    fn new(master: OwnedFd) -> Self {
        Self {
            master: Some(master),
            ring: Scrollback::new(),
            to_master: VecDeque::new(),
            ended: false,
        }
    }

    /// The master's number, while there is one.
    fn fd(&self) -> Option<RawFd> {
        self.master.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// Unplug the terminal.
    ///
    /// **This is load-bearing, not tidiness.** A session leader that holds a
    /// controlling terminal cannot finish exiting until that terminal's output
    /// queue has drained, and the only process that can drain it is this one —
    /// which is about to block in `waitpid`. A supervisor that killed such a
    /// child while still holding an unread master would wait for a death that
    /// can never be completed. Closing the master hangs the terminal up, which
    /// is what unplugging a real one does, and the child's exit completes.
    ///
    /// Every caller drains first, so what the run said is already in the ring
    /// or already on its way to a client.
    fn hang_up(&mut self) {
        self.master = None;
        self.ended = true;
        self.to_master.clear();
    }

    /// Unplug a terminal that is already over, without being asked to.
    ///
    /// [`Self::hang_up`] is what a *stop* does: it ends a terminal that may
    /// still have been working. This is the other half — the master has itself
    /// reported that its last slave is gone, so no further output can arrive and
    /// a write to it can only fail. Holding the descriptor after that keeps a
    /// dead terminal open for the whole idle grace and, on Linux, keeps handing
    /// `poll` a `POLLHUP` it has nothing to do about.
    ///
    /// Drained first, in the same order and for the same reason `hang_up`'s
    /// callers drain: what the client typed is written before the descriptor it
    /// would have been written to goes away. The ring is untouched, so a client
    /// that attaches afterwards still gets everything the run said, and the end
    /// frame is queued from state rather than from the descriptor.
    ///
    /// Idempotent, and it is the same `Option::take` `hang_up` performs, so a
    /// stop that follows cannot close anything twice.
    fn retire(&mut self) {
        if !self.ended || !self.to_master.is_empty() {
            return;
        }
        self.master = None;
    }
}

/// A client that is watching the terminal rather than driving the run.
struct AttachChannel {
    /// Frames arriving from the client.
    decoder: FrameDecoder,
    /// Framed bytes owed to the client.
    outbound: VecDeque<u8>,
    /// How much was owed when progress was last made, and when.
    stall: Option<(usize, Instant)>,
    /// Whether the client has asked to go back to control framing.
    detaching: bool,
    /// Whether the end-of-run frame has been queued.
    announced: bool,
}

impl AttachChannel {
    fn new() -> Self {
        Self {
            decoder: FrameDecoder::new(Peer::Client),
            outbound: VecDeque::new(),
            stall: None,
            detaching: false,
            announced: false,
        }
    }

    /// Queue raw output, split into frames the protocol can carry.
    fn queue_output(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(MAX_ATTACH_PAYLOAD_BYTES) {
            let mut frame = Vec::with_capacity(chunk.len().saturating_add(8));
            if encode_frame(AttachTag::Output, chunk, &mut frame).is_ok() {
                self.outbound.extend(frame);
            }
        }
    }

    /// Queue one non-output frame.
    fn queue_control(&mut self, tag: AttachTag, payload: &[u8]) {
        let mut frame = Vec::with_capacity(payload.len().saturating_add(8));
        if encode_frame(tag, payload, &mut frame).is_ok() {
            self.outbound.extend(frame);
        }
    }

    /// Record whether the last flush moved anything.
    ///
    /// The clock starts when bytes are owed and nothing moves, and is reset by
    /// any progress at all — so a slow client is tolerated and a stopped one is
    /// not.
    fn note_progress(&mut self, before: usize) {
        if self.outbound.is_empty() {
            self.stall = None;
            return;
        }
        match self.stall {
            Some((owed, _)) if owed == self.outbound.len() && before == self.outbound.len() => {}
            _ => self.stall = Some((self.outbound.len(), Instant::now())),
        }
    }

    /// When this channel last failed to make progress on a non-empty queue.
    fn stalled_since(&self) -> Option<Instant> {
        self.stall.map(|(_, since)| since)
    }
}

/// Whether the connection on `fd` has lost its other end.
///
/// Two facts, and a connection that shows either is over: `poll` reports
/// `POLLHUP`/`POLLERR` — which is what the kernel does when the peer's last
/// descriptor is closed, whether the peer said goodbye or was killed — or the
/// stream is readable and a peek finds end of file.
///
/// A *peek*, and this is the load-bearing part: a client that sent a request and
/// then closed has not gone away in the sense that matters, because the request
/// is still owed an answer. Peeking leaves the bytes for the reader that owns
/// them; a read here would eat somebody else's frame.
///
/// A free function for the same reason [`accept_decision`] is one: the whole
/// point is that it can be exercised against a real socket whose peer has really
/// died, without a running supervisor to reach it through.
fn client_is_gone(fd: RawFd) -> bool {
    let mut descriptors = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    if !matches!(poll_fds(&mut descriptors, 0), PollOutcome::Ready) {
        return false;
    }
    let Some(entry) = descriptors.first() else {
        return false;
    };
    if entry.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return true;
    }
    if entry.revents & libc::POLLIN == 0 {
        return false;
    }
    let mut peek = [0_u8; 1];
    // SAFETY: `peek` is a live local of exactly the length passed. `MSG_PEEK`
    // leaves whatever it finds in the socket buffer for the reader that owns
    // it, and `MSG_DONTWAIT` keeps this off the one thread that also watches
    // the run — a zero return is end of file and nothing else.
    let seen = unsafe {
        libc::recv(
            fd,
            peek.as_mut_ptr().cast::<libc::c_void>(),
            peek.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    seen == 0
}

/// The terminal master's place in a poll set, or `None` when it has none.
///
/// Readable while there is somewhere to put the output: an attached client with
/// room in its queue, or the ring, which always has room because it drops its
/// oldest. Writable while the client has typed something the terminal has not
/// taken.
///
/// **`None` is a guard, not a tidy-up.** Linux's `poll` reports `POLLHUP` for an
/// entry whose `events` is zero — `do_pollfd` masks the kernel's answer with
/// `demangle_poll(events) | EPOLLERR | EPOLLHUP`, so those two are never masked
/// out — and `n_tty_poll` sets `EPOLLHUP` permanently once the terminal's other
/// end has closed. A master that had said "no more output" but was still in the
/// set with nothing to wait for would therefore make every `poll` return
/// immediately, forever: the supervisor would spin at 100% of a core until the
/// idle grace expired. macOS's kqueue-backed `poll` synthesises nothing for a
/// zero-`events` entry, which is exactly why this could not be seen there.
///
/// A free function rather than a method so the decision can be tested without a
/// whole running supervisor — two forks, an exec and a record — which is what
/// stopped the previous shape from being exercised at all.
fn terminal_watch(terminal: &Terminal, has_room: bool) -> Option<(RawFd, libc::c_short)> {
    let master = terminal.fd()?;
    let mut events: libc::c_short = 0;
    if !terminal.ended && has_room {
        events |= libc::POLLIN;
    }
    if !terminal.to_master.is_empty() {
        events |= libc::POLLOUT;
    }
    if events == 0 {
        return None;
    }
    Some((master, events))
}

/// The contiguous front of a byte queue, or `None` when it is empty.
fn front_slice(queue: &VecDeque<u8>) -> Option<&[u8]> {
    let (front, back) = queue.as_slices();
    let slice = if front.is_empty() { back } else { front };
    if slice.is_empty() { None } else { Some(slice) }
}

/// What a descriptor in the poll set is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Watched {
    Listener,
    Signals,
    Client,
    Terminal,
    Status,
}

/// The poll set, with each descriptor's meaning kept beside it.
///
/// The set is no longer a fixed shape — the terminal is there only for an
/// interactive run, and the status descriptor only before activation — so the
/// positions are recorded rather than assumed. The bug this prevents is the one
/// a positional `descriptors.get(2)` invites: a set that grew by one and a
/// reader that did not notice, silently reading the terminal's readiness as the
/// client's.
struct WatchSet {
    descriptors: Vec<libc::pollfd>,
    kinds: Vec<Watched>,
}

impl WatchSet {
    fn new() -> Self {
        Self {
            descriptors: Vec::with_capacity(5),
            kinds: Vec::with_capacity(5),
        }
    }

    fn add(&mut self, kind: Watched, fd: RawFd, events: libc::c_short) {
        self.descriptors.push(libc::pollfd {
            fd,
            events,
            revents: 0,
        });
        self.kinds.push(kind);
    }

    /// Whether the named descriptor reported any of `mask`.
    fn ready(&self, kind: Watched, mask: libc::c_short) -> bool {
        self.kinds
            .iter()
            .position(|entry| *entry == kind)
            .and_then(|index| self.descriptors.get(index))
            .is_some_and(|entry| entry.revents & mask != 0)
    }
}

/// The one client a supervisor serves at a time.
struct Client {
    stream: UnixStream,
    /// Whether this connection's hello has been accepted.
    ///
    /// Every other operation is refused until it has: the hello is where the
    /// protocol version, the session, and the generation are agreed, and an
    /// operation sent before it was checked against nothing.
    greeted: bool,
    /// The terminal channel, once an attach has switched this connection into
    /// it. `None` is control framing.
    ///
    /// Attach occupies this one slot, which is the whole of the "one viewer at
    /// a time" rule: a second connection is refused
    /// [`ControlRefusal::Busy`] at accept exactly as it was before, so there is
    /// no second attach for a second answer to be about.
    attached: Option<AttachChannel>,
}

impl Client {
    /// Write one reply with a fresh deadline. Returns whether it landed.
    ///
    /// The deadline is taken here rather than inherited from the read, because
    /// the handling in between can legitimately take longer than a read
    /// allowance — a wait can hold for [`MAX_CONTROL_WAIT`][wait] — and a reply
    /// deadline that had already expired would turn every long operation into a
    /// dropped connection.
    ///
    /// [wait]: super::detached::MAX_CONTROL_WAIT
    fn reply(&mut self, reply: &ControlReply) -> bool {
        write_frame(&mut self.stream, reply, Instant::now() + CONTROL_TIMEOUT).is_ok()
    }
}

/// Accept one connection, consult its peer credential, and act on the answer.
///
/// The whole of the accept path in one free function, so that the guard can be
/// *exercised* rather than only reasoned about: a test can bind a real listener,
/// connect a real client, force the credential source to report a foreign uid,
/// and watch this close the connection without writing a byte. Left as a method
/// on the supervisor, that path would need a whole running supervisor — two
/// forks, an exec and a record — to reach, which is why the uid check was
/// previously only covered through the pure decision table below.
///
/// Returns the stream only when it is to be served.
fn accept_or_refuse(listener: &UnixListener, busy: bool) -> Option<UnixStream> {
    let Ok((mut stream, _)) = listener.accept() else {
        return None;
    };
    match accept_decision(peer_uid(stream.as_raw_fd()), own_uid(), busy) {
        AcceptDecision::Serve => set_nonblocking(stream.as_raw_fd()).ok().map(|()| stream),
        AcceptDecision::Refuse(refusal) => {
            // Told, then closed. A second client that was simply dropped would
            // have to distinguish "busy" from "crashed" by timing.
            if set_nonblocking(stream.as_raw_fd()).is_ok() {
                let deadline = Instant::now() + Duration::from_secs(1);
                let _ = write_frame(&mut stream, &ControlReply::Refused { refusal }, deadline);
            }
            None
        }
        // Dropped without a write: see `accept_decision`.
        AcceptDecision::Close => None,
    }
}

/// What to do with a connection, before a byte of it is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AcceptDecision {
    /// Take it as the one client.
    Serve,
    /// Tell it why not, then close.
    Refuse(ControlRefusal),
    /// Close without a word.
    Close,
}

/// Decide about a connection from its peer's uid and the current slot.
///
/// Pure, and separate from the accept itself, so the refusals can be tested
/// with credentials this test process cannot actually produce — a second uid is
/// not something a unit test can conjure.
///
/// A foreign uid is closed rather than refused: the session store's directory
/// is `0700`, so a peer of another uid should not have been able to reach the
/// socket at all, and answering it would be telling a stranger that the session
/// exists. An unreadable peer credential is treated the same way, because a
/// credential that could not be established is not a credential that matched.
#[must_use]
pub(super) fn accept_decision(peer: Option<u32>, ours: u32, busy: bool) -> AcceptDecision {
    match peer {
        Some(uid) if uid == ours => {
            if busy {
                AcceptDecision::Refuse(ControlRefusal::Busy)
            } else {
                AcceptDecision::Serve
            }
        }
        _ => AcceptDecision::Close,
    }
}

// Fault-injection seam for the peer credential, test builds only.
//
// A second uid is not something a test process can conjure, and a guard that
// can only be reasoned about is a guard that can be deleted without anything
// going red. This is the smallest seam that makes the *live* accept path
// testable: one thread-local override, compiled out of every release build, so
// there is no runtime path by which a real connection's credential could be
// anything but the kernel's answer.
//
// Thread-local rather than a global, because the supervisor loop is
// single-threaded and Rust runs unit tests in parallel: a global would make one
// test's injection another test's flake.
#[cfg(test)]
thread_local! {
    static FORCED_PEER_UID: std::cell::Cell<Option<u32>> =
        const { std::cell::Cell::new(None) };
}

/// The peer's uid, or `None` if the platform would not say.
///
/// Reuses the library's existing peer-credential mechanism rather than a second
/// copy of it: `SO_PEERCRED` on Linux, `getpeereid` on macOS, already written
/// and already exercised by the capability-expansion supervisor.
fn peer_uid(fd: RawFd) -> Option<u32> {
    #[cfg(test)]
    if let Some(forced) = FORCED_PEER_UID.with(std::cell::Cell::get) {
        return Some(forced);
    }
    crate::supervisor::socket::peer_credentials(fd)
        .ok()
        .map(|credentials| credentials.uid)
}

/// This process's real uid.
fn own_uid() -> u32 {
    // SAFETY: `getuid` takes no arguments, touches no memory, and cannot fail.
    unsafe { libc::getuid() }
}

/// The hello branch is handled before the match that would reach this.
fn unreachable_hello() -> ControlReply {
    ControlReply::Refused {
        refusal: ControlRefusal::HelloExpected,
    }
}

/// An `OsString` from raw bytes, without going through UTF-8.
///
/// A store directory's path is bytes on both supported platforms, and a
/// supervisor that could not name a store whose path was not UTF-8 would be a
/// supervisor that could not write its record.
fn os_string_from_bytes(bytes: &[u8]) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_marker_round_trips_through_its_rendering() {
        let marker = Marker {
            bootstrap: 7,
            handshake: 8,
            listener: 9,
        };
        let rendered = marker.render();
        let (name, value) = match rendered.split_once('=') {
            Some(split) => split,
            None => panic!("a rendered marker must be NAME=value: {rendered}"),
        };
        assert_eq!(name, SUPERVISOR_MARKER);
        assert_eq!(Marker::parse(value), Some(marker));
    }

    #[test]
    fn a_marker_this_build_did_not_write_is_not_understood() {
        // Each of these is something an unrelated environment could contain
        // under a name that happened to collide. None of them may be acted on:
        // every one names descriptors this process would then read or write.
        for raw in [
            "",
            "1",
            "1:7",
            "1:7:8",
            "1:7:8:9:10",
            "2:7:8:9",
            "1:x:8:9",
            "1:-1:8:9",
            // Standard stream numbers: the intermediate points those at
            // /dev/null, so a marker naming one cannot have come from it.
            "1:0:8:9",
            "1:7:1:9",
            "1:7:8:2",
        ] {
            assert_eq!(Marker::parse(raw), None, "{raw} must not parse");
        }
    }

    #[test]
    fn the_marker_name_is_this_library_s_own() {
        // Private protocol, not configuration: the prefix is what makes a
        // collision with somebody else's variable implausible, and the test is
        // what stops the name drifting into something generic.
        assert!(
            SUPERVISOR_MARKER.starts_with("NONO_"),
            "{SUPERVISOR_MARKER}"
        );
    }

    #[test]
    fn supervisor_entry_does_nothing_at_all_in_an_ordinary_process() {
        // The whole safety of the hook rests on this: an embedder that calls it
        // in every run must be able to rely on it returning.
        assert_eq!(std::env::var_os(SUPERVISOR_MARKER), None);
        supervisor_entry();
    }

    #[test]
    fn a_peer_of_another_uid_is_closed_without_a_word() {
        // The refusal a second uid gets is silence: the store directory is
        // 0700, so reaching the socket at all is already anomalous, and a typed
        // refusal would confirm that the session exists.
        assert_eq!(
            accept_decision(Some(4242), 1000, false),
            AcceptDecision::Close
        );
        assert_eq!(accept_decision(Some(0), 1000, false), AcceptDecision::Close);
        // A credential that could not be read is not a credential that matched.
        assert_eq!(accept_decision(None, 1000, false), AcceptDecision::Close);
    }

    #[test]
    fn a_second_client_of_our_own_uid_is_told_it_is_busy() {
        assert_eq!(
            accept_decision(Some(1000), 1000, false),
            AcceptDecision::Serve
        );
        assert_eq!(
            accept_decision(Some(1000), 1000, true),
            AcceptDecision::Refuse(ControlRefusal::Busy)
        );
    }

    /// A listener on a short private path, removed when the test ends.
    struct TestListener {
        listener: UnixListener,
        path: PathBuf,
    }

    impl TestListener {
        fn bind() -> Self {
            use std::sync::atomic::AtomicU32;
            static COUNTER: AtomicU32 = AtomicU32::new(0);

            // Short by construction: `sockaddr_un` holds 104 bytes on macOS,
            // and the usual temp roots there leave almost none of it.
            let path = PathBuf::from(format!(
                "/tmp/nono-a{}-{}.sock",
                own_pid(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_file(&path);
            match UnixListener::bind(&path) {
                Ok(listener) => Self { listener, path },
                Err(err) => panic!("a test listener must bind at {}: {err}", path.display()),
            }
        }
    }

    impl Drop for TestListener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Run `body` with the peer credential forced to `uid`.
    ///
    /// Restored afterwards even if the body panics, so one failing test cannot
    /// leave an override behind for the next one on this thread.
    fn with_forced_peer_uid<T>(uid: u32, body: impl FnOnce() -> T) -> T {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                FORCED_PEER_UID.with(|cell| cell.set(None));
            }
        }
        FORCED_PEER_UID.with(|cell| cell.set(Some(uid)));
        let _restore = Restore;
        body()
    }

    /// A uid this process certainly is not.
    fn foreign_uid() -> u32 {
        own_uid() ^ 0x5555_5555
    }

    #[test]
    fn the_live_accept_path_consults_the_peer_credential() {
        use std::io::Read;

        // The removal-detection target. `accept_decision` is a pure table and
        // proves nothing about whether anybody *asks* it: deleting the
        // `peer_uid` call in `accept_or_refuse`, or hardcoding
        // `AcceptDecision::Serve`, leaves the table's own tests green. This
        // drives the real accept — a real listener, a real connection, a real
        // `set_nonblocking` — with the credential source forced to a uid this
        // process is not, and requires the connection to be closed with nothing
        // written on it.
        let listener = TestListener::bind();
        let mut client = match UnixStream::connect(&listener.path) {
            Ok(client) => client,
            Err(err) => panic!("a test client must connect: {err}"),
        };
        if let Err(err) = client.set_read_timeout(Some(Duration::from_secs(5))) {
            panic!("a test client must take a read timeout: {err}");
        }

        let accepted = with_forced_peer_uid(foreign_uid(), || {
            accept_or_refuse(&listener.listener, false)
        });
        assert!(
            accepted.is_none(),
            "a connection from another uid must not become the client"
        );

        // Closed, and closed *silently*: a refusal frame would confirm to a
        // stranger that the session exists.
        let mut heard = [0_u8; 1];
        assert_eq!(
            client.read(&mut heard).ok(),
            Some(0),
            "a foreign peer must see EOF, not a reply"
        );
    }

    #[test]
    fn the_live_accept_path_serves_a_peer_of_our_own_uid() {
        // The positive control for the test above. Without it, a change that
        // refused *every* connection would satisfy the negative case and break
        // the supervisor entirely.
        let listener = TestListener::bind();
        let client = match UnixStream::connect(&listener.path) {
            Ok(client) => client,
            Err(err) => panic!("a test client must connect: {err}"),
        };
        let accepted =
            with_forced_peer_uid(own_uid(), || accept_or_refuse(&listener.listener, false));
        assert!(
            accepted.is_some(),
            "a peer of our own uid must be served when the slot is free"
        );
        drop(client);
    }

    #[test]
    fn the_live_accept_path_refuses_a_second_client_in_words() {
        use std::io::Read;

        // And the third arm: same uid, occupied slot. The refusal is *written*
        // here, unlike the foreign-uid case, so a second client learns why now
        // rather than inferring it from a silent close.
        let listener = TestListener::bind();
        let mut client = match UnixStream::connect(&listener.path) {
            Ok(client) => client,
            Err(err) => panic!("a test client must connect: {err}"),
        };
        if let Err(err) = client.set_read_timeout(Some(Duration::from_secs(5))) {
            panic!("a test client must take a read timeout: {err}");
        }
        let accepted =
            with_forced_peer_uid(own_uid(), || accept_or_refuse(&listener.listener, true));
        assert!(accepted.is_none());

        let mut prefix = [0_u8; 4];
        if let Err(err) = client.read_exact(&mut prefix) {
            panic!("a busy refusal must be written before the close: {err}");
        }
        let length = usize::try_from(u32::from_le_bytes(prefix)).unwrap_or(0);
        assert!(length > 0 && length <= MAX_CONTROL_FRAME_BYTES);
        let mut body = vec![0_u8; length];
        if let Err(err) = client.read_exact(&mut body) {
            panic!("the refusal frame must arrive whole: {err}");
        }
        match serde_json::from_slice::<ControlReply>(&body) {
            Ok(ControlReply::Refused {
                refusal: ControlRefusal::Busy,
            }) => {}
            other => panic!("expected a busy refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_foreign_uid_is_refused_even_when_the_slot_is_free() {
        // The two checks are independent, and the uid one is not a fallback for
        // the busy one: a free slot must not make a stranger welcome.
        assert_eq!(
            accept_decision(Some(4242), 1000, true),
            AcceptDecision::Close
        );
        assert_eq!(
            accept_decision(Some(4242), 1000, false),
            AcceptDecision::Close
        );
    }

    #[test]
    fn this_process_can_read_its_own_uid() {
        // If it could not, `accept_decision` would be comparing against a
        // number that means nothing.
        let _: u32 = own_uid();
        assert!(own_pid() > 0);
    }

    #[test]
    fn a_request_may_not_hold_the_loop_for_a_reply_allowance() {
        // The slow-loris bound. A peer that sends three bytes of a length
        // prefix and stops occupies the one thread that also accepts
        // connections and watches the child; if the request read carried the
        // full reply allowance, it could do that for ten seconds at a time,
        // repeatedly. The reply keeps the longer allowance because a reply can
        // legitimately follow a wait.
        assert!(
            REQUEST_DEADLINE < CONTROL_TIMEOUT,
            "a request must be bounded more tightly than a reply"
        );
        assert!(
            REQUEST_DEADLINE >= Duration::from_secs(1),
            "and not so tightly that an ordinary client on a loaded machine loses"
        );
        // The loop must also stay responsive *between* requests: a poll slice
        // longer than the request bound would defeat it.
        assert!(POLL_SLICE < REQUEST_DEADLINE);
    }

    #[test]
    fn the_grace_period_is_long_enough_to_restart_and_short_enough_to_notice() {
        assert!(IDLE_AFTER_TERMINAL_GRACE >= Duration::from_secs(60));
        assert!(IDLE_AFTER_TERMINAL_GRACE <= Duration::from_secs(3600));
        assert!(READINESS_DEADLINE < IDLE_AFTER_TERMINAL_GRACE);
    }

    #[test]
    fn a_connection_whose_peer_has_closed_is_read_as_gone() {
        use std::io::Write;

        // The fact the slot is freed on. A control connection ends with a
        // `Goodbye` when the client is well, and with nothing at all when it is
        // not — a process that exits has its descriptors closed for it — so
        // "gone" has to be readable from the socket rather than from anything
        // the client said.
        let listener = TestListener::bind();
        let mut client = match UnixStream::connect(&listener.path) {
            Ok(client) => client,
            Err(err) => panic!("a test client must connect: {err}"),
        };
        let (served, _) = match listener.listener.accept() {
            Ok(pair) => pair,
            Err(err) => panic!("a test listener must accept: {err}"),
        };
        assert!(
            !client_is_gone(served.as_raw_fd()),
            "a connection whose peer is alive and quiet is not gone"
        );

        // A peer that has spoken is not gone either, and the byte it sent must
        // still be there afterwards: this runs before every accept decision,
        // and a read here would eat a frame somebody else is about to parse.
        if let Err(err) = client.write_all(b"\x01\x00\x00\x00") {
            panic!("a test client must write: {err}");
        }
        assert!(
            !client_is_gone(served.as_raw_fd()),
            "a connection with a request waiting on it is not gone"
        );

        drop(client);
        assert!(
            client_is_gone(served.as_raw_fd()),
            "a connection whose peer has closed must free the slot"
        );
    }

    #[test]
    fn a_peek_leaves_the_bytes_where_it_found_them() {
        use std::io::{Read, Write};

        let listener = TestListener::bind();
        let mut client = match UnixStream::connect(&listener.path) {
            Ok(client) => client,
            Err(err) => panic!("a test client must connect: {err}"),
        };
        let (mut served, _) = match listener.listener.accept() {
            Ok(pair) => pair,
            Err(err) => panic!("a test listener must accept: {err}"),
        };
        if let Err(err) = client.write_all(b"nono") {
            panic!("a test client must write: {err}");
        }
        assert!(!client_is_gone(served.as_raw_fd()));

        let mut seen = [0_u8; 4];
        if let Err(err) = served.read_exact(&mut seen) {
            panic!("the peeked bytes must still be readable: {err}");
        }
        assert_eq!(&seen, b"nono", "a liveness check must not consume a frame");
    }

    /// A real terminal, with the slave already gone.
    ///
    /// The pair is real because the property under test is about a *descriptor*
    /// in a poll set; a fake number would prove nothing about what the kernel
    /// reports for it. `ended` is then set the way [`Supervisor::pump_from_terminal`]
    /// sets it — that read is the only writer of the flag, and reaching it here
    /// would need a whole running supervisor.
    fn ended_terminal() -> Terminal {
        let pty = match open_pty() {
            Ok(pty) => pty,
            Err(err) => panic!("a test pty must open: {err}"),
        };
        let mut terminal = Terminal::new(pty.master);
        drop(pty.slave);
        terminal.ended = true;
        terminal
    }

    #[test]
    fn a_terminal_that_has_ended_leaves_the_poll_set_entirely() {
        // The removal-detection target for the Linux hot spin. `poll` on Linux
        // reports POLLHUP for an entry whose `events` is zero, and a pty master
        // whose last slave has closed has POLLHUP set for good — so a master
        // left in the set "watched for nothing" makes every poll return at
        // once, forever. macOS synthesises nothing there, which is why only a
        // structural assertion catches this on this host.
        let pty = match open_pty() {
            Ok(pty) => pty,
            Err(err) => panic!("a test pty must open: {err}"),
        };
        let live = Terminal::new(pty.master);
        match terminal_watch(&live, true) {
            Some((_, events)) => assert!(
                events & libc::POLLIN != 0,
                "a live terminal is watched for the output still to come"
            ),
            None => panic!("a live terminal with somewhere to put its output must be watched"),
        }
        drop(pty.slave);
        drop(live);

        let ended = ended_terminal();
        assert!(
            terminal_watch(&ended, true).is_none(),
            "a terminal that has said there is no more output must not be waited on"
        );
    }

    #[test]
    fn a_terminal_with_nowhere_to_put_its_output_is_not_waited_on_either() {
        // The other zero-interest case: a client whose queue is full stops the
        // master being read, which is the backpressure that reaches the run.
        // The descriptor has nothing to report until that changes, and an
        // ended-and-full master would spin for exactly the same reason.
        let pty = match open_pty() {
            Ok(pty) => pty,
            Err(err) => panic!("a test pty must open: {err}"),
        };
        let mut terminal = Terminal::new(pty.master);
        assert!(
            terminal_watch(&terminal, false).is_none(),
            "with nowhere to put more output there is nothing to wait for"
        );
        // Unless something is owed to the terminal, which is a write and is
        // watched for whatever the room situation is.
        terminal.to_master.extend(b"typed".iter().copied());
        match terminal_watch(&terminal, false) {
            Some((_, events)) => assert!(events & libc::POLLOUT != 0),
            None => panic!("input owed to the terminal must still be waited on"),
        }
    }

    #[test]
    fn a_finished_terminal_lets_go_of_the_master_and_keeps_the_ring() {
        let mut terminal = ended_terminal();
        terminal.ring.push(b"everything the run said");

        // Not while the client's keystrokes are still owed to it: the close is
        // a hang-up, and every caller drains first.
        terminal.to_master.extend(b"typed".iter().copied());
        terminal.retire();
        assert!(
            terminal.fd().is_some(),
            "a terminal still owing input must be drained before it is unplugged"
        );

        terminal.to_master.clear();
        terminal.retire();
        assert!(
            terminal.fd().is_none(),
            "an ended, drained terminal must let go of the master"
        );
        // Twice, because a stop can follow and `hang_up` takes the same option.
        terminal.retire();
        terminal.hang_up();
        assert!(terminal.fd().is_none());

        assert_eq!(
            terminal.ring.take(),
            b"everything the run said".to_vec(),
            "the scrollback must survive the close, or a later attach sees nothing"
        );
    }

    #[test]
    fn a_terminal_that_has_not_ended_keeps_its_master() {
        // The positive control. A retirement that fired on any terminal would
        // unplug a running interactive session mid-sentence.
        let pty = match open_pty() {
            Ok(pty) => pty,
            Err(err) => panic!("a test pty must open: {err}"),
        };
        let mut terminal = Terminal::new(pty.master);
        terminal.retire();
        assert!(
            terminal.fd().is_some(),
            "a terminal that has not reported the end must stay plugged in"
        );
        drop(pty.slave);
    }
}
