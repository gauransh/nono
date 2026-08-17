//! Durable session records, and recovery that re-checks identity before it
//! trusts one.
//!
//! Everything before this module dies with its supervisor: a
//! [`PreparedSandbox`] that goes away kills and reaps its child, and a run that
//! outlived the process watching it left no trace anyone could act on. A
//! [`SessionStore`] is the trace. It writes one record per session, updates it
//! at every observed state change, and — this is the part that makes it safe —
//! treats what it reads back as a *claim about the past*, never as a fact about
//! the present.
//!
//! # A record is a claim, not a fact
//!
//! Two things are true at once about a record on disk:
//!
//! - it is written *after* the state change it describes, so it may lag the
//!   live state by one step (a supervisor that died between the transition and
//!   the write leaves a record that is one step stale), and
//! - the pid it names may since have been reaped, reissued to an unrelated
//!   program, or invalidated by a reboot.
//!
//! Neither is designed away, because neither can be. Instead every load runs
//! the record past the live system before anything acts on it: [`recover`]
//! probes the recorded [`ProcessIdentity`] and reduces the pair
//! `(recorded state, probe verdict)` to a [`RecoveryDecision`] through the pure
//! [`reconcile`] function. That reconciliation is what makes a lagging record
//! safe to keep — a stale "running" that the kernel contradicts becomes
//! [`RecoveryDecision::ProcessGone`], never an adoption.
//!
//! [`recover`]: SessionStore::recover
//! [`PreparedSandbox`]: super::PreparedSandbox
//!
//! # The decision table
//!
//! | Recorded state | Probe verdict | Decision |
//! |---|---|---|
//! | `cleanup_verified` | *anything* | [`RecoveryDecision::AlreadyVerified`] |
//! | any other | `ConfirmedAbsent{basis}` | [`RecoveryDecision::ProcessGone`] |
//! | any other | `StillPresent{survivors}` | [`RecoveryDecision::StillRunning`] |
//! | any other | `Indeterminate{reason}` | [`RecoveryDecision::Unsettled`] |
//! | any other | `Unsupported{reason}` | [`RecoveryDecision::Unsupported`] |
//!
//! The first row is the one with teeth: a session whose cleanup was already
//! proven is never re-adopted and never re-verified, whatever a later probe of
//! a long-reissued pid happens to say.
//!
//! # A recovered process is not our child
//!
//! `waitpid` works only on the caller's own children, and a process recovered
//! after a restart is by definition somebody else's — usually `init`'s. So
//! [`RecoveredSession`] has no `wait`, returns no [`SandboxExit`], and never
//! manufactures one: the exit *facts* of a recovered run (its code, its signal)
//! are simply not observable from here. What is observable is presence and
//! absence, so what recovery offers is [`RecoveredSession::kill_group`],
//! [`RecoveredSession::kill_pid`], and a re-probe that polls until the kernel
//! says `ESRCH`. Making exit facts observable across a restart needs a
//! supervisor that stays alive to do the `waitpid`; that is a later slice, and
//! until it lands this limitation is reported rather than papered over.
//!
//! [`SandboxExit`]: super::SandboxExit
//!
//! # On-disk layout
//!
//! ```text
//! <dir>/                      0700, owned by the calling euid
//! <dir>/<session-uuid>.json   0600, one record, JSON
//! <dir>/<session-uuid>.<hex>.tmp   0600, an update in flight
//! ```
//!
//! The store directory is opened once with `O_DIRECTORY | O_NOFOLLOW` and every
//! record is reached with `openat` relative to that descriptor, so no operation
//! after the first re-walks the path: a component swapped for a symlink after
//! the store is open cannot redirect a read or a write. Record names are
//! derived from the session's UUID and nothing else, so a name can never
//! contain a separator or escape the directory.
//!
//! First writes use `O_CREAT | O_EXCL`; updates are written to a
//! randomly-named temporary in the same directory and `renameat`d over the
//! record, so a reader sees either the whole old record or the whole new one
//! and never a half-written file. Both the record and the directory are
//! `fsync`ed, in that order.
//!
//! # Corruption is an answer, not a reason to guess
//!
//! A truncated, malformed, or field-missing record is
//! [`SessionStoreError::SessionCorrupt`] naming the file and what was wrong
//! with it. There is no `Default`, no partial parse, and no
//! silently-skipped entry: [`SessionStore::sessions`] yields one `Result` per
//! record so a corrupt one is *reported* without hiding its healthy siblings.
//! A record written by a newer schema is
//! [`SessionStoreError::UnsupportedSchemaVersion`] rather than a best-effort
//! read of fields that may have changed meaning.
//!
//! # Attribution
//!
//! The `0700`/`0600`, `O_EXCL`-first-write, and temp-plus-rename discipline
//! follows `nono-cli`'s crate-private session registry
//! (`crates/nono-cli/src/session.rs`), which is where this fork's session
//! storage conventions come from. Three things are new here: every record open
//! is `openat`-relative to a directory descriptor opened `O_NOFOLLOW` (the CLI
//! store opens records by path), corruption is a typed error rather than a
//! `debug!` and a skipped entry, and the schema carries a version.

use super::LifecycleError;
use super::cleanup::{
    AbsenceBasis, CleanupError, CleanupVerification, DeathObservation, IndeterminateReason,
    SurvivorEvidence, UnsupportedReason, probe_identity, verify_and_record,
};
use super::detached::{DetachedError, DetachedSession};
use super::events::{
    DETACHED_EVENT_RING_CAPACITY, EventEmitter, EventRing, LifecycleEvent, LifecycleEventKind,
};
use super::exit::{ActivationObservation, SandboxExit, kill_group, kill_pid};
use super::gate::{ActivationHandle, StopError};
use super::identity::ProcessIdentity;
use super::plan::{MAX_PLAN_METADATA_BYTES, ValidatedPlan};
use super::prepare::{PrepareError, PreparedSandbox};
use super::state::{LifecycleOp, LifecycleState};
use super::supervisor;
use super::sync_core::SharedLifecycle;
use nix::dir::Dir;
use nix::fcntl::{OFlag, open, openat, renameat};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat};
use nix::unistd::{UnlinkatFlags, fsync, geteuid, unlinkat};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

/// The schema version this build writes.
///
/// Version 2 added the three fields a detached supervisor needs: the
/// supervisor's own [`ProcessIdentity`], the run's [`SandboxExit`], and the
/// bounded ring of [`LifecycleEvent`]s observed while no caller was connected.
/// A record claiming a version this build has never heard of — anything above
/// this number — is still refused rather than interpreted.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// The oldest schema version this build can still read.
///
/// Version 1 records are loaded through their own shape and upgraded in memory:
/// they carry no supervisor, no exit facts, and no event ring, because nothing
/// that wrote them had any. The upgrade is explicit rather than a lenient parse
/// — the record types are `deny_unknown_fields` in both directions, so a v1
/// record cannot be read as a v2 one or the other way round, and a version
/// nobody implemented cannot slip through as "close enough".
///
/// A loaded v1 record is written back as v2 at its next update. That is the
/// only migration: it happens on write, never on read, so a store that is only
/// read is never modified.
pub const OLDEST_SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Largest record this store will write or read, in bytes.
///
/// Derived from the one unbounded-looking field: the opaque metadata, capped at
/// [`MAX_PLAN_METADATA_BYTES`] and serialized as a JSON array of decimal bytes,
/// so at most four characters each. Everything else in the record is a
/// fixed-shape scalar. The bound exists so a load never allocates on the say-so
/// of a file's own length field.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// Mode a record file is created with and asserted to keep.
///
/// Typed as `mode_t` because that is what `fchmod` takes, and `mode_t` is 16
/// bits on macOS and 32 on Linux.
const RECORD_MODE: libc::mode_t = 0o600;

/// Mode the store directory is created with.
const STORE_MODE: u32 = 0o700;

/// Permission bits that must be clear on the store directory.
///
/// Group and world, both halves. A session record names a live pid and the
/// process group a stop would signal; a directory anyone else can read is a
/// directory anyone else can plant a record in.
const FORBIDDEN_STORE_BITS: u32 = 0o077;

/// How long [`RecoveredSession::verify_cleanup_by`] waits between probes.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Everything the durable store can refuse to do.
///
/// Every variant names the path or session it is about, because a caller
/// reading this in a log has no other way to tell which of several records
/// failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SessionStoreError {
    /// The store directory could not be created.
    #[error("session store {path} could not be created: errno {errno}")]
    StoreCreate {
        /// The directory that was being created.
        path: PathBuf,
        /// Platform error number.
        errno: i32,
    },

    /// The store directory could not be opened.
    #[error("session store {path} could not be opened: errno {errno}")]
    StoreOpen {
        /// The directory that was being opened.
        path: PathBuf,
        /// Platform error number.
        errno: i32,
    },

    /// The store path is a symbolic link, and was not followed.
    ///
    /// `O_NOFOLLOW` refused it. Following would mean the directory the caller
    /// named and the directory the records live in are two different places,
    /// decided by whoever can write the link.
    #[error("session store {path} is a symbolic link and was not followed")]
    StoreSymlink {
        /// The path that was refused.
        path: PathBuf,
    },

    /// The store path exists and is not a directory.
    #[error("session store {path} is not a directory")]
    StoreNotADirectory {
        /// The path that was refused.
        path: PathBuf,
    },

    /// The store directory belongs to another user.
    #[error("session store {path} is owned by uid {owner}, not {expected}")]
    StoreForeignOwner {
        /// The directory that was refused.
        path: PathBuf,
        /// The uid that owns it.
        owner: u32,
        /// The effective uid of this process.
        expected: u32,
    },

    /// The store directory is readable, writable, or searchable by someone
    /// other than its owner.
    #[error("session store {path} is group- or world-accessible (mode {mode:04o}); chmod 700")]
    StorePermissions {
        /// The directory that was refused.
        path: PathBuf,
        /// The permission bits it was found with.
        mode: u32,
    },

    /// A record could not be read.
    #[error("session record {path} could not be read: errno {errno}")]
    RecordRead {
        /// The record file.
        path: PathBuf,
        /// Platform error number.
        errno: i32,
    },

    /// A record could not be written.
    #[error("session record {path} could not be written: errno {errno}")]
    RecordWrite {
        /// The record file, or the temporary standing in for it.
        path: PathBuf,
        /// Platform error number.
        errno: i32,
    },

    /// A record name is a symbolic link, and was not followed.
    ///
    /// The record is refused outright rather than read through the link: a link
    /// in the store directory means something arranged for a read of "the
    /// session record" to land somewhere else, and a write would land there
    /// too.
    #[error("session record {path} is a symbolic link and was not followed")]
    RecordSymlink {
        /// The record name that was refused.
        path: PathBuf,
    },

    /// A record name exists and is not a regular file.
    #[error("session record {path} is not a regular file")]
    RecordNotAFile {
        /// The record name that was refused.
        path: PathBuf,
    },

    /// A record for this session already exists.
    ///
    /// Sessions are one-shot UUIDs, so this means either a collision no CSPRNG
    /// would produce or a caller reusing an id. Both are refused; neither
    /// overwrites.
    #[error("a session record for {session_id} already exists")]
    RecordExists {
        /// The session whose record was already there.
        session_id: Uuid,
    },

    /// No record exists for this session.
    #[error("no session record for {session_id}")]
    SessionNotFound {
        /// The session that was asked for.
        session_id: Uuid,
    },

    /// A record could not be understood, and was not guessed at.
    #[error("session record {path} is corrupt: {why}")]
    SessionCorrupt {
        /// The record file.
        path: PathBuf,
        /// What was wrong with it, in terms a reader can act on.
        why: String,
    },

    /// A record was written by a schema this build does not implement.
    #[error("session record {path} has schema version {found}; this build understands {supported}")]
    UnsupportedSchemaVersion {
        /// The record file.
        path: PathBuf,
        /// The version the record claims.
        found: u32,
        /// The version this build writes and reads.
        supported: u32,
    },

    /// The record is larger than [`MAX_RECORD_BYTES`] and was not written.
    #[error("session record for {session_id} would be {size} bytes (max {max})")]
    RecordTooLarge {
        /// The session whose record was refused.
        session_id: Uuid,
        /// The size the record would have had.
        size: usize,
        /// The bound.
        max: usize,
    },

    /// A temporary name could not be drawn from the system CSPRNG.
    ///
    /// Fatal rather than degraded: a predictable temporary name in a directory
    /// is the classic way to have someone else decide what a rename lands on.
    #[error("a temporary name for session record {session_id} could not be generated")]
    TempNameGeneration {
        /// The session whose update was refused.
        session_id: Uuid,
    },
}

/// One session, as it was last observed.
///
/// # What is *not* here
///
/// No program, no arguments, no environment, no capability set. A record is
/// what recovery needs to reason about a process — who it was, what group it
/// leads, where the machine believed it had got to — plus the caller's own
/// opaque metadata, which the library stores and returns and never reads. A
/// record that carried the run's command line would be a durable copy of
/// whatever secrets that command line held.
///
/// # Generations
///
/// [`Self::generation`] is always 1 in this slice. Sessions are one-shot
/// UUIDs: recovering a session and verifying its cleanup does not create a new
/// one, and nothing here re-prepares into an existing session's slot. The
/// field exists because the re-prepare flow that *does* increment it is a
/// later slice, and a record shape that had to grow a field then would break
/// every record written before it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    /// The schema this record was written by. See [`CURRENT_SCHEMA_VERSION`].
    schema_version: u32,
    /// The session's id, which is also its file name.
    session_id: Uuid,
    /// Which preparation of this session the record describes.
    generation: u64,
    /// The recorded process, with the facts a reissued pid cannot forge.
    identity: ProcessIdentity,
    /// The process group the run leads.
    process_group: i32,
    /// Where the run had got to when this record was last written.
    state: LifecycleState,
    /// Whether the customer's program was ever observed to start, if that was
    /// known when the record was written.
    activation: Option<ActivationObservation>,
    /// Wall-clock milliseconds since the Unix epoch when the record was
    /// created, or `None` if the clock would not say. Advisory: nothing in this
    /// module makes a decision from a timestamp.
    created_unix_millis: Option<u64>,
    /// Wall-clock milliseconds since the Unix epoch when the record was last
    /// written. Same advisory status as [`Self::created_unix_millis`].
    updated_unix_millis: Option<u64>,
    /// The caller's opaque bytes, copied from the plan and never interpreted.
    metadata: Vec<u8>,
    /// The process supervising this run, when one exists.
    ///
    /// `None` for an attached run: the supervisor is the calling process, and a
    /// record that named it would be claiming that the *caller* can be probed
    /// for liveness after the caller is gone, which is circular. `Some` only
    /// for a detached run, where the supervisor is a separate process whose
    /// identity is exactly what tells a later reader whether the control socket
    /// beside this record is live or stale.
    ///
    /// Schema v2. Absent from v1 records, which predate detachment.
    supervisor: Option<ProcessIdentity>,
    /// How the run ended, once its end was observed.
    ///
    /// The point of a detached supervisor: `waitpid` happens in a process that
    /// is still there when the customer's program exits, so the exit facts are
    /// *witnessed* and then written here. A caller that reconnects an hour
    /// later reads a fact rather than an inference. `None` until the end is
    /// observed, and never filled in from a probe — an absent process is not an
    /// exit code.
    ///
    /// Schema v2.
    exit: Option<SandboxExit>,
    /// The last events this run produced, oldest first.
    ///
    /// Bounded at [`DETACHED_EVENT_RING_CAPACITY`][cap] and oldest-dropped.
    /// Written only by a detached supervisor, which has no caller-side
    /// [`EventSink`][sink] to deliver to; an attached run's events go to the
    /// caller's own sink live and are not duplicated here.
    ///
    /// Schema v2.
    ///
    /// [cap]: super::DETACHED_EVENT_RING_CAPACITY
    /// [sink]: super::EventSink
    events: Vec<LifecycleEvent>,
}

/// A schema-v1 record, exactly as version 1 wrote it.
///
/// Kept as its own shape rather than made lenient on the live type, so that
/// "what version 1 looked like" stays a checkable fact instead of a comment.
/// `deny_unknown_fields` in both directions is what makes the two versions
/// distinguishable at all: without it a v2 record would parse as a v1 one with
/// its new fields silently dropped.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRecordV1 {
    schema_version: u32,
    session_id: Uuid,
    generation: u64,
    identity: ProcessIdentity,
    process_group: i32,
    state: LifecycleState,
    activation: Option<ActivationObservation>,
    created_unix_millis: Option<u64>,
    updated_unix_millis: Option<u64>,
    metadata: Vec<u8>,
}

impl From<SessionRecordV1> for SessionRecord {
    fn from(old: SessionRecordV1) -> Self {
        Self {
            // Upgraded in memory. The file on disk is untouched until something
            // writes it, and what it writes then is a v2 record.
            schema_version: CURRENT_SCHEMA_VERSION,
            session_id: old.session_id,
            generation: old.generation,
            identity: old.identity,
            process_group: old.process_group,
            state: old.state,
            activation: old.activation,
            created_unix_millis: old.created_unix_millis,
            updated_unix_millis: old.updated_unix_millis,
            metadata: old.metadata,
            // Nothing that wrote a v1 record had a detached supervisor, could
            // witness an exit after a restart, or kept an event ring. The
            // absence is reported as absence and never invented.
            supervisor: None,
            exit: None,
            events: Vec::new(),
        }
    }
}

impl SessionRecord {
    /// Build the first version of a record for a freshly prepared session.
    pub(crate) fn new(
        session_id: Uuid,
        generation: u64,
        identity: ProcessIdentity,
        process_group: i32,
        state: LifecycleState,
        metadata: Vec<u8>,
    ) -> Self {
        let now = now_unix_millis();
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            session_id,
            generation,
            identity,
            process_group,
            state,
            activation: None,
            created_unix_millis: now,
            updated_unix_millis: now,
            metadata,
            supervisor: None,
            exit: None,
            events: Vec::new(),
        }
    }

    /// Name the process supervising this run.
    ///
    /// Set once, by the detached supervisor itself, before the record's first
    /// write: the identity is the supervisor's own, captured in the supervisor,
    /// so it is a fact about a process that exists rather than a claim the
    /// launcher makes about one it has just forked.
    pub(crate) fn set_supervisor(&mut self, supervisor: ProcessIdentity) {
        self.supervisor = Some(supervisor);
    }

    /// The schema version this record carries.
    #[must_use]
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The session's id.
    #[must_use]
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Which preparation of the session this record describes. Always 1 in
    /// this slice — see the type docs.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The recorded process identity.
    #[must_use]
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// The process group the run leads.
    #[must_use]
    pub fn process_group(&self) -> i32 {
        self.process_group
    }

    /// Where the run had got to when the record was last written. A claim
    /// about the past — see the module docs.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.state
    }

    /// Whether the customer's program was observed to start, if that was known
    /// when the record was written.
    #[must_use]
    pub fn activation(&self) -> Option<ActivationObservation> {
        self.activation
    }

    /// When the record was created, in milliseconds since the Unix epoch.
    #[must_use]
    pub fn created_unix_millis(&self) -> Option<u64> {
        self.created_unix_millis
    }

    /// When the record was last written, in milliseconds since the Unix epoch.
    #[must_use]
    pub fn updated_unix_millis(&self) -> Option<u64> {
        self.updated_unix_millis
    }

    /// The caller's opaque metadata, exactly as the plan carried it.
    #[must_use]
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// The process supervising this run, if it is a detached one.
    ///
    /// The identity, not merely the pid: whether the socket beside this record
    /// is live or stale is decided by
    /// [`ProcessIdentity::is_same_process`][same], and a bare pid can be
    /// reissued to anything.
    ///
    /// [same]: super::ProcessIdentity::is_same_process
    #[must_use]
    pub fn supervisor(&self) -> Option<&ProcessIdentity> {
        self.supervisor.as_ref()
    }

    /// How the run ended, if its end was witnessed and written here.
    ///
    /// Only a detached supervisor fills this in, because only a detached
    /// supervisor is still alive to `waitpid` when the customer's program ends.
    #[must_use]
    pub fn exit(&self) -> Option<&SandboxExit> {
        self.exit.as_ref()
    }

    /// The events kept for a caller that was not connected, oldest first.
    ///
    /// Bounded and oldest-dropped; empty for an attached run and for every v1
    /// record. See [`DETACHED_EVENT_RING_CAPACITY`][cap].
    ///
    /// [cap]: super::DETACHED_EVENT_RING_CAPACITY
    #[must_use]
    pub fn events(&self) -> &[LifecycleEvent] {
        &self.events
    }

    /// Move the record to a newly observed state.
    fn observe(&mut self, state: LifecycleState, activation: Option<ActivationObservation>) {
        self.state = state;
        if activation.is_some() {
            self.activation = activation;
        }
        self.updated_unix_millis = now_unix_millis();
    }

    /// Record the run's end.
    ///
    /// Written once and never overwritten: a run ends once, and a second write
    /// could only ever come from a second observation of the same death.
    fn observe_exit(&mut self, exit: SandboxExit) {
        if self.exit.is_none() {
            self.exit = Some(exit);
        }
        self.updated_unix_millis = now_unix_millis();
    }

    /// Check everything a load must not take on trust.
    ///
    /// The parse already proved the *shape*; this proves the parts that a
    /// hand-edited or truncated-then-patched file could still get wrong.
    fn validate(&self, path: &Path, expected_id: Uuid) -> Result<(), SessionStoreError> {
        if self.session_id != expected_id {
            return Err(SessionStoreError::SessionCorrupt {
                path: path.to_path_buf(),
                why: format!(
                    "record names session {} but the file names {expected_id}",
                    self.session_id
                ),
            });
        }
        if self.metadata.len() > MAX_PLAN_METADATA_BYTES {
            return Err(SessionStoreError::SessionCorrupt {
                path: path.to_path_buf(),
                why: format!(
                    "metadata is {} bytes (max {MAX_PLAN_METADATA_BYTES})",
                    self.metadata.len()
                ),
            });
        }
        if self.events.len() > DETACHED_EVENT_RING_CAPACITY {
            return Err(SessionStoreError::SessionCorrupt {
                path: path.to_path_buf(),
                why: format!(
                    "event ring holds {} events (max {DETACHED_EVENT_RING_CAPACITY})",
                    self.events.len()
                ),
            });
        }
        Ok(())
    }
}

/// One record as enumeration found it, with the file it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    record: SessionRecord,
    path: PathBuf,
}

impl SessionSummary {
    /// The record.
    #[must_use]
    pub fn record(&self) -> &SessionRecord {
        &self.record
    }

    /// The file the record was read from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The session's id.
    #[must_use]
    pub fn session_id(&self) -> Uuid {
        self.record.session_id
    }

    /// The recorded state.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.record.state
    }
}

/// What a load decided about a record, before anything acted on it.
///
/// Pure output of [`reconcile`]: it names what the probe established, never
/// what the caller should do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum RecoveryDecision {
    /// A detached supervisor is still running and can be talked to.
    ///
    /// The one decision that offers an *action* rather than an observation,
    /// because it is the one case where the run is still being watched by
    /// something that can answer questions about it. Reached only when the
    /// record names a supervisor and that supervisor's whole identity — pid,
    /// start time, boot — still matches; a reissued pid answers
    /// [`SupervisorPresence::Gone`] and falls through to the rows below.
    ///
    /// Ranked below [`Self::AlreadyVerified`] and above everything else: a
    /// proven cleanup is terminal and may not be reopened, but for every other
    /// state a live supervisor owns its own record, and a reader that overruled
    /// it from a stale copy of that record would be the two-writers problem
    /// this module exists to avoid.
    ///
    /// Carries no evidence of its own because the evidence is
    /// [`SupervisorPresence::Alive`], which the caller supplied; the identity
    /// that answered the probe is on the record
    /// ([`SessionRecord::supervisor`]) and on the recovered session
    /// ([`RecoveredSession::supervisor`]).
    Attachable,

    /// The record already said cleanup was proven. Nothing is adopted and
    /// nothing is re-verified, whatever a probe of the long-since-reissued pid
    /// says now.
    AlreadyVerified,

    /// The recorded process is gone, and this is what proved it.
    ProcessGone {
        /// The observation the conclusion rests on.
        basis: AbsenceBasis,
    },

    /// The recorded process is still alive and is the one the record names.
    ///
    /// Reached when a held child outlived the supervisor that was going to
    /// release it, or when an activated program outlived the caller watching
    /// it. It is *not* this process's child, so its exit facts are not
    /// observable from here — see the module docs.
    StillRunning {
        /// What was seen.
        survivors: SurvivorEvidence,
    },

    /// The probe could not settle the question.
    Unsettled {
        /// Why no conclusion was reached.
        reason: IndeterminateReason,
    },

    /// This platform offers no probe that could answer the question.
    Unsupported {
        /// What is missing.
        reason: UnsupportedReason,
    },
}

/// Whether the process supervising a recorded run is still that process.
///
/// Three-valued rather than a `bool`, because "this record never had a
/// supervisor" and "this record had one and it is gone" are different facts
/// with different consequences: the first is an attached run whose caller went
/// away, the second is a detached run whose supervisor died and left a stale
/// socket behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorPresence {
    /// The record names no supervisor: the run was never detached.
    NeverDetached,
    /// The recorded supervisor answered the identity probe.
    Alive,
    /// The record names a supervisor that is not the process running now.
    Gone,
}

impl SupervisorPresence {
    /// Probe a recorded supervisor identity, fail-closed.
    ///
    /// Everything ambiguous — an unreadable start time, a changed boot, a pid
    /// that no longer exists — answers [`Self::Gone`], because
    /// [`ProcessIdentity::is_same_process`] is itself fail-closed. Adopting a
    /// socket on a "probably" would mean talking to whatever inherited the
    /// number.
    #[must_use]
    pub fn of(supervisor: Option<&ProcessIdentity>) -> Self {
        match supervisor {
            None => Self::NeverDetached,
            Some(identity) if identity.is_same_process() => Self::Alive,
            Some(_) => Self::Gone,
        }
    }

    /// The stable snake_case name, identical to the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeverDetached => "never_detached",
            Self::Alive => "alive",
            Self::Gone => "gone",
        }
    }
}

impl std::fmt::Display for SupervisorPresence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RecoveryDecision {
    /// The stable snake_case name, identical to the serde tag.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Attachable => "attachable",
            Self::AlreadyVerified => "already_verified",
            Self::ProcessGone { .. } => "process_gone",
            Self::StillRunning { .. } => "still_running",
            Self::Unsettled { .. } => "unsettled",
            Self::Unsupported { .. } => "unsupported",
        }
    }

    /// Whether the recorded process was proven gone by this decision.
    #[must_use]
    pub fn is_process_gone(&self) -> bool {
        matches!(self, Self::ProcessGone { .. })
    }

    /// Whether a live supervisor can be connected to.
    #[must_use]
    pub fn is_attachable(&self) -> bool {
        matches!(self, Self::Attachable)
    }

    /// Whether this decision adopts a live process.
    ///
    /// The invariant the durable store rests on is that this is never true for
    /// a record whose cleanup was already verified.
    #[must_use]
    pub fn is_still_running(&self) -> bool {
        matches!(self, Self::StillRunning { .. })
    }
}

impl std::fmt::Display for RecoveryDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reduce a recorded state and a fresh probe to one decision.
///
/// Total, pure, and free of any syscall: the probe has already happened by the
/// time this is called, so this function is the *policy* and
/// [`CleanupVerification`] is the *evidence*. Keeping them apart is what lets
/// the race between a recovery and a concurrent cleanup be modelled
/// exhaustively (`tests/loom_lifecycle.rs`) rather than argued about.
///
/// Two rules are not straight translations of the verdict, and they are checked
/// in this order.
///
/// A live supervisor wins outright: [`SupervisorPresence::Alive`] answers
/// [`RecoveryDecision::Attachable`] whatever the record says and whatever the
/// child probe found, because a process that is still watching the run is a
/// better authority on it than a copy of a record it is still writing.
///
/// Then, for every record with no live supervisor, one already in
/// [`LifecycleState::CleanupVerified`] answers
/// [`RecoveryDecision::AlreadyVerified`] whatever the probe found. A pid that
/// was proven absent and has since been reissued would otherwise look like a
/// survivor to adopt.
#[must_use]
pub fn reconcile(
    state: LifecycleState,
    verdict: &CleanupVerification,
    supervisor: SupervisorPresence,
) -> RecoveryDecision {
    if state == LifecycleState::CleanupVerified {
        // Checked before the supervisor, so a session whose cleanup was proven
        // is never re-adopted even if a supervisor is somehow still up: the
        // proof is terminal and nothing may reopen it.
        return RecoveryDecision::AlreadyVerified;
    }
    if supervisor == SupervisorPresence::Alive {
        return RecoveryDecision::Attachable;
    }
    match verdict {
        CleanupVerification::ConfirmedAbsent { basis } => {
            RecoveryDecision::ProcessGone { basis: *basis }
        }
        CleanupVerification::StillPresent { survivors } => RecoveryDecision::StillRunning {
            survivors: *survivors,
        },
        CleanupVerification::Indeterminate { reason } => {
            RecoveryDecision::Unsettled { reason: *reason }
        }
        CleanupVerification::Unsupported { reason } => {
            RecoveryDecision::Unsupported { reason: *reason }
        }
    }
}

/// An open, validated session store.
///
/// Cheap to clone: every clone shares one directory descriptor, so a store
/// handed to several parts of a program cannot end up pointing at two
/// different directories with the same name.
#[derive(Debug, Clone)]
pub struct SessionStore {
    inner: Arc<StoreInner>,
}

impl SessionStore {
    /// Create or open a store at `dir`.
    ///
    /// A missing directory (and any missing parent) is created with mode
    /// [`STORE_MODE`]. An existing one is *checked*, never repaired: it must be
    /// a real directory rather than a symlink to one, owned by this process's
    /// effective uid, and closed to group and world. A store that fails any of
    /// those is refused with the matching typed error, because quietly
    /// `chmod`ing someone else's directory and carrying on would hide the fact
    /// that something had been able to read it.
    ///
    /// # Errors
    ///
    /// [`SessionStoreError::StoreCreate`], [`SessionStoreError::StoreOpen`],
    /// [`SessionStoreError::StoreSymlink`],
    /// [`SessionStoreError::StoreNotADirectory`],
    /// [`SessionStoreError::StoreForeignOwner`], or
    /// [`SessionStoreError::StorePermissions`].
    pub fn open(dir: &Path) -> Result<Self, SessionStoreError> {
        create_store_dir(dir)?;

        // Opened once, `O_NOFOLLOW`, and kept: from here on every record is
        // reached by `openat` against this descriptor rather than by walking
        // the path again, so nothing that happens to `dir`'s name later can
        // redirect a read or a write.
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let fd =
            open(dir, flags, Mode::empty()).map_err(|errno| classify_store_open(dir, errno))?;

        let status = fstat(&fd).map_err(|errno| SessionStoreError::StoreOpen {
            path: dir.to_path_buf(),
            errno: errno as i32,
        })?;
        let expected = geteuid().as_raw();
        if status.st_uid != expected {
            return Err(SessionStoreError::StoreForeignOwner {
                path: dir.to_path_buf(),
                owner: status.st_uid,
                expected,
            });
        }
        let mode = permission_bits(status.st_mode);
        if mode & FORBIDDEN_STORE_BITS != 0 {
            return Err(SessionStoreError::StorePermissions {
                path: dir.to_path_buf(),
                mode,
            });
        }

        Ok(Self {
            inner: Arc::new(StoreInner {
                dir: fd,
                path: dir.to_path_buf(),
            }),
        })
    }

    /// The directory this store was opened at.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Prepare a sandboxed child and record the session durably.
    ///
    /// Exactly [`PreparedSandbox::prepare`] plus a record: the child is forked,
    /// sandboxes itself, and reports that it has reached the gate, and only
    /// *then* — with the identity and process group established as facts rather
    /// than intentions — is the record written. The returned handles carry the
    /// record with them, so every later state change (release, exec, exit,
    /// stop, failure, verified cleanup) updates it.
    ///
    /// If the record cannot be written the prepared child is dropped, which
    /// kills and reaps it: a session nobody could recover is not left running.
    ///
    /// # Errors
    ///
    /// [`LifecycleError::Prepare`] if the child could not be prepared, or
    /// [`LifecycleError::Session`] if the record could not be written.
    pub fn prepare(
        &self,
        plan: ValidatedPlan,
    ) -> Result<(PreparedSandbox, ActivationHandle), LifecycleError> {
        // Refused here rather than run attached: this path returns a
        // `PreparedSandbox` whose drop kills and reaps the child, which is the
        // exact opposite of what a detached plan asked for. The typed refusal
        // names the method that does implement it.
        if plan.is_detached() {
            return Err(PrepareError::DetachedNeedsSupervisor.into());
        }
        let metadata = plan.metadata().to_vec();
        let (mut prepared, handle) = PreparedSandbox::prepare(plan)?;
        let record = SessionRecord::new(
            prepared.session_id(),
            prepared.generation(),
            prepared.identity().clone(),
            prepared.process_group(),
            prepared.state(),
            metadata,
        );
        self.inner.create(&record)?;
        let events = prepared.events();
        // The first write is a fact like every later one, and it is reported
        // through the run's own emitter so it takes its place in the run's
        // sequence rather than arriving out of band.
        events.emit(LifecycleEventKind::RecordPersisted {
            schema_version: record.schema_version,
        });
        prepared.attach_session(Arc::new(SessionHandle::attached(
            Arc::clone(&self.inner),
            record,
            Some(events),
        )));
        Ok((prepared, handle))
    }

    /// Prepare a sandboxed child under a supervisor that outlives this caller.
    ///
    /// The run that comes back is owned by a *different process*: a
    /// re-execution of this binary, in its own session, holding the child and
    /// serving a control socket beside the record. This call returns once that
    /// supervisor has reported — over a private handshake descriptor — that it
    /// has adopted the child, seen it reach the gate, and written the record.
    /// Dropping the returned [`DetachedSession`] closes a socket; it does not
    /// end the run.
    ///
    /// # The one line of cooperation this needs
    ///
    /// The supervisor is *this binary*, re-executed. It becomes a supervisor
    /// only because [`supervisor_entry`][entry] is called at the top of `main`
    /// and recognises the private marker in its environment. A binary that does
    /// not call it will run its own `main` instead, report nothing, and this
    /// call will fail at the readiness deadline with
    /// [`PrepareError::SupervisorUnresponsive`], which names the hook. That is
    /// the price of fork-safety, and ADR-0002 states it in full.
    ///
    /// [entry]: super::supervisor_entry
    ///
    /// # Errors
    ///
    /// [`LifecycleError::Prepare`] if the image could not be resolved, the
    /// control socket could not be bound, the fork or the exec failed, the
    /// child failed before the gate, or the supervisor never reported ready;
    /// [`LifecycleError::Session`] if the store itself refused. In every
    /// failing case the socket file is removed and no supervisor is left
    /// running.
    pub fn prepare_detached(
        &self,
        plan: ValidatedPlan,
    ) -> Result<(DetachedSession, ActivationHandle), LifecycleError> {
        supervisor::launch(self, plan)
    }

    /// Connect to the supervisor of an already-detached session.
    ///
    /// The direct route for a caller that knows the session id — after its own
    /// restart, say. [`Self::recover`] is the route for a caller that does not
    /// yet know whether the supervisor is alive at all: it reads the record,
    /// probes the recorded supervisor identity, and only then offers this.
    ///
    /// # Errors
    ///
    /// [`DetachedError::NoSupervisor`] if the record names no supervisor or
    /// names one that is not the process running now, and the connection errors
    /// otherwise. A record that cannot be read is
    /// [`DetachedError::Session`].
    pub fn attach_control(&self, session_id: Uuid) -> Result<DetachedSession, DetachedError> {
        let record = self.inner.load(session_id)?;
        let Some(supervisor) = record.supervisor().cloned() else {
            return Err(DetachedError::NoSupervisor { session_id });
        };
        // The identity, not the pid: a supervisor that died and whose number
        // was reissued must not be connected to. The socket connect below would
        // fail anyway — nothing is listening on a dead process's socket — but
        // failing *here* is the honest answer, because the reason is that the
        // supervisor is gone rather than that a connection was refused.
        if !supervisor.is_same_process() {
            return Err(DetachedError::NoSupervisor { session_id });
        }
        DetachedSession::connect(
            &self.inner.socket_path(session_id),
            session_id,
            record.generation(),
            supervisor,
        )
    }

    /// Where a session's control socket lives.
    ///
    /// Derived from the session id and nothing else, so the name can never
    /// carry a separator or leave the store directory.
    #[must_use]
    pub fn control_socket_path(&self, session_id: Uuid) -> PathBuf {
        self.inner.socket_path(session_id)
    }

    /// The store's shared interior, for the supervisor launch.
    pub(super) fn inner(&self) -> &Arc<StoreInner> {
        &self.inner
    }

    /// Every record in the store, one `Result` at a time.
    ///
    /// A corrupt or unreadable record yields its error in place and the
    /// iteration continues, so one bad file can never hide the rest — the
    /// failure mode of a store that skipped what it could not parse. Entries
    /// that are not record names at all (an update's temporary, an editor's
    /// leftovers) are not records and are not yielded.
    ///
    /// Names are read once, up front; the records themselves are read lazily.
    ///
    /// # Errors
    ///
    /// [`SessionStoreError`] if the directory itself could not be listed. A
    /// failure to read one record is reported per entry instead.
    pub fn sessions(&self) -> Result<Sessions<'_>, SessionStoreError> {
        let mut ids = self.inner.record_ids()?;
        ids.sort_unstable();
        Ok(Sessions {
            store: &self.inner,
            ids: ids.into_iter(),
        })
    }

    /// Load one session and reconcile it against the live system.
    ///
    /// The record is read, its schema checked, and its identity probed *before*
    /// anything is believed about it. What comes back reports what was
    /// established — see [`RecoveryDecision`] and the module's decision table —
    /// and offers only the actions that are honest for a process this one did
    /// not fork.
    ///
    /// A record found in a state where the run was still being watched
    /// (`preparing`, `prepared`, `activating`, `running`, `stopping`) is moved
    /// to [`LifecycleState::Failed`] with [`LifecycleOp::SupervisorLost`] and
    /// the move is persisted: the supervisor that would have observed the rest
    /// of that run is, by the very fact that we are recovering, gone. Cleanup
    /// verification is the only step left, which is exactly what `Failed`
    /// means here.
    ///
    /// # Errors
    ///
    /// [`SessionStoreError::SessionNotFound`] if there is no such record, and
    /// the load errors ([`SessionStoreError::SessionCorrupt`],
    /// [`SessionStoreError::UnsupportedSchemaVersion`],
    /// [`SessionStoreError::RecordSymlink`], …) otherwise.
    pub fn recover(&self, session_id: Uuid) -> Result<RecoveredSession, SessionStoreError> {
        let record = self.inner.load(session_id)?;

        // Three probes, in this order, because each one changes what the next
        // one means. The supervisor first: a live supervisor is still watching
        // the run, so nothing below may declare it lost. The child's identity
        // second. The pure decision third.
        let presence = SupervisorPresence::of(record.supervisor());
        let verdict = probe_identity(record.identity());
        let decision = reconcile(record.state(), &verdict, presence);

        // A supervisor that is named but gone leaves its socket file behind:
        // the process died without unlinking, and a stale socket is a name that
        // answers `ECONNREFUSED` forever. Removed here, where its staleness has
        // just been *established* by an identity check rather than guessed at
        // from a failed connect.
        if presence == SupervisorPresence::Gone {
            self.inner.remove_socket(session_id);
        }

        let shared = SharedLifecycle::new(record.state());
        let attachable = decision.is_attachable();
        let generation = record.generation();
        let socket = self.inner.socket_path(session_id);
        let supervisor = record.supervisor().cloned();
        let handle = Arc::new(SessionHandle::attached(
            Arc::clone(&self.inner),
            record,
            // A recovered run has no sink: this process is not the one that
            // supplied it, and the supervisor that did — if there is one — is
            // reached over the socket, not through a callback.
            None,
        ));
        // Only when the run really has lost its watcher. A detached session
        // whose supervisor answered the identity probe has *not*: moving it to
        // `Failed` here would overwrite the live supervisor's own record with a
        // claim that contradicts the process still writing it.
        if !attachable && let Ok(change) = shared.mark(LifecycleOp::SupervisorLost) {
            handle.persist(change.to, None);
        }

        Ok(RecoveredSession {
            handle,
            shared,
            decision,
            observed: verdict,
            socket,
            generation,
            supervisor,
        })
    }
}

/// Lazy iterator over a store's records.
///
/// Returned by [`SessionStore::sessions`]. Each item is one record's load
/// result; the iterator itself never ends early because of a bad record.
pub struct Sessions<'store> {
    store: &'store StoreInner,
    ids: std::vec::IntoIter<Uuid>,
}

impl Iterator for Sessions<'_> {
    type Item = Result<SessionSummary, SessionStoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.ids.next()?;
        Some(self.store.load(id).map(|record| SessionSummary {
            path: self.store.record_path(id),
            record,
        }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}

impl std::fmt::Debug for Sessions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sessions")
            .field("store", &self.store.path)
            .field("remaining", &self.ids.len())
            .finish()
    }
}

/// A session read back from the store after its supervisor was gone.
///
/// # What this cannot do
///
/// There is no `wait`, no [`SandboxExit`][super::SandboxExit], and no `Drop`
/// that kills anything. A recovered process is not this process's child, so
/// `waitpid` cannot reach it and its exit code or signal is not observable
/// here; and a recovery handle that killed a customer's still-running program
/// merely because it went out of scope would be the worst kind of surprise.
/// What is offered is what can be honestly done to a stranger's process:
/// signal it, and probe until the kernel agrees it is gone.
pub struct RecoveredSession {
    handle: Arc<SessionHandle>,
    /// The state machine, seeded from the record and moved by the same shared
    /// core every live handle uses — so a cleanup confirmation here is refused
    /// twice for the same reason it is refused twice anywhere else.
    shared: SharedLifecycle,
    decision: RecoveryDecision,
    observed: CleanupVerification,
    /// Where this session's control socket is, whether or not anything is
    /// listening on it.
    socket: PathBuf,
    /// The generation the record named, for the hello a reconnection sends.
    generation: u64,
    /// The supervisor the record named, if it named one. Present even when the
    /// probe said it was gone — "the record says pid 4242 supervised this" is a
    /// fact worth reporting alongside "and it is not there any more".
    supervisor: Option<ProcessIdentity>,
}

impl RecoveredSession {
    /// What the load established about the recorded process.
    #[must_use]
    pub fn decision(&self) -> RecoveryDecision {
        self.decision
    }

    /// The supervisor the record named, if any.
    ///
    /// Reported whether it is alive or not; [`Self::decision`] is what says
    /// which.
    #[must_use]
    pub fn supervisor(&self) -> Option<&ProcessIdentity> {
        self.supervisor.as_ref()
    }

    /// Connect to the live supervisor this recovery found.
    ///
    /// The point of R09: a caller that restarted reaches a run it did not
    /// start, activates it if it never was, waits for facts a process it never
    /// forked observed, and stops it. Legal only when [`Self::decision`] is
    /// [`RecoveryDecision::Attachable`] — every other decision describes a
    /// session with nothing left to talk to, and those keep the signal-and-probe
    /// interface below.
    ///
    /// # Errors
    ///
    /// [`DetachedError::NoSupervisor`] when the decision was anything else, and
    /// the connection errors otherwise.
    pub fn attach(&self) -> Result<DetachedSession, DetachedError> {
        let record = self.handle.snapshot();
        let (RecoveryDecision::Attachable, Some(supervisor)) =
            (self.decision, self.supervisor.clone())
        else {
            return Err(DetachedError::NoSupervisor {
                session_id: record.session_id,
            });
        };
        DetachedSession::connect(&self.socket, record.session_id, self.generation, supervisor)
    }

    /// The probe verdict the decision was made from.
    #[must_use]
    pub fn observation(&self) -> &CleanupVerification {
        &self.observed
    }

    /// The record as it now stands, including any move this recovery made.
    #[must_use]
    pub fn record(&self) -> SessionRecord {
        self.handle.snapshot()
    }

    /// The session's id.
    #[must_use]
    pub fn session_id(&self) -> Uuid {
        self.handle.snapshot().session_id
    }

    /// Where the run is now, as this handle has moved it.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.shared.state()
    }

    /// The recorded identity of the process this session is about.
    #[must_use]
    pub fn identity(&self) -> ProcessIdentity {
        self.handle.snapshot().identity
    }

    /// The recorded process group.
    #[must_use]
    pub fn process_group(&self) -> i32 {
        self.handle.snapshot().process_group
    }

    /// Prove the recorded process is gone — or report honestly that it is not.
    ///
    /// The probe asks about the recorded *identity*, never about a reap: a
    /// recovered process was never waited for by anyone here, so pid, start
    /// time, and boot id together are the only thing that can tell a survivor
    /// from a reissued number.
    ///
    /// Only [`CleanupVerification::ConfirmedAbsent`] moves the session to
    /// [`LifecycleState::CleanupVerified`], and that move is persisted before
    /// this returns.
    ///
    /// # Errors
    ///
    /// [`CleanupError`] naming the state that refused: a record still in
    /// `planning`, or a session whose cleanup was already verified.
    pub fn verify_cleanup(&mut self) -> Result<CleanupVerification, CleanupError> {
        let record = self.handle.snapshot();
        let (verification, change) = verify_and_record(
            &self.shared,
            &record.identity,
            record.process_group,
            DeathObservation::NotReaped,
        )?;
        if let Some(change) = change {
            self.handle.persist(change.to, None);
        }
        Ok(verification)
    }

    /// Verify repeatedly until the process is proven gone or `deadline` passes.
    ///
    /// The polling half of "a signal is not proof": after a
    /// [`Self::kill_group`] the kernel has accepted a signal and nothing more,
    /// so this re-probes until it answers `ESRCH` — or until the caller's
    /// deadline runs out, at which point the last verdict is returned as it
    /// stands rather than upgraded.
    ///
    /// # Errors
    ///
    /// [`CleanupError`], exactly as [`Self::verify_cleanup`].
    pub fn verify_cleanup_by(
        &mut self,
        deadline: Instant,
    ) -> Result<CleanupVerification, CleanupError> {
        loop {
            let verification = self.verify_cleanup()?;
            if verification.is_confirmed_absent() || Instant::now() >= deadline {
                return Ok(verification);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// `SIGKILL` the recorded process group.
    ///
    /// The same refusal of group ids 0, 1, and below that every other signal
    /// path in this module makes: `kill(0, …)` names the caller's own group and
    /// `kill(-1, …)` names everything it may signal, so a corrupt record must
    /// never turn into either. `ESRCH` — nothing left in the group — is
    /// success with nothing to do.
    ///
    /// Sending this proves nothing on its own. [`Self::verify_cleanup_by`] is
    /// what turns it into an answer.
    ///
    /// # Errors
    ///
    /// [`StopError::SignalFailed`] naming the target and the errno.
    pub fn kill_group(&self) -> Result<(), StopError> {
        let target = self.handle.snapshot().process_group;
        kill_group(target).map_err(|errno| StopError::SignalFailed { target, errno })
    }

    /// `SIGKILL` the recorded pid.
    ///
    /// Covers the one case the group cannot: a process that left the group it
    /// was born in. Refuses pids of 0 and below for the same reason
    /// [`Self::kill_group`] refuses group ids of 1 and below.
    ///
    /// # Errors
    ///
    /// [`StopError::SignalFailed`] naming the target and the errno.
    pub fn kill_pid(&self) -> Result<(), StopError> {
        let target = self.handle.snapshot().identity.pid();
        kill_pid(target).map_err(|errno| StopError::SignalFailed { target, errno })
    }
}

impl std::fmt::Debug for RecoveredSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let record = self.handle.snapshot();
        f.debug_struct("RecoveredSession")
            .field("session_id", &record.session_id)
            .field("state", &self.shared.state())
            .field("identity", &record.identity)
            .field("decision", &self.decision)
            .finish()
    }
}

/// One session's record, and the store it belongs to.
///
/// Shared by `Arc` between the [`PreparedSandbox`] and the
/// [`ActivatedSandbox`][super::ActivatedSandbox] it hands off to, so the two
/// write the same record rather than two copies that could disagree.
pub(crate) struct SessionHandle {
    store: Arc<StoreInner>,
    record: Mutex<SessionRecord>,
    /// The run's emitter, when the run has one.
    ///
    /// `None` for a recovered session: the supervisor that owned the sink is,
    /// by the fact that we are recovering, gone, and a recovery has no plan to
    /// take one from.
    events: Option<Arc<EventEmitter>>,
    /// The bounded ring a detached supervisor keeps, when this is one.
    ///
    /// `None` for every attached run: its events go to the caller's own sink,
    /// live, and copying them into the record as well would be a second
    /// delivery of the same facts through a lossier channel. `Some` only for a
    /// detached supervisor, which has no caller to deliver to at all.
    ring: Option<Arc<EventRing>>,
}

impl SessionHandle {
    /// Build a handle for a run whose events go to a caller's sink.
    pub(super) fn attached(
        store: Arc<StoreInner>,
        record: SessionRecord,
        events: Option<Arc<EventEmitter>>,
    ) -> Self {
        Self {
            store,
            record: Mutex::new(record),
            events,
            ring: None,
        }
    }

    /// Build a handle for a detached supervisor, which keeps its own ring.
    pub(super) fn detached(
        store: Arc<StoreInner>,
        record: SessionRecord,
        events: Arc<EventEmitter>,
        ring: Arc<EventRing>,
    ) -> Self {
        Self {
            store,
            record: Mutex::new(record),
            events: Some(events),
            ring: Some(ring),
        }
    }

    /// Write the run's end into the record, with the state it left behind.
    ///
    /// The one write a detached supervisor makes that an attached run cannot:
    /// exit facts survive here precisely because the process that `waitpid`ed
    /// is still running when the customer's program ends.
    pub(crate) fn persist_exit(&self, state: LifecycleState, exit: &SandboxExit) {
        let persisted = {
            let mut guard = self.locked();
            guard.observe(state, Some(exit.activation()));
            guard.observe_exit(exit.clone());
            self.fill_ring(&mut guard);
            match self.store.update(&guard) {
                Ok(()) => Some(guard.schema_version),
                Err(err) => {
                    tracing::warn!(
                        session_id = %guard.session_id,
                        state = %state,
                        error = %err,
                        "session record could not be updated; the run's exit facts are not durable"
                    );
                    None
                }
            }
        };
        if let (Some(schema_version), Some(events)) = (persisted, self.events.as_ref()) {
            events.emit(LifecycleEventKind::RecordPersisted { schema_version });
        }
    }

    /// Copy the supervisor's event ring into the record about to be written.
    ///
    /// Under the record lock and never the other way round: the ring's own lock
    /// is only ever taken from here and from an emit, so the order record →
    /// ring is the only order that exists.
    fn fill_ring(&self, record: &mut SessionRecord) {
        if let Some(ring) = &self.ring {
            record.events = ring.snapshot();
        }
    }
    /// Record an already-observed state change.
    ///
    /// Deliberately infallible from the caller's side, and deliberately called
    /// *after* the transition it describes rather than before. Two consequences
    /// are stated rather than hidden:
    ///
    /// - the record can lag the live state by one step, which is what makes
    ///   [`SessionStore::recover`]'s reconciliation load-bearing rather than a
    ///   formality;
    /// - a write that fails is logged and the run carries on, because the
    ///   alternative — failing a `Drop`, or a `waitpid` that already happened,
    ///   because a disk was full — would turn a bookkeeping problem into a
    ///   leaked process.
    pub(crate) fn persist(&self, state: LifecycleState, activation: Option<ActivationObservation>) {
        // The write happens under the record lock; the report happens after it
        // is released. A sink is consumer code and may call back in, and a sink
        // that did so while this held the record lock would deadlock a run over
        // a bookkeeping write.
        let persisted = {
            let mut guard = self.locked();
            guard.observe(state, activation);
            self.fill_ring(&mut guard);
            match self.store.update(&guard) {
                Ok(()) => Some(guard.schema_version),
                Err(err) => {
                    tracing::warn!(
                        session_id = %guard.session_id,
                        state = %state,
                        error = %err,
                        "session record could not be updated; the record now lags the live run"
                    );
                    // No event: nothing was persisted, and reporting a write
                    // that did not happen is the one thing this vocabulary must
                    // never do.
                    None
                }
            }
        };
        if let (Some(schema_version), Some(events)) = (persisted, self.events.as_ref()) {
            events.emit(LifecycleEventKind::RecordPersisted { schema_version });
        }
    }

    /// A copy of the record as it currently stands.
    pub(crate) fn snapshot(&self) -> SessionRecord {
        self.locked().clone()
    }

    /// A copy of the record with the live event ring folded in.
    ///
    /// For a status reply, which must show the events observed since the last
    /// write without *causing* a write: an `fsync`ed record per status request
    /// would make asking a question a durability operation.
    pub(crate) fn snapshot_with_ring(&self) -> SessionRecord {
        let mut record = self.locked().clone();
        self.fill_ring(&mut record);
        record
    }

    /// Report a fact this handle observed, labelled as reconstructed.
    ///
    /// For the one thing a detached supervisor learns about rather than
    /// witnesses: a child that ended at the gate while nobody was asking. The
    /// fidelity label is the point — the supervisor found the descriptor
    /// closed, it did not see the death.
    pub(crate) fn emit_reconstructed(&self, what: LifecycleEventKind) {
        if let Some(events) = &self.events {
            events.emit_with(what, super::events::Observation::Reconstructed);
        }
    }

    /// Take the record lock, recovering from a poisoned one.
    ///
    /// Same reasoning as the shared lifecycle core: the record is a plain value
    /// that is always left consistent, and refusing to hand it back would turn
    /// one caller's panic into a session nobody can update.
    fn locked(&self) -> MutexGuard<'_, SessionRecord> {
        match self.record.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// The open store directory, and every operation that touches it.
pub(super) struct StoreInner {
    /// The directory, opened `O_DIRECTORY | O_NOFOLLOW` once. Every record
    /// operation is `openat`-relative to this, so the path is never re-walked.
    dir: OwnedFd,
    /// The path the directory was opened at. Used to build error messages and
    /// nothing else — never to re-open anything.
    path: PathBuf,
}

impl StoreInner {
    /// The full path of a record, for error messages.
    fn record_path(&self, session_id: Uuid) -> PathBuf {
        self.path.join(record_name(session_id))
    }

    /// The full path of a session's control socket.
    ///
    /// Lives in the same `0700` directory as the record, so the directory's
    /// permissions are the socket's first line of defence and the peer-uid
    /// check at accept is the second.
    pub(super) fn socket_path(&self, session_id: Uuid) -> PathBuf {
        self.path.join(socket_name(session_id))
    }

    /// Remove a session's control socket, if it is there.
    ///
    /// Best effort and `unlinkat`-relative to the directory descriptor, like
    /// every other name operation in this store: a socket that is already gone
    /// is the state we wanted, and a failure to remove one leaves a name that
    /// answers `ECONNREFUSED` rather than a name that answers wrongly.
    pub(super) fn remove_socket(&self, session_id: Uuid) {
        let name = socket_name(session_id);
        if let Err(errno) = unlinkat(&self.dir, name.as_str(), UnlinkatFlags::NoRemoveDir)
            && errno != nix::errno::Errno::ENOENT
        {
            tracing::warn!(
                session_id = %session_id,
                errno = errno as i32,
                "a stale control socket could not be removed"
            );
        }
    }

    /// Write the first version of a record, for the supervisor.
    pub(super) fn create_record(&self, record: &SessionRecord) -> Result<(), SessionStoreError> {
        self.create(record)
    }

    /// Write a record for the first time.
    ///
    /// `O_EXCL`, so a record that already exists is refused rather than
    /// overwritten, and a symlink sitting under the name cannot be followed.
    fn create(&self, record: &SessionRecord) -> Result<(), SessionStoreError> {
        let bytes = self.encode(record)?;
        let name = record_name(record.session_id);
        let path = self.record_path(record.session_id);

        let flags =
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let fd = openat(&self.dir, name.as_str(), flags, record_mode()).map_err(
            |errno| match errno {
                nix::errno::Errno::EEXIST => SessionStoreError::RecordExists {
                    session_id: record.session_id,
                },
                errno => SessionStoreError::RecordWrite {
                    path: path.clone(),
                    errno: errno as i32,
                },
            },
        )?;
        self.fill(fd, &bytes, &path)?;
        self.sync_dir(&path)
    }

    /// Replace a record atomically.
    ///
    /// Written to a randomly-named temporary in the same directory and renamed
    /// over the record, so every reader sees either the whole previous record
    /// or the whole new one. The temporary is `O_EXCL` and mode-fixed exactly
    /// like the record itself: it holds the same contents and is readable for
    /// the same instant.
    fn update(&self, record: &SessionRecord) -> Result<(), SessionStoreError> {
        let bytes = self.encode(record)?;
        let temp = temp_name(record.session_id)?;
        let name = record_name(record.session_id);
        let temp_path = self.path.join(&temp);
        let path = self.record_path(record.session_id);

        let flags =
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let fd = openat(&self.dir, temp.as_str(), flags, record_mode()).map_err(|errno| {
            SessionStoreError::RecordWrite {
                path: temp_path.clone(),
                errno: errno as i32,
            }
        })?;
        if let Err(err) = self.fill(fd, &bytes, &temp_path) {
            // The temporary is no longer going anywhere; leaving it would make
            // the next enumeration walk past a file that means nothing.
            let _ = unlinkat(&self.dir, temp.as_str(), UnlinkatFlags::NoRemoveDir);
            return Err(err);
        }
        renameat(&self.dir, temp.as_str(), &self.dir, name.as_str()).map_err(|errno| {
            let _ = unlinkat(&self.dir, temp.as_str(), UnlinkatFlags::NoRemoveDir);
            SessionStoreError::RecordWrite {
                path: path.clone(),
                errno: errno as i32,
            }
        })?;
        self.sync_dir(&path)
    }

    /// Read one record, refusing everything that is not exactly one.
    fn load(&self, session_id: Uuid) -> Result<SessionRecord, SessionStoreError> {
        let name = record_name(session_id);
        let path = self.record_path(session_id);

        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let fd = openat(&self.dir, name.as_str(), flags, Mode::empty()).map_err(
            |errno| match errno {
                nix::errno::Errno::ENOENT => SessionStoreError::SessionNotFound { session_id },
                // `O_NOFOLLOW` refusing a symlink. Both supported platforms
                // report `ELOOP` for a plain-file open — unlike the directory
                // open in `SessionStore::open`, where macOS answers `ENOTDIR`
                // because `O_DIRECTORY` judges the link itself. The link is
                // named rather than followed, and nothing is read through it.
                nix::errno::Errno::ELOOP => SessionStoreError::RecordSymlink { path: path.clone() },
                errno => SessionStoreError::RecordRead {
                    path: path.clone(),
                    errno: errno as i32,
                },
            },
        )?;

        let status = fstat(&fd).map_err(|errno| SessionStoreError::RecordRead {
            path: path.clone(),
            errno: errno as i32,
        })?;
        if SFlag::from_bits_truncate(status.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
            return Err(SessionStoreError::RecordNotAFile { path });
        }

        // Bounded by the reader itself rather than by anything the file says
        // about its own length: a size read from the filesystem is still data,
        // and a record that grows while it is being read must not be able to
        // make this allocate without limit. One byte over the bound is enough
        // to know the record is not one this store wrote.
        let mut bytes = Vec::new();
        let bound = u64::try_from(MAX_RECORD_BYTES).unwrap_or(u64::MAX);
        File::from(fd)
            .take(bound.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|err| SessionStoreError::RecordRead {
                path: path.clone(),
                errno: err.raw_os_error().unwrap_or(0),
            })?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(SessionStoreError::SessionCorrupt {
                path,
                why: format!("record exceeds {MAX_RECORD_BYTES} bytes"),
            });
        }

        decode(&bytes, &path, session_id)
    }

    /// Every session id the directory holds a record for.
    ///
    /// The listing is taken from a descriptor derived from the store's own
    /// directory descriptor (`openat` of `"."`), so it names the same inode the
    /// records are read from even if the path has since been replaced.
    fn record_ids(&self) -> Result<Vec<Uuid>, SessionStoreError> {
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
        let mut dir = Dir::openat(&self.dir, ".", flags, Mode::empty()).map_err(|errno| {
            SessionStoreError::StoreOpen {
                path: self.path.clone(),
                errno: errno as i32,
            }
        })?;

        let mut ids = Vec::new();
        for entry in dir.iter() {
            let entry = entry.map_err(|errno| SessionStoreError::StoreOpen {
                path: self.path.clone(),
                errno: errno as i32,
            })?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            // Anything that is not exactly `<uuid>.json` is not a record: an
            // update's temporary, a leftover, a directory. Not skipped *records*
            // — not records at all.
            if let Some(id) = record_id(name) {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Serialize a record, refusing one that would exceed the read bound.
    fn encode(&self, record: &SessionRecord) -> Result<Vec<u8>, SessionStoreError> {
        // A serialization failure is not an OS error — the record's own shape
        // is the problem — so the errno is reported as 0 rather than fabricated
        // from something that never happened.
        let bytes = serde_json::to_vec(record).map_err(|_| SessionStoreError::RecordWrite {
            path: self.record_path(record.session_id),
            errno: 0,
        })?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(SessionStoreError::RecordTooLarge {
                session_id: record.session_id,
                size: bytes.len(),
                max: MAX_RECORD_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Write the bytes, fix the mode, and flush the file.
    ///
    /// The explicit `fchmod` is not belt-and-braces: `O_CREAT`'s mode is
    /// filtered through the process umask, so a caller running under an unusual
    /// umask would otherwise get a record with fewer bits than the store
    /// promises. The mode is stated, not hoped for.
    fn fill(&self, fd: OwnedFd, bytes: &[u8], path: &Path) -> Result<(), SessionStoreError> {
        let write_error = |err: std::io::Error| SessionStoreError::RecordWrite {
            path: path.to_path_buf(),
            errno: err.raw_os_error().unwrap_or(0),
        };
        fchmod(&fd, record_mode()).map_err(|errno| SessionStoreError::RecordWrite {
            path: path.to_path_buf(),
            errno: errno as i32,
        })?;
        let mut file = File::from(fd);
        file.write_all(bytes).map_err(write_error)?;
        file.sync_all().map_err(write_error)
    }

    /// Flush the directory entry itself.
    ///
    /// A record that survives a crash while its name does not is a record
    /// nobody will find, so the directory is synced after every create and
    /// every rename.
    fn sync_dir(&self, path: &Path) -> Result<(), SessionStoreError> {
        fsync(&self.dir).map_err(|errno| SessionStoreError::RecordWrite {
            path: path.to_path_buf(),
            errno: errno as i32,
        })
    }
}

impl std::fmt::Debug for StoreInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStore")
            .field("path", &self.path)
            .finish()
    }
}

/// Parse a record, refusing an unknown schema before trusting the shape.
///
/// Two passes on purpose. The version is read first, from a probe that ignores
/// every other field, because a record written by a different schema may not
/// have the fields this build expects — and reporting "corrupt" for a file that
/// is merely older or newer would send a reader looking for a disk fault.
///
/// The version then chooses the *shape*, and each shape is
/// `deny_unknown_fields`. That is what makes the compatibility explicit rather
/// than lenient: a v1 record is parsed as a v1 record and upgraded, a v2 record
/// is parsed as a v2 record, and a record whose version and fields disagree is
/// corrupt in either direction. A version this build has never implemented is
/// [`SessionStoreError::UnsupportedSchemaVersion`], never a best-effort read of
/// fields whose meaning may have changed.
fn decode(
    bytes: &[u8],
    path: &Path,
    expected_id: Uuid,
) -> Result<SessionRecord, SessionStoreError> {
    /// Just enough of a record to find out which shape to read it as.
    #[derive(Deserialize)]
    struct VersionProbe {
        schema_version: u32,
    }

    let probe: VersionProbe =
        serde_json::from_slice(bytes).map_err(|err| SessionStoreError::SessionCorrupt {
            path: path.to_path_buf(),
            why: format!("schema version is unreadable: {err}"),
        })?;

    let corrupt = |err: serde_json::Error| SessionStoreError::SessionCorrupt {
        path: path.to_path_buf(),
        why: err.to_string(),
    };
    let record: SessionRecord = match probe.schema_version {
        OLDEST_SUPPORTED_SCHEMA_VERSION => serde_json::from_slice::<SessionRecordV1>(bytes)
            .map_err(corrupt)?
            .into(),
        CURRENT_SCHEMA_VERSION => serde_json::from_slice(bytes).map_err(corrupt)?,
        found => {
            return Err(SessionStoreError::UnsupportedSchemaVersion {
                path: path.to_path_buf(),
                found,
                supported: CURRENT_SCHEMA_VERSION,
            });
        }
    };
    record.validate(path, expected_id)?;
    Ok(record)
}

/// Create the store directory, and any parent it needs, at [`STORE_MODE`].
///
/// An existing directory is left exactly as it is — the checks in
/// [`SessionStore::open`] judge it on the descriptor, after this returns.
fn create_store_dir(dir: &Path) -> Result<(), SessionStoreError> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt;

    match DirBuilder::new()
        .recursive(true)
        .mode(STORE_MODE)
        .create(dir)
    {
        Ok(()) => Ok(()),
        // Something already occupies that name. Whether it is a directory this
        // store may use is deliberately not decided here: the `O_NOFOLLOW`
        // open below and the checks on the descriptor it returns are the judge,
        // and they answer with the precise reason — a symlink, a regular file,
        // someone else's directory — rather than this function's "could not
        // create".
        Err(_) if std::fs::symlink_metadata(dir).is_ok() => Ok(()),
        Err(err) => Err(SessionStoreError::StoreCreate {
            path: dir.to_path_buf(),
            errno: err.raw_os_error().unwrap_or(0),
        }),
    }
}

/// Name why the store directory would not open.
///
/// The *refusal* is the `open` itself, which already happened; this only
/// decides what to call it. That matters because the two platforms disagree
/// about which errno an `O_NOFOLLOW | O_DIRECTORY` open of a symlink produces:
/// Linux says `ELOOP` (the link was not followed), macOS says `ENOTDIR` (the
/// link itself is not a directory). Both are the same refusal, and a caller
/// should not have to read a per-platform errno to learn that its store path is
/// a link — so the link is looked for and named. The extra `lstat` is
/// label-only: nothing is opened through it, and a path that changed in between
/// merely produces a less specific message.
fn classify_store_open(dir: &Path, errno: nix::errno::Errno) -> SessionStoreError {
    use nix::errno::Errno;

    let is_symlink = std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_symlink());
    match errno {
        Errno::ELOOP => SessionStoreError::StoreSymlink {
            path: dir.to_path_buf(),
        },
        Errno::ENOTDIR if is_symlink => SessionStoreError::StoreSymlink {
            path: dir.to_path_buf(),
        },
        Errno::ENOTDIR => SessionStoreError::StoreNotADirectory {
            path: dir.to_path_buf(),
        },
        errno => SessionStoreError::StoreOpen {
            path: dir.to_path_buf(),
            errno: errno as i32,
        },
    }
}

/// The file name a session's record lives under.
///
/// Derived from the UUID's own hyphenated rendering and nothing else, so a
/// record name can never carry a separator, a `..`, or anything else that
/// would leave the directory.
fn record_name(session_id: Uuid) -> String {
    format!("{session_id}.json")
}

/// The file name a session's control socket lives under.
///
/// Derived from the UUID exactly as [`record_name`] is, and with a different
/// suffix, so a socket is never mistaken for a record by
/// [`StoreInner::record_ids`] and a record is never mistaken for a socket.
fn socket_name(session_id: Uuid) -> String {
    format!("{session_id}.sock")
}

/// The session a file name names, or `None` if it names no session.
///
/// Round-trip checked: the parsed id must render back to exactly the name that
/// was read, so the several other spellings `Uuid::parse_str` accepts (braced,
/// URN) cannot produce a record whose name and id disagree.
fn record_id(name: &str) -> Option<Uuid> {
    let stem = name.strip_suffix(".json")?;
    let id = Uuid::parse_str(stem).ok()?;
    if record_name(id) == name {
        Some(id)
    } else {
        None
    }
}

/// A single-use temporary name in the store directory.
///
/// Random, because a predictable name in a shared-nothing directory is still a
/// name another process in the same session could create first and turn into a
/// symlink; and suffixed `.tmp` rather than `.json`, so an enumeration that
/// races an update walks past it instead of reading a half-written record.
fn temp_name(session_id: Uuid) -> Result<String, SessionStoreError> {
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|_| SessionStoreError::TempNameGeneration { session_id })?;
    let mut suffix = String::with_capacity(nonce.len().saturating_mul(2));
    for byte in nonce {
        use std::fmt::Write;
        // Writing to a String is infallible; the result is consumed so the
        // formatter's own error type never escapes.
        let _ = write!(suffix, "{byte:02x}");
    }
    Ok(format!("{session_id}.{suffix}.tmp"))
}

/// [`RECORD_MODE`] as a `Mode`.
fn record_mode() -> Mode {
    Mode::from_bits_truncate(RECORD_MODE)
}

/// The permission bits of a `st_mode`, without the file type.
///
/// Widened to `u32` because `mode_t` is 16 bits on macOS and 32 on Linux, and
/// an error message that reported a different width per platform would be a
/// gratuitous difference.
///
/// The conversion is therefore *required* on macOS and a no-op on Linux, which
/// is exactly the shape `clippy::useless_conversion` complains about — on one
/// platform only. `#[expect]` cannot express that: it would trade the Linux
/// failure for an "unfulfilled expectation" failure on macOS, which is the same
/// problem facing the other way.
#[allow(clippy::useless_conversion)]
fn permission_bits(st_mode: libc::mode_t) -> u32 {
    u32::from(st_mode) & 0o7777
}

/// Wall-clock milliseconds since the Unix epoch, or `None` if the clock will
/// not say.
fn now_unix_millis() -> Option<u64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(elapsed.as_millis()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::exit::reap;
    use crate::lifecycle::identity::boot_id;
    use crate::lifecycle::plan::SandboxPlan;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// The golden example locked by the schema doc this build writes.
    const GOLDEN_DOC: &str = include_str!("../../../../docs/lifecycle/session-record-v2.md");
    const GOLDEN_PATH: &str = "docs/lifecycle/session-record-v2.md";

    /// The schema doc for the version this build still *reads*.
    const V1_DOC: &str = include_str!("../../../../docs/lifecycle/session-record-v1.md");
    const V1_PATH: &str = "docs/lifecycle/session-record-v1.md";

    fn golden_id() -> Uuid {
        match Uuid::parse_str("019512f0-0000-7000-8000-000000000001") {
            Ok(id) => id,
            Err(_) => Uuid::nil(),
        }
    }

    fn golden_identity() -> ProcessIdentity {
        ProcessIdentity::from_parts(
            4242,
            Some(1_755_000_000_000_000),
            Some("1754990000.000000".to_string()),
        )
    }

    /// The record the schema doc shows: every field at a fixed value, so the
    /// example in the doc is a thing that can be checked rather than described.
    fn golden_record() -> SessionRecord {
        SessionRecord {
            schema_version: CURRENT_SCHEMA_VERSION,
            session_id: golden_id(),
            generation: 1,
            identity: golden_identity(),
            process_group: 4242,
            state: LifecycleState::Running,
            activation: Some(ActivationObservation::Observed),
            created_unix_millis: Some(1_755_000_000_000),
            updated_unix_millis: Some(1_755_000_000_123),
            // Opaque to this library, and shown here as bytes for exactly that
            // reason: the store copies them and never reads them.
            metadata: b"demo".to_vec(),
            supervisor: Some(ProcessIdentity::from_parts(
                4241,
                Some(1_754_999_999_000_000),
                Some("1754990000.000000".to_string()),
            )),
            exit: Some(SandboxExit::new(
                crate::lifecycle::ExitOutcome::Exited { code: 0 },
                ActivationObservation::Observed,
                golden_identity(),
            )),
            events: vec![LifecycleEvent::from_parts(
                Some(golden_id()),
                1,
                4,
                UNIX_EPOCH + Duration::from_millis(1_755_000_000_123),
                Some(golden_identity()),
                crate::lifecycle::Observation::DirectlyObserved,
                LifecycleEventKind::ExecObserved,
            )],
        }
    }

    #[test]
    fn the_golden_example_in_the_schema_doc_still_matches() -> Result<(), serde_json::Error> {
        let serialized = serde_json::to_string_pretty(&golden_record())?;
        assert_eq!(
            serialized,
            crate::lifecycle::doc_golden_example(GOLDEN_DOC, GOLDEN_PATH),
            "the golden example in {GOLDEN_PATH} no longer matches a serialized SessionRecord; \
             the doc and the type must be updated together"
        );
        let parsed: SessionRecord = serde_json::from_str(&serialized)?;
        assert_eq!(parsed, golden_record());
        Ok(())
    }

    #[test]
    fn the_v1_golden_example_still_loads_through_the_compatibility_path()
    -> Result<(), SessionStoreError> {
        // The doc for the old schema is the test fixture for reading it. A
        // record written by a build that predates detachment must keep loading,
        // and must load as *absence* rather than as invented defaults: no
        // supervisor, no exit facts, no event ring.
        let bytes = crate::lifecycle::doc_golden_example(V1_DOC, V1_PATH);
        let record = decode(bytes.as_bytes(), Path::new(V1_PATH), golden_id())?;

        assert_eq!(record.identity(), &golden_identity());
        assert_eq!(record.state(), LifecycleState::Running);
        assert_eq!(record.metadata(), b"demo");
        assert_eq!(record.supervisor(), None, "a v1 record supervised nothing");
        assert_eq!(record.exit(), None, "a v1 record witnessed no exit");
        assert!(record.events().is_empty(), "a v1 record kept no ring");
        assert_eq!(
            record.schema_version(),
            CURRENT_SCHEMA_VERSION,
            "a loaded v1 record is upgraded in memory and written back as v2"
        );
        Ok(())
    }

    #[test]
    fn a_v2_record_is_not_readable_as_a_v1_one_or_the_other_way_round() {
        // What makes the compatibility explicit rather than lenient. If either
        // shape accepted the other's fields, the version number would stop
        // being the thing that decides how a record is read.
        let v2 = match serde_json::to_string(&golden_record()) {
            Ok(json) => json,
            Err(err) => panic!("the golden record must serialize: {err}"),
        };
        assert!(
            serde_json::from_str::<SessionRecordV1>(&v2).is_err(),
            "v2 fields must not be silently dropped by the v1 shape"
        );

        let v1 = crate::lifecycle::doc_golden_example(V1_DOC, V1_PATH);
        assert!(
            serde_json::from_str::<SessionRecord>(&v1).is_err(),
            "a v1 record must not parse as v2 with its new fields defaulted"
        );
    }

    #[test]
    fn a_schema_version_nobody_implemented_is_still_refused() {
        let ahead = format!(
            r#"{{"schema_version": {}, "session_id": "{}"}}"#,
            CURRENT_SCHEMA_VERSION.saturating_add(1),
            golden_id()
        );
        let outcome = decode(ahead.as_bytes(), Path::new("ahead.json"), golden_id());
        assert!(
            matches!(
                outcome,
                Err(SessionStoreError::UnsupportedSchemaVersion { found, supported, .. })
                    if found == CURRENT_SCHEMA_VERSION.saturating_add(1)
                        && supported == CURRENT_SCHEMA_VERSION
            ),
            "a future schema must be named, not guessed at: {outcome:?}"
        );
        // And a version below the oldest supported one, which no build wrote.
        let behind = r#"{"schema_version": 0, "session_id": "x"}"#;
        assert!(matches!(
            decode(behind.as_bytes(), Path::new("behind.json"), golden_id()),
            Err(SessionStoreError::UnsupportedSchemaVersion { found: 0, .. })
        ));
    }

    #[test]
    fn the_event_ring_is_bounded_and_drops_its_oldest() {
        let ring = Arc::new(EventRing::new());
        let emitter = EventEmitter::new(
            Some(Arc::clone(&ring) as Arc<dyn crate::lifecycle::EventSink>),
            golden_id(),
            1,
        );
        let overflow = DETACHED_EVENT_RING_CAPACITY.saturating_add(5);
        for _ in 0..overflow {
            emitter.emit(LifecycleEventKind::GateReady);
        }
        let kept = ring.snapshot();
        assert_eq!(kept.len(), DETACHED_EVENT_RING_CAPACITY);
        // Oldest dropped, newest kept: the last sequence number emitted must be
        // the last one in the ring.
        let last = kept.last().map(LifecycleEvent::seq);
        assert_eq!(last, Some(overflow.saturating_sub(1) as u64));
        let first = kept.first().map(LifecycleEvent::seq);
        assert_eq!(
            first,
            Some(overflow.saturating_sub(DETACHED_EVENT_RING_CAPACITY) as u64)
        );
    }

    /// A private directory to build stores under.
    fn temp_dir() -> TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("test needs a temporary directory: {err}"),
        }
    }

    /// A store at `<temp>/sessions`, created fresh.
    fn store_at(root: &Path) -> SessionStore {
        match SessionStore::open(&root.join("sessions")) {
            Ok(store) => store,
            Err(err) => panic!("store must open: {err}"),
        }
    }

    fn current_pid() -> i32 {
        i32::try_from(std::process::id()).unwrap_or(0)
    }

    /// A record naming a process that is not, and cannot be, running.
    fn absent_record(state: LifecycleState) -> SessionRecord {
        SessionRecord::new(
            Uuid::now_v7(),
            1,
            ProcessIdentity::from_parts(i32::MAX, Some(1), boot_id()),
            i32::MAX,
            state,
            b"caller bytes".to_vec(),
        )
    }

    /// A record naming this very process: alive, and provably the same one.
    fn live_record(state: LifecycleState) -> SessionRecord {
        SessionRecord::new(
            Uuid::now_v7(),
            1,
            ProcessIdentity::capture(current_pid()),
            // Never this process's real group: nothing in these tests may be
            // one typo away from signalling the test runner.
            i32::MAX,
            state,
            Vec::new(),
        )
    }

    /// The mode bits of a path, without following a link.
    fn mode_of(path: &Path) -> u32 {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => meta.permissions().mode() & 0o7777,
            Err(err) => panic!("{} must exist: {err}", path.display()),
        }
    }

    /// [`RECORD_MODE`] at the width [`mode_of`] reports in.
    ///
    /// Same platform split as [`permission_bits`]: `mode_t` is 16 bits on macOS
    /// and 32 on Linux, so the widening is required there and useless here, and
    /// only an `allow` can be true on both.
    #[allow(clippy::useless_conversion)]
    fn record_mode_bits() -> u32 {
        u32::from(RECORD_MODE)
    }

    fn write_raw(store: &SessionStore, name: &str, contents: &str) {
        let path = store.path().join(name);
        if let Err(err) = std::fs::write(&path, contents) {
            panic!("test fixture {} must be writable: {err}", path.display());
        }
    }

    // -----------------------------------------------------------------------
    // The pure decision table.
    // -----------------------------------------------------------------------

    #[test]
    fn a_verified_record_is_never_re_adopted_whatever_the_probe_says() {
        // The invariant with teeth. A pid proven absent can be reissued to
        // anything; a reconciliation that read "still present" off that number
        // and adopted it would hand a caller a stranger's process.
        let verdicts = [
            CleanupVerification::StillPresent {
                survivors: SurvivorEvidence::IdentityMatch { pid: 42 },
            },
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::PidAbsent { pid: 42 },
            },
            CleanupVerification::Indeterminate {
                reason: IndeterminateReason::PidProbeDenied { pid: 42 },
            },
            CleanupVerification::Unsupported {
                reason: UnsupportedReason::NoProcessProbe,
            },
        ];
        for verdict in &verdicts {
            for presence in [
                SupervisorPresence::NeverDetached,
                SupervisorPresence::Alive,
                SupervisorPresence::Gone,
            ] {
                assert_eq!(
                    reconcile(LifecycleState::CleanupVerified, verdict, presence),
                    RecoveryDecision::AlreadyVerified,
                    "a verified record must not be reconsidered: {verdict:?} / {presence}"
                );
            }
        }
    }

    #[test]
    fn a_live_supervisor_outranks_every_probe_of_the_child() {
        // The supervisor is the process still watching the run. A recovery that
        // read "still present" or "gone" off the *child* and acted on it would
        // be a second writer for a record the supervisor is still updating.
        let verdicts = [
            CleanupVerification::StillPresent {
                survivors: SurvivorEvidence::IdentityMatch { pid: 42 },
            },
            CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::PidAbsent { pid: 42 },
            },
            CleanupVerification::Indeterminate {
                reason: IndeterminateReason::PidProbeDenied { pid: 42 },
            },
        ];
        for verdict in &verdicts {
            for state in [
                LifecycleState::Prepared,
                LifecycleState::Running,
                LifecycleState::Exited,
                LifecycleState::Failed,
            ] {
                assert_eq!(
                    reconcile(state, verdict, SupervisorPresence::Alive),
                    RecoveryDecision::Attachable,
                    "{state} / {verdict:?} must be attachable while the supervisor lives"
                );
            }
        }
    }

    #[test]
    fn a_supervisor_that_is_gone_falls_back_to_the_slice_a_table() {
        // The whole point of separating "never detached" from "gone": a
        // detached session whose supervisor died must be treated exactly like
        // an attached one whose caller died, not adopted over a dead socket.
        let verdict = CleanupVerification::ConfirmedAbsent {
            basis: AbsenceBasis::PidAbsent { pid: 42 },
        };
        for presence in [SupervisorPresence::NeverDetached, SupervisorPresence::Gone] {
            assert_eq!(
                reconcile(LifecycleState::Running, &verdict, presence),
                RecoveryDecision::ProcessGone {
                    basis: AbsenceBasis::PidAbsent { pid: 42 }
                },
                "{presence} must not be attachable"
            );
        }
    }

    #[test]
    fn supervisor_presence_is_fail_closed() {
        assert_eq!(
            SupervisorPresence::of(None),
            SupervisorPresence::NeverDetached
        );
        // This very process, which certainly is itself.
        let live = ProcessIdentity::capture(current_pid());
        assert_eq!(
            SupervisorPresence::of(Some(&live)),
            SupervisorPresence::Alive
        );
        // A pid that cannot be probed, and one whose start time moved.
        let absent = ProcessIdentity::from_parts(i32::MAX, Some(1), boot_id());
        assert_eq!(
            SupervisorPresence::of(Some(&absent)),
            SupervisorPresence::Gone
        );
        let reissued = ProcessIdentity::from_parts(
            current_pid(),
            live.start_time().map(|value| value.wrapping_add(1)),
            boot_id(),
        );
        assert_eq!(
            SupervisorPresence::of(Some(&reissued)),
            SupervisorPresence::Gone,
            "a reissued pid must never be adopted as a live supervisor"
        );
        // And an identity the platform would not fully describe.
        let unreadable = ProcessIdentity::from_parts(current_pid(), None, boot_id());
        assert_eq!(
            SupervisorPresence::of(Some(&unreadable)),
            SupervisorPresence::Gone
        );
    }

    #[test]
    fn presence_names_are_stable_snake_case() -> Result<(), serde_json::Error> {
        for presence in [
            SupervisorPresence::NeverDetached,
            SupervisorPresence::Alive,
            SupervisorPresence::Gone,
        ] {
            let json = serde_json::to_string(&presence)?;
            assert_eq!(json, format!("\"{}\"", presence.as_str()));
            assert_eq!(serde_json::from_str::<SupervisorPresence>(&json)?, presence);
            assert_eq!(presence.to_string(), presence.as_str());
        }
        Ok(())
    }

    #[test]
    fn every_verdict_maps_to_exactly_one_decision() {
        let state = LifecycleState::Running;
        assert_eq!(
            reconcile(
                state,
                &CleanupVerification::ConfirmedAbsent {
                    basis: AbsenceBasis::BootIdChanged
                },
                SupervisorPresence::NeverDetached
            ),
            RecoveryDecision::ProcessGone {
                basis: AbsenceBasis::BootIdChanged
            }
        );
        assert_eq!(
            reconcile(
                state,
                &CleanupVerification::StillPresent {
                    survivors: SurvivorEvidence::IdentityMatch { pid: 7 }
                },
                SupervisorPresence::NeverDetached
            ),
            RecoveryDecision::StillRunning {
                survivors: SurvivorEvidence::IdentityMatch { pid: 7 }
            }
        );
        assert_eq!(
            reconcile(
                state,
                &CleanupVerification::Indeterminate {
                    reason: IndeterminateReason::IdentityUnreadable { pid: 7 }
                },
                SupervisorPresence::NeverDetached
            ),
            RecoveryDecision::Unsettled {
                reason: IndeterminateReason::IdentityUnreadable { pid: 7 }
            }
        );
        assert_eq!(
            reconcile(
                state,
                &CleanupVerification::Unsupported {
                    reason: UnsupportedReason::NoProcessProbe
                },
                SupervisorPresence::NeverDetached
            ),
            RecoveryDecision::Unsupported {
                reason: UnsupportedReason::NoProcessProbe
            }
        );
    }

    #[test]
    fn decision_names_are_stable_snake_case() -> Result<(), serde_json::Error> {
        let decisions = [
            RecoveryDecision::AlreadyVerified,
            RecoveryDecision::ProcessGone {
                basis: AbsenceBasis::PidAbsent { pid: 1 },
            },
            RecoveryDecision::StillRunning {
                survivors: SurvivorEvidence::IdentityMatch { pid: 1 },
            },
            RecoveryDecision::Unsettled {
                reason: IndeterminateReason::UnprobablePid { pid: 0 },
            },
            RecoveryDecision::Unsupported {
                reason: UnsupportedReason::NoProcessProbe,
            },
        ];
        for decision in decisions {
            let json = serde_json::to_string(&decision)?;
            assert_eq!(serde_json::from_str::<RecoveryDecision>(&json)?, decision);
            assert!(
                json.contains(&format!("\"decision\":\"{}\"", decision.as_str())),
                "{json}"
            );
            assert_eq!(decision.to_string(), decision.as_str());
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // The store directory.
    // -----------------------------------------------------------------------

    #[test]
    fn a_new_store_directory_is_owner_only() {
        let root = temp_dir();
        let store = store_at(root.path());
        assert_eq!(mode_of(store.path()) & FORBIDDEN_STORE_BITS, 0);
    }

    #[test]
    fn a_group_or_world_accessible_store_is_refused_at_open() {
        let root = temp_dir();
        let path = root.path().join("sessions");
        if let Err(err) = std::fs::create_dir(&path) {
            panic!("test fixture must be creatable: {err}");
        }
        if let Err(err) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)) {
            panic!("test fixture must be chmod-able: {err}");
        }
        assert_eq!(
            SessionStore::open(&path).err(),
            Some(SessionStoreError::StorePermissions {
                path: path.clone(),
                mode: 0o755
            }),
            "a directory anyone can read is a directory anyone can plant a record in"
        );
    }

    #[test]
    fn a_store_path_that_is_a_symlink_is_refused_rather_than_followed() {
        let root = temp_dir();
        let real = root.path().join("real");
        if let Err(err) = std::fs::create_dir(&real) {
            panic!("test fixture must be creatable: {err}");
        }
        let link = root.path().join("sessions");
        if let Err(err) = std::os::unix::fs::symlink(&real, &link) {
            panic!("test fixture must be linkable: {err}");
        }
        assert_eq!(
            SessionStore::open(&link).err(),
            Some(SessionStoreError::StoreSymlink { path: link })
        );
    }

    #[test]
    fn a_store_path_that_is_a_file_is_refused_as_not_a_directory() {
        let root = temp_dir();
        let path = root.path().join("sessions");
        if let Err(err) = std::fs::write(&path, "not a directory") {
            panic!("test fixture must be writable: {err}");
        }
        assert_eq!(
            SessionStore::open(&path).err(),
            Some(SessionStoreError::StoreNotADirectory { path })
        );
    }

    // -----------------------------------------------------------------------
    // Records: permissions, atomicity, refusals.
    // -----------------------------------------------------------------------

    #[test]
    fn a_record_is_created_and_updated_at_0600() {
        let root = temp_dir();
        let store = store_at(root.path());
        let mut record = absent_record(LifecycleState::Prepared);
        if let Err(err) = store.inner.create(&record) {
            panic!("first write must succeed: {err}");
        }
        let path = store.inner.record_path(record.session_id());
        assert_eq!(mode_of(&path), record_mode_bits(), "after create");

        record.observe(LifecycleState::Failed, None);
        if let Err(err) = store.inner.update(&record) {
            panic!("update must succeed: {err}");
        }
        assert_eq!(
            mode_of(&path),
            record_mode_bits(),
            "an update must not widen the record"
        );
    }

    #[test]
    fn a_second_first_write_for_one_session_is_refused_not_overwritten() {
        let root = temp_dir();
        let store = store_at(root.path());
        let record = absent_record(LifecycleState::Prepared);
        if let Err(err) = store.inner.create(&record) {
            panic!("first write must succeed: {err}");
        }
        assert_eq!(
            store.inner.create(&record).err(),
            Some(SessionStoreError::RecordExists {
                session_id: record.session_id()
            }),
            "O_EXCL is what makes the first write a claim rather than a race"
        );
    }

    #[test]
    fn an_update_replaces_the_record_whole_and_leaves_no_temporary() {
        // The rename half of "either fully old or fully new". A reader between
        // these two calls sees one complete record or the other, because the
        // new bytes are only ever reachable under the record's name after a
        // rename that is atomic in the directory.
        let root = temp_dir();
        let store = store_at(root.path());
        let mut record = absent_record(LifecycleState::Prepared);
        if let Err(err) = store.inner.create(&record) {
            panic!("first write must succeed: {err}");
        }
        record.observe(LifecycleState::CleanupVerified, None);
        if let Err(err) = store.inner.update(&record) {
            panic!("update must succeed: {err}");
        }

        let loaded = match store.inner.load(record.session_id()) {
            Ok(loaded) => loaded,
            Err(err) => panic!("record must load: {err}"),
        };
        assert_eq!(loaded.state(), LifecycleState::CleanupVerified);
        assert_eq!(loaded, record, "the whole record, not a merge of two");

        let leftovers: Vec<String> = match std::fs::read_dir(store.path()) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".tmp"))
                .collect(),
            Err(err) => panic!("store must be readable: {err}"),
        };
        assert!(
            leftovers.is_empty(),
            "temporaries left behind: {leftovers:?}"
        );
    }

    #[test]
    fn a_stray_temporary_is_not_a_record_and_is_not_enumerated() {
        let root = temp_dir();
        let store = store_at(root.path());
        let record = absent_record(LifecycleState::Prepared);
        if let Err(err) = store.inner.create(&record) {
            panic!("first write must succeed: {err}");
        }
        // Exactly the shape an update that died mid-write would leave.
        write_raw(
            &store,
            &format!("{}.dead0beef.tmp", record.session_id()),
            "{\"schema_version\":1",
        );
        write_raw(&store, "not-a-session.json", "{}");

        let sessions = match store.sessions() {
            Ok(sessions) => sessions,
            Err(err) => panic!("enumeration must start: {err}"),
        };
        let rendered = format!("{sessions:?}");
        assert!(rendered.contains("remaining: 1"), "{rendered}");

        let summaries: Vec<_> = sessions.collect();
        assert_eq!(summaries.len(), 1, "{summaries:?}");
        match summaries.into_iter().next() {
            Some(Ok(summary)) => {
                assert_eq!(summary.session_id(), record.session_id());
                assert_eq!(summary.record(), &record);
                assert_eq!(summary.path(), store.inner.record_path(record.session_id()));
            }
            other => panic!("the one record must load: {other:?}"),
        }
    }

    #[test]
    fn a_record_that_is_a_symlink_is_refused_and_its_target_is_never_read() {
        let root = temp_dir();
        let store = store_at(root.path());
        let record = absent_record(LifecycleState::Prepared);

        // A perfectly valid record, sitting somewhere the store did not put it,
        // with the record's own name pointing at it. Following the link would
        // succeed and return this — which is the whole point: the test fails
        // by *passing the load* if O_NOFOLLOW is ever dropped.
        let decoy = root.path().join("decoy.json");
        let encoded = match serde_json::to_vec(&record) {
            Ok(encoded) => encoded,
            Err(err) => panic!("test fixture must serialize: {err}"),
        };
        if let Err(err) = std::fs::write(&decoy, &encoded) {
            panic!("test fixture must be writable: {err}");
        }
        let link = store.inner.record_path(record.session_id());
        if let Err(err) = std::os::unix::fs::symlink(&decoy, &link) {
            panic!("test fixture must be linkable: {err}");
        }

        assert_eq!(
            store.inner.load(record.session_id()).err(),
            Some(SessionStoreError::RecordSymlink { path: link }),
            "a record name that is a link must be refused, not followed"
        );
    }

    #[test]
    fn a_record_that_is_not_a_regular_file_is_refused() {
        let root = temp_dir();
        let store = store_at(root.path());
        let id = Uuid::now_v7();
        let path = store.inner.record_path(id);
        if let Err(err) = std::fs::create_dir(&path) {
            panic!("test fixture must be creatable: {err}");
        }
        assert_eq!(
            store.inner.load(id).err(),
            Some(SessionStoreError::RecordNotAFile { path })
        );
    }

    #[test]
    fn a_missing_record_names_the_session_it_looked_for() {
        let root = temp_dir();
        let store = store_at(root.path());
        let id = Uuid::now_v7();
        assert_eq!(
            store.recover(id).err(),
            Some(SessionStoreError::SessionNotFound { session_id: id })
        );
    }

    // -----------------------------------------------------------------------
    // Corruption and schema.
    // -----------------------------------------------------------------------

    #[test]
    fn a_corrupt_record_is_reported_and_never_hides_its_healthy_sibling() {
        let root = temp_dir();
        let store = store_at(root.path());
        let healthy = absent_record(LifecycleState::Stopped);
        if let Err(err) = store.inner.create(&healthy) {
            panic!("first write must succeed: {err}");
        }
        // Three different ways to be unreadable, each of which a store that
        // "skipped what it could not parse" would silently drop.
        let truncated = Uuid::now_v7();
        write_raw(
            &store,
            &record_name(truncated),
            "{\"schema_version\":1,\"session_id\":\"",
        );
        let garbage = Uuid::now_v7();
        write_raw(&store, &record_name(garbage), "not json at all");
        let missing_field = Uuid::now_v7();
        write_raw(
            &store,
            &record_name(missing_field),
            &format!("{{\"schema_version\":1,\"session_id\":\"{missing_field}\"}}"),
        );

        let summaries: Vec<_> = match store.sessions() {
            Ok(sessions) => sessions.collect(),
            Err(err) => panic!("enumeration must start: {err}"),
        };
        assert_eq!(summaries.len(), 4, "every record must be accounted for");

        let mut healthy_seen = 0;
        let mut corrupt_seen = 0;
        for summary in summaries {
            match summary {
                Ok(summary) => {
                    assert_eq!(summary.session_id(), healthy.session_id());
                    assert_eq!(summary.state(), LifecycleState::Stopped);
                    healthy_seen += 1;
                }
                Err(SessionStoreError::SessionCorrupt { path, why }) => {
                    assert!(
                        !why.is_empty(),
                        "{} must say what was wrong",
                        path.display()
                    );
                    corrupt_seen += 1;
                }
                Err(err) => panic!("unexpected error: {err}"),
            }
        }
        assert_eq!(healthy_seen, 1, "the healthy record must still be reported");
        assert_eq!(corrupt_seen, 3, "every corrupt record must be reported");
    }

    #[test]
    fn a_record_whose_id_disagrees_with_its_file_name_is_corrupt() {
        // A copied file, or a hand-edited one. Neither is a record of the
        // session whose name it wears.
        let root = temp_dir();
        let store = store_at(root.path());
        let record = absent_record(LifecycleState::Prepared);
        let encoded = match serde_json::to_string(&record) {
            Ok(encoded) => encoded,
            Err(err) => panic!("test fixture must serialize: {err}"),
        };
        let other = Uuid::now_v7();
        write_raw(&store, &record_name(other), &encoded);

        match store.inner.load(other) {
            Err(SessionStoreError::SessionCorrupt { why, .. }) => {
                assert!(why.contains(&other.to_string()), "{why}");
            }
            other => panic!("a mismatched id must be corrupt, got {other:?}"),
        }
    }

    #[test]
    fn a_newer_schema_version_is_refused_rather_than_guessed_at() {
        let root = temp_dir();
        let store = store_at(root.path());
        let record = absent_record(LifecycleState::Prepared);
        let encoded = match serde_json::to_value(&record) {
            Ok(serde_json::Value::Object(mut map)) => {
                map.insert(
                    "schema_version".to_string(),
                    serde_json::Value::from(CURRENT_SCHEMA_VERSION.saturating_add(1)),
                );
                serde_json::Value::Object(map).to_string()
            }
            other => panic!("a record must serialize to an object, got {other:?}"),
        };
        write_raw(&store, &record_name(record.session_id()), &encoded);

        assert_eq!(
            store.inner.load(record.session_id()).err(),
            Some(SessionStoreError::UnsupportedSchemaVersion {
                path: store.inner.record_path(record.session_id()),
                found: CURRENT_SCHEMA_VERSION.saturating_add(1),
                supported: CURRENT_SCHEMA_VERSION,
            }),
            "a record from a newer writer must not be read field by field"
        );
    }

    #[test]
    fn a_record_round_trips_through_the_store_unchanged() {
        let root = temp_dir();
        let store = store_at(root.path());
        let record = absent_record(LifecycleState::Prepared);
        if let Err(err) = store.inner.create(&record) {
            panic!("first write must succeed: {err}");
        }
        match store.inner.load(record.session_id()) {
            Ok(loaded) => {
                assert_eq!(loaded, record);
                assert_eq!(loaded.schema_version(), CURRENT_SCHEMA_VERSION);
                assert_eq!(loaded.generation(), 1);
                assert_eq!(loaded.metadata(), b"caller bytes");
                assert_eq!(loaded.activation(), None);
            }
            Err(err) => panic!("record must load: {err}"),
        }
    }

    #[test]
    fn a_record_that_would_exceed_the_read_bound_is_never_written() {
        // The write bound and the read bound are the same number on purpose: a
        // record this store would refuse to read back is a record it must not
        // create, or the session becomes unrecoverable at the moment it is
        // written. Plan validation caps the metadata long before this, so this
        // is the second line rather than the first.
        let root = temp_dir();
        let store = store_at(root.path());
        let record = SessionRecord::new(
            Uuid::now_v7(),
            1,
            ProcessIdentity::from_parts(i32::MAX, Some(1), boot_id()),
            i32::MAX,
            LifecycleState::Prepared,
            vec![0_u8; MAX_RECORD_BYTES],
        );
        match store.inner.create(&record) {
            Err(SessionStoreError::RecordTooLarge { size, max, .. }) => {
                assert!(size > max, "{size} vs {max}");
                assert_eq!(max, MAX_RECORD_BYTES);
            }
            other => panic!("an oversized record must be refused, got {other:?}"),
        }
        assert!(
            !store.inner.record_path(record.session_id()).exists(),
            "a refused record must leave nothing behind"
        );
    }

    #[test]
    fn a_record_name_maps_to_exactly_one_session_id() {
        let id = Uuid::now_v7();
        assert_eq!(record_id(&record_name(id)), Some(id));
        // Spellings `Uuid::parse_str` accepts that are not the name this store
        // writes; letting one through would mean two names for one record.
        assert_eq!(record_id(&format!("{{{id}}}.json")), None);
        assert_eq!(record_id(&format!("urn:uuid:{id}.json")), None);
        assert_eq!(record_id(&format!("{id}.tmp")), None);
        assert_eq!(record_id("../escape.json"), None);
        assert_eq!(record_id(".json"), None);
    }

    // -----------------------------------------------------------------------
    // Recovery.
    // -----------------------------------------------------------------------

    #[test]
    fn a_recovered_record_is_reconciled_before_anything_is_believed() {
        // The record claims a pid that is alive — it is this test process — but
        // with a start time that process never had. Trusting the record would
        // adopt a stranger; probing the identity proves the recorded process is
        // gone and the number was reissued.
        let root = temp_dir();
        let store = store_at(root.path());
        let live = ProcessIdentity::capture(current_pid());
        let reused = ProcessIdentity::from_parts(
            live.pid(),
            live.start_time().map(|value| value.wrapping_sub(1)),
            live.boot_id().map(str::to_string),
        );
        let record = SessionRecord::new(
            Uuid::now_v7(),
            1,
            reused,
            i32::MAX,
            LifecycleState::Running,
            Vec::new(),
        );
        let id = record.session_id();
        if let Err(err) = store.inner.create(&record) {
            panic!("first write must succeed: {err}");
        }

        let mut recovered = match store.recover(id) {
            Ok(recovered) => recovered,
            Err(err) => panic!("recovery must succeed: {err}"),
        };
        assert_eq!(
            recovered.decision(),
            RecoveryDecision::ProcessGone {
                basis: AbsenceBasis::IdentityMismatch { pid: live.pid() }
            }
        );
        assert!(!recovered.decision().is_still_running(), "never adopt");
        // The supervisor that was watching this run is, by construction, gone:
        // the run's outcome is no longer observable and cleanup is all that is
        // left.
        assert_eq!(recovered.state(), LifecycleState::Failed);

        assert_eq!(
            recovered.verify_cleanup(),
            Ok(CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::IdentityMismatch { pid: live.pid() }
            })
        );
        assert_eq!(recovered.state(), LifecycleState::CleanupVerified);

        // And the proof is durable: a fresh store reads it back, and a second
        // recovery neither re-verifies nor adopts.
        let reopened = store_at(root.path());
        match reopened.inner.load(id) {
            Ok(loaded) => assert_eq!(loaded.state(), LifecycleState::CleanupVerified),
            Err(err) => panic!("record must load: {err}"),
        }
        match reopened.recover(id) {
            Ok(again) => assert_eq!(again.decision(), RecoveryDecision::AlreadyVerified),
            Err(err) => panic!("second recovery must succeed: {err}"),
        }
    }

    #[test]
    fn a_recovered_process_that_is_still_alive_is_reported_never_adopted_as_a_child() {
        // A supervisor died while its run kept going. The only honest report is
        // "it is still there": this process never forked it, so `waitpid`
        // cannot reach it and no exit facts exist to hand back. `RecoveredSession`
        // has no `wait` for exactly that reason.
        let root = temp_dir();
        let store = store_at(root.path());
        let record = live_record(LifecycleState::Running);
        let id = record.session_id();
        if let Err(err) = store.inner.create(&record) {
            panic!("first write must succeed: {err}");
        }

        let mut recovered = match store.recover(id) {
            Ok(recovered) => recovered,
            Err(err) => panic!("recovery must succeed: {err}"),
        };
        assert_eq!(
            recovered.decision(),
            RecoveryDecision::StillRunning {
                survivors: SurvivorEvidence::IdentityMatch { pid: current_pid() }
            }
        );
        assert_eq!(
            recovered.observation(),
            &CleanupVerification::StillPresent {
                survivors: SurvivorEvidence::IdentityMatch { pid: current_pid() }
            },
            "the evidence the decision was made from is reported, not just the decision"
        );
        assert_eq!(recovered.session_id(), id);
        assert_eq!(recovered.identity().pid(), current_pid());
        assert_eq!(recovered.process_group(), i32::MAX);
        assert_eq!(recovered.record().generation(), 1);
        assert_eq!(recovered.state(), LifecycleState::Failed);
        let rendered = format!("{recovered:?}");
        assert!(rendered.contains("StillRunning"), "{rendered}");
        assert_eq!(
            recovered.verify_cleanup(),
            Ok(CleanupVerification::StillPresent {
                survivors: SurvivorEvidence::IdentityMatch { pid: current_pid() }
            })
        );
        assert_eq!(
            recovered.state(),
            LifecycleState::Failed,
            "a survivor must never be recorded as verified cleanup"
        );
    }

    #[test]
    fn a_deadline_that_has_passed_returns_the_verdict_as_it_stands() {
        // The polling re-verify must not upgrade an unfinished answer just
        // because it ran out of time.
        let root = temp_dir();
        let store = store_at(root.path());
        let record = live_record(LifecycleState::Running);
        let id = record.session_id();
        if let Err(err) = store.inner.create(&record) {
            panic!("first write must succeed: {err}");
        }
        let mut recovered = match store.recover(id) {
            Ok(recovered) => recovered,
            Err(err) => panic!("recovery must succeed: {err}"),
        };
        assert_eq!(
            recovered.verify_cleanup_by(Instant::now()),
            Ok(CleanupVerification::StillPresent {
                survivors: SurvivorEvidence::IdentityMatch { pid: current_pid() }
            })
        );
    }

    #[test]
    fn a_recovered_session_never_signals_a_group_that_would_name_our_own() {
        // `kill(0, …)` is the caller's own process group and `kill(-1, …)` is
        // everything it may signal. A corrupt record carrying either must not
        // reach the kernel.
        let root = temp_dir();
        let store = store_at(root.path());
        for pgid in [0, 1, -1, i32::MIN] {
            let mut record = live_record(LifecycleState::Running);
            record.process_group = pgid;
            let id = record.session_id();
            if let Err(err) = store.inner.create(&record) {
                panic!("first write must succeed: {err}");
            }
            let recovered = match store.recover(id) {
                Ok(recovered) => recovered,
                Err(err) => panic!("recovery must succeed: {err}"),
            };
            assert_eq!(
                recovered.kill_group().err(),
                Some(StopError::SignalFailed {
                    target: pgid,
                    errno: libc::EINVAL
                }),
                "pgid {pgid} must never be signalled"
            );
        }
    }

    #[test]
    fn signalling_a_process_that_is_already_gone_is_not_a_failure() {
        let root = temp_dir();
        let store = store_at(root.path());
        let record = absent_record(LifecycleState::Running);
        let id = record.session_id();
        if let Err(err) = store.inner.create(&record) {
            panic!("first write must succeed: {err}");
        }
        let recovered = match store.recover(id) {
            Ok(recovered) => recovered,
            Err(err) => panic!("recovery must succeed: {err}"),
        };
        assert_eq!(recovered.kill_group(), Ok(()));
        assert_eq!(recovered.kill_pid(), Ok(()));
    }

    #[test]
    fn recovering_a_terminal_record_moves_nothing() {
        let root = temp_dir();
        let store = store_at(root.path());
        let record = absent_record(LifecycleState::CleanupVerified);
        let id = record.session_id();
        if let Err(err) = store.inner.create(&record) {
            panic!("first write must succeed: {err}");
        }
        let mut recovered = match store.recover(id) {
            Ok(recovered) => recovered,
            Err(err) => panic!("recovery must succeed: {err}"),
        };
        assert_eq!(recovered.decision(), RecoveryDecision::AlreadyVerified);
        assert_eq!(recovered.state(), LifecycleState::CleanupVerified);
        assert_eq!(
            recovered.verify_cleanup().err(),
            Some(CleanupError {
                state: LifecycleState::CleanupVerified
            }),
            "counting one proof twice is a caller bug worth seeing"
        );
    }

    // -----------------------------------------------------------------------
    // The whole loop: a durable prepare, a caller that dies, a recovery.
    // -----------------------------------------------------------------------

    #[test]
    fn a_crashed_caller_leaves_a_recoverable_session_whose_cleanup_can_be_proven() {
        let root = temp_dir();
        let store = store_at(root.path());
        let plan = match SandboxPlan::new("/bin/echo")
            .arg("never runs")
            .metadata(b"opaque".to_vec())
            .validate()
        {
            Ok(plan) => plan,
            Err(err) => panic!("test plan must validate: {err}"),
        };

        let (held, handle) = match store.prepare(plan) {
            Ok(pair) => pair,
            Err(err) => panic!("durable prepare must succeed: {err}"),
        };
        let id = held.session_id();
        let pid = held.identity().pid();
        assert_eq!(held.state(), LifecycleState::Prepared);

        // The record exists, at `prepared`, before anything is activated.
        match store.inner.load(id) {
            Ok(record) => {
                assert_eq!(record.state(), LifecycleState::Prepared);
                assert_eq!(record.identity().pid(), pid);
                assert_eq!(record.process_group(), pid);
                assert_eq!(record.metadata(), b"opaque");
                assert_eq!(record.activation(), None);
            }
            Err(err) => panic!("the record must exist at prepare time: {err}"),
        }

        // The caller dies: its descriptors close, the held child reads EOF on
        // the gate and exits by itself, and nothing kills or reaps it. The
        // record is left saying `prepared`, which is now a lie about the
        // present and still a true statement about the past.
        drop(handle);
        held.abandon();
        // Standing in for `init`, which reaps an orphan a real crash would have
        // handed it. Without this the child would linger as a zombie of the
        // test process, and a zombie still answers a liveness probe.
        if let Err(err) = reap(pid) {
            panic!("the abandoned child must be reapable: {err}");
        }

        // A new process opens the same store and finds the stale record.
        let reopened = store_at(root.path());
        let summaries: Vec<_> = match reopened.sessions() {
            Ok(sessions) => sessions.collect(),
            Err(err) => panic!("enumeration must start: {err}"),
        };
        assert_eq!(summaries.len(), 1);
        match summaries.into_iter().next() {
            Some(Ok(summary)) => {
                assert_eq!(summary.session_id(), id);
                assert_eq!(
                    summary.state(),
                    LifecycleState::Prepared,
                    "the record lags the world, which is exactly why it is reconciled"
                );
            }
            other => panic!("the record must load: {other:?}"),
        }

        let mut recovered = match reopened.recover(id) {
            Ok(recovered) => recovered,
            Err(err) => panic!("recovery must succeed: {err}"),
        };
        assert_eq!(
            recovered.decision(),
            RecoveryDecision::ProcessGone {
                basis: AbsenceBasis::PidAbsent { pid }
            },
            "the reconciliation, not the record, is what said the run is over"
        );
        assert_eq!(recovered.state(), LifecycleState::Failed);

        assert_eq!(
            recovered.verify_cleanup(),
            Ok(CleanupVerification::ConfirmedAbsent {
                basis: AbsenceBasis::PidAbsent { pid }
            })
        );
        assert_eq!(recovered.state(), LifecycleState::CleanupVerified);

        // Durable, and durable in the right shape: a third reader sees the
        // proof rather than having to redo it.
        match store_at(root.path()).inner.load(id) {
            Ok(record) => {
                assert_eq!(record.state(), LifecycleState::CleanupVerified);
                assert_eq!(record.schema_version(), CURRENT_SCHEMA_VERSION);
                assert_eq!(record.generation(), 1, "recovery bumps no generation");
            }
            Err(err) => panic!("record must load: {err}"),
        }
    }
}
