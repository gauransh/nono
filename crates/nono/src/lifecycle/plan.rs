//! The sandbox plan and its pre-launch validation.
//!
//! A [`SandboxPlan`] is built the same way as a
//! [`CapabilitySet`][crate::capability::CapabilitySet] — chained methods that
//! consume and return `self` — and describes a run completely before anything
//! is created. [`SandboxPlan::validate`] turns it into a [`ValidatedPlan`],
//! a typestate that nothing else can construct, so a later `prepare()` cannot
//! be handed an unvalidated plan.
//!
//! # Nothing is inherited
//!
//! The permitted environment starts empty and only grows through
//! [`SandboxPlan::env`]. The plan never reads the calling process's
//! environment, so a variable reaches the sandboxed program only because a
//! caller named it.
//!
//! # Validation touches no filesystem
//!
//! Every rule here is a property of the plan's own bytes: shape, absoluteness,
//! interior NULs, size bounds. Existence, type, and canonicalization checks are
//! deliberately absent — those must happen in `prepare()`, immediately before
//! the value is used, or they are a time-of-check/time-of-use gap rather than a
//! guarantee.

use super::events::EventSink;
use super::prepare::FIRST_GENERATION;
use crate::capability::{CapabilitySet, NetworkMode};
use serde::{Deserialize, Serialize};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// Maximum size of [`SandboxPlan::metadata`], in bytes.
///
/// The bound exists because the metadata rides along into durable session
/// records; it is not a statement about what the bytes mean.
pub const MAX_PLAN_METADATA_BYTES: usize = 4096;

/// Whether the run gets an interactive session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    /// Terminal-attached run: the child becomes a session leader with a PTY.
    Interactive,
    /// No controlling terminal. The default — a PTY is a capability, so it is
    /// granted only on request.
    #[default]
    Headless,
}

/// Activation gate settings.
///
/// # How the deadline is measured
///
/// The expiry is measured with [`std::time::Instant`], which does not advance
/// while the machine is suspended: a gate given five minutes still has time
/// left after an hour of sleep. It is also evaluated *lazily* — there is no
/// timer thread. A gate that has run out is discovered at the next
/// `activate`, `stop`, or drop, and the child stays parked at the gate until
/// then. Neither is a leak: the child cannot run without a release, and both
/// choices favour refusing over racing a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GateConfig {
    /// How long a prepared child may sit at the gate before activation is
    /// refused. `None` means the gate stays open until it is used, stopped, or
    /// the supervisor dies. A zero duration is rejected by validation because
    /// it would name a gate that can never be used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_expiry: Option<Duration>,
}

/// Resource ceilings for the sandboxed process tree.
///
/// Non-zero types make "no limit" and "a limit of zero" different values
/// rather than the same one: `None` is unlimited, and a zero ceiling cannot be
/// expressed at all.
///
/// Distinct from [`crate::resource::ResourceLimits`], which is the CLI's
/// cgroup-facing type. This one is the lifecycle's own generic shape and is
/// reachable only as `lifecycle::ResourceLimits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum resident memory for the process tree, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_bytes: Option<NonZeroU64>,
    /// Maximum number of processes and threads in the tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pids: Option<NonZeroU32>,
    /// Maximum accumulated CPU time, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_time_secs: Option<NonZeroU64>,
}

/// Everything a plan can be rejected for.
///
/// Messages name the offending field by position or key, never by value: an
/// argument or environment value that failed validation is exactly the kind of
/// thing that carries a secret.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PlanError {
    /// The program is the empty string.
    #[error("plan program is empty")]
    EmptyProgram,

    /// The program contains an interior NUL and could never become a `CString`.
    #[error("plan program contains an interior NUL byte")]
    ProgramNul,

    /// An argument contains an interior NUL.
    #[error("plan argument at index {index} contains an interior NUL byte")]
    ArgNul {
        /// Position in the argument list.
        index: usize,
    },

    /// The working directory is relative, so it would resolve against whatever
    /// directory the caller happened to be in.
    #[error("plan working directory must be absolute: {path}")]
    RelativeWorkingDir {
        /// The directory as supplied.
        path: PathBuf,
    },
    /// The cgroup parent is not an absolute path.
    ///
    /// A relative one would be resolved against whatever directory the caller
    /// happened to be in, which is not a cgroup anybody chose.
    #[error("cgroup parent must be absolute, got {path:?}")]
    RelativeCgroupParent {
        /// The directory as supplied.
        path: PathBuf,
    },

    /// An environment key is empty.
    #[error("plan environment key at index {index} is empty")]
    EmptyEnvKey {
        /// Position in the environment list.
        index: usize,
    },

    /// An environment key contains an interior NUL.
    #[error("plan environment key at index {index} contains an interior NUL byte")]
    EnvKeyNul {
        /// Position in the environment list.
        index: usize,
    },

    /// An environment key contains `=`, which would smuggle a second
    /// assignment into one `KEY=VALUE` entry.
    #[error("plan environment key at index {index} contains '='")]
    EnvKeyEquals {
        /// Position in the environment list.
        index: usize,
    },

    /// An environment value contains an interior NUL.
    #[error("plan environment value for '{key}' contains an interior NUL byte")]
    EnvValueNul {
        /// The key whose value was rejected. Safe to render: it has already
        /// passed the key rules.
        key: String,
    },

    /// Two environment entries share a key.
    ///
    /// Refused rather than silently deduplicated. The vector reaches `execve`
    /// verbatim, which entry wins is platform-dependent, and a caller who is
    /// surprised by the answer has a dynamic-linker variable set to a value it
    /// did not intend. Picking a winner here would be the library choosing
    /// policy.
    #[error("plan environment sets '{key}' more than once")]
    DuplicateEnvKey {
        /// The repeated key. Safe to render: the *value* is what carries
        /// secrets.
        key: String,
    },

    /// The opaque metadata exceeds [`MAX_PLAN_METADATA_BYTES`].
    #[error("plan metadata is {size} bytes (max: {max} bytes)")]
    MetadataTooLarge {
        /// Size supplied.
        size: usize,
        /// The bound.
        max: usize,
    },

    /// The activation expiry is zero, naming a gate that can never be used.
    #[error("plan activation expiry must be greater than zero")]
    ZeroActivationExpiry,
}

/// A complete description of a sandboxed run, before anything is created.
///
/// Deliberately not [`Default`]: a plan with no program names no run, so
/// [`SandboxPlan::new`] is the only way in.
///
/// # Example
///
/// ```
/// use nono::lifecycle::{SandboxPlan, SessionMode};
///
/// let plan = SandboxPlan::new("/bin/echo")
///     .arg("hello")
///     .working_dir("/tmp")
///     .env("LANG", "C")
///     .session_mode(SessionMode::Headless)
///     .validate()?;
/// assert_eq!(plan.args(), ["hello"]);
/// # Ok::<(), nono::PlanError>(())
/// ```
#[derive(Clone)]
pub struct SandboxPlan {
    program: String,
    args: Vec<String>,
    working_dir: Option<PathBuf>,
    env: Vec<(String, String)>,
    capabilities: CapabilitySet,
    resource_limits: ResourceLimits,
    cgroup_parent: Option<PathBuf>,
    workload_uid: Option<u32>,
    session_mode: SessionMode,
    generation: u64,
    detached: bool,
    gate: GateConfig,
    metadata: Vec<u8>,
    event_sink: Option<Arc<dyn EventSink>>,
}

impl SandboxPlan {
    /// Start a plan for `program`.
    ///
    /// The program is used verbatim as the exec target; it is never run through
    /// a shell and never resolved against `PATH` by the library.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            working_dir: None,
            cgroup_parent: None,
            workload_uid: None,
            env: Vec::new(),
            capabilities: CapabilitySet::new(),
            resource_limits: ResourceLimits::default(),
            session_mode: SessionMode::default(),
            generation: FIRST_GENERATION,
            detached: false,
            gate: GateConfig::default(),
            metadata: Vec::new(),
            event_sink: None,
        }
    }

    /// Append one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments, in order.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set the working directory. Must be absolute.
    ///
    /// Unset means the child inherits the calling process's directory.
    #[must_use]
    pub fn working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Create this run's cgroup under `parent` rather than at the cgroup2 root.
    /// Must be absolute.
    ///
    /// The run still gets its own cgroup named for its session; this only
    /// changes where that cgroup is created. A caller that has attached
    /// enforcement to a cgroup passes it here so the run lands *underneath* the
    /// attachment: a cgroup created at the root shares no ancestor with one
    /// created anywhere else, so an attachment made outside this run would
    /// govern nothing it does.
    ///
    /// Unset means the cgroup2 root, which is what every run did before this
    /// existed. Refused at preparation on platforms with no cgroups, rather
    /// than accepted and ignored — a caller asking for containment it will not
    /// get should hear so.
    #[must_use]
    pub fn cgroup_parent(mut self, parent: impl Into<PathBuf>) -> Self {
        self.cgroup_parent = Some(parent.into());
        self
    }

    /// Make the child drop to `uid` (as its uid *and* gid) just before exec.
    ///
    /// The point is that the workload then runs as a different identity than the
    /// daemon that owns its cgroup: a process may migrate itself between cgroups
    /// only where it has write on the destination's `cgroup.procs`, and that
    /// write is gated on the *euid* that owns the directory. Run the workload as
    /// the daemon uid and it could walk itself out of the cgroup the daemon
    /// placed it in; run it as a distinct `U_w` and that self-migration escape is
    /// closed. The drop happens in the child after the sandbox is sealed — see
    /// `child_main` — so nothing the workload does can undo it.
    ///
    /// Unset means no drop: the child keeps whatever identity it forked with,
    /// which is what every run did before this existed. A Linux-only placement
    /// concern, threaded like [`Self::cgroup_parent`]; a no-op where absent.
    #[must_use]
    pub const fn workload_uid(mut self, uid: u32) -> Self {
        self.workload_uid = Some(uid);
        self
    }

    /// Permit one environment variable.
    ///
    /// Nothing is inherited, so this is the only way a variable reaches the
    /// program. Entries are kept in insertion order; a key set twice is
    /// rejected by [`Self::validate`] rather than deduplicated, because the
    /// vector reaches `execve` verbatim and which entry wins there is
    /// platform-dependent.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Set the capability set the child will apply to itself.
    ///
    /// Replaces any previously set capabilities, including a network mode set
    /// through [`Self::network_mode`].
    #[must_use]
    pub fn capabilities(mut self, capabilities: CapabilitySet) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set the network mode.
    ///
    /// Stored on the plan's [`CapabilitySet`], which is the single source of
    /// truth for network access; this is a shorthand, not a second setting
    /// that could disagree with it.
    #[must_use]
    pub fn network_mode(mut self, mode: NetworkMode) -> Self {
        self.capabilities = self.capabilities.set_network_mode(mode);
        self
    }

    /// Set the resource ceilings.
    #[must_use]
    pub fn resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }

    /// Set the session mode.
    #[must_use]
    pub fn session_mode(mut self, mode: SessionMode) -> Self {
        self.session_mode = mode;
        self
    }

    /// Whether the run outlives the caller.
    #[must_use]
    pub fn detached(mut self, detached: bool) -> Self {
        self.detached = detached;
        self
    }

    /// Bind this run to a caller-chosen policy generation.
    ///
    /// The generation travels into the [`ActivationHandle`] and is compared on
    /// release, so a handle minted under one generation cannot activate a
    /// sandbox prepared under another. Defaults to [`FIRST_GENERATION`].
    ///
    /// Callers that version their policy — a control plane that reissues on
    /// every policy change — need this to be theirs. Before it existed the
    /// field was always `FIRST_GENERATION`, so the comparison on release was
    /// `1 != 1` and could not fail: the check was present but decided nothing.
    /// The activation token is still the primary binding; this is the layer
    /// that makes a *stale-generation* release refusable on its own terms.
    #[must_use]
    pub const fn generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Set the activation gate configuration.
    #[must_use]
    pub fn gate(mut self, gate: GateConfig) -> Self {
        self.gate = gate;
        self
    }

    /// Attach opaque caller metadata, at most [`MAX_PLAN_METADATA_BYTES`].
    ///
    /// The library stores and returns these bytes and never interprets them.
    #[must_use]
    pub fn metadata(mut self, metadata: impl Into<Vec<u8>>) -> Self {
        self.metadata = metadata.into();
        self
    }

    /// Attach an event sink.
    #[must_use]
    pub fn event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.event_sink = Some(sink);
        self
    }

    /// Check the plan and seal it.
    ///
    /// Rules, in order: the program is non-empty and NUL-free; no argument
    /// contains a NUL; the working directory, if set, is absolute; every
    /// environment key is non-empty, NUL-free, `=`-free, and unique, and every
    /// value is NUL-free; the metadata fits [`MAX_PLAN_METADATA_BYTES`]; and an
    /// activation expiry, if set, is non-zero.
    ///
    /// No filesystem access happens here, by design — see the module docs.
    ///
    /// # Errors
    ///
    /// The first [`PlanError`] encountered, in the order above.
    #[must_use = "a plan is only sealed if the returned ValidatedPlan is kept"]
    pub fn validate(self) -> Result<ValidatedPlan, PlanError> {
        if self.program.is_empty() {
            return Err(PlanError::EmptyProgram);
        }
        if contains_nul(&self.program) {
            return Err(PlanError::ProgramNul);
        }
        for (index, arg) in self.args.iter().enumerate() {
            if contains_nul(arg) {
                return Err(PlanError::ArgNul { index });
            }
        }
        if let Some(dir) = &self.working_dir
            && !dir.is_absolute()
        {
            return Err(PlanError::RelativeWorkingDir { path: dir.clone() });
        }
        if let Some(parent) = &self.cgroup_parent
            && !parent.is_absolute()
        {
            return Err(PlanError::RelativeCgroupParent {
                path: parent.clone(),
            });
        }
        for (index, (key, value)) in self.env.iter().enumerate() {
            if key.is_empty() {
                return Err(PlanError::EmptyEnvKey { index });
            }
            if contains_nul(key) {
                return Err(PlanError::EnvKeyNul { index });
            }
            if key.contains('=') {
                return Err(PlanError::EnvKeyEquals { index });
            }
            if self.env[..index].iter().any(|(seen, _)| seen == key) {
                return Err(PlanError::DuplicateEnvKey { key: key.clone() });
            }
            if contains_nul(value) {
                return Err(PlanError::EnvValueNul { key: key.clone() });
            }
        }
        if self.metadata.len() > MAX_PLAN_METADATA_BYTES {
            return Err(PlanError::MetadataTooLarge {
                size: self.metadata.len(),
                max: MAX_PLAN_METADATA_BYTES,
            });
        }
        if let Some(expiry) = self.gate.activation_expiry
            && expiry.is_zero()
        {
            return Err(PlanError::ZeroActivationExpiry);
        }
        Ok(ValidatedPlan { plan: self })
    }
}

/// Debug that names fields without reproducing their contents. Argument and
/// environment values and the opaque metadata are the parts of a plan most
/// likely to hold a secret, so they are summarized rather than printed.
impl std::fmt::Debug for SandboxPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let env_keys: Vec<&str> = self.env.iter().map(|(key, _)| key.as_str()).collect();
        f.debug_struct("SandboxPlan")
            .field("program", &self.program)
            .field("args", &self.args.len())
            .field("working_dir", &self.working_dir)
            .field("cgroup_parent", &self.cgroup_parent)
            .field("workload_uid", &self.workload_uid)
            .field("env_keys", &env_keys)
            .field("capabilities", &self.capabilities)
            .field("resource_limits", &self.resource_limits)
            .field("session_mode", &self.session_mode)
            .field("detached", &self.detached)
            .field("gate", &self.gate)
            .field("metadata_bytes", &self.metadata.len())
            .field("event_sink", &self.event_sink.is_some())
            .finish()
    }
}

/// A plan that has passed [`SandboxPlan::validate`].
///
/// Constructible only by that method, so holding one is proof the rules ran.
/// Read-only: a plan cannot be edited after validation, which is what keeps the
/// checked bytes and the used bytes the same bytes.
#[derive(Clone)]
pub struct ValidatedPlan {
    plan: SandboxPlan,
}

impl ValidatedPlan {
    /// The exec target.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.plan.program
    }

    /// Arguments, in order. Does not include the program itself.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.plan.args
    }

    /// The working directory, if one was set.
    #[must_use]
    pub fn working_dir(&self) -> Option<&Path> {
        self.plan.working_dir.as_deref()
    }

    /// The directory this run's cgroup is created under, if one was set.
    #[must_use]
    pub fn cgroup_parent(&self) -> Option<&Path> {
        self.plan.cgroup_parent.as_deref()
    }

    /// The uid/gid the child drops to just before exec, if one was set.
    #[must_use]
    pub const fn workload_uid(&self) -> Option<u32> {
        self.plan.workload_uid
    }

    /// The permitted environment, in insertion order.
    #[must_use]
    pub fn env(&self) -> &[(String, String)] {
        &self.plan.env
    }

    /// The capabilities the child will apply, including the network mode.
    #[must_use]
    pub fn capabilities(&self) -> &CapabilitySet {
        &self.plan.capabilities
    }

    /// The resource ceilings.
    #[must_use]
    pub fn resource_limits(&self) -> ResourceLimits {
        self.plan.resource_limits
    }

    /// The session mode.
    #[must_use]
    pub fn session_mode(&self) -> SessionMode {
        self.plan.session_mode
    }

    /// Whether the run outlives the caller.
    #[must_use]
    pub fn is_detached(&self) -> bool {
        self.plan.detached
    }

    /// The policy generation this run is bound to.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.plan.generation
    }

    /// The activation gate configuration.
    #[must_use]
    pub fn gate(&self) -> GateConfig {
        self.plan.gate
    }

    /// The opaque caller metadata.
    #[must_use]
    pub fn metadata(&self) -> &[u8] {
        &self.plan.metadata
    }

    /// The event sink, if one was attached.
    #[must_use]
    pub fn event_sink(&self) -> Option<&Arc<dyn EventSink>> {
        self.plan.event_sink.as_ref()
    }
}

impl std::fmt::Debug for ValidatedPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ValidatedPlan").field(&self.plan).finish()
    }
}

fn contains_nul(value: &str) -> bool {
    value.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySet, NetworkMode};
    use crate::lifecycle::events::EventEmitter;
    use crate::lifecycle::{EventSink, LifecycleEvent, LifecycleEventKind, LifecycleState};
    use std::num::{NonZeroU32, NonZeroU64};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use uuid::Uuid;

    const ONE_MIB: NonZeroU64 = match NonZeroU64::new(1024 * 1024) {
        Some(value) => value,
        None => NonZeroU64::MIN,
    };
    const SIXTEEN: NonZeroU32 = match NonZeroU32::new(16) {
        Some(value) => value,
        None => NonZeroU32::MIN,
    };
    const SIXTY: NonZeroU64 = match NonZeroU64::new(60) {
        Some(value) => value,
        None => NonZeroU64::MIN,
    };

    #[derive(Default)]
    struct CountingSink {
        events: Mutex<Vec<LifecycleEvent>>,
    }

    impl CountingSink {
        fn count(&self) -> usize {
            self.events.lock().map(|guard| guard.len()).unwrap_or(0)
        }
    }

    impl EventSink for CountingSink {
        fn emit(&self, event: &LifecycleEvent) {
            if let Ok(mut guard) = self.events.lock() {
                guard.push(event.clone());
            }
        }
    }

    fn minimal() -> SandboxPlan {
        SandboxPlan::new("/bin/echo")
    }

    #[test]
    fn minimal_plan_validates() -> Result<(), PlanError> {
        let validated = minimal().validate()?;
        assert_eq!(validated.program(), "/bin/echo");
        assert!(validated.args().is_empty());
        Ok(())
    }

    #[test]
    fn defaults_are_least_privilege() -> Result<(), PlanError> {
        let validated = minimal().validate()?;
        assert!(
            validated.env().is_empty(),
            "no environment may be inherited implicitly"
        );
        assert_eq!(validated.session_mode(), SessionMode::Headless);
        assert!(!validated.is_detached());
        assert!(validated.metadata().is_empty());
        assert!(validated.working_dir().is_none());
        assert!(validated.gate().activation_expiry.is_none());
        assert_eq!(validated.resource_limits(), ResourceLimits::default());
        assert!(validated.event_sink().is_none());
        Ok(())
    }

    #[test]
    fn full_plan_round_trips_through_validation() -> Result<(), PlanError> {
        let limits = ResourceLimits {
            max_memory_bytes: Some(ONE_MIB),
            max_pids: Some(SIXTEEN),
            cpu_time_secs: Some(SIXTY),
        };
        let validated = SandboxPlan::new("/usr/bin/env")
            .arg("--chdir")
            .args(["one", "two"])
            .working_dir("/tmp")
            .env("PATH", "/usr/bin")
            .env("LANG", "C")
            .capabilities(CapabilitySet::new().block_network())
            .resource_limits(limits)
            .session_mode(SessionMode::Interactive)
            .detached(true)
            .gate(GateConfig {
                activation_expiry: Some(Duration::from_secs(5)),
            })
            .metadata(vec![1, 2, 3])
            .validate()?;

        assert_eq!(validated.program(), "/usr/bin/env");
        assert_eq!(validated.args(), ["--chdir", "one", "two"]);
        assert_eq!(validated.working_dir(), Some(Path::new("/tmp")));
        assert_eq!(
            validated.env(),
            [
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("LANG".to_string(), "C".to_string()),
            ]
        );
        assert_eq!(
            validated.capabilities().network_mode(),
            &NetworkMode::Blocked
        );
        assert_eq!(validated.resource_limits(), limits);
        assert_eq!(validated.session_mode(), SessionMode::Interactive);
        assert!(validated.is_detached());
        assert_eq!(
            validated.gate().activation_expiry,
            Some(Duration::from_secs(5))
        );
        assert_eq!(validated.metadata(), [1, 2, 3]);
        Ok(())
    }

    #[test]
    fn network_mode_is_stored_on_the_capability_set() -> Result<(), PlanError> {
        let validated = minimal()
            .network_mode(NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![],
            })
            .validate()?;
        assert_eq!(
            validated.capabilities().network_mode(),
            &NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![],
            }
        );
        Ok(())
    }

    #[test]
    fn later_capability_set_replaces_the_network_mode_builder() -> Result<(), PlanError> {
        // Single source of truth: the capability set holds the network mode,
        // so a later `capabilities()` call wins over an earlier one.
        let validated = minimal()
            .network_mode(NetworkMode::Blocked)
            .capabilities(CapabilitySet::new())
            .validate()?;
        assert_eq!(
            validated.capabilities().network_mode(),
            &NetworkMode::AllowAll
        );
        Ok(())
    }

    #[test]
    fn empty_program_is_rejected() {
        assert_eq!(
            SandboxPlan::new("").validate().err(),
            Some(PlanError::EmptyProgram)
        );
    }

    #[test]
    fn program_with_interior_nul_is_rejected() {
        assert_eq!(
            SandboxPlan::new("/bin/ec\0ho").validate().err(),
            Some(PlanError::ProgramNul)
        );
    }

    #[test]
    fn arg_with_interior_nul_is_rejected() {
        assert_eq!(
            minimal().arg("ok").arg("ba\0d").validate().err(),
            Some(PlanError::ArgNul { index: 1 })
        );
    }

    #[test]
    fn relative_working_dir_is_rejected() {
        assert_eq!(
            minimal().working_dir("relative/dir").validate().err(),
            Some(PlanError::RelativeWorkingDir {
                path: PathBuf::from("relative/dir")
            })
        );
    }

    #[test]
    fn validation_does_not_touch_the_filesystem() -> Result<(), PlanError> {
        // Existence and canonicalization are prepare()'s job; validate() is pure.
        let validated = minimal()
            .working_dir("/nonexistent-nono-lifecycle-dir/deeper")
            .validate()?;
        assert_eq!(
            validated.working_dir(),
            Some(Path::new("/nonexistent-nono-lifecycle-dir/deeper"))
        );
        Ok(())
    }

    #[test]
    fn empty_env_key_is_rejected() {
        assert_eq!(
            minimal().env("", "value").validate().err(),
            Some(PlanError::EmptyEnvKey { index: 0 })
        );
    }

    #[test]
    fn env_key_with_interior_nul_is_rejected() {
        assert_eq!(
            minimal()
                .env("PATH", "/usr/bin")
                .env("BA\0D", "x")
                .validate()
                .err(),
            Some(PlanError::EnvKeyNul { index: 1 })
        );
    }

    #[test]
    fn env_key_containing_equals_is_rejected() {
        assert_eq!(
            minimal().env("A=B", "x").validate().err(),
            Some(PlanError::EnvKeyEquals { index: 0 })
        );
    }

    #[test]
    fn a_repeated_env_key_is_rejected_not_silently_resolved() {
        // `execve` takes the vector verbatim and the winner is
        // platform-dependent, so the only safe answer is to refuse.
        assert_eq!(
            minimal()
                .env("PATH", "/usr/bin")
                .env("LANG", "C")
                .env("PATH", "/attacker/bin")
                .validate()
                .err(),
            Some(PlanError::DuplicateEnvKey {
                key: "PATH".to_string()
            })
        );
    }

    #[test]
    fn distinct_env_keys_are_kept_in_insertion_order() -> Result<(), PlanError> {
        let validated = minimal().env("B", "2").env("A", "1").validate()?;
        assert_eq!(
            validated.env(),
            [
                ("B".to_string(), "2".to_string()),
                ("A".to_string(), "1".to_string()),
            ]
        );
        Ok(())
    }

    #[test]
    fn env_value_with_interior_nul_is_rejected() {
        assert_eq!(
            minimal().env("PATH", "/usr\0/bin").validate().err(),
            Some(PlanError::EnvValueNul {
                key: "PATH".to_string()
            })
        );
    }

    #[test]
    fn metadata_at_the_limit_is_accepted() -> Result<(), PlanError> {
        let validated = minimal()
            .metadata(vec![0_u8; MAX_PLAN_METADATA_BYTES])
            .validate()?;
        assert_eq!(validated.metadata().len(), MAX_PLAN_METADATA_BYTES);
        Ok(())
    }

    #[test]
    fn metadata_over_the_limit_is_rejected() {
        let size = MAX_PLAN_METADATA_BYTES + 1;
        assert_eq!(
            minimal().metadata(vec![0_u8; size]).validate().err(),
            Some(PlanError::MetadataTooLarge {
                size,
                max: MAX_PLAN_METADATA_BYTES
            })
        );
    }

    #[test]
    fn zero_activation_expiry_is_rejected() {
        assert_eq!(
            minimal()
                .gate(GateConfig {
                    activation_expiry: Some(Duration::ZERO)
                })
                .validate()
                .err(),
            Some(PlanError::ZeroActivationExpiry)
        );
    }

    #[test]
    fn event_sink_survives_validation_and_receives_events() -> Result<(), PlanError> {
        let sink = Arc::new(CountingSink::default());
        let validated = minimal()
            .event_sink(sink.clone() as Arc<dyn EventSink>)
            .validate()?;

        let emitted = match validated.event_sink() {
            Some(emitted) => emitted,
            None => panic!("event sink must survive validation"),
        };
        // Emitted through the run's own emitter, which is the only thing that
        // builds an event: the envelope's session, sequence, and clock are not
        // a caller's to invent.
        EventEmitter::new(Some(Arc::clone(emitted)), Uuid::nil(), 1).emit(
            LifecycleEventKind::StateChanged {
                from: LifecycleState::Planning,
                to: LifecycleState::Preparing,
            },
        );
        assert_eq!(sink.count(), 1);
        Ok(())
    }

    #[test]
    fn debug_output_does_not_leak_env_values_or_metadata() -> Result<(), PlanError> {
        let plan = minimal()
            .env("TOKEN", "super-secret-value")
            .metadata(b"opaque-secret-blob".to_vec());
        let rendered = format!("{plan:?}");
        assert!(rendered.contains("TOKEN"), "{rendered}");
        assert!(!rendered.contains("super-secret-value"), "{rendered}");
        assert!(!rendered.contains("opaque-secret-blob"), "{rendered}");

        let rendered = format!("{:?}", plan.validate()?);
        assert!(!rendered.contains("super-secret-value"), "{rendered}");
        assert!(!rendered.contains("opaque-secret-blob"), "{rendered}");
        Ok(())
    }

    #[test]
    fn resource_limits_serde_round_trips() -> Result<(), serde_json::Error> {
        let limits = ResourceLimits {
            max_memory_bytes: Some(ONE_MIB),
            max_pids: Some(SIXTEEN),
            cpu_time_secs: None,
        };
        let json = serde_json::to_string(&limits)?;
        assert_eq!(json, r#"{"max_memory_bytes":1048576,"max_pids":16}"#);
        assert_eq!(serde_json::from_str::<ResourceLimits>(&json)?, limits);
        Ok(())
    }

    #[test]
    fn session_mode_serde_names_are_stable() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::to_string(&SessionMode::Interactive)?,
            "\"interactive\""
        );
        assert_eq!(
            serde_json::to_string(&SessionMode::Headless)?,
            "\"headless\""
        );
        Ok(())
    }
}
