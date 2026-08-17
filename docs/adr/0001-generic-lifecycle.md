# ADR-0001: Generic prepared-process lifecycle in `crates/nono`

Status: accepted (fork) · Date: 2026-08-17 · Run: EF1A07E7-A38C-4C5E-98CA-9444CA7CFD5C

## Context

Upstream (149579a7) exposes a single-shot model: build `CapabilitySet`, call
`Sandbox::apply_*`, irreversibly, in the calling process. The process model
(fork/exec strategies, supervisor, PTY, sessions, attach) is `nono-cli`-private
(`AGENTS.md` places `ExecStrategy` explicitly in the CLI). The frozen stream
contract requires a *library* lifecycle:

    SandboxPlan -> PreparedSandbox -> ActivatedSandbox -> SandboxExit -> CleanupVerification

with a real pre-exec hold, single-use unforgeable activation, durable
supervision, attach, typed exit facts, and PID-reuse-safe cleanup verification —
all generic (no CrystalOS/HCP/Leash/Cedar concepts).

## Decision

### 1. New additive module `crates/nono/src/lifecycle/`

The lifecycle is mechanism, not policy, so it belongs in the library under
upstream's own boundary rule ("library = pure sandbox primitive"). It is added
as a new module; existing APIs (`CapabilitySet`, `Sandbox::apply_*`) are
untouched, so upstream tests stay green. `nono-cli` is NOT rewritten onto it in
this stream; lifting CLI PTY/attach internals happens by extraction into the
library where needed (R09), keeping CLI behavior and tests intact.

Layout:

    lifecycle/
      mod.rs           public re-exports
      plan.rs          SandboxPlan + full pre-launch validation (PlanError)
      state.rs         typed state machine (pure; loom-testable)
      gate.rs          activation gate: token issue/verify, single-use CAS
      prepare.rs       fork + trusted child pre-exec (apply sandbox, hold)
      supervisor.rs    durable supervisor: wait/stop/query/recover
      session_store.rs schema-versioned durable session records
      exit.rs          SandboxExit facts
      cleanup.rs       CleanupVerification
      identity.rs      ProcessIdentity (pid + start_time + boot_id/equivalent)
      events.rs        EventSink trait + LifecycleEvent (fidelity-labeled)
      support.rs       SupportReport (typed, per-capability)

### 2. Typed state machine (`state.rs`)

States: `Planning, Preparing, Prepared, Activating, Running, Exited, Stopping,
Stopped, CleanupVerified, Failed`. Transitions are a total function
`(State, Op) -> Result<State, TransitionError>`; illegal transitions are typed
errors, never panics (workspace denies unwrap). The machine is a pure value
type with interior mutability only at the supervisor layer (CAS over an enum),
so Loom can exhaust interleavings without OS access: two activations → exactly
one winner; activate vs stop; wait vs stop; supervisor-exit vs activate;
duplicate cleanup.

### 3. Prepared process and hold point (`prepare.rs`)

`prepare(plan)`: validate plan → create session (store v2) → fork.
Child (trusted nono code only): establish PTY/session leadership as requested →
apply platform sandbox (Landlock `restrict_self` / Seatbelt `sandbox_init` —
both survive exec) → block on `read()` of the **gate fd** → on release byte
`execve` the customer argv directly (no shell) → pre-exec failures are reported
as typed records written to the **status fd**, then `_exit`; exit-code
sentinels (126/127) are never used as protocol.

Descriptor discipline: gate fd and status fd are `O_CLOEXEC` ends of
`socketpair`/`pipe2`; customer code can never observe them (pre-release only
trusted code runs; at exec both close atomically). EOF-without-error-record on
the status fd is the **positive observation that exec occurred**
(`activation_occurred = true`), replacing stderr scraping.

### 4. Activation gate (`gate.rs`)

`prepare()` returns an opaque `ActivationHandle { session_id, generation,
token: [u8; 32] }` (crypto-rand via `getrandom`, `zeroize` on drop). The
supervisor stores only a SHA-256 digest of the token (never the token, never
logged, never in argv/env/files). `activate(handle)`:

1. session + generation must match the live prepared session (typed errors
   `WrongSession`, `WrongGeneration`),
2. constant-time digest compare,
3. CAS `Prepared -> Activating`; a lost race or repeat returns
   `AlreadyActivated`; after stop returns `AlreadyStopped`; after configured
   expiry returns `ActivationExpired`,
4. winner writes the release byte to the gate fd and transitions to `Running`
   on positive exec observation.

The gate closes permanently on first outcome (release, stop, expiry,
supervisor death → child read() returns 0 → child `_exit`s via status-fd
record). Nono defines only these mechanics; product authorization stays in the
consumer.

### 5. Exit facts (`exit.rs`), cleanup (`cleanup.rs`), identity (`identity.rs`)

`SandboxExit` carries directly observed facts only: `Exited(i32)` /
`Signaled(i32)` from `waitpid`, `SandboxApplicationFailure(typed)` /
`PreExecFailure(typed)` from the status fd, `SupervisorFailure(typed)`,
`activation_occurred`, `ProcessIdentity`, optional denial observations with
fidelity labels. No product statuses.

`CleanupVerification` = `ConfirmedAbsent | StillPresent | Indeterminate |
Unsupported`, each with evidence. A sent signal is never proof. Identity =
pid + start-time (`/proc/<pid>/stat` field 22 on Linux; `proc_pidinfo`
pbi_start_tvsec on macOS) + boot id (`/proc/sys/kernel/random/boot_id`;
`kern.boottime`), all captured at fork time and re-checked at verification.

### 6. Durable sessions (`session_store.rs`)

Records: `schema_version` (u32, starts at 1 for the fork store), session id
(UUIDv7), generation (u64, incremented per prepare), identity, state, paths.
Storage: 0700 dir / 0600 files, `O_NOFOLLOW`, write-to-temp + `rename`,
corruption → typed `SessionCorrupt` (never default), reconcile against live
identity before trust. Recovery API enumerates sessions and re-adopts or
verifies cleanup after caller restart.

### 7. Events (`events.rs`) and support (`support.rs`)

`trait EventSink: Send + Sync { fn emit(&self, LifecycleEvent); }` — consumer
implements; library never forwards to product systems. Every event carries
`source: Observation::{DirectlyObserved, Reconstructed}`; events invisible to
the platform are absent, not synthesized. `SupportReport` is a typed
per-capability report (OS, arch, kernel, Landlock ABI + rights, seccomp,
seccomp-unotify, Seatbelt, network, PTY, detach, attach, identity fidelity,
cleanup fidelity, event fidelity, dark spots, refusal reasons) — upstream's
boolean `SupportInfo` remains for compatibility.

## Consequences

- Main rebase-conflict surface: none initially (module is additive); grows if
  R09 extracts CLI PTY/attach code — each extraction is recorded in
  NONO_UPSTREAM_DELTA.md with its deletion condition (upstream adopts the
  library lifecycle or the fork drops it).
- Upstream-suitable: the whole module respects "library applies only what the
  client asks"; candidate for an upstream RFC after stabilization (upstream
  policy requires issue-first; see AGENTS.md Coding Agent Contribution Policy).
- Security-critical new code concentrates in `gate.rs`/`prepare.rs`; every
  guard gets a test that fails when the guard is deliberately removed (R-row
  test discipline), and the pure state machine gets Loom coverage before the
  API ossifies.
