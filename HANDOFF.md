# HANDOFF — Parallel Stream 1: Crystal Nono fork (generic sandbox substrate)

Run: EF1A07E7-A38C-4C5E-98CA-9444CA7CFD5C · **FINAL form**, iteration 11 · 2026-08-17

STATUS: this stream's work is complete to the limit of what this host can verify.
It is **not** a declaration that the combined system is done — only the final
integration agent may say that. This file is the frozen-contract state of THIS
repository, and it is what leash-rs builds against.

**Read these three things first, in this order:** §8 (the one external blocker),
§9 (integration instructions, including the one line you must add to `main`),
and `BLOCKED_ROWS.json` (the authoritative per-row status). Everything else here
is reference.

---

## 1. Branch and base

- **Branch:** `parallel/nono-substrate-v1`
- **Repository:** local working checkout (see fork remote below)
- **Upstream base (pin):** `nolabs-ai/nono` @
  `149579a7b0753ee413680169fa937eea82da46a0`
- **HEAD convention:** the branch tip is authoritative. Each iteration's commit
  updates this file in the same commit; the final SHA is the tip of
  `parallel/nono-substrate-v1` at handoff. Do not cite a SHA from prose in this
  file as the integration pin — read the tip.
- **Fork remote:** `https://github.com/gauransh/nono` (public fork of
  `nolabs-ai/nono`), branch `parallel/nono-substrate-v1` — pushed and
  CI-verified. leash-rs pins it by `rev` (§9.1).
- **No upstream PR has been opened.** Upstream's `AGENTS.md` hard-stops any PR
  that has no prior issue and disclosure in that issue's discussion. Candidates
  and their order are in `docs/UPSTREAMING.md`; filing the issues is an
  operator decision.

### 1.1 Upstream has moved — the re-diff

Upstream `main` is now `9078ffcf`, **three commits past the pin**. All three were
fetched and diffed at iteration 11. Full analysis in `NONO_UPSTREAM_DELTA.md` §2;
the summary an integrator needs:

| Commit | Scope | Affects the fork? |
|---|---|---|
| `5be192ad` refactor(seccomp): all filters include arch guard | `crates/nono/src/sandbox/linux.rs`, 461 lines. `ArchGuarded<T>` makes the arch prologue **structurally unskippable**; `af_unix` filter grows 8 → 14 rules. | Same file the fork edits, but **no conflict** (measured). Strictly improves the fail-closed story the fork depends on. |
| `36243aa5` feat(policy): allow unlink for atomic-write temp files | CLI only. | Conceptually overlaps F11's `FsMode::AtomicWrite`, solved at CLI-policy level where F11 solves it at capability level. **They must not both ship.** |
| `9078ffcf` feat(remote): remote session connect and ps | CLI only, +2151 lines, WebSocket to a hosted console. | No library conflict. Conceptually adjacent to F9/F10's attach, at a different layer. |

**The rebase onto `9078ffcf` is textually clean** — verified by
`git merge-tree --write-tree` (returns a tree) and by a full `git rebase` of all
11 fork commits in an isolated `git clone --shared` ("Successfully rebased",
zero conflicts). The predicted `linux.rs` conflict did not materialise: the
fork's additions sit ~370 lines from upstream's. **One caveat that matters:**
`sandbox/linux.rs` is `cfg(target_os = "linux")` in its entirety, so a macOS host
cannot *compile* the rebased file at all. Rebase, then read the `ubuntu-latest`
job of `.github/workflows/stream-gates.yml` before believing the clean result.

---

## 2. Crates and packages

| Crate | Path | Role |
|---|---|---|
| **`nono`** | `crates/nono` | **The library leash-rs consumes.** Version `0.73.0`. Not published to crates.io by this stream. |
| `nono-cli` | `crates/nono-cli` | Unchanged from upstream except two test-hygiene fixes (F1/F1b). Not a dependency of `nono`. |
| `nono-proxy`, `nono-test-support` | | Unchanged roles from upstream. |
| `nono-ffi` | `bindings/c` | Unchanged role; one forced `map_error` arm because its match is exhaustive. |

`crates/nono` is a **leaf** in the workspace graph — it does not depend on
`nono-cli`, so no CLI code is reachable from the library even indirectly
(`BLOCKED_ROWS.json` R14).

---

## 3. API entry points — the complete list

Audited at iteration 11 against `crates/nono/src/lib.rs:100-114` (crate-root
re-exports) and `crates/nono/src/lifecycle/mod.rs:124-164` (module re-exports).

Everything below is reachable as `nono::<name>` unless the row says
`lifecycle::` only.

### 3.1 Plan

`SandboxPlan` · `ValidatedPlan` · `PlanError` · `GateConfig` · `SessionMode` ·
`MAX_PLAN_METADATA_BYTES` · `lifecycle::ResourceLimits` *(module-only — see §3.12)*

`SandboxPlan::new(program)` → builder (`.args`, `.env`, `.working_dir`,
`.capabilities`, `.session_mode`, `.detached`, `.gate`, `.metadata`, `.sink`) →
`.validate() -> Result<ValidatedPlan, PlanError>`. Validation is the typestate
boundary: nothing forks until a plan is `Validated`.

### 3.2 Prepare

`PreparedSandbox` · `PrepareError`

- `PreparedSandbox::prepare(ValidatedPlan) -> Result<(PreparedSandbox, ActivationHandle)>`
  — ephemeral, no store, no file.
- `PreparedSandbox::{activate, stop_before_activation, verify_cleanup, apply}`
- `Drop` kills the process group, then the pid, then reaps.

### 3.3 Activate

`ActivationHandle` · `ActivationError` · `ACTIVATION_TOKEN_BYTES`

- `PreparedSandbox::activate(&ActivationHandle) -> Result<ActivatedSandbox, ActivationError>`
- `ActivationHandle::{from_parts, token}` — the token is public **because it has
  to be**: a detached run is very often activated by a different process than
  prepared it, and the library cannot transport bytes for you. See §9.5.

### 3.4 Wait and exit facts

`ActivatedSandbox` · `SandboxExit` · `ExitOutcome` · `ActivationObservation` ·
`PreExecStage` · `SupervisorStage` · `ReapError` · `PRE_EXEC_EXIT_CODE`

- `ActivatedSandbox::{wait, try_wait, stop, verify_cleanup}`
- `SandboxExit` is verbatim `waitpid`: `Exited{code}` / `Signaled{signal}` —
  never `128 + n`. `PreExecFailure{stage, errno}` arrives on a 5-byte status
  record, so a sentinel exit code carries no protocol.
- `ActivationObservation` is **three-valued** (`Observed` / `NotActivated` /
  `ExecOrKilledPreExec`) and there is deliberately **no `bool` accessor**.

### 3.5 Stop

`StopError` · `PreparedSandbox::stop_before_activation` ·
`ActivatedSandbox::stop` · `DetachedSession::stop`

### 3.6 Cleanup verification

`CleanupVerification` · `AbsenceBasis` · `SurvivorEvidence` ·
`IndeterminateReason` · `UnsupportedReason` · `CleanupError`

Four answers, closed enum, typed evidence payloads. **A sent signal is never a
basis.** `verify_cleanup` on `PreparedSandbox`, `ActivatedSandbox`,
`DetachedSession`; `RecoveredSession::{verify_cleanup, verify_cleanup_by}`.

### 3.7 State machine

`LifecycleState` · `LifecycleOp` · `TransitionError`

10 states × 11 ops, exhaustive matrix test. Every mutation anywhere in the module
goes through `LifecycleState::apply`, so the legal-transition table has exactly
one definition.

### 3.8 Sessions, durability and recovery

`SessionStore` · `SessionRecord` · `SessionSummary` · `RecoveredSession` ·
`RecoveryDecision` · `SupervisorPresence` · `SessionStoreError` ·
`CURRENT_SCHEMA_VERSION` · `OLDEST_SUPPORTED_SCHEMA_VERSION` · `MAX_RECORD_BYTES` ·
`lifecycle::{Sessions, reconcile}` *(module-only)*

- `SessionStore::{open, prepare, prepare_detached, sessions, recover,
  attach_control, control_socket_path}`
- `RecoveredSession::{attach, supervisor, kill_group, kill_pid, verify_cleanup,
  verify_cleanup_by}`

### 3.9 Detached supervisor and control protocol

`lifecycle::supervisor_entry` · `DetachedSession` · `DetachedError` ·
`SessionStatus` · `WaitOutcome` · `ControlRequest` · `ControlReply` ·
`ControlRefusal` · `FrameError` · `CONTROL_PROTOCOL_VERSION` ·
`CONTROL_TIMEOUT` · `MAX_CONTROL_WAIT` · `MAX_CONTROL_FRAME_BYTES` ·
`DETACHED_EVENT_RING_CAPACITY`

`DetachedSession::{activate, wait, stop, status, verify_cleanup, attach, detach,
supervisor, opened_in}`. Dropping a `DetachedSession` closes a socket and the run
carries on — the opposite of every other handle in the module.

### 3.10 Terminal and attach

`AttachedTerminal` · `TerminalEvent` · `TerminalEnd` · `AttachAck` ·
`WindowSize` · `AttachError` · `AttachViolation` · `AttachTag` · `Peer` ·
`MAX_ATTACH_PAYLOAD_BYTES` (32 KiB) · `SCROLLBACK_CAPACITY_BYTES` (256 KiB)

`DetachedSession::attach(WindowSize) -> AttachedTerminal`;
`AttachedTerminal::{write_input, resize, ping, read_event, activate, detach, ack,
session_id, supervisor}`. Every call is deadline-bounded; `read_event` takes the
deadline explicitly and can answer `TerminalEvent::Idle`, because a quiet
terminal is a fact and not a timeout.

### 3.11 Identity, events, support

- `ProcessIdentity` — pid + platform start time + boot id.
- `EventSink` · `LifecycleEvent` · `LifecycleEventKind` · `ActivationOutcome` ·
  `Observation`
- `SupportReport::gather()` (infallible) · `lifecycle::Capability` *(module-only)* ·
  `SupportStatus` · `Determination` · `SupportReason` · `HostFacts` ·
  `KernelFacts` · `LandlockFacts` · `LandlockRight` · `LandlockRightSupport` ·
  `NetworkFilteringFacts` · `NetworkMechanism` · `NetworkMechanismSupport` ·
  `IdentityFacts` · `CleanupFacts` · `EventObservationSupport` · `EventFamily` ·
  `EventFidelity` · `DarkSpot` · `DarkSpotEntry` ·
  `SUPPORT_REPORT_SCHEMA_VERSION`

### 3.12 Capability modes (F11)

`FsMode` · `FsModeSet` · `FsModeCapability` · `CompiledModes` · `ModeBundle` ·
`ModeRefusal` · `ModeAlwaysAllowed` · `ModeDelegation` · `ModeEnforceability` ·
`BundleReason` · `RefusalReason` · `AlwaysAllowedReason` · `DelegationTarget` ·
`ModeTarget`

Plus `CapabilitySet::{allow_path_modes, allow_file_modes, fs_mode_capabilities,
add_fs_modes}` and `Sandbox::compile_fs_modes(&caps) -> Result<Vec<CompiledModes>>`.

### 3.13 Errors, and three deliberate non-exports

`LifecycleError` is the single aggregate, reached through `NonoError::Lifecycle`,
with a `diagnostic_code` arm per variant.

Three names are **module-only on purpose**, documented at `lib.rs:93-99`:

| Name | Why not at the crate root |
|---|---|
| `lifecycle::ResourceLimits` | Would collide with `resource::ResourceLimits`, a different type for a different purpose (cgroup ceilings on the CLI's enforcement path). |
| `lifecycle::Capability` | At the crate root it would read as a peer of `CapabilitySet`. It is not — it is "what a platform supports", not "what a sandbox grants". |
| `lifecycle::{Sessions, reconcile}` | An iterator type and a name too generic for a crate root. |

### 3.14 Upstream API, unchanged

`CapabilitySet` · `AccessMode` · `Sandbox::{apply_auto, apply_landlock,
apply_seccomp, apply_external}` · `QueryContext` · `SandboxState` ·
`SupportInfo` · `supervisor::{SupervisorSocket, SupervisorListener,
ApprovalBackend, …}` — all behave exactly as they did at `149579a7`.

---

## 4. Toolchain, flags, cfgs and markers

### 4.1 Toolchain

- **MSRV 1.95** (workspace `rust-version`), **edition 2024**.
- Built and verified on 1.88.0 and 1.96.0 aarch64-apple-darwin.

### 4.2 Cargo feature flags

| Feature | Default | Meaning |
|---|---|---|
| `system-keyring` | **on** | OS keyring access (macOS Keychain / Linux Secret Service). Headless and container consumers opt out with `default-features = false`. |

**No lifecycle-specific feature flag exists.** The lifecycle is unconditionally
compiled. That is deliberate: a sandbox lifecycle behind a feature flag is a
lifecycle some builds silently do not have.

### 4.3 cfg gates

| cfg | Set by | Effect |
|---|---|---|
| `nono_loom` | `RUSTFLAGS='--cfg nono_loom'`, only for the loom gate | Makes `lifecycle::sync_core` public so the out-of-crate `tests/loom_lifecycle.rs` can drive it from several threads, and swaps in loom's instrumented primitives. **Never set for a released build** — the public API is identical either way. |

The cfg is `nono_loom`, **not** loom's own `loom`, and this is not cosmetic:
`RUSTFLAGS` reaches every crate in the build, and `--cfg loom` makes `tokio`
compile out `tokio::net`, which `hyper-util` (transitive via `sigstore-verify`)
then fails to find. `build.rs` declares the cfg via `cargo::rustc-check-cfg`, so
`unexpected_cfgs` still catches a real typo.

### 4.4 Environment markers — protocol, not configuration

| Variable | Set by | Read by |
|---|---|---|
| `NONO_LIFECYCLE_SUPERVISOR` | The library, on the `execve` that creates a supervisor. Private. | `supervisor_entry()` |

**This is a protocol field that happens to travel in the environment. It is not a
configuration knob and must not be documented, set, forwarded, logged or
inspected by a consumer.** `supervisor_entry()` **removes it from the environment
before any other work**, so it can never be inherited by a customer child.
Setting it yourself makes your process a supervisor for a session that does not
exist.

That removal is also why "first statement of `main`" is a hard requirement rather
than a style note: removing an environment variable is sound only while the
process is single-threaded.

### 4.5 Platform requirements

| | macOS | Linux |
|---|---|---|
| Mechanism | Seatbelt (`sandbox_init`) | Landlock + seccomp |
| Minimum | any macOS with Seatbelt | Landlock ABI per `SupportReport`; **fail-closed below**, never degraded |
| `truncate` mode | supported | needs Landlock **ABI ≥ 3**; refused below |
| `rename` / `atomic_write` modes | supported | needs Landlock **ABI ≥ 2**; refused below |
| `read_metadata` mode | **enforceable** (the one place macOS is finer) | **unrestrictable** — Landlock has no right covering `stat(2)` |
| Live-verified by this stream | **yes** | **no** — see §8 |

Unix only. There is no Windows path and none is planned.

---

## 5. Final test matrix

Produced by `scripts/stream-gates.sh` on `Darwin arm64`, iteration 11. **This is
the gate report** — the script's output is the artifact, not a transcription of
one.

```
PASS     workspace-tests        3744 passed / 0 failed / 2 ignored (35 suites)
PASS     nono-crate-tests       1145 passed / 0 failed / 1 ignored (8 suites)
PASS     lifecycle-live         25 passed / 0 failed / 0 ignored (1 suites)
PASS     lifecycle-modes-live   14 passed / 0 failed / 0 ignored (1 suites)
PASS     lifecycle-detached     27 passed / 0 failed / 1 ignored (1 suites)
PASS     loom-lifecycle         7 passed / 0 failed / 0 ignored (1 suites)
PASS     clippy-strict          clean
PASS     clippy-loom            clean
PASS     fmt-check              clean
PASS     lint-docs              clean
PASS     lint-aliases           clean
PASS     doc-tests              11 passed / 0 failed / 0 ignored (1 suites)
NOT_RUN  miri-pure-lifecycle    miri component not installed: rustup +nightly component add miri
NOT_RUN  linux-landlock-live    Linux execution environment unavailable: docker daemon down (open Docker Desktop once and accept the first-run prompt)
NOT_RUN  linux-lifecycle-live   Linux execution environment unavailable: docker daemon down (open Docker Desktop once and accept the first-run prompt)

gates: 12 PASS  0 FAIL  3 NOT_RUN  (of 15)
```

**`NOT_RUN` is never `PASS`.** The script exits nonzero only on `FAIL`, so a host
that cannot answer a gate reports honestly on the ones it can — and a row whose
evidence depends on a `NOT_RUN` gate is `BLOCKED` in `BLOCKED_ROWS.json`, not
`PASS`.

CI: `.github/workflows/stream-gates.yml` runs the same script on `macos-latest`
and `ubuntu-latest`. **The ubuntu job is what will close the Linux halves the
first time this fork is pushed to a remote with Actions enabled.** No upstream
workflow was modified.

---

## 6. Row status summary

Authoritative source: `BLOCKED_ROWS.json`. **All 20 rows PASS**, verified in CI
at the branch tip on both platforms (run `32058841453`):

```
ubuntu-latest   14 PASS  0 FAIL  1 NOT_RUN   (macOS-only target; its Linux half passed)
macos-latest    13 PASS  0 FAIL  2 NOT_RUN   (the two Linux gates, on a Docker-less host)
```

No row is BLOCKED. The Linux execution blocker that once held seven rows is
cleared: verification runs on every push and depends on no developer machine.

Running on Linux for the first time, and on macOS 26 for the first time, found
five real defects that the development host could never surface — all fixed,
each with a test that fails when its guard is removed:

| Defect | Only visible on |
|---|---|
| A dead client held the session's client slot, breaking caller-death reattach | Linux (macOS passed by timing luck) |
| Terminal backpressure starved control traffic from any client, so a run that ignored its stdin could stop the supervisor answering `Hello` | Linux (present on macOS, hidden by buffer sizes) |
| 100%-CPU supervisor spin on a finished terminal (`POLLHUP` on a zero-interest entry) | Linux |
| A second client silently overwritten instead of refused during an in-flight request | either, once looked for |
| Directory-only Landlock rights silently masked away when requested on a file | Linux |

## 7. Fork deltas

Eleven rows, one per slice, each with files, upstreaming disposition and deletion
condition in `NONO_UPSTREAM_DELTA.md` §4.

- **F1/F1b** *(upstream-suitable)* — BSD-grep trailing-slash portability fix in
  two scripts; `ENV_LOCK` acquisition in four flaky tests.
- **F2** *(fork-only)* — the stream's process artifacts.
- **F3–F10** *(fork substrate)* — `crates/nono/src/lifecycle/`: pure typed
  skeleton, OS-backed prepare/activate/wait, loom core, cleanup verification,
  durable session store, support report + event vocabulary, detached supervisor,
  supervisor-owned PTY.
- **F11** *(upstream-suitable candidate)* — `crates/nono/src/capability_modes/`,
  the mode vocabulary and its two platform mappings.

---

## 8. Remaining external blockers

**None.**

Linux verification runs on every push, on a real kernel, via the fork's own
`stream-gates` workflow (`.github/workflows/stream-gates.yml`, `ubuntu-latest`
job). It does not depend on this or any developer machine.

> **Reproduce:**
> ```
> gh run list  --repo gauransh/nono --branch parallel/nono-substrate-v1
> gh run view <id> --repo gauransh/nono --log
> ```

**Result at the branch tip (run `32058841453`):**

```
ubuntu-latest    gates: 14 PASS  0 FAIL  1 NOT_RUN
  linux-landlock-live   129 passed / 0 failed
  linux-lifecycle-live   56 passed / 0 failed / 1 ignored
  workspace-tests      3769 passed / 0 failed
  miri-pure-lifecycle    56 passed / 0 failed
macos-latest     gates: 13 PASS  0 FAIL  2 NOT_RUN
  lifecycle-modes-live   14 passed / 0 failed      (macOS 26.5.2)
  lifecycle-detached     31 passed / 0 failed
```

Every `NOT_RUN` names the capability its host lacks and is never counted as a
pass: on Linux it is the macOS-only Seatbelt mode matrix (whose Linux half,
`linux-landlock-live`, passed); on macOS it is the two Linux gates.

**Local Docker on the development machine remains wedged** (backend process
runs, no daemon socket; `docker desktop status` cannot reach it while `docker
desktop start` reports it already running; the disk is also near full). This is
a convenience gap only — it is no longer on the path to Linux verification, and
`scripts/stream-gates.sh` reports the two Linux gates honestly as `NOT_RUN` with
the operator action when run on a Docker-less macOS host.

### 8.1 A note for whoever ports this further

Two of the five defects CI found were invisible on the development platform for
the same structural reason: **macOS and Linux disagree about what a poll on a
descriptor nobody is interested in means, and about how much a socket or pty
will buffer before it pushes back.** A supervisor written and tested on one of
them will encode the other's timing as an assumption without anyone noticing.
Run the `ubuntu-latest` job before believing any change to `supervisor.rs`,
`terminal.rs`, or `prepare.rs` — a green macOS suite is not evidence for those
files.

## 9. Integration instructions for leash-rs

### 9.1 Pin

```toml
[dependencies]
nono = { git = "https://github.com/gauransh/nono", rev = "<tip of parallel/nono-substrate-v1>" }
```

Read the tip rather than copying a SHA out of this file:

```
git ls-remote https://github.com/gauransh/nono parallel/nono-substrate-v1
```

A path dependency on a local checkout also works for development.

**Pin by `rev`, never by `branch`.** A branch pin means the substrate under your
sandbox can change without your lockfile moving.

Headless or container consumers that do not want an OS keyring:

```toml
nono = { path = "../nono", default-features = false }
```

### 9.2 The one line you must add

```rust
fn main() {
    nono::lifecycle::supervisor_entry();   // MUST be the first statement
    // ... your program, unchanged ...
}
```

It returns immediately and does nothing in every ordinary run. It matters because
a library has no binary of its own to re-execute and cannot fork a long-running
supervisor out of a threaded caller (allocator locks held by threads that no
longer exist; the macOS ObjC runtime aborts outright). **The supervisor *is* your
binary, re-executed**, and that call is how it recognises itself.

Without it, `SessionStore::prepare_detached` fails closed at a 20-second
readiness deadline with `PrepareError::SupervisorUnresponsive`, **whose message
names this function**.

"First statement" is a hard requirement: the call removes a private environment
marker (§4.4), which is sound only while the process is single-threaded.

### 9.3 The flow

```rust
use nono::lifecycle::{SandboxPlan, SessionMode, SessionStore, WindowSize};
use nono::{CapabilitySet, FsMode, FsModeSet};

// 1. PLAN — nothing forks until validate() succeeds.
let plan = SandboxPlan::new("/usr/bin/my-tool")
    .args(["--flag", untrusted_arg])       // literal: there is no shell
    .env("PATH", "/usr/bin:/bin")
    .working_dir("/absolute/path")
    .capabilities(caps)
    .validate()?;                          // -> ValidatedPlan

// 2. PREPARE — forks, applies the sandbox, sweeps descriptors, HOLDS.
//    The customer program has not started. Nothing of yours is reachable by it.
let (prepared, handle) = PreparedSandbox::prepare(plan)?;

// ... your authorization decision happens HERE, on your side, in your terms ...

// 3. ACTIVATE — single-use. A replay is AlreadyActivated; a stop makes it
//    refuse forever; an expiry refuses even a correct token.
let activated = prepared.activate(&handle)?;

// 4. WAIT — typed facts, verbatim from waitpid.
let exit = activated.wait()?;
match exit.outcome() {
    ExitOutcome::Exited { code }     => { /* the program's own code */ }
    ExitOutcome::Signaled { signal } => { /* never 128 + n */ }
    ExitOutcome::PreExecFailure { stage, errno } => { /* never a customer code */ }
    ExitOutcome::GateAborted         => { /* stop or expiry, never Exited{1} */ }
    ExitOutcome::SupervisorFailure { .. } => { /* the reap itself failed */ }
}

// 5. CLEANUP VERIFY — four answers, and a sent signal is never a basis.
match activated.verify_cleanup()? {
    CleanupVerification::ConfirmedAbsent { basis }  => { /* proven gone */ }
    CleanupVerification::StillPresent { survivors } => { /* honest: something is left */ }
    CleanupVerification::Indeterminate { reason }   => { /* NOT a proof of absence */ }
    CleanupVerification::Unsupported { reason }     => { /* stated, not inferred */ }
}
```

**Detached and interactive**, when the run must outlive the process that started
it:

```rust
let store = SessionStore::open(state_dir)?;             // 0700, checked not repaired

let plan = SandboxPlan::new("/bin/sh")
    .args(["-i"])
    .session_mode(SessionMode::Interactive)             // requires .detached(true)
    .detached(true)
    .capabilities(caps)
    .validate()?;

let (session, handle) = store.prepare_detached(plan)?;  // needs §9.2's line

// Attach BEFORE activating: the window size has to reach the terminal before
// the program starts, or a program that reads its size at startup reads the
// zeroes a fresh PTY carries.
let mut term = session.attach(WindowSize::new(40, 100))?;
term.activate(&handle)?;
term.write_input(b"echo hello\n")?;
match term.read_event(deadline)? {
    TerminalEvent::Output(bytes) => { /* ... */ }
    TerminalEvent::Ended(end)    => { /* end.exit() is the typed SandboxExit */ }
    TerminalEvent::Idle          => { /* a quiet terminal is a fact */ }
    TerminalEvent::Pong          => { /* ... */ }
}
term.detach()?;              // the run carries on
// ... your process restarts ...
let store = SessionStore::open(state_dir)?;
match store.recover(session_id)? {
    RecoveryDecision::Attachable      => { let s = store.attach_control(session_id)?; }
    RecoveryDecision::AlreadyVerified => { /* terminal; never re-adopt */ }
    RecoveryDecision::ProcessGone { basis }  => { /* ... */ }
    RecoveryDecision::StillRunning { survivors } => { /* ... */ }
    RecoveryDecision::Unsettled { reason } | RecoveryDecision::Unsupported { reason } => { }
}
```

### 9.4 Boundary rules — what stays on your side

**The library provides mechanics and never meaning.** These stay in leash-rs and
must not migrate into the fork (`BLOCKED_ROWS.json` R15 is the standing grep
guard, and it is re-run at every gate):

- CrystalOS / HCP / Cedar / Leash policy types and evaluation.
- What an activation *authorizes* — the library gives you a start button for a
  held child, not an authorization decision.
- Event forwarding, aggregation, retention and interpretation. `EventSink` is
  caller-side by design.
- Any product concept in a session record. The record deliberately carries no
  command line and no environment: a record that carried the run's argv would be
  a durable copy of whatever secrets it held.

### 9.5 The activation token

`ActivationHandle::token()` is public. It has to be — the process that activates
a detached run is very often not the one that prepared it, and the library cannot
transport bytes for you.

The library never puts those bytes in an argv, an environment, a log, a `Debug`
impl, an event or a record. **Where you put them is your decision, and it is a
security decision.** They are a start button for a held child.

### 9.6 Process-exec scoping — read this before adopting modes

**One behaviour change, scoped precisely to opt-in callers.**

A capability set that uses only `allow_path` / `allow_file` compiles to exactly
what it compiled to before, byte for byte, **including macOS's unconditional
`(allow process-exec*)`**. Every existing consumer is unaffected.

A capability set carrying **at least one** mode grant gets
`(allow process-exec* (<filter>))` per `execute`-granted path instead of the
blanket grant. A program in a directory granted only `read_contents` is then
refused at `execve` with
`ActivationError::PreExecFailed { stage: Exec, errno: EPERM }`.

**So a consumer that adopts the mode vocabulary must grant `execute` on the paths
its program *and its interpreters* live in.** The live tests use `/bin`, `/usr`,
`/System`, `/private/var/db`. `process-exec*` rather than `process-exec` is
deliberate, so a `#!` program whose interpreter is granted still runs.

Two more things to plan around:

1. **`read_metadata` is `unrestrictable` on Linux.** Landlock has no right
   covering `stat(2)`, so a metadata-only grant is a no-op there and a metadata
   *denial* cannot be expressed at all. Check `SupportReport::fs_modes()` rather
   than assuming parity.
2. **`truncate` needs ABI ≥ 3 and `rename` (so `atomic_write`) needs ABI ≥ 2.**
   Below those the grant is **refused**, not degraded — because on those kernels
   the operation is not restrictable at all, and a rule that compiled to nothing
   would read as enforcement.

Read the compilation before you apply it:

```rust
for compiled in Sandbox::compile_fs_modes(&caps)? {
    compiled.enforced();        // what the platform will actually enforce
    compiled.bundled();         // modes you did NOT ask for that this grant confers anyway
    compiled.always_allowed();  // the platform cannot restrict this — an ABSENCE of
                                // enforcement, not a denial
    compiled.refused();         // fails prepare with NonoError::ModeUnsupported
    compiled.delegated();       // enforced, by another mechanism (UnixSocketCapability)
}
```

It is the **same** compilation the profile or ruleset is built from, so the
disclosure and the enforcement cannot disagree.

### 9.6b macOS 26 evaluates inherited descriptors — plan your child's stdio

Found live on the `macos-latest` runner (macOS 26.5.2 / Darwin 25.5.0), and it
reaches real callers, not just tests.

**macOS 26 evaluates `file-read-metadata` when a confined process `fstat`s a
descriptor it merely *inherited*. macOS 14 does not evaluate it at all.**

So a sandboxed child whose stdout you redirect to a file the profile does not
name will see `Operation not permitted` from `fstat(1)` — even though nothing
about the file it is actually reading or writing is denied. This is not
hypothetical: it is how `cat(1)` fails, because `raw_cat` sizes its copy buffer
from `fstat(fileno(stdout))` and dies with `cat: stdout: Operation not
permitted` while holding a perfectly good read. Any tool that stats its own
standard streams behaves the same way — and the failure names *stdout*, not the
file you were debugging, which is what makes it expensive to diagnose.

What this means for you:

- If you hand a sandboxed run a stdout/stderr that is a **file**, grant
  `read_metadata` on that path (`allow_path_modes`) or accept that
  metadata-stating tools will fail there on macOS 26.
- Pipes and PTYs are unaffected in what we observed; the detached supervisor's
  interactive path gives the child a PTY, and the headless detached path gives
  it `/dev/null`.
- **Nono does not do this for you.** The library emits no grant for the child's
  inherited standard streams, by either the mode-aware or the coarse
  `AccessMode` emitter. Emitting one would be a real widening of every profile,
  so it is a policy decision that belongs on your side of the boundary (§9.4) —
  and if you decide the substrate should do it, it must arrive as a disclosed
  bundle in `CompiledModes`, never silently.

The coarse-emitter half of that last point is inferred from reading the emitter,
not observed live; the mode-aware half was observed on the runner.

### 9.7 `LifecycleEvent` is a struct, not an enum

**API shape note for anyone porting from an early iteration.** `LifecycleEvent`
was an enum through iteration 6 and is now an **envelope struct**:

```rust
pub struct LifecycleEvent {
    session_id: Option<Uuid>,   // Some in practice
    generation: u64,
    seq: u64,                   // THE ordering authority
    observed_at: SystemTime,    // explicitly NOT the ordering authority — a wall clock can step
    identity: Option<ProcessIdentity>,
    observation: Observation,   // Direct vs Reconstructed
    what: LifecycleEventKind,
}
```

`LifecycleEvent::StateChanged { from, to, observation }` is now
`LifecycleEventKind::StateChanged { from, to }`, reached via `event.what()`, with
`observation` on the envelope. **A consumer that matched the old enum matches
`event.what()` instead.** No other public type changed shape.

`seq` counts a run's events from zero and is unbroken across the
prepared → activated handoff. Events the platform cannot show **do not exist in
the vocabulary** — there is no kernel-denial variant to synthesize one into.

---

## 10. Known incompatibilities and stated limits

Nothing here is a bug report. Each is a limit that is disclosed rather than
discovered.

1. **No Linux verification.** See §8. Every Linux-facing claim in this document
   should be read as "this is what the code intends" until the `ubuntu-latest`
   job has been green once.
2. **Generations are always 1.** Re-prepare into an existing session's slot with
   an incremented generation was scoped for R09 and did not land. The field, the
   wire checks on both sides and the record column all exist and are exercised;
   nothing increments them.
3. **A headless detached run's standard streams are `/dev/null`.** A supervisor
   holding its launcher's terminal or pipes would keep them open after the
   launcher exited, which is the thing detachment is for. Output comes back via
   the PTY path (§9.3), not from a headless run.
4. **One viewer at a time.** Attach occupies the supervisor's single client slot;
   a second connection is refused `ControlRefusal::Busy`. There is deliberately
   no separate "already attached" answer, because a second attach cannot reach
   the supervisor to be refused.
5. **Scrollback is bounded and lossy, and says so.** 256 KiB oldest-dropped ring;
   `AttachAck::dropped()` is how many bytes were lost. Output already handed to a
   client and not consumed is **not** replayed — the ring covers from the detach
   onwards.
6. **A stalled client is dropped; the run is not.** After a 10-second stall the
   client goes, output returns to the ring, and the run carries on.
7. **A stop hangs the terminal up**, so a stopped interactive run may be observed
   as `Signaled { SIGHUP }` rather than `SIGKILL`. This is not cosmetic: a
   session leader holding a controlling terminal cannot finish exiting until that
   terminal has drained, and the process that would drain it is the one about to
   block in `waitpid`. The exit reports what was seen, as always.
8. **`ExecOrKilledPreExec` is genuinely ambiguous.** A child killed between the
   gate release and `execve` closes its status descriptor exactly as a successful
   exec does. Reported as a third value, never collapsed to a bool.
9. **A descendant that calls `setsid` escapes the process group** and is
   invisible to both `stop` and cleanup verification. Closing it needs a
   cgroup-class mechanism this stream does not build.
10. **Process-group ids are reusable after the reap.** A later group hit is
    reported as "something is in that group", mitigated but not eliminated by the
    boot-id re-check.
11. **Gate expiry freezes while the machine sleeps.** The deadline is measured
    with `Instant`, which does not advance across suspend; and expiry is
    evaluated *lazily*, at the next operation, so an abandoned never-activated
    detached session holds its supervisor until something asks.
12. **Same-uid is not a boundary.** Peer-UID checks and 0700/0600 permissions
    keep *other* users out. A hostile process running as the same uid can read
    the store, connect to the socket legitimately, and `ptrace` its peers. See
    `THREAT_MODEL.md` §3.
13. **macOS `killpg` answers `EPERM`, not `ESRCH`,** for a process group whose
    every member is already a zombie. `ActivatedSandbox::{stop, drop}` read that
    as "nothing left to signal" — **and only there**, where the group id is an
    unreaped child's own pid and so cannot have been reissued.
    `RecoveredSession::kill_group` keeps the strict reading, because its recorded
    group id may well have been.
14. **Darwin `TIOC*` constants are hand-carried** in `lifecycle/terminal.rs`
    because `libc` declares none for Apple targets. A unit test recomputes all
    three from the BSD `_IOC` encoding rule, so a transposed digit fails there
    rather than as an `ENOTTY` at the point of use.
15. **The sandbox-extension path is not mode-aware.** `sandbox_extension_consume`
    and its three filter rules are untouched by F11; the mode vocabulary does not
    describe what a consumed token widens.
16. **A byte-for-byte copy of a macOS platform binary cannot be `execve`d at
    all** on a recent macOS — the kernel `SIGKILL`s it (exit 137) over the trust
    cache, and `codesign --force --sign -` does not change that. This bit the
    live test fixtures and is recorded so it does not bite an integrator who
    assumes a sandbox denial.

---

## 11. Proposed upstream PRs

Full procedure, ordering rationale and compliance steps in
**`docs/UPSTREAMING.md`**. Summary:

| Order | Delta | Why here |
|---|---|---|
| 1 | **F1/F1b** — portability + test hygiene | Smallest, independent, a bug fix for maintainers on macOS, evidence is a failure rate (16/20 → 0/20) rather than an argument. |
| 2 | **F11** — mode-aware fs capability vocabulary | Answers a gap upstream documents in its own words; adds no dependency; changes no existing behaviour. **Do not open until the ubuntu job is green** — its Linux half has never run. |
| 3 | **The lifecycle (F3–F10)** — **RFC first, PR second** | ~15 modules, a staged model upstream does not have, and one line of embedder cooperation in `main`. That is a design conversation, not a diff. `SupportReport` (part of F8) is adoptable alone and may be worth proposing first if the larger conversation stalls. |
| never | **F2** + gate tooling | Process artifacts. Strip list in `docs/UPSTREAMING.md` §6.1. |

**Hard stop, quoted from upstream `AGENTS.md`:** an agent *must not* open a pull
request if "an issue does not already exist for the proposed change". **No issue
exists upstream for F1, F11 or the lifecycle.** Every one of them is currently
under that hard stop. Holding the work locally is not a contribution attempt and
is not prohibited; filing the issues is an operator decision.
