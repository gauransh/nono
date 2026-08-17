# WORKLOG — parallel/nono-substrate-v1

Run ID: EF1A07E7-A38C-4C5E-98CA-9444CA7CFD5C
Base: nolabs-ai/nono @ 149579a7b0753ee413680169fa937eea82da46a0

## 2026-08-17 — Iteration 1: source lock + discovery

- Resolved and froze source lock (see SOURCE_LOCK.json).
- Cloned upstream at pinned SHA; created branch `parallel/nono-substrate-v1`.
- Started upstream baseline: `cargo test --workspace --no-fail-fast` on macOS host.
- Launched 8-way parallel discovery over: public API, lifecycle/exec path,
  Linux substrate (Landlock/seccomp), macOS substrate (Seatbelt),
  supervisor/session/PTY/IPC, events/support-report, consumer usage in
  itsm-sandbox-policy-engine, test/CI inventory.
- Pending: acceptance-row matrix derivation, NONO_UPSTREAM_DELTA.md,
  API_BASELINE.md, PLATFORM_CAPABILITY_BASELINE.md, THREAT_MODEL.md.

## 2026-08-17 — Iteration 1 (cont.): discovery synthesis

- Baseline run completed: 3409 passed / 3 failed / 1 ignored on macOS host. All 3
  failures are macOS-host-only upstream portability bugs (BSD-grep trailing slash in
  scripts/test-list-aliases.sh + scripts/lint-docs.sh; /private/var temp state root vs
  system_read_macos overlap guard in command_runtime dry-run test). Fix in progress
  as delta F1 (upstream-suitable).
- 8/8 discovery readers returned (1.11M subagent tokens, 292 tool uses). Synthesized:
  API_BASELINE.md, PLATFORM_CAPABILITY_BASELINE.md, NONO_UPSTREAM_DELTA.md,
  THREAT_MODEL.md, CONTRACT_ASSUMPTIONS.md, BLOCKED_ROWS.json (R01-R20 matrix).
- Headline findings: no lifecycle/activation/exit/cleanup types exist anywhere in the
  library (all net-new work in crates/nono); session/PTY/attach machinery is real but
  CLI-crate-private; no `wait` operation exists at all; no loom/miri/fuzz infra;
  SupportInfo is the single-boolean anti-pattern; macOS support_info hardcodes true;
  macOS denials are log-stream reconstruction; run_stop SIGKILL path treats signal as
  proof; SessionRecord has no schema version; AccessMode is 3-valued with disclosed
  bundling; consumer repo consumes nono only via CLI on an unmerged branch (R14's
  anti-goal) and pins nothing.

## 2026-08-17 — Iteration 1 (close): R01 green + ADR-0001

- F1 landed: dropped trailing slash on 4 `grep -R` dir args (BSD grep `crates//`
  output defeated allowlist regexes in scripts/test-list-aliases.sh + lint-docs.sh).
- F1 landed: ENV_LOCK guard in command_runtime dry-run test (ambient-$HOME read raced
  env-mutating siblings; 16/20 macOS failures -> 0/20).
- F1b landed: same ENV_LOCK guard in 3 tool-sandbox/dynamic_providers git tests
  (PATH stub race; 7/20 baseline flake -> 0/20 across full-binary 20x stress).
- Gates: workspace tests 3412/0/1 green x5; clippy clean; fmt clean; both scripts exit 0.
- R01 -> PASS in BLOCKED_ROWS.json. ADR-0001 (generic lifecycle architecture) written.
- HANDOFF.md v1 created. Committing: (1) fix(tests) F1/F1b, (2) docs(stream) artifacts.
- Residual (recorded, not acted on): ENV_LOCK discipline is unenforced by lint; upstream
  issue #567 is the proper fix. Docker daemon still down (Linux gate env pending).

## 2026-08-17 — Iteration 2: R02 lifecycle skeleton (delta F3)

- crates/nono/src/lifecycle/ landed: state.rs (10x11 pure transition machine,
  exhaustive matrix test, single-use/stop-blocks-activation/one-death-one-fact
  refusals test-locked), plan.rs (SandboxPlan -> ValidatedPlan typestate, full
  validation, secrets-redacting Debug), events.rs (EventSink + Observation
  fidelity), LifecycleError -> NonoError::Lifecycle (+forced FFI map_error arm).
- Design decisions accepted on review: network_mode writes through to
  CapabilitySet (single authority); lifecycle::ResourceLimits not re-exported at
  root (name collision with cgroup type — revisit before ossification);
  working_dir optional (None = inherit); duplicate env keys allowed for now.
- Gates: 45+2 new tests; workspace 3459/0/1; strict clippy clean; fmt clean;
  lint scripts green.
- Environment: disk hit 100% during builds (ld errno=28); target/debug/incremental
  purged twice + CARGO_INCREMENTAL=0 for final gate. Host cleanup pass required
  before next build-heavy iteration.

## 2026-08-17 — Iteration 3: R03/R04/R10 gate + prepare + typed exit (delta F4)

- Host cleanup: deleted agent-resource-observatory/target (39 GiB regenerable cargo
  cache, CACHEDIR.TAG verified); disk 1.5 GiB -> 39 GiB free.
- Landed prepare.rs/gate.rs/exit.rs/identity.rs + lifecycle_live.rs: fork ->
  sandbox-in-child -> fd sweep -> gate hold -> nonce release -> execve; 5-byte
  status records; positive-exec observation; typed SandboxExit; ProcessIdentity
  (pid+start_time+boot_id); Drop = abort+SIGKILL+reap.
- Independent adversarial review (architect): ship-with-fixes. 2 HIGH (child fd
  inheritance until exec; forgeable constant release byte), 4 MEDIUM (EOF=exec
  overclaim; finish_failed reap-without-kill + fact fabrication; stop/expiry
  sentinel-as-outcome; event sink unwired), 5 LOW. ALL applied same iteration:
  close_inherited_descriptors sweep (removal-detection-verified live test),
  random 16-byte release/abort nonces (ct classify), three-valued
  ActivationObservation (bool accessor removed), kill_and_reap_observed,
  GateAborted outcomes, sink threaded through wait(), token post-fork
  parent-only, DuplicateEnvKey hoisted to validate().
- Gates: lifecycle 96 unit + 16 live (10x consecutive clean); workspace
  3527/0/1; strict clippy clean; fmt clean; lint scripts green.
- Known residuals: no deadline on blocking reads (SIGSTOPped child blocks
  supervisor — supervisor slice); Linux path compiled-unverified (Docker blocker
  recorded in R07 note; cross-compile dead-ends at aws-lc-sys needing
  x86_64-linux-gnu-gcc).

## 2026-08-17 — Iteration 4: R05 Loom race harness (delta F5)

- lifecycle/sync_core.rs: SharedLifecycle — one Mutex owns LifecycleState +
  three-valued GateEffect (Open/ClosedToActivation/Spent); try_begin_activate
  runs the release effect inside the critical section; begin_stop reserves the
  abort write (so expiry still emits GateAborted); claim_gate_close once-only.
  PreparedSandbox/ActivatedSandbox rewired; zero public-API change; 96 existing
  unit + 16 live tests pass unmodified.
- 5 Loom models exhaust interleavings (activate x2, activate-vs-stop,
  death-vs-stop, supervisor-lost-vs-activate, cleanup x2). Bug-detection
  demonstrated: weakened CAS -> 3/5 models fail; restored -> green.
- cfg is `nono_loom` (RUSTFLAGS --cfg loom breaks tokio/hyper-util transitively);
  loom is a cfg-gated dependency, not an unconditional dev-dep.
- Gates: 109 unit + 16 live x3; workspace 3540/0/1 x2; strict clippy clean (also
  under nono_loom); fmt clean; lint scripts green; loom gate 5/5.
- Disk pressure recurred (~950 MiB free): parallel streams' builds; cleanup pass
  before next slice.

## 2026-08-17 — Iteration 5: R11 typed cleanup verification (delta F6)

- Foundation: child calls `setpgid(0, 0)` right after closing the parent's
  channel ends, so the run is a process group and not just a pid; failure is the
  new typed `PreExecStage::ProcessGroup` (tag 0x0F) through the existing status
  record. Parent records the pgid (== child pid, made true before the "at the
  gate" record is written).
- lifecycle/cleanup.rs: `CleanupVerification` (closed enum) with typed evidence —
  reaped runs probe `kill(-pgid, 0)`, unobserved deaths probe the identity. A
  sent signal is never a basis; `is_same_process` deliberately not reused (its
  fail-closed `false` would become a proof of absence). Decisions recorded:
  boot-id change ⇒ `ConfirmedAbsent{BootIdChanged}` (a reboot destroys every
  process; "Indeterminate" would be false modesty); pgid-reuse-after-reap caveat
  kept visible in the type's docs and mitigated by the boot re-check; targets ≤ 1
  refused before any syscall so a corrupt record cannot aim at the supervisor's
  own group.
- API: `ActivatedSandbox::{stop, verify_cleanup}`, `PreparedSandbox::verify_cleanup`,
  `CleanupError`, `StopError::SignalFailed`. Only `ConfirmedAbsent` records
  `CleanupConfirmed`; `StillPresent`/`Indeterminate` leave the state alone, and a
  duplicate verification is refused by the state machine (matrix already locked
  it). `stop()` kills the group *and* the child pid — a descendant that called
  `setsid` would otherwise leave the reap waiting forever.
- Gates: 126 unit (17 new) + 21 live (5 new) x3; loom 5/5 unchanged; workspace
  3562/0/1; strict clippy clean; fmt clean; lint scripts green.
- Removal detection: deleting the `setpgid` line fails the group test and makes
  the survivor test report `ConfirmedAbsent` while `/bin/sleep 30` still runs —
  the exact dishonesty the group discipline exists to prevent. Restored green.
- Known dark spot (documented in prepare.rs, not silently accepted): a descendant
  that calls `setsid`/`setpgid` leaves the group and is invisible to both stop and
  verification; closing it needs a cgroup-class mechanism. Second consequence: a
  terminal's Ctrl-C no longer reaches the run by accident.
- Residual: `ActivatedSandbox`'s drop path still kills only the child pid, not the
  group (unchanged from F4); a consumer that drops a running handle can leave
  descendants behind. Candidate for the supervisor slice.

## 2026-08-17 — Iteration 6: R09 slice A durable session store (delta F7)

- lifecycle/session_store.rs: `SessionRecord` v1 — `schema_version` (const
  `CURRENT_SCHEMA_VERSION = 1`), session UUIDv7, generation, `ProcessIdentity`,
  process group, `LifecycleState`, optional `ActivationObservation`,
  created/updated wall timestamps (`Option<u64>` ms — `None` when the clock will
  not say; advisory, nothing decides on them), and a bounded copy of the plan's
  opaque caller metadata. Nothing product-shaped, and deliberately no command
  line or environment: a record that carried the run's argv would be a durable
  copy of whatever secrets it held.
- Storage: directory created-or-opened at 0700 and *checked* rather than
  repaired (real directory / owned by the effective uid / no group-or-world
  bits, each a typed refusal — quietly `chmod`ing someone else's directory would
  hide that it had been readable). Opened once `O_DIRECTORY | O_NOFOLLOW`; every
  record reached by `openat` against that descriptor, so nothing after the first
  open re-walks the path. Records `<uuid>.json` at 0600 (explicit `fchmod`,
  because `O_CREAT`'s mode is filtered through the umask), first write `O_EXCL`,
  updates write-to-temp + `renameat` in the same directory, `fsync` file then
  directory. Record names derive from the UUID and are round-trip checked, so a
  name can never carry a separator or a second spelling.
- Corruption is an answer: `SessionCorrupt{path, why}`, never `Default` and
  never a skipped entry. `sessions()` yields one `Result` per record so a
  corrupt one is reported *beside* its healthy siblings — the opposite of the
  CLI store's `debug!`-and-skip. A foreign schema is found by a version probe
  that reads that one field before the rest, so a newer writer is
  `UnsupportedSchemaVersion` rather than a field-by-field guess.
- Durable prepare: `SessionStore::prepare(plan)` = `PreparedSandbox::prepare`
  plus a record written *after* the gate-ready observation, when the identity and
  pgid are facts. The record travels by `Arc` into the `ActivatedSandbox` and is
  updated at every transition — always outside the `SharedLifecycle` lock and
  always after the change. **Honesty consequence, documented not hidden: the
  record can lag the live state by one step.** Reconciliation-on-load is what
  makes that safe. Ephemeral `PreparedSandbox::prepare` is untouched: no store,
  no file, no behaviour change.
- Recovery: `recover(id)` loads, probes the recorded identity, and reduces
  `(recorded state, verdict)` through the pure `reconcile()` to a
  `RecoveryDecision`. Decision table: a record already `cleanup_verified` is
  `AlreadyVerified` **whatever the probe says** (a proven-absent pid can be
  reissued; adopting the reissue is the failure this rule exists to prevent);
  otherwise `ConfirmedAbsent → ProcessGone`, `StillPresent → StillRunning`,
  `Indeterminate → Unsettled`, `Unsupported → Unsupported`. A record found in a
  watched state is moved to `Failed` with `SupervisorLost` and persisted — the
  supervisor that would have observed the rest of that run is, by the fact that
  we are recovering, gone.
- **Limitation reported rather than designed away:** a recovered process is not
  this process's child, so `waitpid` cannot reach it and its exit code or signal
  is unobservable. `RecoveredSession` therefore has no `wait`, returns no
  `SandboxExit`, and has no `Drop` that kills anything. What it offers is
  `kill_group`/`kill_pid` (same `targets <= 1` refusal as `stop`) and
  `verify_cleanup` / `verify_cleanup_by(deadline)`, which polls until the kernel
  says `ESRCH` instead of treating a sent signal as proof. Making exit facts
  survive a restart needs the detached supervisor of slice B.
- Generations stay at 1. Sessions are one-shot UUIDs; recover-then-cleanup bumps
  nothing and nothing re-prepares into an existing slot. The field is kept
  because the re-prepare flow that increments it is slice B, and a record shape
  that grew a field then would break every record written before it.
- F6 follow-up: `ActivatedSandbox::drop` now kills the process **group** before
  the pid and the reap, so "let it go out of scope" is no longer a quietly
  weaker guarantee than calling `stop()`.
- Loom (completes R05 scenario 6): 2 models added, 7 total — a recovery
  reconciling while another party confirms the same cleanup (exactly one
  `CleanupConfirmed` winner, and a recovery that sees the cleanup already proven
  records nothing), and a recovery racing a stop-then-cleanup (never adopt after
  cleanup). The recovery's read-decide-record is deliberately *not* one critical
  section — `reconcile` is pure over an already-read state — and these models are
  what say that gap is safe.
- Gates: 153 unit (126 + 27 new) + 23 live (21 + 2 new) x3; loom 7/7; workspace
  3591/0/1, 33 suites; strict clippy clean (also under `nono_loom`); fmt clean;
  both lint scripts exit 0.
- Removal detection (each restored to green afterwards): dropping `O_NOFOLLOW`
  from the record open makes the symlinked-record test *pass the load* and
  return the decoy (`left: None`); dropping it from the store-directory open
  lands the store on the link's 0755 target (`StorePermissions{mode: 493}`
  instead of `StoreSymlink`); making enumeration skip what it cannot parse turns
  4 accounted-for records into 1; deleting the schema-version check reads a
  version-2 record as if it were version 1; deleting the directory permission
  check accepts a 0755 store. The explicit record `fchmod` is deliberately NOT
  claimed as a detectable guard: umask can only *remove* bits from `O_CREAT`'s
  0600, so its removal cannot widen a record — it makes the stated mode exact
  rather than umask-dependent, and any umask restrictive enough to demonstrate
  it also stops the test from creating its own directories.
- Not tested, and named as such: the foreign-owner refusal
  (`StoreForeignOwner`). Planting a directory owned by another uid needs
  privileges the test suite does not have; the code path is one `st_uid`
  comparison beside the permission check that *is* removal-detected.

## 2026-08-17 — Iteration 7: R12 support report + R13 event vocabulary (delta F8)

- R12, `lifecycle/support.rs` (new: 1630 lines of module + a 533-line test module
  whose bulk is the hand-built golden report): `SupportReport::gather()`,
  infallible, returning a tree of `Capability<T>` instead of a boolean. Every
  capability carries three things a `bool` cannot: a four-valued `SupportStatus`
  (`available`/`partial`/`unavailable`/**`unknown`**), a `Determination` saying
  *how* we know (`probed_live` / `platform_api` / `declared`), and a typed
  `SupportReason`. **The contract is locked structurally, not by review:** a test
  walks the serialized `serde_json::Value` and rejects `Value::Bool` at any
  depth.
- The two honesty calls worth recording, because both could have been quietly
  rounded up:
  - **macOS Seatbelt is `platform_api`, not `probed_live`.** `sandbox_init` is
    linked, so its presence is a compile-time fact — but calling it sandboxes
    *the calling process*, permanently. There is no cheap live probe: a
    "trivial" profile is still process-wide, so the only honest one forks
    (which is what `nono setup --check-only` does, and that is CLI machinery).
    The rationale rides in `reason.why_not_probed` and a macOS test asserts it
    mentions the fork.
  - **Linux seccomp user-notification is `unknown`.** Establishing
    `SECCOMP_FILTER_FLAG_NEW_LISTENER` means installing a filter that cannot be
    removed from the process that installs it; upstream's fork-isolated probe
    covers only the static block-all filter, and inventing a second probe is a
    mechanism this slice was told not to add. A kernel release number is not
    proof either (`CONFIG_SECCOMP_FILTER` can be off). `unknown` with the reason
    is the answer; "no" would have been a guess in the safe-looking direction.
- Everything else is reuse, not new mechanism: Landlock's per-right table comes
  from upstream's own `Sandbox::detect_abi` + `DetectedAbi::has_*` (zero diff to
  `sandbox/*`), seccomp from upstream's `probe_seccomp_block_network_support`,
  and the cleanup probes from `cleanup::{probe_pid, probe_group}` (made
  `pub(crate)` so the report cannot drift from the mechanism it describes).
- Two shapes added deliberately to stop a misreading: `pty` (live
  `posix_openpt`, closed immediately) is **separate from**
  `interactive_session` (`not_implemented`), so `pty: available` cannot be read
  as "the lifecycle will give you one"; and `seatbelt_per_port_tcp` appears in
  the network table as an explicit `platform_cannot_express`, so its absence is
  stated rather than left to a reader's inference.
- `event_observation` reports `kernel_denial` as `not_observed` on **both**
  platforms. The lifecycle installs no seccomp-notify listener, macOS Seatbelt
  denials reach userspace only through the system log, and the CLI's
  `log stream` reconstruction is named in the report as *not* library
  machinery. `dark_spots` is the typed index of the four limits already recorded
  in the module docs, each pointing back at the file that records it.
- R13, `lifecycle/events.rs`: `LifecycleEvent` became an envelope
  (`session_id`, `generation`, `seq`, `observed_at`, `identity`, `observation`)
  around a closed `LifecycleEventKind` of 14 variants. `StateChanged` is kept —
  it is the fact existing consumers already act on — and the rest of the
  vocabulary was added at the points where the facts are observed.
  **API shape change, recorded in HANDOFF:** the type is now a struct, so a
  consumer matches `event.what()`.
- `seq` is owned by a crate-internal `EventEmitter` shared by `Arc` across the
  prepared→activated handoff, so a run is one unbroken sequence. Documented
  guarantee: **`seq` is the ordering authority and `observed_at` is not** — a
  wall clock can step, and a report that told a consumer to sort by it would be
  handing over an ordering the library cannot promise.
- `ActivationOutcome` names the check that refused and never the value that
  failed it. Locked by walking the serialized tree: no key named
  token/nonce/secret/digest, no array at any depth (every secret here is a
  `[u8; N]`), and no long alphanumeric run in either the serde or the `Debug`
  form.
- `SessionHandle::persist` was restructured to release the record mutex
  *before* emitting `RecordPersisted`. The write already happened outside the
  lifecycle lock; this closes the smaller version of the same rule — consumer
  code must not run under a library lock — and a write that failed emits
  nothing at all.
- Schema docs with golden examples, each locked by a snapshot test that reads
  the document itself (`include_str!` + the `## Golden example` block), so drift
  fails the build and the assertion names the doc path:
  `docs/lifecycle/{session-record,support-report,lifecycle-event}-v1.md`. The
  support-report example is deliberately a **macOS** capture-shaped value: no
  Linux example is published, because no Linux host has been observed on this
  stream and a hand-written Linux capture would be exactly the kind of claim
  this report exists to prevent.
- Gates: 181 unit (153 + 28) + 25 live (22 + 3) x3; loom 7/7 unchanged;
  workspace 3621/0/1, 33 suites; strict clippy clean (also under `nono_loom`);
  fmt clean; both lint scripts exit 0; no new dependency.
- Removal detection (each restored to green afterwards): adding one `bool` to
  `CleanupFacts` fails both no-bare-boolean tests and prints the JSON pointer
  `/cleanup_verification/facts/probes_work`; adding a `token_digest` field to an
  `ActivationOutcome` variant fails the token-material test with the offending
  JSON; giving `ActivatedSandbox` its own emitter instead of sharing the
  prepared one restarts `seq` at 0 mid-run (`left: 0, right: 9`) and fails both
  live sequence tests; changing `"seq": 4` to `"seq": 5` in the event schema doc
  fails that document's snapshot test.
- Not verified, and named as such: every Linux branch of `support.rs`
  (`gather_landlock`, `gather_seccomp`, `gather_seccomp_user_notification`, the
  Linux arm of `gather_network_filtering`) is written-unverified behind the R07
  Docker blocker. The macOS branches and all platform-independent machinery are
  live-verified on this host.

## 2026-08-17 — Iteration 8: R09 slice B detached supervisor (delta F9)

- Landed `docs/adr/0002-detached-supervisor.md` as the binding design and built
  it: `crates/nono/src/lifecycle/{supervisor,protocol,detached}.rs` plus schema
  v2 in `session_store.rs` and the adoption half of `prepare.rs`.
- **The shape of the thing, and why.** A library cannot re-exec "the nono
  binary" — it has none — and cannot fork a *long-running* supervisor out of a
  threaded caller: after `fork` only async-signal-safe calls are defined, and
  on macOS the Objective-C runtime aborts a forked child that touches it.
  ADR-0001's gate child survives fork only because it is syscall-only until
  `execve`. So the supervisor is **this binary re-executed**, and the embedder
  opts in with `nono::lifecycle::supervisor_entry()` as the first statement of
  `main`. That is one line of cooperation and it is stated in the API docs, the
  support report, HANDOFF, and the typed error a missing hook produces.
- **Two forks, and each is load-bearing for a different reason.** The second
  one is what makes a supervisor possible: `execve` replaces an image and not a
  process, so a customer child forked *before* the exec is still the child of
  the same pid afterwards, and `waitpid` reaches it. That single fact is why a
  detached run's exit facts are directly observed rather than inferred, and it
  is also why **nothing about the plan crosses the exec** — the policy, the
  argv and the environment are built and used on the launcher's side, so a
  `CapabilitySet` never has to be serialized and re-trusted.
  The first fork was added because a test found the hole: the supervisor was
  the launcher's own child, so a launcher that outlived it collected a zombie
  it cannot be expected to reap, and test (g) could not even observe the
  supervisor's death (`kill(pid, 0)` succeeds on a zombie). The launcher now
  forks an intermediate that forks the supervisor, names it on the handshake,
  and exits; the launcher reaps *that*, in a wait it knows will return.
- **The token got stronger, not weaker.** On the attached path the token is
  drawn after the fork so it never reaches the child; here it is drawn *in the
  supervisor, after the exec*, so it never exists in the customer child's
  address space at all. It comes back to the launcher on the private handshake.
  The gate's release/abort pair has to go the other way — the child was forked
  holding it — so it travels on a private bootstrap pipe and both sides zeroize
  the buffer it arrived in.
- **The bind race was removed rather than narrowed.** The launcher binds and
  listens before the fork and passes the *listening descriptor* through the
  exec, so "the supervisor reported ready" implies a socket that has been
  listening since before the supervisor existed. The alternative — the
  supervisor binds and the launcher retries a connect — has no upper bound and
  no way to tell "not yet" from "never".
- **Protocol v1** is length-prefixed frames with the 64 KiB bound checked *from
  the prefix, before a byte of body is read or allocated*; hello first in both
  directions; refusals that carry the module's own typed results rather than
  strings (which is why `ActivationError` and `StopError` gained serde);
  peer-uid checked at accept by reusing `supervisor::socket::peer_credentials`
  rather than writing a second one. Every read and write on both sides is
  `poll`-deadline-bounded, which closes ADR-0001's unbounded-read residual for
  this path.
- **Honest about events.** `EventSink` is caller-side by design, so a
  supervisor with no caller has nowhere to deliver to. Nothing was invented to
  paper over that: the supervisor keeps a bounded ring of 32 events in the
  record, oldest dropped, and says so in the constant, the schema doc, and the
  client module. A consumer that needs every event stays connected.
- **Honest about the record.** Schema v2 adds `supervisor`, `exit` and
  `events`. v1 compatibility is explicit rather than lenient: the version probe
  chooses between two `deny_unknown_fields` shapes, a v1 record is parsed as v1
  and upgraded *in memory* (absence reported, never invented), the file is not
  touched until something writes it, and a version neither shape implements is
  still refused. `docs/lifecycle/session-record-v1.md` is now both the
  historical schema and the compatibility test's fixture.
- **Honest about recovery.** `reconcile` gained a third pure input,
  `SupervisorPresence`, and a `RecoveryDecision::Attachable` that outranks every
  child probe but *not* `AlreadyVerified` — a proven cleanup stays terminal. An
  attachable record is deliberately **not** moved to `Failed`: the live
  supervisor owns it, and overwriting it from a stale copy would be the
  two-writers hazard the store exists to avoid.
- **Stated limits, not omissions.** A headless detached run's standard streams
  are `/dev/null` — a supervisor holding its launcher's pipes is precisely what
  detachment is for, and giving output back is slice C's PTY. Gate expiry stays
  lazily evaluated at the next control operation, exactly as on the attached
  path, so an abandoned never-activated detached session holds its supervisor
  until that next operation notices the deadline.
- **Tests.** A new `harness = false` target, `tests/lifecycle_detached.rs`,
  whose own `main` installs the entry hook — libtest owns `main` and offers no
  pre-main hook. The same `main` is what makes the R09 core proof possible: the
  binary re-runs *itself* as a launcher that prepares a detached session, prints
  the session id and token, and exits, after which a process that forked nothing
  involved recovers, attaches, activates and waits.
- Gates: 213 unit (181 + 32); `--test lifecycle_detached` 15 passed / 1 ignored
  x3, with no leaked supervisor processes and no leftover store directories;
  `--test lifecycle_live` 25 passed x3, unmodified; loom 7/7 unchanged;
  workspace 3669/0/2 across 34 suites; strict clippy clean (also under
  `nono_loom`); fmt clean; both lint scripts exit 0; no new dependency.
- Removal detection (each restored to green afterwards): deleting the hello
  version check greets a wrong-version client instead of refusing it
  (`left: Hello{protocol: 1, …}`); deleting the frame-length bound makes the
  supervisor read a body that never arrives, and the oversize test fails with
  "the supervisor must answer"; deleting the stale-socket unlink from `recover`
  fails with "recovery must remove the stale socket it just proved dead";
  deleting the hello-first guard serves a `Status` sent before any hello.
- One API addition beyond the slice's own surface, and it is deliberate:
  `ActivationHandle::{token, from_parts}` are now public. A detached run is
  activated by whichever process holds the token, which is very often not the
  one that prepared it, and the library cannot transport the bytes on a
  caller's behalf. The docs say plainly that they are a start button and that
  where they go is the caller's decision — and that the ready-made answer for
  the detached path needs no decision at all, because `prepare_detached`
  already returns a connected session that carries the token over its own
  uid-checked socket.
- Not verified, and named as such: the Linux `close_range` arm of the extended
  descriptor sweep is the only new platform-specific code and, like every other
  Linux path in this module, has not been executed on a Linux kernel by this
  stream (R07).

### Iteration 8 (cont.): adversarial review #2 — approve-with-fixes, all seven applied

The reviewer confirmed the core invariants clean (descriptor trace, sole
`gate_write` holder, frame bounds, ring token-material guard, v2 load bounds)
and raised seven items. All applied before commit.

1. **(MEDIUM) The peer-uid guard was not removal-detectable.** The honest
   version of the problem: only the *pure* `accept_decision` table had tests, so
   deleting the `peer_uid` call — or hardcoding `AcceptDecision::Serve` — left
   the whole suite green. A guard nothing can break is a guard nobody is
   keeping. The accept path is now the free function `accept_or_refuse`, the
   credential source has a `#[cfg(test)]` thread-local injection seam (compiled
   out of every release build, so no runtime path can make a real connection's
   credential anything but the kernel's answer), and three tests drive the
   *live* path with a real listener and a real connection: foreign uid closed
   with nothing written, own uid served, busy refused in words. Both removals
   now fail, transcripts in the report.
2. **(MEDIUM) The token's socket hop was not zeroized.** `write_frame`'s
   serialization buffer, its assembled frame, `read_frame`'s body, the readiness
   frame, and the `Activate` token copy on both sides all dropped un-wiped.
   Fixed unconditionally rather than on the paths that "can" carry a token: a
   branch deciding which frame is secret is a branch that can be got wrong, and
   the existing `GateSecrets` discipline is unconditional for the same reason.
3. The request read is bounded by a new `REQUEST_DEADLINE` (2 s) rather than the
   10 s reply allowance. A request is a few hundred bytes the client wrote in
   one call; a peer that sends three of them and stops was otherwise holding the
   one thread that also accepts connections and watches the child, for the full
   allowance, on every cycle. Replies keep the longer bound because a reply can
   legitimately follow a `wait`.
4. Close-on-exec is re-armed on all five inherited descriptors as soon as the
   supervisor has them. The intermediate had to clear the flag to pass them
   through the exec and the customer child was forked before that, so nothing is
   left that needs to inherit any of them — and slice C's PTY path will exec.
5. The `SIGCHLD` self-pipe is installed *before* the readiness write, so
   `HANDSHAKE_READY` means fully ready rather than nearly. Otherwise a child
   that died immediately after activation was noticed only by the 250 ms
   backstop, in a window a caller had already been told was serving.
6. The handshake no longer assumes `SPAWNED` arrives before `READY`. Two
   unsynchronized writers share that pipe: the supervisor is forked *before* the
   intermediate writes its record, so in principle it can exec, adopt and report
   first. In practice the intermediate wins every time — which is exactly what
   made the assumption dangerous, since the failure would be a typed error on a
   race that reproduces never. `await_handshake` now tolerates either order and
   is bounded by a record count as well as a deadline.
7. `MAX_CONTROL_FRAME_BYTES` is now `MAX_RECORD_BYTES` + a 4 KiB envelope
   allowance (69632). The two were equal, and a status reply is a record *inside*
   a `SessionStatus` inside a tagged `ControlReply` — so a record that was
   perfectly legal to write could have been refused on the wire, with the
   failure landing on the reply rather than on the write that caused it. The
   inequality is held by a module-level `const _: () = assert!(…)`, so a build
   that broke it would not compile, and the "always fits" comment now states the
   arithmetic instead of asserting the conclusion.
- Gates after: 218 unit (213 + 5 new: 3 live-accept, 1 request-bound, 1
  frame-bound arithmetic); `--test lifecycle_detached` 15 passed x3;
  `--test lifecycle_live` 25 passed x3; loom 7/7; workspace 3674/0/2 across 34
  suites; strict clippy clean (also under `nono_loom`); fmt clean; both lint
  scripts exit 0; doctests 11.
- Removal detection for finding 1 (both restored to green afterwards): replacing
  `peer_uid(stream.as_raw_fd())` with `Some(own_uid())` fails
  `the_live_accept_path_consults_the_peer_credential` with "a connection from
  another uid must not become the client"; replacing the whole
  `accept_decision(…)` consult with a hardcoded `AcceptDecision::Serve` fails
  that test *and* `the_live_accept_path_refuses_a_second_client_in_words`.

## 2026-08-17 — Iteration 9: R09 slice C supervisor-owned PTY + terminal attach (delta F10)

- Goal: give a detached run a real terminal that outlives its caller, and a way
  to attach to it, type at it, resize it, leave it, and come back.
- New module `crates/nono/src/lifecycle/terminal.rs` (1577 lines): the PTY
  primitives, the attach framing, the bounded scrollback ring, and the client's
  `AttachedTerminal`. Everything else is edits to `supervisor.rs` (the launcher's
  allocation, the intermediate's descriptor discipline, the loop), `prepare.rs`
  (the child's session/`TIOCSCTTY` branch and the ownership refusal),
  `protocol.rs` (`Attach`/`AttachAck`/`NoTerminal`), `detached.rs` (the entry
  point), `exit.rs` (a new pre-exec stage, and the `killpg` reading below), and
  `support.rs` + the schema doc.

### The three decisions worth recording

1. **Interactive is a question of ownership, not a feature flag.** A PTY master
   has to be held for as long as the run lives, and the ephemeral paths have
   nothing that outlives the call to hold one. So `SessionMode::Interactive` is
   supported on the detached path *only*, and `refuse_unsupported` now judges it
   exactly as it already judged detachment — same shape, same `supervised` flag,
   new typed `PrepareError::InteractiveNeedsSupervisor` that names the method
   which does implement it. Running such a plan headless behind the caller's
   back was the alternative, and it is the failure mode this whole module
   exists to avoid.

2. **An interactive child leads a SESSION, not just a group.** `TIOCSCTTY` is
   refused for a process that is not a session leader, so `setpgid(0, 0)`
   becomes `setsid()` for an interactive run. That was the one place where the
   change could have quietly weakened R11: it does not, because `setsid` also
   puts the process in a *new process group* whose id is again the child's own
   pid — the number the parent recorded — so the group probe cleanup
   verification depends on is unchanged. Stated in the child's own comment
   rather than left for a reader to reconstruct.

3. **Raw bytes and controls are distinct by framing, not by content.** The
   attach channel is `[u8 tag][u32 LE len][bytes]`, so an `Input` payload
   reaches the master byte for byte — `0xFF`, NULs, and a sequence that *is* a
   well-formed frame header all travel unchanged, because the length prefix
   already said how many bytes the frame owns. There is no escape to get wrong.
   Proven at the unit level and end to end through a real `/bin/cat` behind
   `stty raw -echo`.

### Two deadlocks the live tests found, both real

Both were reproduced with standalone C programs before anything was changed, so
the fix is against a measured fact rather than a theory.

1. **A session leader holding a controlling terminal cannot finish exiting until
   that terminal's output has drained** — and the only process that can drain it
   is the one about to block in `waitpid`. Measured: `waitpid` never returns
   (100 × 10 ms and still `?Es`), while draining or closing the master reaps in
   10 ms. So `Supervisor::stop` drains and then *hangs the terminal up* before
   the kill; `Supervisor::wait` services the terminal on every slice (without
   which a run that outran the tty buffer blocked writing while its own caller
   waited for it to finish — that is what made the ring-flood test hang); and
   the loop hangs up before any handle's `Drop` can reap. Consequence stated
   rather than hidden: a stopped interactive run may be observed as
   `Signaled { SIGHUP }` rather than `SIGKILL`, and a later attach still works
   and still replays the ring.

2. **macOS `killpg` answers `EPERM`, not `ESRCH`, for a group whose every member
   is already a zombie.** Measured directly: `kill(zombie) rc=0`,
   `killpg(zombie) rc=-1 errno=1`. So a stop that raced the run's own exit
   reported "the stop signal could not be delivered" — a pre-existing R11
   fragility that slice C's hang-up made deterministic, and which no test had
   ever reached because nothing exercised `ActivatedSandbox::stop` over the
   control socket. `ActivatedSandbox::{stop, drop}` now go through a private
   `kill_own_group` that reads `EPERM` as "nothing left in the group to signal",
   **and only there**: the group id is an unreaped child's own pid and so cannot
   have been reissued. `RecoveredSession::kill_group` deliberately keeps the
   strict reading, because its recorded group id may well have been. This is the
   one change outside slice C's stated scope and it is flagged as such.

### Deviations from the brief, with reasons

- **No `AttachBusy` refusal.** The brief resolved to "keep the existing
  single-client-at-a-time socket discipline; a second connection still gets
  `Busy`". With that discipline a second attach cannot reach the supervisor to
  be refused, so an `AttachBusy` variant would be unreachable code — which the
  repository forbids. `Busy` is the answer, and the protocol docs say why.
- **`AttachedTerminal::activate` rather than attach-after-activate.** Test (a)
  needs the window size to reach the terminal before the program starts, so the
  attach has to precede the activation. `activate` leaves attach mode for one
  control exchange and returns to it; nothing is lost across the gap because
  output with nobody attached goes to the ring. The alternative — new frame tags
  to tunnel control operations — would have widened the wire vocabulary the
  brief specified exactly.
- **`interactive_session` and `attach` are `platform_api`, not `probed_live`.**
  The brief said `ProbedLive` was acceptable given the live tests. The module's
  own definition of `ProbedLive` is "a probe ran *in this process, during this
  call*", and a test that ran elsewhere is not that; claiming it would make the
  strongest word in the report mean something weaker. `interactive_session`
  takes its *status* from the live `posix_openpt` probe (a host with no PTY
  cannot run one however good the supervisor is) but not its *determination*.
- **Darwin `TIOC*` constants are carried in-tree.** `libc` declares no `TIOC*`
  numbers for Apple targets and no `ptsname_r`. `TIOCSCTTY`, `TIOCSWINSZ` and
  `TIOCPTYGNAME` are defined in `terminal.rs` from the platform header, and a
  unit test recomputes all three from the BSD `_IOC` encoding rule so a
  transposed digit fails there rather than as an `ENOTTY` at the point of use.

- Gates after: 235 lifecycle unit (218 + 17 new); `--test lifecycle_detached`
  27 passed / 1 ignored ×3; `--test lifecycle_live` 25 passed ×3; loom 7/7
  unchanged; workspace 3703/0/2 across 34 suites; strict clippy clean (also
  under `nono_loom`); fmt clean; both lint scripts exit 0; doctests 11.
- Removal detection (each restored to green afterwards):
  - unknown-tag guard deleted from `FrameDecoder::next_frame` (decode as `Input`
    instead) → `a_tag_this_protocol_does_not_have_is_named_not_skipped` FAILED,
    and the live `a_frame_tag_this_protocol_does_not_have_ends_the_channel_not_the_run`
    FAILED with "an unknown terminal frame tag must end the channel".
  - scrollback bound deleted from `Scrollback::push` →
    `the_ring_stays_bounded_and_counts_what_it_dropped` FAILED
    (`left: 524288, right: 262144`), `the_ring_keeps_the_tail_not_the_head`
    FAILED (`left: 262150, right: 262144`), and the live
    `the_scrollback_ring_stays_bounded_and_says_what_it_dropped` FAILED with
    "the ring must stay bounded: 406282 bytes buffered, bound is 262144".
  - `EPERM` arm deleted from `kill_own_group` →
    `a_group_of_zombies_is_nothing_left_to_signal_not_a_refusal` FAILED on
    macOS, and with it every detached stop that races the run's own exit.
- Still Linux-unverified behind R07: the whole PTY path — `open_pty`'s Linux
  `ptsname_r` arm, `setsid`/`TIOCSCTTY`, and the master's `EIO`-on-last-slave-close
  end of file (macOS returns 0; both are folded into `ReadOutcome::Ended`).

## 2026-08-17 — Iteration 10: R06 mode-aware filesystem vocabulary (delta F11)

- Goal: replace "read / write / read+write" with words for the operations a
  caller actually means, and — the harder half — make the platform say out loud
  what it cannot do with them.
- New directory `crates/nono/src/capability_modes/`: `mod.rs` (the vocabulary,
  the disclosure types, and the shared compile), `landlock_map.rs` (Linux),
  `sbpl_map.rs` (macOS). New live suite
  `crates/nono/tests/lifecycle_modes_live.rs`. Everything else is additive edits
  to `capability.rs`, `error.rs`, `lib.rs`, `sandbox/{linux,macos,mod}.rs`,
  `lifecycle/support.rs`, `bindings/c/src/lib.rs`, and three docs.

### The five decisions worth recording

1. **The new module is a new directory, and that is a rebase decision.**
   `capability.rs` is 3810 lines and is exactly the file upstream would touch if
   it ever evolved `AccessMode` — the conflict surface F2 predicted. So the
   vocabulary lives somewhere a rebase cannot conflict, and what
   `capability.rs` gains is four things: one `use`, one `fs_modes` field, the
   four-method builder block, and a behaviour-preserving extraction of
   `FsCapability::new_dir`/`new_file`'s canonicalise-then-check-type bodies into
   `resolve_directory`/`resolve_file`. The extraction is the only edit that
   rewrites existing lines, and it exists so the two grant types cannot drift
   apart on TOCTOU handling — two paths that canonicalise differently would be
   two security properties wearing one name.

2. **`bundled` reports what the caller did *not* ask for.** The first shape I
   tried listed every implication, which meant a caller who asked for both
   `write` and `append` was told about a "bundle" that surprised nobody. The
   rule that survived is sharper and is the anti-silent-widening guarantee in
   one sentence: an entry appears exactly when the grant confers a mode the
   caller did not name. A caller who named both halves is not being widened, so
   there is nothing to disclose.

3. **`create` is `MAKE_REG` and nothing else.** Landlock has seven make-rights
   and coarse `Write` grants all seven. Folding them into one mode would mean a
   caller who asked to create a file also got to create a device node and a
   symlink — the exact widening this vocabulary exists to stop. So `create` is
   regular files only, the other six have *no* mode, and the absence is written
   down in `landlock.mdx`, in the baseline, and in a test whose deletion is what
   a silent widening of `create` would look like. A caller who needs `mkdir`
   inside a sandbox still uses `allow_path` and takes the coarse bundle
   knowingly.

4. **An ABI gate refuses; it does not drop.** On a kernel below V3 there is no
   `TRUNCATE` right — which means truncation is not restrictable *at all*, so a
   `truncate` grant that quietly compiled to no right would leave the caller
   believing something was enforced. `RefusalReason::UnsupportedRight { right,
   abi, needed_abi }` becomes `NonoError::ModeUnsupported` and fails
   prepare/apply. Same for `rename`/`REFER` below V2, and therefore for
   `atomic_write`, which is a name for a set containing `rename`.

5. **The Linux mapping is testable on macOS by construction.**
   `landlock_map::compile` takes a `LandlockRightsAvailable` — an ABI number —
   instead of reading the kernel, so all ten leaf arms, both gates, the
   always-allowed disclosure, the delegation and the bundle closure run in the
   ordinary macOS suite months before a Linux runner exists. Only
   `access_fs_for`, `abi_version_number` and the two rule loops in
   `sandbox/linux.rs` need a kernel, and one of their `cfg(target_os = "linux")`
   tests asserts the pure availability table agrees with `AccessFs::from_all`
   for every right at every ABI — the one claim the pure tests cannot make for
   themselves.

### The macOS exec change, stated plainly

`(allow process-exec*)` at `macos.rs:555` was unconditional, so on macOS "which
binary may run" was never a capability. `FsMode::Execute` makes it one, and the
switch is the *presence of a mode grant*, not a flag: a capability set built
entirely from `allow_path` — which is every existing consumer, including all of
`nono-cli` — gets that exact line, byte for byte, and the upstream suite is
untouched. A set carrying one mode grant gets `(allow process-exec* (<filter>))`
per `execute`-granted path and nothing else.

### What did not work, and why the fixture changed

The Execute pair was meant to run a copy of `/bin/echo`. On this host a
byte-for-byte copy of a platform binary cannot be `execve`d **at all** — the
kernel `SIGKILL`s it (exit 137) because its code signature is not the one the
trust cache holds for that path, and `codesign --force --sign -` does not change
that. Verified outside any sandbox before changing anything, so the sandbox was
never suspected. The fixture is now a `#!` program, which is unsigned by nature;
it also exercises the `*` in `process-exec*`, since the kernel's interpreter exec
is a `process-exec-interpreter` check against `/bin/sh`.

### Deviations from the row as scoped

- `CompiledModes` has a **fifth** field, `delegated`, beyond the specified
  `{enforced, bundled, always_allowed, refused}`. `unix_socket_connect` is
  enforced — by `UnixSocketCapability`, which already models socket grants on
  both platforms — and it is none of the other four. Folding it into `bundled`
  would have needed a self-referential entry, into `refused` would have broken a
  working grant, and into `always_allowed` would have been false. Adding a word
  was cheaper than rounding one off. `ModeEnforceability` gains the matching
  `delegated { target }` for the same reason.
- The Linux availability flags are derived from the ABI *number* rather than
  from `DetectedAbi::has_*`. `has_refer`/`has_truncate` are themselves
  `AccessFs::from_all` lookups so they agree by construction; `has_execute` is
  deliberately *not* used, because it answers a stricter question (whether the
  second execute-only `restrict_execute` layer is usable, V3+) than "does the
  ABI carry `EXECUTE`" (V1+). Using it would have refused a working `execute`
  grant on V1 and V2. The agreement between the number-driven table and the
  crate's own table is asserted by a Linux test.

- Gates after: 1012 lib unit (24 new `capability_modes`, 3 new `support`);
  `--test lifecycle_modes_live` 14 passed ×3; `--test lifecycle_live` 25 passed
  ×3 unmodified; `--test lifecycle_detached` 27 passed / 1 ignored unmodified;
  loom 7/7 unchanged; workspace 3744/0/2 across 35 suites; strict clippy clean;
  fmt clean; both lint scripts exit 0; doctests 11.
- Removal detection (each restored to green afterwards):
  - ABI gate deleted (`landlock_map::compile`'s `refuse` closure made to return
    `None`) → `truncate_is_refused_below_abi_v3_rather_than_dropped`,
    `rename_is_refused_below_abi_v2_rather_than_dropped` and
    `atomic_write_fails_closed_on_a_kernel_without_refer` FAILED; the first
    printed `left: []` against `right: [ModeRefusal { mode: Truncate, why:
    UnsupportedRight { right: Truncate, abi: 1, needed_abi: 3 } }]` — the empty
    list *is* the silent widening.
  - Landlock's always-allowed arm deleted from `compile_common` →
    `read_metadata_is_a_disclosed_no_op_not_a_grant` FAILED at
    `assertion failed: compiled.modes.enforced().is_empty()`: a `stat` grant
    would have been reported as enforced on a platform that cannot enforce it.
  - macOS exec scoping deleted (unconditional `(allow process-exec*)` restored
    for mode-built profiles) → the live pair
    `execute_granted_runs_an_unheard_of_program_and_ungranted_is_refused_at_exec`
    FAILED with "activation was expected to fail; the run ended
    `Ok(Exited { code: 0 })`".
- Still Linux-unverified behind R07: `access_fs_for`, `abi_version_number`,
  `mode_cap_access` and the two `fs_mode_capabilities()` rule loops in
  `sandbox/linux.rs`, plus their six `cfg(target_os = "linux")` tests. The
  mapping they call is fully host-tested. Cross-compilation is still not a
  workaround — `aws-lc-sys` wants `x86_64-linux-gnu-gcc`, reconfirmed this
  iteration.

## 2026-08-17 — Iteration 11: consolidation, gate tooling, final statuses (no delta row)

No substrate change this iteration. Nothing was added to `crates/nono`. The work
was making the stream's own claims checkable by someone who did not write them,
and then reading the result honestly.

### The upstream re-diff, and a prediction that was wrong

`NONO_UPSTREAM_DELTA.md` §2 had said "UNKNOWN — not yet diffed" since iteration 1,
which was true at clone time (pinned == tip) and had quietly stopped being true.
Upstream is now `9078ffcf`, three commits on: a 461-line seccomp arch-guard
refactor of `crates/nono/src/sandbox/linux.rs`, a CLI atomic-write unlink rule,
and 2151 lines of remote `connect`/`ps`. Each verified with `git show --stat`
before a word was written about it.

**The predicted conflict did not happen, and the measurement is more useful than
the prediction was.** The expectation going in was a real rebase conflict in
`linux.rs` against F11's mapping additions and F4's `prepare_seccomp` use. It is
clean:

```
$ git merge-tree --write-tree HEAD origin/main
5b5c174d704fd262ee0c5e72cf99024a3c075856          # a tree, not a conflict report

$ git rebase 9078ffcf                             # in an isolated --shared clone
Successfully rebased and updated refs/heads/probe. # all 11 fork commits, 0 conflicts
```

The reason is worth recording because it is a payoff and not luck. The fork's
placement rule has been "append functions, never weave" since F4, and the hunk
table shows what that bought: fork hunks at old lines 5 / 594 / 910 / 1271 / 5801,
upstream's at 1642–3368 and 4901–5010. Nearest approach ~370 lines.
`prepare_seccomp_with_abi`'s signature is byte-identical either side, so F4's one
call site and F11's two rule loops need no edit at all.

Two things kept the finding honest rather than triumphant. `rustfmt --edition 2024
--check` parses the merged file with no diff — that is a *parse*, not a compile.
And `sandbox/linux.rs` is `cfg(target_os = "linux")` in its entirety, so a macOS
host cannot compile the one file both changesets touch. §5.0 now says so in as
many words: **rebase, then run the ubuntu job before believing the clean result.**

One semantic hazard survives the clean rebase and git will never mention it:
upstream `36243aa5` extended `nono-cli/src/capability_ext.rs` — the file F11
ported the atomic-write temp-sibling rule *out of*, with attribution — so the two
copies can now drift. Recorded in §5.1 as a semantic-only row, and in
`docs/UPSTREAMING.md` §1.3 as "re-read this file after every rebase".

`36243aa5` is also the most interesting of the three: upstream solved atomic-write
unlink as one more hardcoded CLI policy rule, which is exactly the fourth member
of F11's published `ATOMIC_WRITE_MEMBERS` arriving one rule at a time. That is
evidence the bundle is the right shape — and a warning that the two must not both
ship, or the CLI regex and the mode compiler both emit `file-write-unlink` for the
same pattern and only one of them discloses it.

### `scripts/stream-gates.sh` — three outcomes, and no fourth

The contract's §12 asks CI to distinguish PASS / FAIL / NOT_RUN and never let
NOT_RUN read as PASS. The script is that, and the design decision behind it is
one line long: **a NOT_RUN reason must name the capability this host lacks, not
the fact that it lacks one.** "unavailable" is not a reason; "docker daemon down
(open Docker Desktop once and accept the first-run prompt)" is. Every reason is
*probed* rather than hardcoded, so a host that has since started Docker gets a
different line rather than a stale one.

Fifteen gates. The exit status is nonzero if and only if something FAILed, so a
host that can answer twelve questions reports honestly on twelve instead of
failing on three.

Two judgements inside it worth writing down:

- **`lifecycle-modes-live` is NOT_RUN on Linux, not PASS.** The target is
  `#![cfg(target_os = "macos")]`, so on Linux it compiles to zero tests — and
  zero tests passing is precisely the kind of green that means nothing. The
  Linux half of that vocabulary is a different gate.
- **The miri filter is a deliberate subset and says so.** State machine, gate
  classification, plan validation and the recovery decision table: 56 tests, and
  the reason the rest are excluded is that they fork, exec, bind sockets and
  write files, none of which miri interprets. Claiming "miri passes on the
  lifecycle" would be the overclaim; the gate name is `miri-pure-lifecycle`.

`.github/workflows/stream-gates.yml` runs the same script on `macos-latest` and
`ubuntu-latest`. No upstream workflow was touched. The header comment says what
the ubuntu job is *for*, because a future reader should not have to infer that it
is the thing standing between seven BLOCKED rows and PASS.

### The gate matrix

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
NOT_RUN  linux-landlock-live    Linux execution environment unavailable: docker daemon down (…)
NOT_RUN  linux-lifecycle-live   Linux execution environment unavailable: docker daemon down (…)

gates: 12 PASS  0 FAIL  3 NOT_RUN  (of 15)
```

Miri was left NOT_RUN rather than installed. No nightly toolchain exists on this
host, and `df -h /` reports **1.9 GiB free** — installing a nightly plus the miri
component plus a separate interpreter target directory on that is a good way to
turn a missing gate into a broken host. The gate names the exact command
(`rustup +nightly component add miri`) so the operator can make that trade
knowingly. Miri is a supplement to the loom gate here, not a substitute for it.

### Evidence gates run for the row statuses

```
$ grep -rnE 'Command::new\("nono"\)|CARGO_BIN_EXE_nono' crates/nono/src
(no output, exit 1)
```

R14 empty. The grep is only the tripwire; the real claim is that `crates/nono` is
a workspace leaf with no dependency on `nono-cli`, so a CLI invocation is not
reachable even indirectly. The one place the library re-executes anything is the
detached supervisor, and what it re-executes is `current_exe()` — the consumer's
own binary — never a looked-up path, because a path is something an attacker can
arrange to control.

```
$ grep -rnE 'RuntimeProvider|LaunchRequest|PolicyBundle|SandboxEvent|Cedar|HCP|CrystalOS|Leash' \
    crates/nono/src docs/lifecycle docs/adr
docs/adr/0001-generic-lifecycle.md:17:all generic (no CrystalOS/HCP/Leash/Cedar concepts).
```

R15: zero hits in `crates/nono/src`, zero in `docs/lifecycle`, one in an ADR — and
that one is the *negative* statement, the sentence that declares the boundary this
row exists to enforce. Deleting it would make the grep cleaner and the repository
less honest. Justified in the row rather than suppressed.

Both blocker reproduce commands re-verified verbatim: `docker ps` still answers
"Cannot connect to the Docker daemon at
`unix:///Users/gauranshtandon/.docker/run/docker.sock`", and `which
x86_64-linux-gnu-gcc` still answers "not found" — while the
`x86_64-unknown-linux-gnu` *target* is installed, which is the detail that makes
the cross-compile dead end easy to re-walk if it is not written down.

### The row calls, including the ones that went against the brief

Final: **11 PASS, 7 BLOCKED, 1 IN_PROGRESS, 1 aggregate PASS.**

Three calls needed a judgement rather than a lookup.

**R05 → PASS, not BLOCKED.** Its six siblings are BLOCKED for a Linux runner, and
at first glance R05 looks the same. It is not. Loom is a model checker: it
replaces std's atomics, cells and locks with instrumented ones and enumerates
interleavings inside one process. It performs no syscall, forks nothing, and
every model drives `sync_core`, which is pure synchronisation over
`LifecycleState::apply`. **There is no Linux half of this row to be missing.** A
Linux runner would run the same enumeration and reach the same verdict. Marking
it BLOCKED would have been a false humility that made the file less accurate, not
more.

**R08 → PASS, with the residual named rather than rounded off.** The row's three
scope items are met and audited by name: fourteen live positive/negative mode
pairs, atomic-write as a capability concept with a published expansion, and
disclosure that cannot disagree with enforcement because it *is* the compilation.
It is a macOS-only row, so the Docker wall does not reach it. But
`sandbox_extension_consume` and its three unconditional filter rules are untouched
by F11, and the vocabulary still does not describe what a consumed token widens.
The row says PASS *on the reading that* "mode-aware extension honesty" means the
mode-aware extension of the vocabulary — and says, in the same breath, that if the
operator reads it as covering sandbox extensions the row should be re-opened. A
PASS that names the reading it depends on is checkable; one that does not is a
guess wearing a green label.

**R20 → IN_PROGRESS, against the instruction to mark it PASS at commit.** The
instruction was also to leave this iteration uncommitted. Both cannot be true at
once, and the tie-breaker is the stream's own rule: a row is PASS when it is
verified, and "it will be committed shortly" is not a verification. `git status`
is non-empty, so the row is not PASS. Its evidence names the eight uncommitted
paths and notes that all eight are documentation and gate tooling — no library
source, no test, no manifest — so the commit that lands them cannot invalidate the
matrix that produced this iteration's evidence.

R07 was also promoted from TODO to BLOCKED with a structured blocker. TODO reads
as "not started", and the truth is "cannot be started here"; it is the root
blocker six other rows point at, and it was the only one of the seven not carrying
a machine-readable one.

And the one thing R07 still owns in its own right, which did **not** get fixed and
should not have: `SignalMode::Isolated` degrades silently below Landlock V6 with
only a `debug!`. The candidate fail-closed fix was deliberately not made, because
changing fail-closed behaviour on a platform this stream cannot execute would be a
change nobody could test. Recorded as a decision, not an oversight.

### The threat model, from requirements to mechanisms

`THREAT_MODEL.md` was a discovery seed: boundaries written as "Fork must add…".
Every one of them now exists as running code, so §1 is a mapping from each seed
requirement to the mechanism that answers it, plus three boundaries the seed did
not have (the re-exec entry hook, the control socket, the PTY attach codec). §2
records both adversarial reviews as finding→fix pairs — thirteen findings, all
applied in the iteration they were raised.

§3 is the part that matters most and is the part a threat model usually gets
wrong. Nine residual risks, each accepted and disclosed rather than mitigated into
vagueness; the first four are typed entries in `SupportReport::dark_spots()`, so a
consumer reads them from the machine-readable report and not from a document. The
ninth is stated in capitals because it is the largest and the easiest to lose in a
list: **no part of this has ever executed on a Linux kernel**, the mapping logic
is host-tested against a *faked ABI* which tests the decision table and not the
kernel's answer, and every Linux-facing sentence in that document should be read
as intent until the ubuntu job has been green once.

### `docs/UPSTREAMING.md`

Rebase procedure with the order that makes it recoverable (record the re-diff
*first*, measure the conflict surface *before* creating one, dry-run in a
`--shared` clone), per-delta-row conflict resolutions, the four places the
upstream pin is written down and must move together, and the three things a rebase
must not do.

Then the PR ordering — F1 first because it is smallest and its evidence is a
failure rate; F11 second, and **not until the ubuntu job is green**, because
proposing Linux behaviour that has only been tested against a faked ABI is exactly
what upstream's §7 says to stop over; the lifecycle third and **as an RFC, not a
PR**, because ~15 modules and a library that asks you to change `main` is a design
conversation.

Upstream's Coding Agent Contribution Policy is quoted verbatim rather than
paraphrased, because a paraphrase of a hard stop is a way to get one wrong. The
conclusion is uncomfortable and is written down anyway: **no issue exists upstream
for F1, F11 or the lifecycle, so all three are currently under a hard stop.**
Holding the work here is not a contribution attempt and is not prohibited; filing
the issues is an operator decision, and an agent filing an issue to unblock its
own PR is the letter of that policy but arguably not its spirit.

### Gates after

`scripts/stream-gates.sh` = 12 PASS / 0 FAIL / 3 NOT_RUN, exit 0. `cargo fmt
--all -- --check`, `./scripts/lint-docs.sh` and `./scripts/test-list-aliases.sh`
are inside the matrix (`fmt-check`, `lint-docs`, `lint-aliases`) and each ran
clean. No source file changed this iteration, so no removal-detection transcript
applies.

### Left uncommitted, by instruction

`BLOCKED_ROWS.json`, `HANDOFF.md`, `NONO_UPSTREAM_DELTA.md`, `THREAT_MODEL.md`,
`WORKLOG.md` (modified); `docs/UPSTREAMING.md`, `scripts/stream-gates.sh`,
`.github/workflows/stream-gates.yml` (new).
