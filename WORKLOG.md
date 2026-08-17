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
