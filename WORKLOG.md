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
