# HANDOFF — Parallel Stream 1: Crystal Nono fork (generic sandbox substrate)

Run: EF1A07E7-A38C-4C5E-98CA-9444CA7CFD5C · Updated: 2026-08-17, iteration 7

STATUS: IN PROGRESS — this stream is NOT yet done. Only the final integration
agent may declare the combined system complete; this file records the current
frozen-contract state of THIS repository only.

## Branch and base

- Branch: `parallel/nono-substrate-v1` (local repo: /Users/gauranshtandon/Documents/Vedaya/nono)
- Upstream base: nolabs-ai/nono @ `149579a7b0753ee413680169fa937eea82da46a0` (main at lock time)
- HEAD SHA: recorded per-iteration below; the branch tip is authoritative
  (convention: each iteration's commit updates this file in the same commit
  where possible; the final SHA is stated by the last iteration entry).
- No GitHub fork remote exists yet (`gauransh/nono` absent). Push/publish is an
  explicit pending integration step requiring operator authorization.

## Crates / packages

- `nono` (crates/nono) — the library leash-rs will consume. NOT published to
  crates.io by this stream; consume via git/path pin (below).
- `nono-cli`, `nono-proxy`, `nono-test-support`, `nono-ffi` (bindings/c) —
  unchanged roles from upstream.

## API entry points (target shape; see docs/adr/0001-generic-lifecycle.md)

- Today (upstream baseline): `nono::CapabilitySet` → `nono::Sandbox::apply_auto/
  apply_landlock/apply_seccomp/apply_external`; `QueryContext`; `SandboxState`;
  `supervisor::{SupervisorSocket, ApprovalBackend, …}`.
- Landed (iteration 2): `nono::lifecycle::{LifecycleState, LifecycleOp,
  TransitionError, SandboxPlan, ValidatedPlan, PlanError, GateConfig,
  SessionMode, EventSink, LifecycleEvent, Observation, LifecycleError}`
  (pure layer: state machine + validation + event trait).
- Landed (iteration 3, macOS live-verified; Linux written-unverified):
  `PreparedSandbox::prepare(ValidatedPlan) -> (PreparedSandbox,
  ActivationHandle)`, `activate(&handle) -> ActivatedSandbox`,
  `stop_before_activation()`, `ActivatedSandbox::wait() -> SandboxExit`,
  `SandboxExit` (typed exit facts + `ActivationObservation`),
  `ProcessIdentity` (pid + start_time + boot_id). Security review pass
  applied (fd sweep in child, random release/abort nonces, honest
  three-valued activation observation).
- Landed (iteration 4): the lifecycle state and its one-shot gate write moved
  behind a single lock (`lifecycle::sync_core::SharedLifecycle`, crate-internal
  — public only under `--cfg loom`), with `PreparedSandbox`/`ActivatedSandbox`
  rewired onto it. No public API change: same types, same signatures, same
  observable behavior; the 96 existing lifecycle unit tests and all 16 live
  tests pass unmodified. Proven by 5 Loom models (ADR-0001 §2).
- Landed (iteration 5, macOS live-verified; Linux written-unverified):
  `nono::lifecycle::{CleanupVerification, AbsenceBasis, SurvivorEvidence,
  IndeterminateReason, UnsupportedReason, CleanupError}` plus
  `ActivatedSandbox::{stop, verify_cleanup}` and
  `PreparedSandbox::verify_cleanup`. The prepared child now leads its own
  process group (`setpgid(0, 0)`, typed `PreExecStage::ProcessGroup` on
  failure), so a stop signals the whole run and verification probes a group
  rather than a pid `waitpid` already consumed. A sent signal is never a
  basis; only `ConfirmedAbsent` moves the run to `CleanupVerified`.
- Landed (iteration 6, macOS live-verified; Linux written-unverified):
  `nono::lifecycle::{SessionStore, SessionRecord, SessionSummary, RecoveredSession,
  RecoveryDecision, SessionStoreError, CURRENT_SCHEMA_VERSION, MAX_RECORD_BYTES}`
  plus `lifecycle::{Sessions, reconcile}` (module-only). The durable half of
  ADR-0001 §6: `SessionStore::open(dir)` (0700, checked-not-repaired, opened
  `O_DIRECTORY | O_NOFOLLOW` with every record reached by `openat` against that
  descriptor), `SessionStore::prepare(plan)` (a schema-versioned 0600 record
  written after the gate-ready observation, updated at every later transition),
  `sessions()` (one `Result` per record — a corrupt record is reported beside
  its healthy siblings, never instead of them), and `recover(id)` (probe the
  recorded identity, then the pure `reconcile()` decision table).
  `PreparedSandbox::prepare` is unchanged: without a store nothing is written
  and nothing behaves differently.

  Two contract points a consumer must build on:

  1. **A record may lag the live state by one step.** It is written after the
     transition it describes, outside the lifecycle lock. Reconciliation on load
     is what makes that safe; a consumer must not treat a record's `state` as a
     statement about the present.
  2. **A recovered process is not the recovering process's child**, so its exit
     code or signal is *not observable* — `RecoveredSession` has no `wait` and
     returns no `SandboxExit`. Recovery reports presence and absence
     (`kill_group` / `kill_pid` / `verify_cleanup_by(deadline)`, which polls
     until `ESRCH` rather than treating a sent signal as proof). Exit facts that
     survive a caller restart need the detached supervisor of the next slice.

- Landed (iteration 7, macOS live-verified; Linux written-unverified):
  **R12, the machine-readable support report.**
  `nono::lifecycle::{SupportReport, SUPPORT_REPORT_SCHEMA_VERSION, Capability,
  SupportStatus, Determination, SupportReason, HostFacts, KernelFacts,
  LandlockFacts, LandlockRight, LandlockRightSupport, NetworkFilteringFacts,
  NetworkMechanism, NetworkMechanismSupport, IdentityFacts, CleanupFacts,
  EventObservationSupport, EventFamily, EventFidelity, DarkSpot,
  DarkSpotEntry}` (all re-exported at the crate root except `Capability`,
  which stays `lifecycle::Capability` so it cannot be misread as a peer of
  `CapabilitySet`).

  `SupportReport::gather() -> SupportReport` is **infallible**. Every field is
  a `Capability<T>` carrying `status` (`available` / `partial` / `unavailable`
  / `unknown`), `determination` (`probed_live` / `platform_api` / `declared`),
  a typed `reason`, and optional typed `facts`. **No bare boolean appears
  anywhere in the serialized tree**, and a test walks the JSON to keep it that
  way. Upstream's `SupportInfo { is_supported: bool, … }` is untouched.

  Three points a consumer should read before trusting it:

  1. On macOS, `seatbelt` is `platform_api`, **not** `probed_live`.
     `sandbox_init` is linked (so certainly present) but applies to the
     calling process irreversibly; the only honest live probe forks first, and
     this library will not fork a consumer to answer a diagnostic question.
     The rationale is in `reason.why_not_probed`.
  2. On Linux, `seccomp` is `probed_live` (upstream already ships a
     fork-isolated probe) but `seccomp_user_notification` is `unknown` — it
     cannot be established without installing a filter that cannot be removed,
     and a kernel version is not proof.
  3. `event_observation` reports `kernel_denial` as `not_observed` on **both**
     platforms. The library emits no denial events; the CLI's macOS
     `log stream` reconstruction is CLI machinery and is not claimed here.

- Landed (iteration 7): **R13, the generic event vocabulary.**
  `nono::lifecycle::{LifecycleEvent, LifecycleEventKind, ActivationOutcome}`.
  **API shape change:** `LifecycleEvent` is now a struct — an envelope
  (`session_id`, `generation`, `seq`, `observed_at`, `identity`,
  `observation`) around a closed `what: LifecycleEventKind`. The previous
  `LifecycleEvent::StateChanged { from, to, observation }` survives as
  `LifecycleEventKind::StateChanged { from, to }`; a consumer that matched the
  old enum matches `event.what()` instead. No other public type changed.

  `seq` counts a run's events from zero, is kept across the
  prepared→activated handoff, and is **the ordering authority**;
  `observed_at` is a wall clock and explicitly is not. `ActivationOutcome`
  carries no token material by construction, locked by a structural test.
  Events the platform cannot show do not exist in the vocabulary — there is no
  kernel-denial variant to synthesize one into.

- Schema documents, each with a golden JSON example locked by a snapshot test
  that reads the document itself: `docs/lifecycle/session-record-v1.md`,
  `docs/lifecycle/support-report-v1.md`,
  `docs/lifecycle/lifecycle-event-v1.md`.

- Still being added: detached supervisor (exit facts across a restart,
  re-prepare with an incremented generation), attach/detach/resize,
  interactive (PTY) sessions — each reported as `not_implemented` by
  `SupportReport` rather than left to inference (ADR-0001 §6).

## Toolchain and platform requirements

- MSRV: 1.95 (workspace `rust-version`); edition 2024.
- Feature flags: `system-keyring` (default-on) — no lifecycle-specific flags yet.
- Platforms: macOS (Seatbelt) and Linux (Landlock ≥ ABI per support report;
  fail-closed below). Live-Linux gates require a Linux environment (Docker
  provisioning in progress on this host).

## Test commands and results (this iteration)

| Command | Result |
|---|---|
| `cargo test --workspace --no-fail-fast` (upstream baseline @149579a7, macOS) | 3409 passed / 3 failed / 1 ignored — all 3 macOS-host portability bugs (see WORKLOG) |
| same, after F1+F1b fixes | 3412 passed / 0 failed / 1 ignored — green on 5 consecutive runs; full bin-test binary stressed 20x, 0 failures (baseline: 23/20 runs) |
| `cargo test --workspace --no-fail-fast` (after F3+F4, iteration 3) | 3527 passed / 0 failed / 1 ignored, 32 suites |
| `cargo test --workspace --no-fail-fast` (after F5, iteration 4) | 3540 passed / 0 failed / 1 ignored, 33 suites — reproduced on 2 runs |
| `cargo test -p nono lifecycle` / `--test lifecycle_live` | 96 unit + 16 live; live suite clean on 10 consecutive runs |
| same, after F5 (shared lifecycle core) | 109 unit (96 unchanged + 13 new `sync_core`) + 16 live, unmodified |
| `cargo test --workspace --no-fail-fast` (after F6, iteration 5) | 3562 passed / 0 failed / 1 ignored, 33 suites |
| `cargo test -p nono lifecycle` / `--test lifecycle_live` (after F6) | 126 unit (109 unchanged + 17 new `cleanup`) + 21 live (16 unchanged + 5 new: own-process-group, verify-after-exit + duplicate refusal, honest `StillPresent` survivor then `ConfirmedAbsent`, `stop()` kills the group, stopped-before-activation verify); live suite clean on 3 consecutive runs |
| removal detection for the R11 foundation | deleting the child's `setpgid(0, 0)` fails 2 live tests: the group assertion (`getpgid(child) == child`) and — the load-bearing one — the survivor test, which then reports `ConfirmedAbsent{ReapedAndGroupEmpty}` while `/bin/sleep 30` is still running |
| `cargo test --workspace --no-fail-fast` (after F7, iteration 6) | 3591 passed / 0 failed / 1 ignored, 33 suites |
| `cargo test -p nono lifecycle` / `--test lifecycle_live` (after F7) | 153 unit (126 unchanged + 27 new `session_store`) + 23 live (21 unchanged + 2 new: a dropped `ActivatedSandbox` ends the whole group, a durable session recorded at every state the run passes through); live suite clean on 3 consecutive runs |
| removal detection for the F7 guards | record `O_NOFOLLOW` dropped → the symlinked record is followed and the planted decoy is returned (`left: None`); store-dir `O_NOFOLLOW` dropped → the store lands on the link's 0755 target (`StorePermissions{mode: 493}`); skip-on-parse-failure → 4 accounted-for records become 1; schema check deleted → a version-2 record is read as version 1; directory permission check deleted → a 0755 store is accepted; F7 group kill deleted from `ActivatedSandbox::drop` → a dropped run leaves its `sleep` descendant alive |
| `RUSTFLAGS='--cfg nono_loom' cargo test -p nono --test loom_lifecycle --release` (after F7) | 7 loom models pass (5 unchanged + 2 new: recovery-vs-cleanup → exactly one `CleanupConfirmed` winner; recovery-vs-stop-then-cleanup → never adopt after cleanup). Completes the R05 scenario set |
| `RUSTFLAGS='--cfg nono_loom' cargo clippy -p nono --all-targets --all-features` | clean |
| `RUSTFLAGS='--cfg nono_loom' cargo test -p nono --test loom_lifecycle --release` | 5 loom models pass (all interleavings); harness verified to fail when the activation CAS is weakened. Cfg name is `nono_loom`, not loom's own `loom`: RUSTFLAGS reaches every crate, and `--cfg loom` makes tokio compile out `tokio::net`, breaking hyper-util (transitive via sigstore-verify) |
| `cargo test --workspace --no-fail-fast` (after F8, iteration 7) | 3621 passed / 0 failed / 1 ignored, 33 suites |
| `cargo test -p nono lifecycle` / `--test lifecycle_live` (after F8) | 181 unit (153 unchanged + 28 new: 17 `support`, 8 `events`, 1 `session_store` golden, 2 reshaped) + 25 live (22 unchanged + 3: whole-vocabulary happy run, stopped run, refused activation carries no token material); live suite clean on 3 consecutive runs |
| removal detection for the F8 guards | adding one `bool` field to `CleanupFacts` fails both no-bare-boolean tests *and* the golden-example test, naming the JSON pointer `/cleanup_verification/facts/probes_work`; adding a `token_digest` field to an `ActivationOutcome` variant fails the token-material test with the offending JSON; giving `ActivatedSandbox` its own emitter instead of sharing the prepared one restarts `seq` at 0 mid-run and fails both live sequence tests (`left: 0, right: 9`); changing one field of one golden example in `docs/lifecycle/*.md` fails that document's snapshot test |
| `RUSTFLAGS='--cfg nono_loom' cargo test -p nono --test loom_lifecycle --release` (after F8) | 7 loom models pass, unchanged — F8 adds no shared-state machinery, and the one lock it touches (`SessionHandle`'s record mutex) is now released *before* the sink is called |
| `./scripts/lint-docs.sh`, `./scripts/test-list-aliases.sh` | exit 0 after F1; re-run green after F8 |
| `cargo clippy --workspace --all-targets` | clean |
| `cargo fmt --all -- --check` | clean |

Full gate for every iteration: `make ci` equivalent (clippy -D warnings -D
clippy::unwrap_used, fmt check, workspace tests) + scripts above.

## Fork deltas so far

- F1 (upstream-suitable): BSD-grep trailing-slash portability fix in
  scripts/test-list-aliases.sh + scripts/lint-docs.sh; ENV_LOCK acquisition in
  command_runtime dry-run test (+ F1b: same for 3 flaky tool-sandbox git
  tests). Details: NONO_UPSTREAM_DELTA.md.
- F2 (fork-only docs): SOURCE_LOCK.json, baseline docs, ADR-0001, this file.
- F3-F8 (fork substrate): the `crates/nono/src/lifecycle/` module, one row per
  slice in NONO_UPSTREAM_DELTA.md with its disposition and deletion condition.

## Remaining external blockers

- Linux verification environment (blocks Linux halves of R03/R04/R07/R10 and
  the F4 Linux code path): Docker daemon down on this macOS host — Docker
  Desktop launched headlessly but needs its GUI first-run acceptance.
  Reproduce: `docker ps` → "Cannot connect to the Docker daemon". Operator
  action: open Docker Desktop once and accept the prompt.
  Cross-compile is NOT a workaround: the `nono` lib depends on
  `sigstore-verify` → `aws-lc-sys`, which requires `x86_64-linux-gnu-gcc`.
  Reproduce: `RUSTC=~/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/rustc
  cargo check --target x86_64-unknown-linux-gnu -p nono`.

## Integration instructions for leash-rs (current)

1. Pin: `nono = { git = "<fork remote once pushed>", rev = "<final HEAD>" }`
   — until a remote exists, use a path dependency on this checkout.
2. Consume library APIs only; no `nono` CLI invocation is or will be required
   (guarded by grep gate, BLOCKED_ROWS R14).
3. Product semantics (CrystalOS/HCP/Cedar/Leash policy, activation
   authorization meaning, event forwarding) stay in leash-rs; the fork provides
   only generic mechanics (BLOCKED_ROWS R15 guard).
4. The full lifecycle contract and its guarantees will be documented in
   docs/adr/ + API docs as rows land; BLOCKED_ROWS.json is the authoritative
   per-row status.

## Known incompatibilities

- None yet beyond upstream's own platform limits (see
  PLATFORM_CAPABILITY_BASELINE.md).

## Proposed upstream PRs

- F1/F1b as a portability+test-hygiene PR (upstream requires issue-first per
  AGENTS.md Coding Agent Contribution Policy — not filed; listed for the
  operator).
