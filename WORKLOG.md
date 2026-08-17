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
