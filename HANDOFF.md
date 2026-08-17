# HANDOFF — Parallel Stream 1: Crystal Nono fork (generic sandbox substrate)

Run: EF1A07E7-A38C-4C5E-98CA-9444CA7CFD5C · Updated: 2026-08-17, iteration 1

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
  (pure layer: state machine + validation + event trait; no OS interaction yet).
- Still being added (R02+): `PreparedSandbox, ActivationHandle,
  ActivatedSandbox, SandboxExit, CleanupVerification, SupportReport` (OS-backed;
  ADR-0001 §3-6).

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
| `./scripts/lint-docs.sh`, `./scripts/test-list-aliases.sh` | exit 0 after F1 |
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

## Remaining external blockers

- None declared yet. Candidates being resolved: Linux execution environment
  (Docker daemon not yet up on this macOS host — `docker ps` fails; Docker
  Desktop launched, may require GUI first-run acceptance. Reproduce:
  `docker ps` → "Cannot connect to the Docker daemon").

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
