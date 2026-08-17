# NONO_UPSTREAM_DELTA — fork vs nolabs-ai/nono @ 149579a7

Maintained per the stream contract. Every fork change lands here with its upstreaming
disposition and deletion condition. Last updated: 2026-08-17 (iteration 1 — discovery).

## 1. Capabilities already present in pinned upstream (149579a7)

Reuse these; do not duplicate (evidence in API_BASELINE.md / PLATFORM_CAPABILITY_BASELINE.md):

- Landlock: V6→V1 HardRequirement ABI probing (`DetectedAbi`), fail-closed ruleset build,
  seccomp network fallbacks (BlockAll / ProxyOnly notify / hard-error on inexpressible),
  arch-guarded hand-built BPF, `restrict_execute` FullyEnforced second layer,
  allocation-free `PreparedLandlockSandbox::apply_raw`.
- Seatbelt: fail-closed `generate_profile` + `sandbox_init` with 132 unit tests; distinct
  Blocked/ProxyOnly/AllowAll SBPL; honest `NetworkFilterUnsupported` for per-port TCP.
- Fork-then-sandbox-then-execve process model with `_exit(126)` fail-closed pre-exec paths;
  no shell anywhere (`which::which` + direct execve).
- PID-reuse-safe liveness (`is_process_alive(pid, started_epoch)`, per-platform start time).
- Session storage with 0700/0600 perms, symlink validation, O_EXCL first-write,
  temp+rename updates (CLI-private).
- Supervisor-owned PTY, ATTACH_ACK_OK/BUSY/DENIED single-client attach protocol,
  detached launch via setsid with readiness polling (CLI-private).
- Supervisor Unix-socket IPC with peer-UID checks on bind+accept (149579a7 itself).
- Hash-chained + Merkle NDJSON audit log (closed payload enum).
- Runtime capability-expansion IPC (`ApprovalBackend` et al.) with request_id replay cache.
- cgroup-v2 lineage marker (fail-closed) and memory/pids resource leaves (CLI, Linux,
  delegation-gated).
- `#[ignore = "reason"]` convention for environment-blocked tests (14 instances) — adopted
  as the R18 blocker-marking mechanism.

## 2. Capabilities present only in newer upstream

**UNKNOWN — not yet diffed.** At clone time upstream main == 149579a7 (pinned == tip).
TODO: re-diff `149579a7..upstream/main` before any rebase or upstream PR; record here.

## 3. Capabilities genuinely missing vs the frozen contract

- Generic staged lifecycle types (plan → prepared → activated → exit → cleanup-verify):
  zero matches repo-wide; current model is one-shot `CapabilitySet` → `Sandbox::apply_*`.
- Pre-exec hold + opaque single-use release capability (activation gate): no discrete
  "prepared, not released" state exists; apply and exec are one synchronous flow.
- Typed exit facts: waitpid results collapse to `i32` (128+signal); `_exit(126/127)`
  sentinels collide with customer exit codes; no ActivationOccurred / SupervisorFailure /
  SandboxApplicationFailure distinction; no positive "customer code started" observation.
- Typed cleanup verification (ConfirmedAbsent/StillPresent/Indeterminate/Unsupported):
  only bool liveness; SIGKILL path never re-checks; cgroup teardown result swallowed.
- Machine-readable support report: `SupportInfo{is_supported: bool, …, details: String}`;
  macOS hardcodes true; `DetectedAbi` granularity internal-only.
- Generic event sink: audit log is a concrete file writer with a closed enum; no subscriber
  API; no per-event fidelity (direct vs reconstructed) flag.
- Library-level session/PTY/attach/wait/stop/recover APIs: all CLI-crate-private; no `wait`
  operation exists even in the CLI.
- Mode-aware fs capability vocabulary: `AccessMode` is Read/Write/ReadWrite only; no
  append/create/truncate/remove/rename/metadata/exec toggles; atomic-write is a CLI regex
  hack (macOS); exec unconditionally allowed on macOS profiles.
- Deterministic concurrency harness: no loom/miri/fuzz anywhere; no race tests for
  stop/attach/activate/wait.
- Session schema versioning: `SessionRecord` has no version field.
- Linux: SignalMode::Isolated silently degrades without V6 scoping (debug! only) —
  candidate fail-closed fix.

## 4. Changes introduced by this fork

| # | Change | Files | Disposition | Deletion condition |
|---|--------|-------|-------------|--------------------|
| F1 | macOS-host baseline fixes (landed iteration 1): (a) BSD-grep trailing-slash bug — dropped trailing slash from 4 `grep -R` dir args so BSD grep stops emitting `crates//` paths that defeat allowlist regexes; (b) ENV_LOCK acquisition in `command_runtime` dry-run test (reads ambient `$HOME` → raced env-mutating siblings; failed 16/20 on macOS, 0/20 after); (c) F1b: same ENV_LOCK guard in 3 `tool-sandbox/dynamic_providers` git tests (PATH stub race; 7/20 baseline flake → 0/20). All test-side serialization only; production overlap guard untouched. Related upstream context: issue #567 (test env mutation cleanup) cited in `test_env.rs:7` | `scripts/test-list-aliases.sh`, `scripts/lint-docs.sh`, `crates/nono-cli/src/command_runtime.rs`, `crates/nono-cli/src/tool-sandbox/dynamic_providers.rs` | **Upstream-suitable** (pure portability/test hygiene) | Delete on upstream merge of equivalent fix |
| F2 | Stream documentation set (SOURCE_LOCK.json, this file, API_BASELINE.md, PLATFORM_CAPABILITY_BASELINE.md, THREAT_MODEL.md, CONTRACT_ASSUMPTIONS.md, BLOCKED_ROWS.json, WORKLOG.md, HANDOFF.md) | repo root | **Fork-only** (process artifacts) | Remove before any upstream PR branch |

(Substrate changes will be appended as they land, one row each.)

## 5. Expected rebase conflicts

- `crates/nono-cli/src/exec_strategy.rs` (234KB, single file): any upstream churn here will
  conflict with lifecycle extraction work. Mitigation: build the generic lifecycle in
  `crates/nono` as new modules; keep exec_strategy.rs edits minimal and mechanical.
- `crates/nono/src/capability.rs` if upstream evolves `AccessMode` while the fork extends the
  mode vocabulary.
- `crates/nono/src/sandbox/{linux,macos}.rs` for mode-mapping changes.
- Scripts under `scripts/` if upstream touches the same lint tooling (F1).

## 6. Deletion conditions policy

Every fork-only row must state how it dies: either (a) upstream merges an equivalent, or
(b) the generic feature it supports is upstreamed and the fork-only shim becomes
unnecessary, or (c) the stream ends and process artifacts are stripped from the PR branch.
