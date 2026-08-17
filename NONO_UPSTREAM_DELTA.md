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
  (Addressed in the fork by F6; the upstream gap statement stands for 149579a7.)
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
| F3 | Generic lifecycle skeleton (`crates/nono/src/lifecycle/`: state.rs pure typed state machine, plan.rs SandboxPlan/ValidatedPlan typestate validation, events.rs EventSink + Observation fidelity, mod.rs + LifecycleError). Wiring: one `NonoError::Lifecycle` variant + 2 diagnostic_code arms (error.rs, +10 lines), `pub mod lifecycle` + curated re-exports (lib.rs), one forced `map_error` arm in bindings/c (exhaustive match requires mapping for new variants). Known API smell recorded: `lifecycle::ResourceLimits` intentionally NOT re-exported at crate root (collides with cgroup-specific `nono::ResourceLimits`); duplicate env keys currently allowed (insertion order preserved) — both revisit-before-ossification | crates/nono/src/lifecycle/*, crates/nono/src/{error,lib}.rs, bindings/c/src/lib.rs | **Upstream-suitable candidate** after stabilization (mechanism only, respects library-is-policy-free boundary; upstream requires issue-first) | Delete if upstream adopts an equivalent staged lifecycle; otherwise carried by fork |

| F4 | OS-backed prepare/activate/wait (`crates/nono/src/lifecycle/`: prepare.rs fork + trusted child pre-exec hold, gate.rs ActivationHandle/single-use release, exit.rs SandboxExit typed facts + ActivatedSandbox::wait, identity.rs ProcessIdentity). Reuses upstream's own primitives: Linux `Sandbox::prepare_seccomp_with_abi` + allocation-free `PreparedLandlockSandbox::apply_raw`; macOS `generate_profile` + `sandbox_init`. **Lifted from CLI-private code:** per-platform process start time, adapted from `nono-cli/src/session.rs::get_process_start_time` (Linux `/proc/<pid>/stat` field 22 parsed after the last `)`; macOS `PROC_PIDTBSDINFO` layout + `proc_pidinfo`), reproduced in `lifecycle/identity.rs` with checked arithmetic and a new boot-identity half — the CLI copy is unchanged, so the two must be reconciled when R09 extracts session code. Hardening beyond upstream's model: the child closes every inherited descriptor before it waits (`close_range` on Linux, bounded loop on macOS) so neither a concurrent `prepare` nor the embedding process leaks descriptors into the customer's program; the gate is released by a 16-byte CSPRNG nonce rather than a constant byte, so a stray copy of the gate descriptor is a denial-of-service at worst; "did the program run" is the three-valued `ActivationObservation` rather than a bool, because a child killed between release and `execve` produces the same EOF as a successful one. Wiring: 4 new `LifecycleError` variants + 4 diagnostic_code arms (error.rs), crate-root re-exports (lib.rs), 2 crate-internal Seatbelt accessors (`generate_seatbelt_profile`, `sandbox_init_raw` in sandbox/{mod,macos}.rs) so the profile is built in the parent and installed in the child, `uuid` dependency and `nix` features `process`/`signal` on both platform dep blocks. Resolves the F3 "duplicate env keys allowed" smell: `SandboxPlan::validate` now refuses them (`PlanError::DuplicateEnvKey`) rather than letting `execve` pick a platform-dependent winner | crates/nono/src/lifecycle/{prepare,gate,exit,identity,plan,mod}.rs, crates/nono/src/sandbox/{mod,macos}.rs, crates/nono/src/{error,lib}.rs, crates/nono/Cargo.toml, crates/nono/tests/lifecycle_live.rs | **Upstream-suitable candidate** after stabilization (mechanism only; no policy) | Delete if upstream adopts an equivalent lifecycle; the identity lift dies when R09 extracts `session.rs` into the library and both callers share one implementation |

| F5 | Shared lifecycle core + Loom race harness (ADR-0001 §2). `lifecycle/sync_core.rs`: `SharedLifecycle` holds the `LifecycleState` and the run's single gate write behind one `Mutex`, exposing `try_begin_activate(effect)` (the activation CAS, which runs the release closure inside the winning critical section, so the gate write is executable at most once for the life of the value across any interleaving of activate/stop/expiry/drop), `begin_stop()` (shuts the gate to activation in the same breath as the transition), `mark(op)`, `state()`, and `claim_gate_close()`. It adds no transitions: every mutation still goes through `LifecycleState::apply`, so the legal-transition table keeps exactly one definition. `PreparedSandbox`/`ActivatedSandbox` are rewired onto it with zero public-API change (same types, signatures, and observable behavior; the 96 existing lifecycle unit tests and all 16 live tests pass unmodified), each holding its own core so the documented freeze-at-handoff behavior survives. `tests/loom_lifecycle.rs` proves five invariants over all interleavings: two activations → one winner + one release; activate vs stop → never both, and no release after a stop wins; child-death vs stop-request → one death records one fact; supervisor-loss vs activate → no release after `Failed`; duplicate cleanup → one winner. Verified to detect a weakened (non-atomic read-then-write) CAS. **Deviation from the loom README:** the cfg is `nono_loom`, not `loom` — RUSTFLAGS reaches every crate in the build, and `--cfg loom` makes `tokio` compile out `tokio::net`, which `hyper-util` (transitive via `sigstore-verify`) then fails to find; the Cargo wiring is otherwise exactly the README's cfg-gated normal dependency. `build.rs` declares the cfg via `cargo::rustc-check-cfg` so `unexpected_cfgs` stays on for real typos | `crates/nono/src/lifecycle/{sync_core,prepare,exit,mod}.rs`, `crates/nono/tests/loom_lifecycle.rs`, `crates/nono/{Cargo.toml,build.rs}` | **Upstream-suitable candidate** after stabilization (mechanism only; loom is dev-only and cfg-gated out of every ordinary build) | Delete with F4 if upstream adopts an equivalent lifecycle |

| F6 | Typed cleanup verification + process-group discipline (ADR-0001 §5). `lifecycle/cleanup.rs`: `CleanupVerification = ConfirmedAbsent{basis} \| StillPresent{survivors} \| Indeterminate{reason} \| Unsupported{reason}` — a closed enum (deliberately not `#[non_exhaustive]`: the four answers are the contract) whose payloads are typed evidence, never a sent signal. `AbsenceBasis::{ReapedAndGroupEmpty, PidAbsent, IdentityMismatch, BootIdChanged}`, `SurvivorEvidence::{ProcessGroupMember, IdentityMatch}`, `IndeterminateReason::{UnprobableProcessGroup, UnprobablePid, ProcessGroupProbeDenied, PidProbeDenied, ProbeFailed, IdentityUnreadable}`, `UnsupportedReason::NoProcessProbe`. Foundation: the child calls `setpgid(0, 0)` immediately after closing the parent's channel ends (async-signal-safe; failure is the new typed `PreExecStage::ProcessGroup`, wire tag `0x0F`, reported through the existing status record), so the run is a *process group* and the parent records its id. Two probes: a reaped run probes `kill(-pgid, 0)` (ESRCH ⇒ ConfirmedAbsent; success ⇒ StillPresent — verification never kills what it finds; EPERM ⇒ Indeterminate), an unobserved death probes the identity (`kill(pid,0)` ESRCH ⇒ ConfirmedAbsent; alive + start-time match ⇒ StillPresent; alive + mismatch ⇒ ConfirmedAbsent{IdentityMismatch}). `ProcessIdentity::is_same_process` is deliberately NOT reused there: its fail-closed `false` would become a *proof of absence*. **Decision recorded:** a boot id that changed since capture is `ConfirmedAbsent{BootIdChanged}`, not Indeterminate — no process survives a reboot, and it is checked before any probe so a reissued number cannot answer for the original. **Caveat kept visible, not designed away:** after a reap the pgid (= the reaped pid) can in principle be reused, so a later group hit is reported as "something is in that group", mitigated by the boot re-check. New APIs: `ActivatedSandbox::{stop, verify_cleanup}`, `PreparedSandbox::verify_cleanup`, `CleanupError` (a refused verification names the state — duplicate confirmation is refused by the same state machine, not absorbed). `stop()` sends SIGKILL to the group *and* to the child pid (a descendant that called `setsid` would otherwise leave the reap waiting), then reports the `waitpid` observation; delivery failures are the new typed `StopError::SignalFailed`. Targets ≤ 1 (`kill(0,…)` = own group, `kill(-1,…)` = everything signalable) are refused before the syscall on both the probe and the stop path. **Known dark spot, documented in `prepare.rs` rather than silently accepted:** a descendant that calls `setsid`/`setpgid` leaves the group and is invisible to both stop and verification — closing it needs a cgroup-class mechanism this slice does not build; a second consequence is that a terminal's Ctrl-C no longer reaches the run by accident. Wiring: 1 `LifecycleError` variant + 1 diagnostic arm, 6 crate-root re-exports, `boot_id` made `pub(crate)` | `crates/nono/src/lifecycle/{cleanup,exit,prepare,gate,identity,mod}.rs`, `crates/nono/src/{error,lib}.rs`, `crates/nono/tests/lifecycle_live.rs` | **Upstream-suitable candidate** after stabilization (mechanism only; the CLI's `run_stop` signal-as-proof path is the thing it would replace) | Delete with F4 if upstream adopts an equivalent lifecycle |

(Further substrate changes appended as they land, one row each.)

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
