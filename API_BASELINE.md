# API_BASELINE — upstream nolabs-ai/nono @ 149579a7

Ground truth of the public library surface at the pinned base, before any fork change.
Evidence gathered 2026-08-17 by 8-way parallel read (run EF1A07E7).

## Workspace shape

- Members: `crates/nono` (library), `crates/nono-cli` (`[[bin]] name = "nono"`, no lib.rs),
  `crates/nono-proxy`, `crates/nono-test-support`, `bindings/c` (`nono-ffi`, cdylib+staticlib).
- Dependency edge: `nono-cli/Cargo.toml:44` and `bindings/c/Cargo.toml:18` path-depend on `nono`.
  The library is a leaf: zero dependency on the CLI, zero `Command::new("nono")` /
  `CARGO_BIN_EXE_nono` in `crates/nono/src` (R14 holds at baseline).
- Features: `system-keyring` only (default-on; zbus/async-secret-service on Linux,
  apple-native keyring on macOS). No CLI-only gate on core functionality.

## Public library surface (`crates/nono/src/lib.rs:48-107`)

15 pub modules, re-exported at crate root: audit, capability, diagnostic, error, keystore,
manifest, manifest_convert, net_filter, path, query, resource, sandbox, scrub, state,
supervisor, trust, undo.

Key types:

| Symbol | Location | Role |
|---|---|---|
| `CapabilitySet` | `capability.rs:927` (impl :990) | Builder consumed by value (`allow_path`/`allow_file`/`allow_unix_socket`/`block_network` → `Result<Self>`). The only plan-like object; not a typed lifecycle stage. |
| `AccessMode` | `capability.rs:86-93` | **3 values only**: Read / Write / ReadWrite. |
| `UnixSocketCapability` | `capability.rs:349-578` | Separate model: `Connect`/`ConnectBind` × `File`/`DirChildren`/`DirSubtree`. |
| `Sandbox::apply_auto/apply_landlock/apply_seccomp/apply_external` | `sandbox/mod.rs:77-235` | Static, irreversible, restrict the **current** process in one call. No staging. |
| `Sandbox::support_info` → `SupportInfo` | `sandbox/mod.rs:45-54,213-234` | `{is_supported: bool, platform: &'static str, details: String}` — single-boolean anti-pattern (R12 target). |
| `NonoError` | `error.rs:8` | Flat enum. Has `SessionNotFound`/`AttachBusy`/`SessionGone` (consumed only by nono-cli); **no** activation-replay / expiry / generation-mismatch variants. |
| `supervisor::{ApprovalBackend, CapabilityRequest, ApprovalRequest, ApprovalDecision, AuditEntry, SupervisorSocket, SupervisorListener}` | `supervisor/mod.rs`, `supervisor/types.rs`, `supervisor/socket.rs` | Mid-session runtime capability-**expansion** IPC (sandboxed child asks unsandboxed parent for more access). request_id replay protection scoped to approval requests. NOT an activation gate. |
| `state::SandboxState` | `state.rs:14` | Serde snapshot of a CapabilitySet for rollback/diagnostics. Not a lifecycle stage. |
| `query::QueryContext/QueryResult` | `query.rs:13,52` | Pre-apply dry-run permission check. |
| `diagnostic::SessionDiagnosticReport` | `diagnostic/report.rs:15` | Post-hoc report; `exit_code: i32` only. |
| `audit::{AuditRecorder, AuditEventRecord, AuditEventPayload}` | `audit.rs:49,209,402` | Hash-chained + Merkle NDJSON file writer; closed payload enum; no pluggable sink. |

## What has NO API expression at baseline

Repo-wide grep: zero matches for `SandboxPlan`, public `PreparedSandbox`, `ActivatedSandbox`,
`SandboxExit`, `CleanupVerification`, `ActivationToken`/`ReleaseToken`, single-use activation,
generation binding. The only `PreparedSandbox` is `pub(crate)` in
`crates/nono-cli/src/sandbox_prepare.rs:403` (CLI-internal, different concept).

Functionality that exists **only** inside nono-cli (crate-private, unreachable by library
consumers — the core of the fork's work is lifting generic equivalents into `crates/nono`):

- Process launch: `ExecStrategy{Direct,Supervised}` (`exec_strategy.rs:184`; AGENTS.md's
  "Monitor" strategy does not exist in code). Supervised (default): `fork()` at
  `exec_strategy.rs:873`; child runs only trusted code — cgroup self-attach, chdir,
  `Sandbox::apply_*` (:1021-1074), seccomp-notify install (:1087-1298) — then direct
  `libc::execve` at :1332 (pre-resolved absolute path via `which::which`, prebuilt argv/envp,
  no shell). Every pre-exec failure `_exit(126)`s fail-closed (~13 sites).
- Exit observation: `waitpid`/`WaitStatus` (`exec_strategy.rs:2173` + PTY variants), collapsed
  to bare `i32` (128+signal) at :1620-1640. No typed exit facts; `_exit(126/127)` sentinel
  collides with customer exit codes; "activation occurred" is never positively observed.
- Sessions: `SessionRecord` (`session.rs:23`, JSON at `$XDG_STATE_HOME/nono/sessions/{id}.json`,
  0700 dir / 0600 files, O_EXCL first-write, temp+rename updates, **no schema-version field**);
  PID-reuse-safe liveness `is_process_alive(pid, started_epoch)` (`session.rs:469-573`,
  /proc start-time on Linux, proc_pidinfo on macOS; no boot_id).
- PTY/attach: `PtyProxy`/`PtyPair` (`pty_proxy.rs:239,112`, supervisor owns master),
  length-prefixed handshake `ATTACH_ACK_OK/BUSY/DENIED` (exactly-one-client),
  `run_detached_launch` (`startup_runtime.rs:26`, single fork + setsid, polls session file +
  socket before success). **No `nono wait` subcommand exists.**
- Second exec path: tool-sandbox `ResolvedToolSandboxPlan` + `execveat(AT_EMPTY_PATH)` on a
  hashed fd (`tool-sandbox/platform/linux.rs:151,~999`), macOS `libc::execve`
  (`platform/macos.rs:762`); unreconciled with exec_strategy.rs.

## Consumer reality (read-only reference)

itsm-sandbox-policy-engine checked-out HEAD (branch `aro/governed-runtime` @ 7256528 — note:
NOT the pinned CRYSTAL_BASE_SHA 9dfbc16, which is origin/main) has **zero** nono references;
it uses the `leash` CLI (BPF-LSM) + bwrap-runtime. The unmerged branch
`origin/feat/nono-runtime-provider` (ff7d2fa..7fdb64e) adds `NonoRuntime`
(`crates/hcp/src/runtime/nono.rs`, 1360 lines): pure CLI subprocess consumption —
`nono run --silent [--detached] [--profile P] [--deny-domain D]... [--block-net] --name S
--allow DIR -- cmd...`, `nono stop`, `nono attach`, `nono ps`. No Cargo dependency on nono
anywhere; only version reference is an informal "probed against nono 0.73.0" note. Cedar
lowering (`extract_forbids`, `lower_policy`) lives entirely consumer-side. This is the
CLI-invocation pattern R14 forbids as a requirement — the fork's library lifecycle is what
replaces it.
