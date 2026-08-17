# PLATFORM_CAPABILITY_BASELINE — upstream @ 149579a7

Honest per-platform capability model as implemented at the pinned base.
Host for live verification: aarch64-apple-darwin (Darwin 23.6.0). Linux live runs require a
provisioned environment (Docker/CI) — see BLOCKED_ROWS.json notes.

## Linux (crates/nono/src/sandbox/linux.rs, 5802 lines)

### Landlock
- ABI probing: `detect_abi`/`detect_abi_uncached`/`probe_abi_candidate` (:391-452, :229-337)
  probe V6→V1 with `CompatLevel::HardRequirement` (mismatch errors, never silently drops
  bits), cached in a `OnceLock`. `DetectedAbi` exposes `has_refer/has_truncate/has_execute/
  has_network/has_ioctl_dev/has_scoping` — real granularity, but **internal only** (not
  surfaced in `SupportInfo`).
- Ruleset build: `apply_with_abi_inner` (:953-1320) — HardRequirement for fs/net/scope
  handling; BestEffort only for per-rule `add_rule`; hard-errors `RulesetStatus::NotEnforced`;
  accepts+logs `PartiallyEnforced` (comment: only reachable from fs-feature fallback).
- Allocation-free path: `PreparedLandlockSandbox::apply_raw` (:128-227) for raw clone(2)
  children (no libc/heap).
- Access mapping `access_to_landlock` (:538-593): Read ⇒ {ReadFile, ReadDir, **Execute**};
  Write ⇒ {WriteFile, MakeChar/Dir/Reg/Sock/Fifo/Block/Sym, RemoveFile, RemoveDir, Refer,
  Truncate}. Bundling is disclosed in `docs/cli/internals/landlock.mdx` ("Access Rights
  Mapping"; atomic-write is why Remove/Refer/Truncate ride along with Write). **No independent
  append/create/truncate/remove/rename/metadata/exec toggles** — coarseness, honestly
  documented.
- `IoctlDev` (V5+): granted only for detected device paths/dirs, not blanket.
- Execute narrowing: `Sandbox::restrict_execute` (:1336-1421) and CLI
  `apply_outer_exec_gate` (`tool-sandbox/platform/linux.rs:3093-3175`) stack a second
  execute-only layer; both require `FullyEnforced` (stricter than the main path).

### Network
- TCP: per-port `AccessNet::ConnectTcp/BindTcp` rules (ABI V4+) for proxy port, bind_ports,
  tcp_connect_ports/tcp_bind_ports, localhost ports/ranges (skipped in AllowAll). Port 0
  (macOS wildcard) hard-rejected on Linux.
- ABI<V4 fallbacks (`seccomp_network_fallback_mode` :2763-2784): Blocked →
  `SeccompNetFallback::BlockAll` (hand-written BPF, allow-only-AF_UNIX, deny
  socket/socketpair/io_uring_setup); Blocked-with-port-exceptions → **hard error**
  (inexpressible ⇒ refuse, not widen); ProxyOnly → seccomp-notify
  (`SECCOMP_RET_USER_NOTIF`) mediation: traps connect/bind/sendto/sendmsg/sendmmsg,
  inspects sockaddrs via /proc/PID/mem, `notif_id_valid` re-validation against notify TOCTOU,
  `classify_af_unix` (:2585-2618) fail-closes unclassifiable addresses to Unnamed/deny.
  Disclosed residual: multi-threaded sockaddr mutation race on the ALLOWED path only
  (landlock.mdx); denied path race-free.
- All static BPF is hand-built `SockFilterInsn` installed via raw `SYS_seccomp`, each guarded
  by `seccomp_arch_guard()` (rejects non-native AUDIT_ARCH and the x32 syscall-bit trick).

### Scopes / IPC / signals (Landlock V6)
- `SignalMode::AllowSameSandbox` → requests `Scope::Signal`, **hard-errors** without V6.
- `SignalMode::Isolated` → requests scoping if available, otherwise **silently proceeds with
  a debug! log** — a silent-degrade caveat vs the fail-closed bar (flagged; candidate fix).
- `IpcMode::SharedMemoryOnly` → `Scope::AbstractUnixSocket` when available; `IpcMode::Full`
  unscoped by explicit compatibility choice.
- Pathname AF_UNIX mediation is opt-in (`linux.af_unix_mediation`, off by default).

### Confirmed absent on Linux (grep-verified, not merely undocumented)
- **Namespaces**: zero CLONE_NEW*/unshare/setns anywhere.
- **rlimits**: zero setrlimit/RLIMIT_*. Resource limits exist only as CLI cgroup-v2
  memory/pids leaves (`resource_cgroup.rs`; requires delegated hierarchy; 7 #[ignore] tests).
- **Child ptrace restriction**: no seccomp ptrace filter, no Yama management. Only
  supervisor self-protection: `PR_SET_DUMPABLE(0)` (`exec_strategy.rs:1282,1389`).
- Process-tree attribution: cgroup-v2 lineage marker (`lineage_cgroup.rs`, 556 lines,
  fail-closed when no writable cgroup base); Landlock inheritance is the kernel's own
  per-process property, not re-verified for descendants.

## macOS (crates/nono/src/sandbox/macos.rs, 2231 lines, 132 unit tests)

- `generate_profile` (:529) emits SBPL from `(version 1)`/`(deny default)`; `apply`
  (:899-940) calls private `sandbox_init` FFI (:23-26) in the current process; any non-zero
  return, non-UTF8 path, control char, or unsupported request ⇒ `Err` — fail-closed by
  construction. One source of truth: tool-sandbox reuses `Sandbox::apply_auto` (platform/
  macos.rs:729).
- Applied fork-then-sandbox: child applies profile strictly before execve
  (`exec_strategy.rs:522+`, "fail-closed: never run unconfined").
- Inheritance: kernel-native; `(allow process-fork)`/`(allow process-exec*)`; consumed
  sandbox-extension tokens documented to survive fork/exec (:115-116).
- Network: `NetworkMode::{Blocked, ProxyOnly{port,bind_ports}, AllowAll}` emit distinct SBPL;
  per-port TCP filtering **honestly rejected** (`NonoError::NetworkFilterUnsupported`,
  :883-890 — Seatbelt cannot filter by TCP port).
- Atomic-write: CLI-layer regex injection only — `add_atomic_write_rule`
  (`nono-cli/src/capability_ext.rs:434-460`) emits
  `(allow file-write* file-read-metadata (regex "^<path>\.tmp\.[0-9]+\.[0-9a-f]+$"))` per
  Write grant; hex-suffix + read-metadata fix in 5f0b95a0. Not a library capability concept;
  unverified whether reachable via tool-sandbox `FsGrantSpec` at all.
- Loader/interpreter flows: shebang/`env` interpreter grants
  (`env_shebang_target_interpreter`), Python.framework bundle carve-outs, dyld shared-cache
  paths — in `tool-sandbox/platform/macos.rs` (~2748-2886) with unit tests.
- Mode model: same 3-value `AccessMode`, structural on macOS (SBPL `file-read*`/`file-write*`
  are themselves wildcard bundles). Metadata-only rules exist solely as internal parent-dir/
  PATH traversal derivations (:660-668, :754-798), not a selectable mode.
- **Exec is not per-path gated**: `(allow process-exec*)` unconditional (:555); executable
  restriction relies on process-model timing, not a capability bit.
- `macos::support_info` (:162-174) hardcodes `is_supported: true` — no probe. The real probe
  (fork + `sandbox_init`) exists only in `nono setup --check-only`
  (`nono-cli/src/setup.rs:91-165`), println-only, no machine-readable output.

## Observation fidelity (both platforms)

- Linux path/IPC denials: directly observed (seccomp-notify / supervisor socket).
- macOS Seatbelt denials: **reconstructed** post-hoc from `log stream`/`log show`
  (`nono-cli/src/sandbox_log.rs:19-240`), PID/process-name string attribution, cap
  MAX_VIOLATIONS=50, `log show --last 10s` fallback. Doc-comment discloses best-effort
  (`diagnostic/records.rs:108-135`).
- `NonoDiagnosticDetail` (:9) tags origin (SupervisedDenial/IpcDenial/SeatbeltViolation/
  StderrObservation) but has **no directly-observed-vs-reconstructed flag**;
  `StderrObservation` is heuristic PTY/stderr text inference mixed into the same feed.
- Cleanup: `run_stop` SIGTERM path polls PID-reuse-safe liveness, but SIGKILL-on-timeout
  prints "Stopped (forced)" with **no post-kill re-check** (signal treated as proof —
  R11 violation). Real kernel-backed verification exists only in
  `resource_cgroup.rs::teardown` (cgroup.kill + poll cgroup.procs before rmdir) and its
  StillPresent outcome is swallowed into `tracing::warn!`.
