# PLATFORM_CAPABILITY_BASELINE — upstream @ 149579a7

Honest per-platform capability model as implemented at the pinned base.
Host for live verification: aarch64-apple-darwin (Darwin 23.6.0). Linux live runs require a
provisioned environment (Docker/CI) — see BLOCKED_ROWS.json notes.

> **Fork delta (R06).** The three-value `AccessMode` described below is unchanged and still
> means what it meant. A **mode vocabulary** now sits beside it: `FsModeSet` over thirteen
> named operations, granted with `CapabilitySet::allow_path_modes`, compiled per platform into
> a `CompiledModes` that names every bundling, every unrestrictable operation, every delegation
> and every refusal. See "Mode-aware filesystem vocabulary" at the end of this file for the
> full two-platform table and for what it changes about macOS `process-exec`.

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
  documented. *(Fork delta R06: `allow_path_modes` adds those toggles as a parallel grant
  list; `access_to_landlock` and the three coarse modes are unchanged.)*
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
  restriction relies on process-model timing, not a capability bit. *(Fork delta R06: still
  unconditional for a coarse-only capability set — byte-identical to upstream — but scoped to
  the `execute`-granted paths as soon as the set carries one mode grant.)*
- `macos::support_info` (:162-174) hardcodes `is_supported: true` — no probe. The real probe
  (fork + `sandbox_init`) exists only in `nono setup --check-only`
  (`nono-cli/src/setup.rs:91-165`), println-only, no machine-readable output.

## Mode-aware filesystem vocabulary (fork delta, R06)

`crates/nono/src/capability_modes/` — `FsMode` (13 modes), `FsModeSet`, `FsModeCapability`,
`CompiledModes`. Builder entry `CapabilitySet::allow_path_modes(path, modes)` /
`allow_file_modes`. `allow_path`/`allow_file` and `AccessMode` are untouched;
`FsModeSet::describes_access_mode` states each coarse bundle in the new vocabulary's words.

The mapping tables are **pure functions over platform capability data**, not `cfg`-gated code:
`landlock_map::compile` takes a `LandlockRightsAvailable` (an ABI number), so every Linux arm
— both ABI gates included — is exercised by unit tests on this macOS host. Only
`access_fs_for` / `abi_version_number` / the two rule loops in `sandbox/linux.rs` need a
kernel.

| `FsMode` | Linux (Landlock) | macOS (Seatbelt SBPL) |
|---|---|---|
| `read_contents` | `READ_FILE` — enforceable | `file-read-data` + `file-map-executable` — enforceable |
| `read_dir` | `READ_DIR` — enforceable | `file-read-data` — **bundled with `read_contents`** (one op covers `read(2)` and `readdir(3)`) |
| `read_metadata` | **none — unrestrictable**; grant is a disclosed no-op (`always_allowed`) | `file-read-metadata` — **enforceable**; the one place macOS is finer than Linux |
| `write` | `WRITE_FILE` — enforceable | `file-write-data` — enforceable |
| `append` | `WRITE_FILE` — **bundled with `write`** (`AppendImpliesWrite`) | `file-write-data` — **bundled with `write`** (same reason) |
| `create` | `MAKE_REG` **only** — enforceable; the other six `MAKE_*` are deliberately not granted and have no mode | `file-write-create` — enforceable, but covers **all** node types (SBPL cannot narrow to regular files) |
| `truncate` | `TRUNCATE`, **ABI ≥ 3** — else typed refusal `UnsupportedRight{right, abi, needed_abi}`, failing prepare/apply closed | `file-write-data` — **bundled with `write`** (`SeatbeltTruncateIsWriteData`) |
| `remove_file` | `REMOVE_FILE` — enforceable | `file-write-unlink` — enforceable |
| `remove_dir` | `REMOVE_DIR` — enforceable | `file-write-unlink` — **bundled with `remove_file`** |
| `rename` | `REFER`, **ABI ≥ 2** — else typed refusal | `file-write-create` + `file-write-unlink` — **bundled with `create`** (and transitively `remove_file`); SBPL has no rename op |
| `execute` | `EXECUTE` — enforceable | `process-exec*` **scoped to the path** + `file-map-executable` — enforceable |
| `unix_socket_connect` | none — **delegated** to `UnixSocketCapability` (Landlock has no AF_UNIX right; enforced only under the opt-in seccomp-notify mediation) | none — **delegated** to `UnixSocketCapability`'s own `network-outbound` rules |
| `atomic_write` | union of `create`+`write`+`rename`+`remove_file`; inherits `rename`'s ABI-2 gate | same union, plus the hex-suffixed temp-sibling rule for *file* grants (`^<path>[.]tmp[.][0-9]+[.][0-9a-f]+$`, ported from `nono-cli/src/capability_ext.rs:434-460`, narrowed from `file-write*` to the four operations a temp write performs) |

`CompiledModes { enforced, bundled: [(requested, also_granted, why)], always_allowed, refused,
delegated }` — readable before applying via `Sandbox::compile_fs_modes(&caps)`. A refusal is an
error at prepare/apply; nothing is dropped and nothing is widened without an entry naming it.

**The table above is for a grant on a directory. On Linux the path type is part of the
vocabulary.** A Landlock rule whose path is not a directory may carry only the kernel's
`ACCESS_FILE` set — `EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV` — and
`landlock_add_rule` answers `EINVAL` for a rule that carries anything else
(`security/landlock/fs.c`, `add_rule_path_beneath`). So `allow_file_modes(f, …)` naming
`read_dir`, `create`, `remove_file`, `remove_dir`, `rename` — or `atomic_write`, three of whose
four members are in that group — is a typed refusal `DirectoryOnlyRightOnFile{right}`, exactly
like the ABI gates above and for the same reason: the alternatives are a kernel `EINVAL` inside
the forked child (raw `apply_raw` path) or `rust-landlock`'s best-effort mask silently emptying
the rule (`PathBeneath` path, `landlock-0.4.5 src/fs.rs:285-308`, "Linux would return EINVAL"),
and a grant that grants nothing while reading as enforcement is the thing this vocabulary
exists to prevent. macOS has no equivalent restriction: `is_file` there selects only the
atomic-write temp-sibling rule. The per-mode support table reports directory scope, which is
the wider of the two; the file-scope restriction is reported per grant, at compile time.

**What this changes about macOS exec.** The unconditional `(allow process-exec*)` at
`macos.rs:555` is now emitted only when the capability set has **no** mode grants — which is
every existing consumer including all of `nono-cli`, so upstream behaviour is byte-identical
there. A set with at least one mode grant gets `(allow process-exec* (<filter>))` per
`execute`-granted path and nothing else, which turns "which binary may run" from a property of
the process model's timing into a capability bit. Proven live: a `#!` program in a
`read_contents`-granted directory is refused at `execve` with a typed
`ActivationError::PreExecFailed { stage: Exec, errno: EPERM }`, and the same program with
`execute` added exits 0 (`crates/nono/tests/lifecycle_modes_live.rs`).

**Support report.** `SupportReport.fs_modes` carries the per-mode enforceability table
(`enforceable` / `bundled_with{mode}` / `unrestrictable` / `needs_abi{abi}` / `unsupported` /
`delegated{target}`), `probed_live` on Linux against the real detected ABI and `platform_api`
on macOS. `partial` on both platforms, for opposite reasons.

**Verification status.** macOS: live-proven, 14 positive/negative lifecycle pairs. Linux:
mapping logic host-tested against a faked ABI (every arm, all three gates — the two ABI ones
and the file/directory one); the ruleset wiring ran green on the ubuntu job for the first time
in R20 (`linux-landlock-live` 122/0, `linux-lifecycle-live` 52/0), against directory grants
only — the file-scope refusal added in R20 has Linux coverage in
`sandbox/linux.rs::a_directory_only_mode_on_a_file_refuses_the_apply_instead_of_emptying_the_rule`
but has not yet been observed green on a runner.

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
