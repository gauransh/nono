# THREAT_MODEL — Crystal Nono fork (generic substrate)

Seeded from discovery @ 149579a7 (2026-08-17). Grows with each substrate change.
Scope: the generic library substrate only. Product authorization semantics (CrystalOS/HCP/
Leash/Cedar) are out of scope by boundary contract — Nono provides mechanics, never meaning.

## Trust boundaries

1. **Sandboxed child ↔ supervisor (Unix socket IPC).**
   Upstream defends: peer-UID check on both `SupervisorSocket::bind()` and
   `SupervisorListener::accept()` (added in 149579a7, `supervisor/socket.rs:79,481,613`);
   private per-uid socket paths via short symlink (`session.rs:628-692`); request_id replay
   cache for capability-expansion requests (`exec_strategy.rs:3287-3296`).
   Fork must add/verify: bounded length-prefixed framing limits (audit exists but bounds not
   yet verified), protocol-version refusal, unknown-state-transition refusal, stale-socket
   cleanup safety, another-local-user connect test, same-user stale-client replay test.

2. **Session state files (`$XDG_STATE_HOME/nono/sessions/`).**
   Upstream defends: 0700 dir / 0600 files with owner+mode+symlink validation on every
   access (`validate_sessions_dir`, `ensure_private_dir`); O_EXCL first write; temp+rename
   atomic updates; fsync of file+parent.
   Fork must add: schema versioning (SessionRecord has none — corruption/downgrade
   awareness), generation binding, reconciliation against live process identity before
   trusting a state file (partially present via `reconcile_session_record`), corruption-aware
   parse failure modes.

3. **Release capability / activation gate (to be built — does not exist upstream).**
   Requirements from the contract: not visible in argv/env/files/logs/process listings; not
   inheritable by the customer process (close-on-exec discipline, no fd leak past execve);
   single-use with exactly-one-winner under concurrency; bound to session + generation;
   dead after stop/expiry; supervisor-crash leaves a clear state; caller-crash leaves a
   recoverable prepared session or provable cleanup. Threats: replay, cross-session confusion,
   token exfiltration by the (not-yet-activated) child, TOCTOU between verify and exec.

4. **PID identity / reuse.**
   Upstream defends: pid + platform start-time comparison (`is_process_alive`,
   `session.rs:469-573`); cgroup-v2 lineage marker surviving reparenting
   (`lineage_cgroup.rs`, fail-closed).
   Fork must add: boot identity (no boot_id anywhere upstream); typed cleanup verification —
   upstream's SIGKILL path treats signal-send as proof (`run_stop`,
   `session_commands.rs:245-292`) and cgroup teardown swallows StillPresent into a warn log.

5. **Pre-exec window (fork → apply → execve).**
   Upstream defends: only trusted code in the child window; `_exit(126)` fail-closed on any
   setup failure; sandbox applied strictly before execve; no shell; absolute-path resolution
   before sandboxing; tool-sandbox path uses fd-hash verification + `execveat(AT_EMPTY_PATH)`.
   Threats the fork's prepared-process work must not introduce: extending this window into a
   long-lived "hold" state must not let the held (pre-customer) process be manipulated into
   running customer code early; the hold trampoline must remain trusted Nono code only.

6. **seccomp user-notification TOCTOU.**
   Upstream defends: `notif_id_valid` re-validation, bounded /proc/PID/mem reads,
   `classify_af_unix` fail-closed on unclassifiable, arch guard vs non-native/x32.
   Disclosed residual: multi-threaded sockaddr mutation on ALLOWED connect/bind only.
   Fork must: keep the residual disclosed in the support report / event fidelity docs, add
   multi-threaded mutation race tests (contract §6).

7. **Ptrace.**
   Upstream: supervisor self-protection only (PR_SET_DUMPABLE(0); PT_DENY_ATTACH on macOS).
   The sandboxed child's own ptrace use is NOT restricted on Linux (no seccomp ptrace
   filter, no Yama management). Fork decision needed: represent honestly in the support
   report as a dark spot, and/or add a generic ptrace-restriction capability.

8. **Hooks & auxiliary exec surfaces.**
   `hook_runtime.rs` runs profile-configured scripts OUTSIDE the sandbox boundary;
   tool-sandbox `launch.rs` re-invokes the nono binary as a trusted launcher. Both are
   trusted-config surfaces; the generic library lifecycle must not expose them implicitly.

9. **Event integrity & fidelity.**
   Upstream: hash-chain + Merkle on the NDJSON audit log. macOS Seatbelt denials are
   log-stream reconstruction (PID/name string match, cap 50) and stderr-heuristic
   observations share the diagnostic feed without a fidelity flag. Fork must: label
   direct-vs-reconstructed per event, never present reconstruction as kernel observation
   (contract §9), document per-platform fidelity in the support report.

10. **Filesystem capability honesty.**
    Upstream: disclosed coarse bundling (Read⊃Execute+ReadDir; Write⊃Remove+Rename+Truncate+
    Make*), macOS `(allow process-exec*)` unconditional, SignalMode::Isolated silent
    degrade on <V6. Fork must: fail closed where a requested right cannot be represented,
    never silently widen, and expose unsupported rights explicitly in the support report.

## Non-threats (by design)

- Cedar/policy semantics: never parsed or evaluated here.
- Cross-user isolation beyond peer-UID + 0700 state: the substrate targets same-user
  sandboxing; privilege separation across users is out of contract scope.
