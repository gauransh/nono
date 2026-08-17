# ADR-0002: Detached supervisor via self-re-exec entry hook

Status: accepted (fork) · Date: 2026-08-17 · Run: EF1A07E7-A38C-4C5E-98CA-9444CA7CFD5C

## Context

R09 requires sessions that survive the launching client: a supervisor process
owning the child (and later the PTY), reachable over IPC, observing exit facts
while no client is connected. Upstream's CLI achieves detach by re-exec'ing the
`nono` binary with setsid. A library cannot do that: it has no binary of its
own, and fork-without-exec of a *long-running* supervisor from a threaded
caller is undefined-behavior territory (allocator and lock state after fork;
the Objective-C runtime on macOS aborts outright). The gate child of ADR-0001
survives fork only because it is syscall-only until execve — a supervisor that
runs Rust indefinitely has no such discipline available.

## Decision

1. **Self-re-exec entry hook.** The embedder opts in by calling
   `nono::lifecycle::supervisor_entry()` first thing in `main()`. The call is
   a no-op unless a private environment marker + inherited handshake
   descriptor identify this process as a supervisor launch; in that case it
   never returns — it runs the supervisor loop and exits. Detached prepare
   launches `current_exe()` (argv[0]-independent, canonicalized at prepare
   time) via ordinary fork+execve — the fork obeys ADR-0001 child discipline
   (syscall-only to exec), and the re-exec'd image is fresh and fork-safe.
2. **Honest support reporting.** `SupportReport.detached_supervisor` cannot be
   probed without launching; it reports the mechanism and its precondition
   (entry hook must be installed by the embedder). A detached prepare against
   a binary whose entry hook is absent fails closed at the readiness handshake
   deadline with a typed error naming the hook.
3. **Supervisor duties.** setsid; owns gate/status ends and the child (same
   prepare internals as ADR-0001); persists every transition to the session
   store; observes waitpid and persists `SandboxExit` (exit facts while
   detached are therefore durable and observable later); serves a control
   socket; exits after cleanup verification or on idle-after-terminal state.
4. **Control protocol v1** (contract §11): Unix socket in the 0700 session
   store dir; peer-UID checked at accept; hello carries protocol version,
   session id, generation — mismatches are typed refusals; length-prefixed
   frames (u32 LE, bounded); malformed, oversize, unknown-op, and
   wrong-state frames are typed refusals; the activation token transits only
   this UID-checked private socket, is compared supervisor-side by digest, and
   never appears in logs or records. Every read on both sides carries a
   deadline (poll-based; closes the ADR-0001 unbounded-read residual for the
   detached path). Stale sockets (dead supervisor identity) are detected via
   record identity reconciliation and cleaned by the store, typed.
5. **Client API.** `DetachedSession` — connect by session id via the store,
   `activate(handle)`, `wait(deadline)`, `stop()`, `status()`,
   `verify_cleanup()`, `detach()` (drop the connection; the session runs on).
   `SessionStore::recover` returns an attachable handle when the record's
   supervisor identity is alive; otherwise the ADR/R09-slice-A cleanup path.

## Consequences

- Detached support requires one line of embedder cooperation; that is the
  price of fork-safety and it is stated in the API docs, the support report,
  and HANDOFF integration instructions (leash-rs adds `supervisor_entry()` at
  the top of its main).
- Test binaries install the hook via their own harness main; live tests can
  therefore exercise true caller-death survival.
- PTY ownership and attach/resize/detach framing build on this in slice C and
  reuse the same socket with a distinct channel discipline (raw bytes vs
  control frames), per contract §8.
