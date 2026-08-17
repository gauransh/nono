# CONTRACT_ASSUMPTIONS — parallel/nono-substrate-v1

Assumptions made where the frozen contract leaves latitude. Each is binding on this stream
until the integration agent overrides it. Run EF1A07E7 · 2026-08-17.

1. **Type names differ, semantics do not.** The contract permits different Rust names for
   SandboxPlan/PreparedSandbox/ActivatedSandbox/SandboxExit/CleanupVerification. We will use
   those exact names in `crates/nono` (they are unclaimed there) — the CLI-private
   `pub(crate) PreparedSandbox` in `nono-cli/src/sandbox_prepare.rs` will be renamed or
   reconciled to avoid namesake confusion. The consumer repo's identically-named types in
   `itsm-sandbox-policy-engine/crates/hcp/src/runtime/mod.rs` are a different, product-side
   vocabulary; no code relationship exists and none will be created.

2. **Lifecycle lands in `crates/nono` (the library), never in `nono-cli`** — required to keep
   R14 true once R02 exists. The CLI becomes a consumer of the library lifecycle over time,
   but rewiring the CLI is NOT an acceptance requirement of this stream; upstream CLI
   behavior must merely stay green (R01).

3. **Consumer integration shape.** leash-rs is expected to consume the fork as a Rust
   library dependency (path or git+sha pin per HANDOFF). The only existing consumer
   precedent (unmerged `feat/nono-runtime-provider` branch) shells out to the CLI; that
   pattern is treated as the anti-goal R14 replaces, not as a compatibility target.

4. **CRYSTAL_BASE_SHA refers to origin/main (9dfbc16).** The local read-only checkout of
   itsm-sandbox-policy-engine is on branch `aro/governed-runtime` @ 7256528, which contains
   zero nono references; nono-consumption evidence was read from the unmerged remote branch
   `origin/feat/nono-runtime-provider` via `git show` without checkout. Consumer facts are
   flagged with their actual ref of origin.

5. **"Upstream tests remain green" (R01) means green on this stream's gate matrix**: full
   `cargo test --workspace --no-fail-fast` on the macOS host (after fixing 3 pre-existing
   macOS-host-only upstream failures, documented as delta F1) plus, when a Linux environment
   is provisioned, the same inside Linux. Upstream's own GitHub CI is not re-run by this
   stream. `make ci` parity note: local `make test` omits doc tests; our gate adds
   `cargo test --doc --workspace` to match upstream CI.

6. **Linux live enforcement** (R07 live rows, seccomp-notify races, cgroup tests) requires a
   provisioned Linux environment. Assumption: Docker on this host or CI is acceptable; only
   if neither is available do those rows become BLOCKED with reproduce instructions.
   Landlock inside Docker requires a Landlock-capable kernel (host kernel decides) — Docker
   Desktop on macOS runs a LinuxKit VM whose kernel supports Landlock in recent versions;
   the exact achievable ABI will be recorded in the support-report tests, and rows that need
   a newer ABI than the VM provides will be marked with the exact refusal.

7. **Pre-exec hold mechanism** is assumed to be: supervisor forks the child, child applies
   the platform sandbox, then blocks in trusted Nono code on the release gate (fd/socket
   read) before execve of the customer command. "Customer code unreachable before release"
   is interpreted as: no instruction of the customer executable, interpreter, or loader runs
   pre-release; the held process image is still the trusted Nono binary.

8. **PARALLEL_RUN_ID** appears in docs/handoff artifacts only, never in code or APIs.

9. **Branch stays local** (no fork repo exists on GitHub; gh auth is available). Pushing/
   creating `gauransh/nono` is an outward-facing action deferred to explicit authorization;
   HANDOFF will carry the local branch + HEAD SHA and exact push instructions.

10. **AGENTS.md inaccuracies are not contract.** Upstream AGENTS.md claims a third "Monitor"
    exec strategy that does not exist in code; code reality governs.

11. **Generic event sink** will be delivered as a library trait with per-event fidelity
    labels (DirectlyObserved vs Reconstructed vs Heuristic). macOS Seatbelt denial
    reconstruction stays available but is never presented as a kernel-observed event; the
    contract's "events not visible to the platform remain absent" is satisfied by the
    fidelity label plus per-platform documentation, keeping the existing reconstruction
    features intact for CLI users.

12. **Resource limits**: contract requires "generic resource limits" representable in the
    plan. Upstream has cgroup-v2 memory/pids only (Linux, delegation-gated, CLI-level).
    Assumption: the plan API represents requested limits; the support report states
    per-platform enforceability (macOS: largely Unsupported; Linux: cgroup-v2 when
    delegated); fail-closed only when the caller marks a limit required.
