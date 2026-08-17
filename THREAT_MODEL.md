# THREAT_MODEL — Crystal Nono fork (generic substrate)

Seeded from discovery @ `149579a7` (2026-08-17). Refreshed at iteration 11 against the
implemented substrate (F3–F11) and re-diffed upstream `9078ffcf`.

Scope: the generic library substrate only. Product authorization semantics (CrystalOS/HCP/
Leash/Cedar) are out of scope by boundary contract — Nono provides mechanics, never meaning.

**What changed between the seed and now.** The seed listed boundaries as *requirements*
("Fork must add…"). Every one of those boundaries now exists as running code with a
mechanism, a typed refusal and, in most cases, a removal-detection transcript in
`WORKLOG.md`. §1 is that mapping. §2 records the two adversarial reviews as finding→fix
pairs. §3 is the honest part: what is still true and accepted, including the largest one —
**none of this has ever run on a Linux kernel.**

---

## 1. Trust boundaries as implemented

### 1.1 Activation gate: the launcher ↔ the held pre-customer child

*Seed status: "to be built — does not exist upstream."* Now `lifecycle/gate.rs` +
`lifecycle/prepare.rs`.

The boundary is a **pipe pair across a fork**, not a name anything can look up. A prepared
child is trusted Nono code that has applied the sandbox and is blocked reading a descriptor;
what crosses is a byte, and the byte is a secret.

| Requirement (seed) | Mechanism (now) |
|---|---|
| Not visible in argv/env/files/logs/process listings | The activation token is a 32-byte CSPRNG draw taken **after** the fork, parent-side only, held in `Zeroizing`. It is never written to a record, an environment, an argv, a `Debug` impl or an event. `ActivationOutcome` is structurally proven token-free by a test that walks the serialized tree rejecting any key named token/nonce/secret/digest **and any array** (every secret here is a `[u8; N]`, so an array is the shape a leak would take). |
| Not inheritable by the customer process | The child sweeps **every** inherited descriptor above 2 except its two channel ends before it waits — `close_range` on Linux, a bounded `getdtablesize` loop on macOS. Removal-detected live: the test asks the child to `/bin/test -e /dev/fd/N` and requires exit 1. |
| Single-use, exactly one winner under concurrency | `SharedLifecycle` (`sync_core.rs`) holds the state and the run's one gate write behind a single `Mutex`; `try_begin_activate` runs the release closure **inside** the winning critical section, so the write is executable at most once across any interleaving of activate/stop/expiry/drop. Seven Loom models exhaust the interleavings; the harness is verified to fail when the CAS is weakened to read-then-write. |
| Bound to session + generation | Checked on both sides of the control protocol and by the gate itself; a cross-session or cross-generation activation is a typed refusal, not a silent no-op. |
| Dead after stop/expiry | `begin_stop` shuts the gate to activation **in the same transition** that records the stop. Stop-then-activate is refused forever. |
| Caller crash leaves a recoverable or provably-cleaned session | `SessionStore` + `reconcile` (§1.3). |

Threats considered and where they land: **replay** → the state machine answers
`AlreadyActivated`, not the protocol, so the refusal is the same whichever path asked;
**forgery** → release and abort are per-gate random 16-byte nonces compared in constant time
(`black_box`), so a fixed-byte guess is refused and a stray copy of the gate descriptor is a
denial of service at worst, not an activation; **cross-session confusion** → session +
generation are part of the compare; **token exfiltration by the held child** → on the
detached path the token is drawn *in the supervisor, after the exec*, so it never exists in
the customer child's address space at all, which is strictly stronger than the attached path
where it exists between fork and exec.

### 1.2 Control socket: an arbitrary local process ↔ a detached supervisor

*Seed status: "bounds not yet verified, protocol-version refusal, stale-socket cleanup
safety."* Now `lifecycle/protocol.rs` + `lifecycle/supervisor.rs`.

The socket lives at `<store>/<session>.sock`, 0600 inside a 0700 store. It is **bound and
listening before the fork** and the listening descriptor is passed through the `execve`, so
"the supervisor is ready" implies "the socket has been listening since before the supervisor
existed" — there is no window in which a name exists and nothing is behind it.

- **Peer identity.** Every accept consults `supervisor::socket::peer_credentials` — upstream's
  own code, reused rather than reimplemented. A foreign uid is closed **without a word**,
  because answering at all would confirm the session exists.
- **Frame bounds.** `MAX_CONTROL_FRAME_BYTES` (64 KiB) is checked **from the u32-LE length
  prefix before a single byte of body is read or allocated**. The constant is
  `MAX_RECORD_BYTES + 4 KiB`, and the inequality is held by a module-level
  `const _: () = assert!(…)` — a build that broke it would not compile.
  `MAX_ATTACH_PAYLOAD_BYTES` (32 KiB) is enforced the same way on the raw channel.
- **Protocol version and session binding.** Hello first in both directions, carrying
  `{version, session, generation}`, each checked on both sides. An operation before hello is
  refused. Removal-detected: deleting the version check greets a wrong-version client;
  deleting the hello-first guard serves a `Status` sent before any hello.
- **Liveness.** Every read and write on both sides is `poll`-deadline-bounded — this closes
  ADR-0001's unbounded-read residual for this path. Requests carry a tighter 2 s deadline
  than replies (10 s), because a request is a few hundred bytes the client already wrote,
  and the thread being held is the same one that accepts connections and watches the child.
- **Single client.** A second connection is told `ControlRefusal::Busy` and closed, never
  queued.
- **Stale sockets.** A `Gone` supervisor's socket is unlinked by the store at the point its
  staleness was established **by identity**, not guessed from a failed connect.

The raw attach channel is a distinct concern and is separated **by framing, not by content**:
after `AttachAck` both sides speak `[u8 tag][u32 len][bytes]`, so an `Input` payload reaches
the PTY master byte for byte including `0xFF`, NULs and a sequence that *is* a well-formed
frame header — the length prefix already said how many bytes the frame owns, so there is no
escape to get wrong and no in-band sequence to collide with. Direction is enforced (an
`Output` from a client is a peer claiming to own the other end). An unknown tag, wrong
direction or oversize length is a typed `AttachViolation` and ends the **channel**, never the
run — which a successful reattach proves.

### 1.3 Session state files: the store ↔ anything else with the same uid

*Seed status: "schema versioning (SessionRecord has none), generation binding, reconciliation
before trusting a state file."* Now `lifecycle/session_store.rs`.

The discipline is **open the directory once, then never walk a path again**: the store is
opened `O_DIRECTORY | O_NOFOLLOW` and every record is reached by `openat` against that
descriptor. Directory permissions are **checked, not repaired** (real directory, owned by the
effective uid, no group or world bits — each a distinct typed refusal), because silently
fixing a wrong-permission store is indistinguishable from silently accepting an attacker's.

Records are `<uuid>.json` at 0600 by explicit `fchmod` (`O_CREAT`'s mode is filtered through
the umask, so the mode argument alone is not a guarantee), first-written `O_EXCL`, updated
write-to-temp + `renameat` in the same directory with the temp `O_EXCL`, 0600, randomly named
and deliberately **not** a record name so an enumeration racing an update walks past it, then
`fsync` file and directory.

- **Schema version is a probe, not a guess.** One field is read before the rest of the shape;
  a version neither v1 nor v2 implements is `UnsupportedSchemaVersion`. v1 compatibility is
  *explicit*: two `deny_unknown_fields` shapes, a v1 record upgraded **in memory** with
  absence reported (no supervisor, no exit, empty ring) rather than invented.
- **Corruption is reported beside its siblings**, not instead of them: `sessions()` yields one
  `Result` per record. The CLI's own registry `debug!`s and skips, which is the failure mode
  this exists to avoid.
- **A record is never trusted as a statement about the present.** It is written *after* the
  transition it describes and outside the lifecycle lock, so it may lag by one step. That is
  stated, and it is exactly why `recover()` reconciles against a live identity probe before
  anything is believed.
- **Nothing product-shaped is durable.** No command line, no environment, no policy: a record
  that carried the run's argv would be a durable copy of whatever secrets it held.

Removal-detected: dropping the record's `O_NOFOLLOW` follows a symlink and returns a planted
decoy; dropping the store's `O_NOFOLLOW` lands the store on a link's 0755 target; deleting the
skip-on-parse-failure turns 4 accounted-for records into 1; deleting the schema check reads a
v2 record as v1; deleting the permission check accepts a 0755 store.

### 1.4 Pre-exec window: fork → terminal → sandbox → sweep → execve

*Seed concern: "extending this window into a long-lived hold must not let the held process be
manipulated into running customer code early; the trampoline must remain trusted Nono code
only."* Held.

The child is **syscalls only over parent-built buffers until `execve`**. Nothing in the window
allocates, takes a lock or walks the filesystem — all of which are undefined behaviour after
`fork` in a threaded process. The ordering is load-bearing and is the ordering a reviewer
should check first:

```
close parent's ends
  → setsid (interactive) or setpgid(0,0) (headless)
  → dup2(slave, 0/1/2), TIOCSCTTY with arg 0 — never 1, which STEALS a terminal
  → close the spare slave AND the master
  → sandbox apply
  → sweep every other descriptor
  → block on the gate
  → execve
```

The terminal is adopted **before** the sandbox apply, so a confined child is never granted the
right to open a device node. The child closes the master as well as the spare slave, because a
program holding the master of its own controlling terminal could read back everything it wrote
and everything typed at it. Any failure in the sequence is a typed `PreExecStage` carried out
on a 5-byte status record — sentinel exit codes carry no protocol, so a customer exit code can
never be mistaken for a supervisor fact.

**No shell, anywhere.** Hostile argv arrives at the program literally; there is no interpreter
between the plan and `execve` to reinterpret it.

The two-fork detached path keeps the same discipline: the launcher forks an intermediate that
forks the supervisor-to-be and `_exit(0)`s, so the supervisor is reparented to init and a
long-lived launcher never accumulates a zombie it cannot be expected to reap. **Nothing about
the plan crosses the exec** — image, argv, environment and platform policy are built and used
on the launcher's side, so a `CapabilitySet` is never serialized and re-trusted across a
boundary.

### 1.5 The re-exec entry hook

New boundary, introduced by F9, with no upstream analogue: `nono::lifecycle::supervisor_entry()`
as the **first statement of `main`**.

It is a no-op without a private environment marker (`NONO_LIFECYCLE_SUPERVISOR`), and the
marker is **protocol, not configuration** — it is removed from the environment before any
other work, so it can never be inherited by a customer child. "First statement" is a real
requirement and not a style note: removing an environment variable is sound only while the
process is single-threaded.

The threat this shape avoids: a library that re-executed *some* binary would need a path to
re-execute, and a path is something an attacker can arrange to control. The supervisor is
**this binary**, `current_exe()`, re-executed. The failure mode when the hook is absent is
closed and named: `PrepareError::SupervisorUnresponsive`, whose message names the function
that is missing.

### 1.6 PID identity and reuse

*Seed: "Fork must add boot identity (no boot_id anywhere upstream); typed cleanup verification."*
Now `lifecycle/identity.rs` + `lifecycle/cleanup.rs`.

`CleanupVerification` is a closed four-answer enum with typed evidence payloads, and **a sent
signal is never a basis** — which is precisely what upstream's `run_stop` treats as proof. The
run leads its own process group, so a reaped run probes `kill(-pgid, 0)` rather than a pid
`waitpid` already consumed.

The reuse defences, in the order they are consulted: a **boot id that changed** is
`ConfirmedAbsent { BootIdChanged }` and is checked *before* any probe, so a reissued number
cannot answer for the original; **alive but a different start time** is
`ConfirmedAbsent { IdentityMismatch }`; an **unreadable start time** is `Indeterminate`, never
a proof of absence. `ProcessIdentity::is_same_process` is deliberately *not* reused on this
path — its fail-closed `false` would become a proof of absence, which is the one direction a
fail-closed answer must not be allowed to travel. Targets ≤ 1 (`kill(0, …)` = own group,
`kill(-1, …)` = everything signalable) are refused before the syscall on both probe and stop.

### 1.7 Event integrity and fidelity

*Seed: "label direct-vs-reconstructed, never present reconstruction as kernel observation."*
Held, and taken one step further: **the vocabulary has no variant for what the platform does
not show.** There is no kernel-denial event to synthesize one into. `event_observation` in the
support report reports `kernel_denial` as `not_observed` on **both** platforms, and the CLI's
macOS `log stream` reconstruction is explicitly not claimed as library machinery.

Every event carries an `Observation` fidelity label. The two places the supervisor *learns*
rather than *witnesses* — a child that ended at the gate while nobody asked, and the
`PrepareStarted` of an adopted child whose fork happened in the launcher before the supervisor
image existed — are emitted as `Observation::Reconstructed`.

`seq` is the documented ordering authority and `observed_at` explicitly is not, because a wall
clock can step. Removal-detected: giving `ActivatedSandbox` its own emitter instead of sharing
the prepared one restarts `seq` at 0 mid-run and fails both live sequence tests.

### 1.8 Filesystem capability honesty

*Seed: "fail closed where a requested right cannot be represented, never silently widen,
expose unsupported rights explicitly."* Now `capability_modes/` (F11).

The anti-silent-widening guarantee is one rule: `CompiledModes::bundled` lists exactly the
modes the caller did **not** ask for that the grant confers anyway, and it is produced by the
*same* compilation the profile or ruleset is built from — so the disclosure and the
enforcement cannot disagree. Three consequences worth stating as security properties:

- **An ABI gate refuses; it does not drop.** On a kernel below Landlock V3 there is no
  `TRUNCATE` right, so truncation is not restrictable *at all*; a `truncate` grant that
  compiled to nothing would read as enforcement. It is `NonoError::ModeUnsupported` instead.
- **`create` is `MAKE_REG` and nothing else.** Landlock has seven make-rights and coarse
  `Write` grants all seven. Folding them into one mode would mean a caller who asked to create
  a file also got to create a device node and a symlink.
- **`read_metadata` is `unrestrictable` on Linux and says so.** Landlock has no right covering
  `stat(2)`, so a metadata *denial* cannot be expressed there at all. The grant is a typed
  `always_allowed` disclosure — an absence of enforcement, not a denial.

The macOS `execute` scoping closes the seed's specific complaint that `(allow process-exec*)`
was unconditional: it still is, byte-for-byte, for a capability set with no mode grants (every
existing consumer), and becomes a per-path filter as soon as the set carries one.

### 1.9 Boundaries inherited unchanged from upstream

Recorded so the fork's silence about them is deliberate rather than an omission. **The fork
adds no defence and removes none:** seccomp user-notification TOCTOU (`notif_id_valid`
re-validation, bounded `/proc/PID/mem` reads, `classify_af_unix` fail-closed, arch guard — and
upstream `5be192ad` has since made the arch prologue **structurally unskippable** via
`ArchGuarded<T>`, which strictly improves this boundary for us on the next rebase); ptrace
(supervisor self-protection only — the sandboxed child's own ptrace use is unrestricted on
Linux, carried below as an accepted residual); hooks and auxiliary exec surfaces
(`hook_runtime.rs` runs profile-configured scripts *outside* the sandbox boundary; the generic
library lifecycle does not expose them, implicitly or otherwise); the hash-chained + Merkle
NDJSON audit log.

---

## 2. Defences added by adversarial review

Two independent reviews. Every finding was applied in the same iteration it was raised; the
transcripts are in `WORKLOG.md`.

### Review #1 — iteration 3, against F4 (prepare/activate/wait). Verdict: ship with fixes.

| Sev | Finding | Fix |
|---|---|---|
| HIGH | The held child inherited every descriptor the embedding process had open, right up to `execve` — so a customer program could start life holding the caller's file handles. | `close_inherited_descriptors`: sweep everything above 2 except the two channel ends. Removal-detection-verified by a live test that asks the child to `/bin/test -e /dev/fd/N`. |
| HIGH | The gate release was a **constant byte** — forgeable by anyone who could write to the descriptor. | Per-gate random 16-byte release *and* abort nonces, classified in constant time. A fixed-byte forgery is test-locked as refused. |
| MED | EOF on the status pipe was read as "the program ran", but a child killed between release and `execve` produces the same EOF. | Three-valued `ActivationObservation { Observed, NotActivated, ExecOrKilledPreExec }`; the `bool` accessor was **removed** rather than kept as a convenience, because a convenience is how the overclaim comes back. |
| MED | `finish_failed` reaped without killing and then fabricated an exit fact. | `kill_and_reap_observed`: kill first, and report only what `waitpid` said. |
| MED | A stop or expiry surfaced as the sentinel exit code, i.e. as a *customer* outcome. | `GateAborted` is its own outcome; stop and expiry never report `Exited { 1 }`. |
| MED | The event sink was accepted by the plan and never called. | Threaded through `wait()`. (Later grown into the full R13 vocabulary.) |
| LOW×5 | incl. the activation token drawn before the fork; duplicate env keys left for `execve` to resolve platform-dependently. | Token drawn post-fork, parent-only. `PlanError::DuplicateEnvKey` hoisted into `validate()`. |

### Review #2 — iteration 8, against F9 (detached supervisor). Verdict: approve with fixes.

| # | Finding | Fix |
|---|---|---|
| 1 | **The peer-UID guard was not removal-detectable.** Only the pure `accept_decision` table had tests, so deleting the `peer_uid` call — or hardcoding `Serve` — left the whole suite green. A guard nothing can break is a guard nobody is keeping. | The accept path is the free function `accept_or_refuse`; the credential source has a `#[cfg(test)]` thread-local injection seam (compiled out of every release build); three tests drive the **live** path with a real listener and a real connection. Both removals now fail. |
| 2 | The activation token's socket hop was **not zeroized** — `write_frame`'s serialization buffer and assembled frame, `read_frame`'s body, the readiness frame, and the `Activate` copy on both sides all dropped un-wiped. | Zeroized **unconditionally**, not on the paths that "can" carry a token: a branch deciding which frame is secret is a branch that can be got wrong. |
| 3 | The request read used the 10 s reply allowance, so a three-byte slow-loris could hold the single thread that also accepts connections and watches the child, on every cycle. | A separate `REQUEST_DEADLINE` of 2 s. |
| 4 | Close-on-exec had been cleared to pass descriptors through the exec and was never re-armed. | Re-armed on all five as soon as the supervisor has them. |
| 5 | The `SIGCHLD` self-pipe was installed *after* the readiness write, so `HANDSHAKE_READY` meant "nearly ready" — a child that died immediately after activation was noticed only by a 250 ms backstop, inside a window the caller had been told was serving. | Installed before the readiness write. |
| 6 | The handshake assumed `SPAWNED` precedes `READY`, but two unsynchronized writers share that pipe. In practice the intermediate wins every time — **which is what made the assumption dangerous**, since the failure would be a typed error on a race that reproduces never. | `await_handshake` tolerates either order, bounded by a record count as well as a deadline. |
| 7 | `MAX_CONTROL_FRAME_BYTES` and `MAX_RECORD_BYTES` could drift apart, letting a legal record become an illegal frame. | `MAX_RECORD_BYTES + 4 KiB` envelope allowance, held by a module-level `const _: () = assert!(…)` — a build that broke it does not compile. |

---

## 3. Residual risks, accepted and disclosed

Each of these is a **stated limit**, not an unknown. The first four are typed entries in
`SupportReport::dark_spots()` with a consequence and the file that documents them, so a
consumer reads them from the machine-readable report rather than from this document.

1. **Same-uid is not a boundary.** The substrate targets same-user sandboxing. Peer-UID checks
   and 0700/0600 permissions keep *other* users out; they do nothing against another process
   running as the same uid, which can already `ptrace` the supervisor's peers, read the store
   with the same rights, and connect to the socket legitimately. Everything in §1.2 and §1.3
   raises the cost of a *confused* same-uid process, not of a *hostile* one. Privilege
   separation across users is out of contract scope, and a consumer that needs it needs a
   different uid, not a different flag.

2. **`ExecOrKilledPreExec` is genuinely ambiguous.** A child killed between the gate release
   and `execve` closes its status descriptor exactly as a successful exec does. The API
   reports the ambiguity as a third value rather than collapsing it; there is no
   `did_it_run() -> bool`, deliberately.
   *(`DarkSpot::ExecOrKilledPreExecAmbiguity`)*

3. **A descendant that calls `setsid` escapes the process group** and is invisible to both
   `stop` and cleanup verification. Closing this needs a cgroup-class mechanism the library
   does not build. A visible second consequence: a terminal's Ctrl-C no longer reaches the run
   by accident.
   *(`DarkSpot::ProcessGroupEscapeViaSetsid`)*

4. **Process-group ids are reusable after the reap.** Once the direct child is reaped its pid —
   and therefore its process group id — can be reissued, so a later group hit is reported as
   "something is in that group" rather than "the run survived". Mitigated but not eliminated by
   the boot-id re-check.
   *(`DarkSpot::ProcessGroupIdReuseAfterReap`)*

5. **Gate expiry freezes while the machine sleeps.** The activation deadline is measured with
   `Instant`, which does not advance across system suspend on either platform, so a laptop
   closed for an hour extends a 50 ms deadline by an hour of wall time. Expiry is also
   evaluated *lazily*, at the next operation, on both the attached and detached paths — so an
   abandoned never-activated detached session holds its supervisor until something asks.
   *(`DarkSpot::GateExpiryFrozenWhileSuspended`)*

6. **A detach discards output already in flight.** Scrollback covers **from the detach
   onwards**; bytes handed to a client and not consumed are not replayed. The 256 KiB ring is
   oldest-dropped and **counts what it dropped**, and the count rides on the next `AttachAck` —
   so the loss is measurable rather than silent. A consumer that needs every byte stays
   attached. Relatedly, a client that stops reading is dropped after a 10 s stall and the run
   is not; that is a deliberate choice of which party to sacrifice.

7. **The sandboxed child's own `ptrace` is unrestricted on Linux.** Inherited from upstream, not
   introduced here: there is no seccomp ptrace filter and no Yama management. Within one uid
   this is consistent with (1), but it is worth naming because it means a confined child can
   inspect *other* same-uid processes, not merely evade its own confinement.

8. **The `atomic_write` bundle grants four operations to satisfy one intent.** `{create, write,
   rename, remove_file}` is strictly more than "replace this file atomically", and on a
   directory grant the members apply to the whole directory. This is disclosed by construction
   (`ATOMIC_WRITE_MEMBERS` is public and every unrequested member appears in `bundled`), but
   disclosure is not narrowing — a caller who wants less must name the members individually.

9. **THE LARGEST ONE: no part of this has ever executed on a Linux kernel.** Landlock rule
   construction, seccomp preparation, the Linux `close_range` sweep arm, the Linux
   `ptsname_r`/`TIOCSCTTY` PTY arm, `/proc/<pid>/stat` start-time parsing and boot-id reading
   are **written-unverified**. The mapping *logic* is host-tested against a faked ABI, which is
   a real test of the decision table and **not** a test of the kernel's answer. The gates
   `linux-landlock-live` and `linux-lifecycle-live` in `scripts/stream-gates.sh` report
   `NOT_RUN`, never `PASS`, precisely so this cannot be mistaken for verified. Every
   Linux-facing claim in this document should be read as "this is what the code intends"
   until the `ubuntu-latest` job of `.github/workflows/stream-gates.yml` has been green once.
   Reproduce the wall: `docker ps` → "Cannot connect to the Docker daemon". Operator action:
   open Docker Desktop once and accept the first-run prompt.

---

## 4. Non-threats (by design)

- **Cedar/policy semantics.** Never parsed or evaluated here. The library provides mechanism;
  meaning belongs to the consumer. `BLOCKED_ROWS.json` R15 is the standing grep guard against
  a product type arriving by accident.
- **Cross-user isolation beyond peer-UID + 0700 state.** See residual (1).
- **The activation token as an authorization decision.** It is a start button for a held child,
  not a capability grant and not an authorization statement. `ActivationHandle::token()` is
  public because a detached run is very often activated by a different process than prepared
  it and the library cannot transport bytes for a consumer; what the bytes *mean* — who may
  press the button, and on what evidence — is the consumer's decision and stays consumer-side.
- **Denial-of-service by the consumer against itself.** A caller who leaks `PreparedSandbox`
  handles, never activates, or abandons detached sessions consumes its own descriptors and
  supervisors. Bounded where it is cheap to bound (idle-after-terminal grace, stall deadlines,
  frame caps), not defended against as an adversary.
