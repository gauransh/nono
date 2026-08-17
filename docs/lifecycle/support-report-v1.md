# Support report, schema version 1

What a `nono` build can actually enforce, observe, and refuse, as data.

Source of truth: `crates/nono/src/lifecycle/support.rs` (`SupportReport`). The
golden example below is locked by a test in that file — if the type changes
without the doc, that test fails and names this path.

Built by `SupportReport::gather()`, which **cannot fail**. A probe that will not
answer produces `unknown` with the reason it would not answer; a capability
nothing implements yet is `unavailable` with the work that would implement it.
Nothing here panics, and nothing fills a gap with an assumption.

Upstream's `Sandbox::support_info() -> SupportInfo { is_supported: bool, … }` is
untouched and still means what it always meant. This is an addition, not a
replacement — and it exists because one boolean cannot say *which* mechanism is
available, nor whether the answer was observed or merely believed.

## The shape of a capability

Every capability field is an object with the same three keys, plus optional
typed `facts`:

| Key | Type | Nullable | Meaning |
|---|---|---|---|
| `status` | enum | no | `available`, `partial`, `unavailable`, or `unknown`. `partial` and `unknown` are the two a boolean cannot express, and they are the two that matter: a mechanism weaker than asked for, and one this process could not establish without changing itself irreversibly. `unknown` is never a synonym for "no". |
| `determination` | enum | no | `probed_live` (a probe ran in this process during this call, and its result *is* the status), `platform_api` (the answer rests on an API this build links, whose presence is settled at compile time — certainly there, but nothing was asked of it), `declared` (this build states it: an unimplemented slice, another platform's mechanism, or an `unknown` whose probe could not be run). |
| `reason` | tagged object | no | Why, typed. See the table below. |
| `facts` | object | **yes** | Typed detail. Omitted entirely when the capability has none. |

### `reason` variants

| `reason` | Payload | Means |
|---|---|---|
| `probed` | `probe` | A probe ran and its answer is the status, whatever that status is. |
| `probe_refused` | `probe`, `detail` | The probe could not be completed, so nothing was established by it. |
| `other_platform` | `mechanism`, `this_target_os` | The mechanism belongs to a platform this build does not target. |
| `platform_api_linked` | `api`, `why_not_probed` | The API is linked, so it is certainly present; no probe was run, and this says why not. Never empty — an unprobed claim has to justify itself. |
| `not_implemented` | `slice` | Nothing implements this yet, named so the gap is trackable. |
| `not_observable_without_irreversible_change` | `what` | Finding out would change this process in a way that cannot be undone, so the library does not find out. |
| `platform_cannot_express` | `mechanism`, `refusal` | The platform's mechanism cannot express what was asked for, and the library refuses rather than widening to something it can express. |

## Top-level fields

| Field | Type | Nullable | Meaning |
|---|---|---|---|
| `schema_version` | `u32` | no | The schema this report was written by. Bumped when a field's meaning changes, not when one is added. |
| `host` | capability of `HostFacts` | no | The machine, as compiled for and as running. |
| `landlock` | capability of `LandlockFacts` | no | Landlock and its per-right table (Linux). `other_platform` elsewhere. |
| `fs_modes` | capability of `FsModeFacts` | no | The filesystem mode vocabulary (`FsModeSet`) and how enforceable each of its thirteen modes is here. `partial` on **both** platforms, for opposite reasons — see below. |
| `seccomp` | capability | no | Whether a seccomp filter can be installed (Linux). |
| `seccomp_user_notification` | capability | no | Whether `SECCOMP_RET_USER_NOTIF` mediation is available (Linux). |
| `seatbelt` | capability | no | Seatbelt (macOS). |
| `network_filtering` | capability of `NetworkFilteringFacts` | no | Network filtering, per mechanism. |
| `pty` | capability | no | The platform's pseudo-terminal primitive. **Not** a statement that the lifecycle will give a run a PTY — that is `interactive_session`. |
| `interactive_session` | capability | no | Whether the lifecycle will run a PTY session. Its `status` is `pty`'s, because a host that will not give this process a pseudo-terminal cannot run one however good the supervisor is; its `determination` is `platform_api` rather than the probe's `probed_live`, because the supervisor half was not established. **With a precondition**: an interactive plan must also be a detached plan — a PTY master has to be held for as long as the run lives, and only the supervisor outlives the call. The ephemeral paths refuse with `PrepareError::InteractiveNeedsSupervisor`. |
| `detached_supervisor` | capability | no | Whether a run can outlive its supervisor by design. `available` / `platform_api`, **with a precondition**: the mechanism is a re-exec of `current_exe()` and it works only if the embedder calls `nono::lifecycle::supervisor_entry()` first thing in `main`. That cannot be probed without launching a supervisor, so `why_not_probed` states it and a binary without the hook fails closed at the readiness deadline with `PrepareError::SupervisorUnresponsive`. See [ADR-0002](../adr/0002-detached-supervisor.md). |
| `attach` | capability | no | Whether a caller can attach to a run it did not start. `available` since R09 slice C, for both kinds: the control conversation (`SessionStore::attach_control`, `RecoveredSession::attach` — activate, wait, stop, status, verify cleanup) and the run's *terminal* (`DetachedSession::attach` → `AttachedTerminal`). **Three limits ride in `why_not_probed`**: attach occupies the supervisor's single client slot, so a second connection is refused `ControlRefusal::Busy`; a headless run has no terminal, so an attach to one is refused `ControlRefusal::NoTerminal`; and output produced while nobody is attached is kept in a bounded ring, oldest dropped, with the dropped count reported on the next `AttachAck`. |
| `process_identity` | capability of `IdentityFacts` | no | Whether the facts that make a pid non-reusable are readable here. |
| `cleanup_verification` | capability of `CleanupFacts` | no | Whether the probes cleanup verification is built on answer here. |
| `event_observation` | array | no | Which event families this library observes, and which it does not. |
| `dark_spots` | array | no | Known limits, stated. |

### `HostFacts`

| Field | Type | Nullable | Meaning |
|---|---|---|---|
| `compiled_os` / `compiled_arch` | string | no | `std::env::consts::OS` / `ARCH` — what this binary was built for. |
| `kernel` | object | **yes** | `uname(2)`: `sysname`, `release`, `version`, `machine`. Absent when `uname` would not answer, which makes the capability `partial` rather than a refusal. The host's **node name is deliberately not read**: a hostname is not a capability fact, and this report is the kind of thing that gets pasted into an issue. |

### `LandlockFacts` (Linux)

| Field | Type | Nullable | Meaning |
|---|---|---|---|
| `abi` | string | **yes** | The detected ABI, e.g. `V4`, from upstream's own `V6`-down-to-`V1` probe with `CompatLevel::HardRequirement`. Absent when detection did not answer. |
| `rights` | array of `{right, status}` | no | Per-right availability: `filesystem_base`, `refer`, `truncate`, `execute`, `tcp_network`, `ioctl_dev`, `scoping`. The ABI number alone is not actionable; this table is the same information in the shape a decision is made from. |

The capability is `available` only when every right is; anything less is
`partial`, because the difference is exactly what a consumer has to plan around.

### `FsModeFacts`

| Field | Type | Nullable | Meaning |
|---|---|---|---|
| `mechanism` | string | no | The platform mechanism the table is about, named so a reader does not infer it from the host fields. |
| `modes` | array of `{mode, enforceability}` | no | One entry per mode in `FsMode::ALL` order — **including the ones that are not enforceable**, so nothing is left to inference. |

`enforceability` is a tagged object:

| `enforceability` | Extra fields | Meaning |
|---|---|---|
| `enforceable` | — | The platform expresses this mode as a grant distinct from the others. |
| `bundled_with` | `mode` | It cannot be separated from `mode`: granting either grants both. The **narrower** request is the one that names its partner; where neither is narrower, the earlier in `FsMode::ALL` keeps `enforceable`. |
| `unrestrictable` | — | The platform cannot restrict the operation at all. A grant is a no-op, and the *absence* of a grant is not a denial. |
| `needs_abi` | `abi` | The platform could express it, but not at the version detected here. A grant is **refused** (`NonoError::ModeUnsupported`), not silently dropped. |
| `unsupported` | — | The platform has no mechanism for it. |
| `delegated` | `target` | Enforced, but by a sibling capability — `unix_socket_capability` — rather than by the filesystem rules. |

The rolled-up status is `partial` on both platforms and for **opposite** reasons,
which is the fact this table exists to make readable:

- **Linux**: `read_metadata` is `unrestrictable`. Landlock has no access right
  covering `stat(2)`, so a metadata grant changes nothing and a metadata
  *denial* is not expressible. `truncate` and `rename` are `needs_abi` below V3
  and V2 respectively, read from the ABI detected in this process — so the entry
  is `probed_live`.
- **macOS**: `read_metadata` is `enforceable` (`file-read-metadata` is a real
  SBPL operation), but `append`, `truncate`, `read_dir`, `remove_dir` and
  `rename` are all `bundled_with` something, because SBPL has one operation
  where the contract has two. The entry is `platform_api`, not `probed_live`:
  SBPL has no version negotiation, so what a mode compiles to is a property of
  this build, and the only live probe available is to install a profile, which
  cannot be undone.

`atomic_write` is a *named bundle* over `create`, `write`, `rename` and
`remove_file`, so it is as enforceable as its weakest member — on Linux that is
`rename`, and therefore `REFER`.

### `NetworkFilteringFacts`

`mechanisms` is an array of `{mechanism, status, reason}` over
`landlock_tcp_port_rules`, `seccomp_block_all`, `seccomp_user_notify_proxy`,
`seatbelt_network_all_or_nothing`, and `seatbelt_per_port_tcp`. The last is
listed *so that its absence is a stated fact*: Seatbelt has no TCP port
predicate, and a port-scoped policy is refused
(`NonoError::NetworkFilterUnsupported`) rather than widened to
`(allow network*)`.

The rolled-up status is `partial` whenever some mechanism works and some does
not, which is the permanent state of both platforms.

### `IdentityFacts` and `CleanupFacts`

`IdentityFacts` reports `start_time`, `boot_id`, and `self_recognition` as
statuses, probed by capturing *this* process's identity and re-checking it. We
know the answer for this process, so a failure here is a statement about the
platform, not about the process.

`CleanupFacts` reports `pid_probe` and `process_group_probe`, probed with
signal 0 against this process and its own group — signal 0 performs the
existence and permission check and delivers nothing.

### `event_observation`

Each entry is `{family, fidelity, basis}`. `fidelity` is `directly_observed`,
`reconstructed`, or `not_observed`.

`kernel_denial` is `not_observed` **on both platforms**, and is listed for
exactly that reason. The lifecycle installs no seccomp user-notification
listener, and macOS Seatbelt denials reach userspace only through the system
log. `nono-cli` reconstructs those from `log stream`, but that is CLI machinery
and is not claimed by the library.

### `dark_spots`

Each entry is `{spot, consequence, documented_in}` over
`process_group_escape_via_setsid`, `process_group_id_reuse_after_reap`,
`exec_or_killed_pre_exec_ambiguity`, and
`gate_expiry_frozen_while_suspended`. `documented_in` points at the module
documentation that records the limit, so this list is an index rather than a
second source of truth.

## Determination on macOS: why Seatbelt is not `probed_live`

`sandbox_init` is linked into this build, so its presence is a compile-time
fact — but calling it is irreversible and **process-wide**. A "trivial" probe
profile would sandbox the caller's own process for the rest of its life. The
only honest live probe forks first (which is what `nono setup --check-only`
does), and forking a consumer's process to answer a diagnostic question is a
cost this library does not impose without being asked. So: `platform_api`, with
the rationale in `reason.why_not_probed`.

Linux's seccomp answer is `probed_live` for the opposite reason: upstream
already provides a fork-isolated probe
(`probe_seccomp_block_network_support`), so an answer is available without
inventing a mechanism. `seccomp_user_notification` remains `unknown`, because
establishing it means installing a filter that cannot be removed, and a kernel
release number is not proof (`CONFIG_SECCOMP_FILTER` can be off on a kernel new
enough to have the flag).

## Golden example

The example below is a **macOS** report: macOS is the platform this stream
verifies live, so the example is the shape `gather()` really produces here. No
Linux example is published because no Linux host has been observed on this
stream (see `BLOCKED_ROWS.json`, R07) — a hand-written Linux capture would be
the kind of claim this report exists to prevent.

```json
{
  "schema_version": 1,
  "host": {
    "status": "available",
    "determination": "probed_live",
    "reason": {
      "reason": "probed",
      "probe": "uname(2)"
    },
    "facts": {
      "compiled_os": "macos",
      "compiled_arch": "aarch64",
      "kernel": {
        "sysname": "Darwin",
        "release": "23.6.0",
        "version": "Darwin Kernel Version 23.6.0",
        "machine": "arm64"
      }
    }
  },
  "landlock": {
    "status": "unavailable",
    "determination": "declared",
    "reason": {
      "reason": "other_platform",
      "mechanism": "Landlock LSM",
      "this_target_os": "macos"
    }
  },
  "fs_modes": {
    "status": "partial",
    "determination": "platform_api",
    "reason": {
      "reason": "platform_api_linked",
      "api": "sandbox_init(3) SBPL filesystem operations",
      "why_not_probed": "SBPL has no version negotiation: which operation a mode compiles to is a property of this build, not of the running kernel, and the only live probe available is to install a profile — which applies to the calling process and cannot be undone"
    },
    "facts": {
      "mechanism": "Seatbelt SBPL filesystem operations",
      "modes": [
        {
          "mode": "read_contents",
          "enforceability": {
            "enforceability": "enforceable"
          }
        },
        {
          "mode": "read_dir",
          "enforceability": {
            "enforceability": "bundled_with",
            "mode": "read_contents"
          }
        },
        {
          "mode": "read_metadata",
          "enforceability": {
            "enforceability": "enforceable"
          }
        },
        {
          "mode": "write",
          "enforceability": {
            "enforceability": "enforceable"
          }
        },
        {
          "mode": "append",
          "enforceability": {
            "enforceability": "bundled_with",
            "mode": "write"
          }
        },
        {
          "mode": "create",
          "enforceability": {
            "enforceability": "enforceable"
          }
        },
        {
          "mode": "truncate",
          "enforceability": {
            "enforceability": "bundled_with",
            "mode": "write"
          }
        },
        {
          "mode": "remove_file",
          "enforceability": {
            "enforceability": "enforceable"
          }
        },
        {
          "mode": "remove_dir",
          "enforceability": {
            "enforceability": "bundled_with",
            "mode": "remove_file"
          }
        },
        {
          "mode": "rename",
          "enforceability": {
            "enforceability": "bundled_with",
            "mode": "create"
          }
        },
        {
          "mode": "execute",
          "enforceability": {
            "enforceability": "enforceable"
          }
        },
        {
          "mode": "unix_socket_connect",
          "enforceability": {
            "enforceability": "delegated",
            "target": "unix_socket_capability"
          }
        },
        {
          "mode": "atomic_write",
          "enforceability": {
            "enforceability": "enforceable"
          }
        }
      ]
    }
  },
  "seccomp": {
    "status": "unavailable",
    "determination": "declared",
    "reason": {
      "reason": "other_platform",
      "mechanism": "seccomp-bpf",
      "this_target_os": "macos"
    }
  },
  "seccomp_user_notification": {
    "status": "unavailable",
    "determination": "declared",
    "reason": {
      "reason": "other_platform",
      "mechanism": "seccomp user notification (SECCOMP_RET_USER_NOTIF)",
      "this_target_os": "macos"
    }
  },
  "seatbelt": {
    "status": "available",
    "determination": "platform_api",
    "reason": {
      "reason": "platform_api_linked",
      "api": "sandbox_init(3) (libSystem)",
      "why_not_probed": "sandbox_init applies to the calling process and cannot be undone, so any live probe must fork first; this report does not fork the caller to answer a question the linker already settled"
    }
  },
  "network_filtering": {
    "status": "partial",
    "determination": "platform_api",
    "reason": {
      "reason": "platform_api_linked",
      "api": "sandbox_init(3) SBPL network rules",
      "why_not_probed": "the SBPL a policy compiles to is a compile-time property of this build; what it cannot express is stated per mechanism below"
    },
    "facts": {
      "mechanisms": [
        {
          "mechanism": "seatbelt_network_all_or_nothing",
          "status": "available",
          "reason": {
            "reason": "platform_api_linked",
            "api": "sandbox_init(3) (libSystem)",
            "why_not_probed": "sandbox_init applies to the calling process and cannot be undone, so any live probe must fork first; this report does not fork the caller to answer a question the linker already settled"
          }
        },
        {
          "mechanism": "seatbelt_per_port_tcp",
          "status": "unavailable",
          "reason": {
            "reason": "platform_cannot_express",
            "mechanism": "Seatbelt SBPL has no TCP port predicate",
            "refusal": "NonoError::NetworkFilterUnsupported — a port-scoped policy is refused rather than widened to (allow network*)"
          }
        }
      ]
    }
  },
  "pty": {
    "status": "available",
    "determination": "probed_live",
    "reason": {
      "reason": "probed",
      "probe": "posix_openpt(O_RDWR | O_NOCTTY), closed immediately"
    }
  },
  "interactive_session": {
    "status": "available",
    "determination": "platform_api",
    "reason": {
      "reason": "platform_api_linked",
      "api": "posix_openpt(3) + grantpt(3) + unlockpt(3) in the launcher, setsid(2) and TIOCSCTTY in the customer child, with the master held by the detached supervisor",
      "why_not_probed": "PRECONDITION: an interactive plan must also be a detached plan (SandboxPlan::detached(true) + SessionStore::prepare_detached), because a PTY master has to be held for as long as the run lives and only the supervisor outlives the call — the ephemeral paths refuse with PrepareError::InteractiveNeedsSupervisor. That supervisor in turn needs the entry hook named under detached_supervisor. Establishing either would mean launching a run, so what is probed here is the terminal primitive and what is reported is the mechanism above it."
    }
  },
  "detached_supervisor": {
    "status": "available",
    "determination": "platform_api",
    "reason": {
      "reason": "platform_api_linked",
      "api": "fork(2) + execve(2) of std::env::current_exe(), setsid(2), and a unix(7) control socket in the session store",
      "why_not_probed": "PRECONDITION: the embedder must call nono::lifecycle::supervisor_entry() as the first statement of main(). The supervisor is this binary re-executed, and it becomes a supervisor only because that call recognises a private environment marker; a library cannot install the hook on its embedder's behalf. Whether this binary has it cannot be established without launching a supervisor, so it is not probed. A detached prepare against a binary without the hook fails closed at the readiness deadline with PrepareError::SupervisorUnresponsive, which names the function. See docs/adr/0002-detached-supervisor.md"
    }
  },
  "attach": {
    "status": "available",
    "determination": "platform_api",
    "reason": {
      "reason": "platform_api_linked",
      "api": "unix(7) control socket in the session store, peer-uid checked at accept; control protocol v1 frames, and after ControlRequest::Attach the tagged terminal framing of nono::lifecycle::terminal",
      "why_not_probed": "Establishing it means launching a supervisor and a run — see detached_supervisor. Two limits are worth knowing before depending on it: attach occupies the supervisor's single client slot, so a second connection is refused ControlRefusal::Busy; and a headless run has no terminal, so an attach to one is refused ControlRefusal::NoTerminal. Output produced while nobody is attached is kept in a bounded ring (SCROLLBACK_CAPACITY_BYTES), oldest dropped, and the count of what was dropped rides on the next AttachAck."
    }
  },
  "process_identity": {
    "status": "available",
    "determination": "probed_live",
    "reason": {
      "reason": "probed",
      "probe": "ProcessIdentity::capture(self) then is_same_process()"
    },
    "facts": {
      "start_time": "available",
      "boot_id": "available",
      "self_recognition": "available"
    }
  },
  "cleanup_verification": {
    "status": "available",
    "determination": "probed_live",
    "reason": {
      "reason": "probed",
      "probe": "kill(self, 0) and killpg(own group, 0) — signal 0 delivers nothing"
    },
    "facts": {
      "pid_probe": "available",
      "process_group_probe": "available"
    }
  },
  "event_observation": [
    {
      "family": "lifecycle_transition",
      "fidelity": "directly_observed",
      "basis": "every transition goes through the shared lifecycle core, and the sink is told after the state moved"
    },
    {
      "family": "sandbox_application",
      "fidelity": "directly_observed",
      "basis": "the trusted child writes its at-the-gate record only after the sandbox applied; the parent reads that record"
    },
    {
      "family": "activation_outcome",
      "fidelity": "directly_observed",
      "basis": "the gate's single-use claim decides the outcome in this process"
    },
    {
      "family": "exec_observation",
      "fidelity": "directly_observed",
      "basis": "EOF on the close-on-exec status descriptor, which is why the observation is the three-valued ActivationObservation and not a bool"
    },
    {
      "family": "child_exit",
      "fidelity": "directly_observed",
      "basis": "waitpid on this process's own child"
    },
    {
      "family": "stop_outcome",
      "fidelity": "directly_observed",
      "basis": "the stop request is this process's own, and the death is the waitpid that follows it"
    },
    {
      "family": "cleanup_verdict",
      "fidelity": "directly_observed",
      "basis": "a signal-0 probe made after the fact; a sent signal is never the evidence"
    },
    {
      "family": "record_persistence",
      "fidelity": "directly_observed",
      "basis": "the durable write returns before the event is emitted"
    },
    {
      "family": "kernel_denial",
      "fidelity": "not_observed",
      "basis": "this library emits no denial events on either platform. The lifecycle installs no seccomp user-notification listener, and macOS Seatbelt denials reach userspace only through the system log. nono-cli reconstructs those from `log stream`, but that is CLI machinery and is not claimed here."
    }
  ],
  "dark_spots": [
    {
      "spot": "process_group_escape_via_setsid",
      "consequence": "a descendant that leaves the run's process group is signalled by neither stop nor drop, and is invisible to cleanup verification: it shows up as neither killed nor confirmed absent. Closing it needs a cgroup-class mechanism this slice does not build.",
      "documented_in": "crates/nono/src/lifecycle/prepare.rs (module docs, \"The run is a process group, not a process\")"
    },
    {
      "spot": "process_group_id_reuse_after_reap",
      "consequence": "once the direct child is reaped its pid — and so its process group id — can be reissued, so a later group hit is reported as StillPresent (\"something is in that group\") rather than as proof of a survivor. The boot id is re-checked, which stops a number reused across a reboot from answering.",
      "documented_in": "crates/nono/src/lifecycle/cleanup.rs (module docs, \"The caveat that is not designed away\")"
    },
    {
      "spot": "exec_or_killed_pre_exec_ambiguity",
      "consequence": "a child killed between the gate release and execve closes the status descriptor exactly as a successful execve does, so activation is the three-valued ActivationObservation; wait() resolves it only when the exit status is one that only a real execve could produce.",
      "documented_in": "crates/nono/src/lifecycle/prepare.rs (module docs, \"Descriptors\")"
    },
    {
      "spot": "gate_expiry_frozen_while_suspended",
      "consequence": "the activation deadline is measured with Instant, which does not advance while the machine is suspended, and is evaluated lazily at the next activate/stop/drop: a gate given five minutes still has time left after an hour of sleep, and an expired gate is discovered rather than fired.",
      "documented_in": "crates/nono/src/lifecycle/plan.rs (GateConfig, \"How the deadline is measured\")"
    }
  ]
}
```
