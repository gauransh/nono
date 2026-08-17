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
| `seccomp` | capability | no | Whether a seccomp filter can be installed (Linux). |
| `seccomp_user_notification` | capability | no | Whether `SECCOMP_RET_USER_NOTIF` mediation is available (Linux). |
| `seatbelt` | capability | no | Seatbelt (macOS). |
| `network_filtering` | capability of `NetworkFilteringFacts` | no | Network filtering, per mechanism. |
| `pty` | capability | no | The platform's pseudo-terminal primitive. **Not** a statement that the lifecycle will give a run a PTY — that is `interactive_session`. |
| `interactive_session` | capability | no | Whether the lifecycle will run a PTY session. |
| `detached_supervisor` | capability | no | Whether a run can outlive its supervisor by design. |
| `attach` | capability | no | Whether a caller can attach to a run it did not start. |
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
    "status": "unavailable",
    "determination": "declared",
    "reason": {
      "reason": "not_implemented",
      "slice": "interactive session (PTY): PreparedSandbox::prepare refuses SessionMode::Interactive rather than running headless"
    }
  },
  "detached_supervisor": {
    "status": "unavailable",
    "determination": "declared",
    "reason": {
      "reason": "not_implemented",
      "slice": "R09 slice B (detached supervisor): dropping a handle today kills and reaps the run, and a run that outlives its supervisor is only recoverable, never supported"
    }
  },
  "attach": {
    "status": "unavailable",
    "determination": "declared",
    "reason": {
      "reason": "not_implemented",
      "slice": "R09 slice B (attach): SessionStore::recover reports presence and absence, and a recovered process is not this process's child, so its exit is not observable"
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
