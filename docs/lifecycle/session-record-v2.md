# Session record, schema version 2

The durable record `nono::lifecycle::SessionStore` writes for one session, one
file per session at `<store>/<session-id>.json`, mode `0600`. A detached
session also has a control socket beside it at `<store>/<session-id>.sock`,
which is not a record and is never enumerated as one.

Source of truth: `crates/nono/src/lifecycle/session_store.rs`
(`SessionRecord`). The golden example below is locked by a test in that file —
if the type changes without the doc, that test fails and names this path.

Version 1 is [`session-record-v1.md`](session-record-v1.md) and is still
**read**. It is never written.

## What changed in version 2

Three fields, all of them things only a *detached supervisor* can supply:

| Field | Why version 1 could not have it |
|---|---|
| `supervisor` | Version 1 had no supervisor process. The caller was the supervisor, and a record naming the caller would be claiming that the caller can be probed for liveness after the caller is gone. |
| `exit` | Version 1 could not witness an exit across a restart: `waitpid` reaches only the caller's own children, so a recovered run's exit code was simply not observable. A detached supervisor is still running when the child ends, so the facts are witnessed and then written. |
| `events` | `EventSink` is caller-side. A detached supervisor has no caller to deliver to, so it keeps a bounded ring instead. Version 1 delivered every event live and had nothing to keep. |

## How the two versions are told apart

The version is read first, on its own, from a probe that ignores every other
field. That number then chooses which *shape* the record is parsed as, and both
shapes are `deny_unknown_fields`:

- `1` → parsed as the version-1 shape, then upgraded in memory: `supervisor` and
  `exit` become absent and `events` becomes empty. Nothing is invented.
- `2` → parsed as the shape below.
- anything else → `SessionStoreError::UnsupportedSchemaVersion`, naming both
  numbers.

A v1 file is not modified by being read. The upgrade reaches disk only if
something writes the record afterwards, at which point what it writes is a v2
record.

## What a record is for, and what it is not

A record exists so that a caller which crashed can reason about a process it no
longer supervises — and, from version 2, so that a caller which crashed can
*reconnect* to the process still supervising it. It carries who the processes
were, what group the run leads, where the machine believed the run had got to,
and the facts a detached supervisor witnessed.

There is **no program, no argument list, no environment, and no capability
set** in a record, and there is **no activation token or token digest**. A
record that carried the run's command line would be a durable copy of whatever
secrets that command line held; a record that carried the token would be a
durable start button. The only caller-owned bytes in it are `metadata`, which
the library copies and returns and never interprets.

Three properties a consumer must build on:

1. **A record may lag the live state by one step.** It is written *after* the
   transition it describes, outside the lifecycle lock. `SessionStore::recover`
   reconciles a loaded record against the live system rather than believing it;
   a consumer must not treat `state` as a statement about the present. A
   connected `DetachedSession::status()` reports the supervisor's *live* state
   alongside the record for exactly this reason.
2. **A record from an unimplemented schema version is refused, not
   interpreted.** See above.
3. **`events` is bounded and lossy by design.** It holds at most
   `DETACHED_EVENT_RING_CAPACITY` (32) entries, oldest dropped. It is not a log
   and must not be treated as one: a consumer that needs every event stays
   connected and supplies an `EventSink`.

## Fields

| Field | Type | Nullable | Meaning |
|---|---|---|---|
| `schema_version` | `u32` | no | The schema this record was written by. `2` for everything this build writes; `1` still loads. |
| `session_id` | UUID (v7 string) | no | The session's id, which is also its file name and the stem of its control socket name. A record whose id disagrees with its file name is `SessionCorrupt`. |
| `generation` | `u64` | no | Which preparation of this session the record describes. Always `1` today: sessions are one-shot UUIDs and nothing re-prepares into an existing slot. The field exists because the flow that increments it would otherwise have to change the shape. |
| `identity` | object | no | The recorded child process, with the facts a reissued pid cannot forge. See below. |
| `identity.pid` | `i32` | no | The pid as the kernel issued it. |
| `identity.start_time` | `u64` | **yes** | Platform-opaque process start time — Linux clock ticks since boot, macOS microseconds since the epoch. Comparable for equality only. `null` when the platform would not say, which makes every later identity check fail closed. |
| `identity.boot_id` | string | **yes** | Opaque identifier for the boot the pid was issued in (`/proc/sys/kernel/random/boot_id`; `kern.boottime` on macOS). `null` when the platform would not say. |
| `process_group` | `i32` | no | The process group the run leads, equal to the child's pid by construction. Recorded rather than re-derived: a reaped pid is a number the kernel may reissue, while the group this run used is a fact about the run. |
| `state` | enum | no | Where the run had got to when the record was last written. One of `planning`, `preparing`, `prepared`, `activating`, `running`, `exited`, `stopping`, `stopped`, `cleanup_verified`, `failed`. A claim about the past — see above. |
| `activation` | enum | **yes** | Whether the customer's program was observed to start, if that was known when the record was written: `observed`, `not_activated`, `exec_or_killed_pre_exec`. `null` until the run's end is known. Deliberately three-valued: a child killed between the gate release and `execve` closes the status descriptor exactly as a successful `execve` does. |
| `created_unix_millis` | `u64` | **yes** | Wall-clock milliseconds since the Unix epoch when the record was created, or `null` if the clock would not say. Advisory: nothing in the library decides anything from a timestamp. |
| `updated_unix_millis` | `u64` | **yes** | Same, for the last write. |
| `metadata` | array of `u8` | no (may be empty) | The caller's opaque bytes, copied from the plan and never interpreted. Bounded by `MAX_PLAN_METADATA_BYTES` (4096); a longer array on load is `SessionCorrupt`. |
| `supervisor` | object | **yes** | **v2.** The detached supervisor's own `ProcessIdentity`, captured *by that supervisor*. `null` for an attached run. This is what `SessionStore::recover` probes to decide whether the control socket beside the record is live (`RecoveryDecision::Attachable`) or stale (unlinked, and the slice-A cleanup path taken). |
| `exit` | object | **yes** | **v2.** The run's `SandboxExit` — `outcome`, `activation`, and the `identity` the facts are about — once its end was witnessed. Written only by a detached supervisor. `null` until then, and never filled in from a probe: an absent process is not an exit code. |
| `events` | array | no (may be empty) | **v2.** The bounded ring of `LifecycleEvent`s, oldest first. Each entry has the shape in [`lifecycle-event-v1.md`](lifecycle-event-v1.md). Empty for every attached run and every v1 record; a longer array than the capacity on load is `SessionCorrupt`. |

Absent optional fields are omitted from the JSON rather than written as `null`
where the type allows it; both forms load.

## Golden example

```json
{
  "schema_version": 2,
  "session_id": "019512f0-0000-7000-8000-000000000001",
  "generation": 1,
  "identity": {
    "pid": 4242,
    "start_time": 1755000000000000,
    "boot_id": "1754990000.000000"
  },
  "process_group": 4242,
  "state": "running",
  "activation": "observed",
  "created_unix_millis": 1755000000000,
  "updated_unix_millis": 1755000000123,
  "metadata": [
    100,
    101,
    109,
    111
  ],
  "supervisor": {
    "pid": 4241,
    "start_time": 1754999999000000,
    "boot_id": "1754990000.000000"
  },
  "exit": {
    "outcome": {
      "kind": "exited",
      "code": 0
    },
    "activation": "observed",
    "identity": {
      "pid": 4242,
      "start_time": 1755000000000000,
      "boot_id": "1754990000.000000"
    }
  },
  "events": [
    {
      "session_id": "019512f0-0000-7000-8000-000000000001",
      "generation": 1,
      "seq": 4,
      "observed_at": {
        "secs_since_epoch": 1755000000,
        "nanos_since_epoch": 123000000
      },
      "identity": {
        "pid": 4242,
        "start_time": 1755000000000000,
        "boot_id": "1754990000.000000"
      },
      "observation": "directly_observed",
      "what": {
        "kind": "exec_observed"
      }
    }
  ]
}
```
