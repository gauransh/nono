# Session record, schema version 1

The durable record `nono::lifecycle::SessionStore` writes for one session, one
file per session at `<store>/<session-id>.json`, mode `0600`.

Source of truth: `crates/nono/src/lifecycle/session_store.rs`
(`SessionRecord`). The golden example below is locked by a test in that file —
if the type changes without the doc, that test fails and names this path.

## What a record is for, and what it is not

A record exists so that a caller which crashed can reason about a process it no
longer supervises. It carries who the process was, what group it leads, and
where the machine believed the run had got to — nothing else.

There is **no program, no argument list, no environment, and no capability
set** in a record. A record that carried the run's command line would be a
durable copy of whatever secrets that command line held. The only caller-owned
bytes in it are `metadata`, which the library copies and returns and never
interprets.

Two properties a consumer must build on:

1. **A record may lag the live state by one step.** It is written *after* the
   transition it describes, outside the lifecycle lock. `SessionStore::recover`
   reconciles a loaded record against the live system rather than believing it;
   a consumer must not treat `state` as a statement about the present.
2. **A record from another schema version is refused, not interpreted.** The
   version is read on its own before the rest of the shape, so a newer writer
   is never read field by field.

## Fields

| Field | Type | Nullable | Meaning |
|---|---|---|---|
| `schema_version` | `u32` | no | The schema this record was written by. Version 1 is the first; any other value — higher *or* lower — is `SessionStoreError::UnsupportedSchemaVersion`. |
| `session_id` | UUID (v7 string) | no | The session's id, which is also its file name. A record whose id disagrees with its file name is `SessionCorrupt`. |
| `generation` | `u64` | no | Which preparation of this session the record describes. Always `1` today: sessions are one-shot UUIDs and nothing re-prepares into an existing slot. The field exists because the flow that increments it would otherwise have to change the shape. |
| `identity` | object | no | The recorded process, with the facts a reissued pid cannot forge. See below. |
| `identity.pid` | `i32` | no | The pid as the kernel issued it. |
| `identity.start_time` | `u64` | **yes** | Platform-opaque process start time — Linux clock ticks since boot, macOS microseconds since the epoch. Comparable for equality only. `null` when the platform would not say, which makes every later identity check fail closed. |
| `identity.boot_id` | string | **yes** | Opaque identifier for the boot the pid was issued in (`/proc/sys/kernel/random/boot_id`; `kern.boottime` on macOS). `null` when the platform would not say. |
| `process_group` | `i32` | no | The process group the run leads, equal to the child's pid by construction. Recorded rather than re-derived: a reaped pid is a number the kernel may reissue, while the group this run used is a fact about the run. |
| `state` | enum | no | Where the run had got to when the record was last written. One of `planning`, `preparing`, `prepared`, `activating`, `running`, `exited`, `stopping`, `stopped`, `cleanup_verified`, `failed`. A claim about the past — see above. |
| `activation` | enum | **yes** | Whether the customer's program was observed to start, if that was known when the record was written: `observed`, `not_activated`, `exec_or_killed_pre_exec`. `null` until the run's end is known. Deliberately three-valued: a child killed between the gate release and `execve` closes the status descriptor exactly as a successful `execve` does. |
| `created_unix_millis` | `u64` | **yes** | Wall-clock milliseconds since the Unix epoch when the record was created, or `null` if the clock would not say. Advisory: nothing in the library decides anything from a timestamp. |
| `updated_unix_millis` | `u64` | **yes** | Same, for the last write. |
| `metadata` | array of `u8` | no (may be empty) | The caller's opaque bytes, copied from the plan and never interpreted. Bounded by `MAX_PLAN_METADATA_BYTES` (4096); a longer array on load is `SessionCorrupt`. |

Absent optional fields are omitted from the JSON rather than written as `null`
where the type allows it; both forms load.

## Golden example

```json
{
  "schema_version": 1,
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
  ]
}
```
