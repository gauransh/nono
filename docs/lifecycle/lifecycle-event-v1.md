# Lifecycle event, schema version 1

One fact `nono::lifecycle` observed, as it is handed to a consumer's
`EventSink`.

Source of truth: `crates/nono/src/lifecycle/events.rs` (`LifecycleEvent`,
`LifecycleEventKind`). The golden example below is locked by a test in that
file — if the type changes without the doc, that test fails and names this
path.

## What is and is not in this vocabulary

The library emits facts; it never routes them anywhere. **Events the platform
cannot show are absent, never synthesized.** There is no kernel-denial event in
this vocabulary because this library does not observe kernel denials — see
`SupportReport::event_observation`, which says so in machine-readable form.

Every event is emitted *after* the fact it reports and *outside* the lifecycle's
internal lock, because a sink is consumer code that may do anything, including
calling back in. The consequence is stated rather than hidden: a supervisor that
dies between the fact and the emit reports one event fewer.

## Envelope fields

| Field | Type | Nullable | Meaning |
|---|---|---|---|
| `session_id` | UUID (v7 string) | **yes** | The run this event is about. The type allows `None` so it can describe a moment before a session exists; nothing in this slice emits one, so in practice it is always present. |
| `generation` | `u64` | no | Which preparation of that session. Always `1` today. |
| `seq` | `u64` | no | This run's own counter, from `0`. **The ordering authority.** One counter per run, kept across the handoff from `PreparedSandbox` to `ActivatedSandbox`, so a consumer sees one unbroken sequence. Numbers are allocated by a single atomic immediately before the sink is called, so there are no gaps; two events emitted from different threads may still *arrive* out of order, and `seq` is what puts them back. |
| `observed_at` | object (`secs_since_epoch`, `nanos_since_epoch`) | no | Wall clock read at the moment of observation. **Not** an ordering key: a wall clock can step backwards. It is there to correlate with a consumer's own logs. |
| `identity` | object | **yes** | The child's pid, start time, and boot id — the same shape as a session record's `identity`. Absent only on `prepare_started`, which happens before the fork. |
| `observation` | enum | no | `directly_observed` or `reconstructed`. Everything this slice emits is directly observed. |
| `what` | object | no | The fact, tagged by `kind`. |

## Event kinds

| `kind` | Payload | When it is emitted |
|---|---|---|
| `state_changed` | `from`, `to` (lifecycle states) | Every transition of the state machine, after it happened. |
| `prepare_started` | — | A child is about to be forked. The only event with no `identity`. |
| `sandbox_applied` | — | The trusted child's status record arrived; it writes that record only *after* applying the sandbox. |
| `gate_ready` | — | Same record: the child is blocked at the gate and nothing of the customer's program has run. |
| `activation_attempted` | `outcome` | Every activation attempt, at the point its outcome is known. Carries **no token material** — see below. |
| `released` | — | The release message was written to the gate, by the attempt that won the single-use claim. |
| `exec_observed` | — | The status descriptor reached EOF with no record. Deliberately not "the program started": a child killed just before `execve` closes it the same way. |
| `child_exited` | `outcome` (exit facts) | The child's death was observed on a path that was not a stop: `wait()`, a prepare failure, or a failed activation. |
| `stop_requested` | — | A stop was requested. The signal is not the result. |
| `stop_observed` | `outcome` (exit facts) | The death a stop asked for was observed by `waitpid`. |
| `gate_aborted` | — | A live gate was closed without releasing the child: stop, expiry, failed activation, or drop. Emitted only when a gate was actually closed here, so a stop followed by a drop is not two events. |
| `supervisor_failure` | `stage`, `errno` | The supervisor's own machinery failed; nothing is claimed about the child at that point. |
| `cleanup_verdict` | `verdict` | Every cleanup verification verdict, not only a proof of absence: "something is still there" is exactly as much a fact as "nothing is". |
| `record_persisted` | `schema_version` | A durable session record was written and `fsync`ed. Never emitted for a write that failed. |

### `activation_attempted` outcomes

`outcome` is one of `accepted`, `refused_wrong_session`,
`refused_wrong_generation`, `refused_gate_closed` (with the `state` that
refused), `refused_expired`, `refused_invalid_token`.

Each refusal names **the check that refused, never the value that failed it**.
No activation token, token digest, or gate release/abort nonce can appear in an
event: an event is the thing most likely to be logged, forwarded, or pasted into
an issue, and a single copy of the token is a start button for a held child. A
test in `events.rs` locks this structurally over both the serde and the `Debug`
form.

## Ordering, for a happy run

```text
prepare_started
sandbox_applied
gate_ready
state_changed preparing -> prepared
activation_attempted accepted
state_changed prepared -> activating
released
exec_observed
state_changed activating -> running
child_exited
state_changed running -> exited
```

A run created through `SessionStore::prepare` interleaves a `record_persisted`
after each `state_changed`, plus one for the record's creation.

The rule the order follows: **the fact first, then the state change it caused.**

## Golden example

```json
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
    "kind": "activation_attempted",
    "outcome": {
      "outcome": "accepted"
    }
  }
}
```
