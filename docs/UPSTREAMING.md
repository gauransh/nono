# UPSTREAMING — rebasing this fork, and proposing its pieces upstream

Fork-only document. Companion to `NONO_UPSTREAM_DELTA.md`, which is the table of *what*
changed; this is the procedure for *moving* it — forward onto newer upstream, or outward as
pull requests.

Two audiences, in this order:

1. **A maintainer of this fork** who needs to rebase onto a newer `nolabs-ai/nono` without
   losing the substrate. → §1, §2, §3.
2. **Whoever prepares an upstream PR** from one of these deltas. → §4, §5, §6, §7.

Read §5 before doing anything in §4: upstream's contribution policy has hard stops that make
"open a PR and see" a policy violation rather than a first draft.

---

## 1. Rebasing onto newer upstream

### 1.1 Ground rules

- **Rebase, don't merge.** Every fork delta is one commit with one row in
  `NONO_UPSTREAM_DELTA.md`; a merge commit would fuse them and destroy the row-to-commit
  mapping that makes an upstream PR extractable later.
- **Never hand-resolve `Cargo.lock`.** Take upstream's, then `cargo check -p nono` and let
  cargo re-add the fork's own dependencies (`uuid`, `loom` under `nono_loom`, the `nix`
  features). A hand-merged lock is how a phantom version skew gets committed.
- **A clean rebase is not a passing build**, and on this repository it is not even a
  compiling one — see §1.4.

### 1.2 The order

```bash
# 0. Start green. A rebase begun on a red tree cannot tell you what it broke.
./scripts/stream-gates.sh          # must be 0 FAIL before you start

git fetch origin
git log --oneline <current-pin>..origin/main     # read every commit message
git diff --stat <current-pin>..origin/main -- crates/nono/       # library churn is the risk

# 1. Record the re-diff FIRST, while the diff is in front of you.
#    NONO_UPSTREAM_DELTA.md §2 gets one table row per upstream commit:
#    what it adds, whether it touches the fork, and its relationship to a fork delta.
#    §2 is a deliverable, not a note — R16 is PASS only when it is current.

# 2. Measure the conflict surface before creating one.
comm -12 <(git diff --name-only <current-pin> HEAD | sort) \
         <(git diff --name-only <current-pin> origin/main | sort)
git merge-tree --write-tree HEAD origin/main     # a tree = clean; a report = conflicts

# 3. Dry-run the rebase in an isolated clone. Nothing touches your working tree.
git clone --shared --no-checkout . /tmp/rebase-probe
git -C /tmp/rebase-probe checkout -b probe HEAD
git -C /tmp/rebase-probe rebase origin/main

# 4. Only then, for real.
git rebase origin/main

# 5. Re-pin and re-run.
#    SOURCE_LOCK.json, HANDOFF.md "Upstream base", NONO_UPSTREAM_DELTA.md title line.
./scripts/stream-gates.sh
```

### 1.3 Expected conflicts, per delta row

`NONO_UPSTREAM_DELTA.md` §5 is the live version of this table and takes precedence. The short
form, keyed to the delta rows:

| Delta | File it shares with upstream | Conflict shape | Resolution |
|---|---|---|---|
| F1 | `scripts/lint-docs.sh`, `scripts/test-list-aliases.sh` | Whole-line, if upstream touches the same `grep -R` invocations | Take upstream's line, re-drop the trailing slash from the directory argument. The bug is BSD grep emitting `crates//path`, so the fix is one character. |
| F3–F10 | none | The whole lifecycle is new files under `crates/nono/src/lifecycle/`. Directories that do not exist upstream cannot conflict. | — |
| F3–F10 wiring | `crates/nono/src/{lib,error}.rs`, `bindings/c/src/lib.rs` | Re-export list and `NonoError` variant list are append-only blocks in alphabetical order; a conflict here is a two-line resolution. `bindings/c` conflicts only because `map_error`'s match is exhaustive. | Take both sides. If upstream added a `NonoError` variant, add its `diagnostic_code` arm and its `map_error` arm; the compiler will name both. |
| F11 | `crates/nono/src/capability.rs` | Only the `resolve_directory`/`resolve_file` extraction rewrites existing lines | Take upstream's `FsCapability::new_dir`/`new_file`, then re-extract the canonicalise-then-check-type body. The extraction is behaviour-identical by construction, which is what makes "take theirs, re-extract" safe. |
| F11 | `crates/nono/src/sandbox/linux.rs` | **Measured clean at `9078ffcf` despite a 461-line upstream refactor of the same file** — the fork's additions are appended functions and appended `for` loops, ~370 lines away from upstream's seccomp work. | If it ever *does* conflict: our side is always the appended block. Re-apply it after upstream's, never interleaved. |
| F11 | `crates/nono/src/sandbox/macos.rs` | One existing line: the unconditional `(allow process-exec*)` | Keep the fork's call, which emits that exact string byte-for-byte when the capability set carries no mode grants. If upstream changed the line's content, change what the no-mode-grants branch emits to match. |
| F11 | `crates/nono-cli/src/capability_ext.rs` | **Semantic, never textual.** The fork does not edit this file; it ported the atomic-write temp-sibling rule out of it with attribution, and upstream `36243aa5` has since extended the original with an unlink rule. | Git will not tell you. Re-read `capability_ext.rs` after every rebase and check whether the fork's `sbpl_map` port has drifted from it. |
| F2 (docs) | none | Fork-only files at repo root | — |

### 1.4 Verification gates to re-run, and the one that matters

Re-run the whole matrix — `./scripts/stream-gates.sh` — and read the NOT_RUN lines as
carefully as the FAIL lines.

**The gate that decides whether a rebase of `sandbox/linux.rs` actually worked is
`linux-landlock-live`, and on a macOS host it is NOT_RUN.** That file is
`cfg(target_os = "linux")` in its entirety, so a macOS `cargo check` compiles *zero* of it —
including the parts the rebase just merged. Textual cleanliness is genuinely all a macOS host
can establish about that file.

So: **rebase, push, and read the `ubuntu-latest` job of `.github/workflows/stream-gates.yml`
before believing a clean rebase.** Locally the equivalent is a container built from
`docker/Dockerfile-CI` with the source mounted.

Beyond the standard matrix, three things are worth re-running by hand after a rebase that
touched `crates/nono`:

```bash
# The doc snapshot tests: they read docs/lifecycle/*.md through include_str! and fail
# if a schema doc and its type drift apart. A rebase can move a type.
cargo test -p nono --lib -- lifecycle::support:: lifecycle::session_store:: lifecycle::events::

# The live suites, three consecutive times. They fork, exec, and bind sockets; a single
# green run of a concurrency-shaped suite is weaker evidence than it looks.
for i in 1 2 3; do cargo test -p nono --test lifecycle_live --test lifecycle_detached || break; done

# Loom, which is the only thing that speaks about interleavings the live tests sample.
RUSTFLAGS='--cfg nono_loom' cargo test -p nono --test loom_lifecycle --release
```

---

## 2. Re-pinning after a rebase

Four places state the upstream base. All four must move together, or the next reader is
working from a lie:

| File | Field |
|---|---|
| `SOURCE_LOCK.json` | the pinned upstream SHA |
| `NONO_UPSTREAM_DELTA.md` | title line (`— fork vs nolabs-ai/nono @ <sha>`) and §2 |
| `HANDOFF.md` | "Branch and base" → Upstream base |
| `BLOCKED_ROWS.json` | R16's evidence, if the re-diff changed what §2 says |

---

## 3. What a rebase must not do

- **Do not adopt upstream's CLI-level solution to a problem the fork solved at the library
  level, and do not carry both.** The live example is atomic-write unlink: upstream
  `36243aa5` adds a CLI policy rule; F11 has `FsMode::AtomicWrite` with a published member
  set. Carrying both means two independent things emit `file-write-unlink` for the same temp
  pattern, and only one of them is disclosed to the caller.
- **Do not let a fork test assert an upstream internal's size.** Upstream `5be192ad` changed
  `prepare_seccomp_af_unix_filter` from 8 rules to 14 and updated its own assertion. No fork
  test asserts a filter length today, and none should start.
- **Do not resolve a conflict by deleting a fork guard.** Every guard in the lifecycle module
  has a removal-detection transcript in `WORKLOG.md`; a conflict resolution that quietly drops
  one is exactly the failure those transcripts exist to catch. If a guard has to go, the
  transcript is the thing to read first.

---

## 4. Upstream PR candidates, in order

The disposition column of `NONO_UPSTREAM_DELTA.md` §4 is the source of truth. Ordered by
"smallest thing a maintainer can say yes to" first, because each acceptance makes the next
conversation easier:

### PR 1 — F1/F1b: portability and test hygiene

**Smallest, cleanest, and independent of everything else in the fork.**

- BSD-grep trailing-slash bug in `scripts/test-list-aliases.sh` and `scripts/lint-docs.sh`:
  a trailing `/` on a `grep -R` directory argument makes BSD grep emit `crates//path`, which
  then fails the allowlist regexes. Four arguments, one character each.
- `ENV_LOCK` acquisition in the `command_runtime` dry-run test and three
  `tool-sandbox/dynamic_providers` git tests, which read ambient `$HOME`/`PATH` and race
  env-mutating siblings. Measured: 16/20 failures before, 0/20 after; and 7/20 → 0/20 for the
  second group.

Why it goes first: it is a **bug fix for maintainers on macOS**, it touches no production
code path, and the evidence is a failure rate rather than an argument. It also has a natural
issue hook — `crates/nono-cli/src/test_env.rs:7` already cites upstream issue #567 about test
env mutation cleanup, so the issue-first requirement (§5) has an obvious home.

Scope discipline: **this PR contains F1 only.** Not the lifecycle, not the mode vocabulary,
not one line of `crates/nono/src/lifecycle/`.

### PR 2 — F11: the mode-aware filesystem capability vocabulary

**Second, because it answers a gap upstream documents in its own words** ("No independent
append/create/truncate/remove/rename/metadata/exec toggles") and because it adds no
dependency and changes no existing behaviour.

What to lead with in the issue:

- `AccessMode`, `allow_path` and `allow_file` are **untouched**. A capability set that uses
  none of the new API compiles to the same profile bytes, including macOS's unconditional
  `(allow process-exec*)`. Upstream's own suite is byte-identically green — that is the first
  thing a maintainer will want to know.
- The one place emitted output can differ is macOS `execute` scoping, and it differs **only**
  for capability sets built with an API upstream does not yet have. Flag this for review
  explicitly rather than letting a reviewer find it.
- `atomic_write` overlaps upstream `36243aa5`. Say so in the issue and offer the trade
  honestly: the CLI regex and the capability bundle should not both ship.
- Attribution is a policy requirement, not a courtesy (§5.3): the macOS temp-sibling rule is
  ported from `nono-cli/src/capability_ext.rs:434-460`, narrowed from `file-write*` to four
  operations, with the hex-suffix fix from `5f0b95a0`. Name the file, the lines and the
  commit in the PR body.
- The mapping tables are pure functions (`capability_modes/{landlock_map,sbpl_map}.rs`) with
  no dependency on the lifecycle, so **upstream can adopt part of this** — which is worth
  saying, because a maintainer who cannot take all of it may take some.

Blocking precondition: F11's Linux half has never executed on a Linux kernel. **Do not open
this PR until the `ubuntu-latest` job of the stream-gates workflow is green**, or open it
disclosing that limitation in the first paragraph. Claiming Linux behaviour that has only
been host-tested against a faked ABI is exactly the kind of thing §5.7 says to stop over.

### PR 3 — the lifecycle (F3–F10), as an RFC first and a PR second

**This one is not a pull request. It is a design conversation that may become several.**

Size and shape are why:

- ~15 new modules and four new test targets under `crates/nono`.
- It presumes a staged model (plan → prepared → activated → exit → cleanup-verified) that
  upstream does not have; upstream's model is one-shot `CapabilitySet` → `Sandbox::apply_*`.
- F9's detached supervisor requires **one line of embedder cooperation**
  (`nono::lifecycle::supervisor_entry()` as the first statement of `main`). A library asking
  its consumers to change `main` is a design decision a maintainer must own, not a diff to
  review. ADR-0002 exists to make that arguable.
- F10's PTY work found two real deadlocks and a macOS/Linux `killpg` divergence. Those are
  the interesting part of the conversation and they do not fit in a PR description.

So the order is: file **one issue** proposing the staged lifecycle as a concept, linking
`docs/adr/0001-generic-lifecycle.md` and `docs/adr/0002-detached-supervisor.md`. Ask whether
upstream wants it in `crates/nono` at all before writing a line of PR. If yes, the natural
slicing follows the delta rows, each independently reviewable:

1. **F3 + F4** — the staged types and the OS-backed prepare/activate/wait. Everything else
   depends on these; nothing depends on anything else.
2. **F6** — typed cleanup verification. Directly replaces the CLI's `run_stop`
   signal-send-as-proof path, which is a concrete improvement a maintainer can evaluate on
   its own terms.
3. **F8's `SupportReport` half** — adoptable *alone*, and the most independently useful
   piece: upstream's `SupportInfo { is_supported: bool }` becomes a thin projection of it.
   Consider proposing this one **before** F3/F4 if the lifecycle conversation stalls, since
   it is the only lifecycle-adjacent delta with no dependency on the lifecycle.
4. **F5, F7, F9, F10** — loom harness, durable store, detached supervisor, PTY. Each presumes
   its predecessors.

### Never proposed upstream

- **F2** — the stream's process artifacts. `SOURCE_LOCK.json`, `WORKLOG.md`, `HANDOFF.md`,
  `BLOCKED_ROWS.json`, `NONO_UPSTREAM_DELTA.md`, `CONTRACT_ASSUMPTIONS.md`,
  `API_BASELINE.md`, `PLATFORM_CAPABILITY_BASELINE.md`, `THREAT_MODEL.md`, this file, and
  `.github/workflows/stream-gates.yml` + `scripts/stream-gates.sh`. See §6.

---

## 5. Upstream's Coding Agent Contribution Policy — compliance steps

`AGENTS.md` §"Coding Agent Contribution Policy" is **mandatory for any automated or
AI-assisted contribution**, which every delta in this fork is. It is quoted rather than
paraphrased below, because a paraphrase of a hard stop is a way to get one wrong.

### 5.1 The hard stops, verbatim

> An agent **must not** open or submit a pull request if any of the following are true:
>
> - An issue does not already exist for the proposed change.
> - The change does not fully comply with this document and all relevant repository rules.
> - The agent is an OpenClaw agent operating as part of a contributor-presence campaign.
>
> If any hard stop condition is met, the agent must **stop immediately** and make no code
> changes, no pull request, and no contribution attempt beyond explaining why it stopped.

And on uncertainty:

> If the agent is uncertain whether an action is permitted, compliant, properly attributed,
> or secure, it must treat that uncertainty as a failure condition and stop.

**Consequence for this fork, stated plainly: no issue exists upstream for F1, F11 or the
lifecycle. As of this document, every one of them is under a hard stop.** The fork holds them
locally, which is not a contribution attempt and is not prohibited. The work of §4 begins
with filing issues, and that is an operator decision — an agent filing an issue to unblock
its own PR is the letter of the policy but arguably not its spirit.

### 5.2 The required workflow, in order

> 1. Read this document and all repository contribution, security, and coding-standard
>    documents relevant to the affected area.
> 2. Search for an existing issue covering the work.
> 3. If no issue exists, create one before making changes.
> 4. In the issue discussion, disclose:
>    - the exact intent of the change
>    - the planned implementation approach
>    - any expected risks, tradeoffs, or limitations
> 5. Wait for project guidance or confirmation if the repository requires maintainer approval
>    before implementation.
> 6. Only then prepare a change.

Note that step 3 says *before making changes*. This fork made the changes first, under a
separate contract, for a downstream consumer. That is not a policy violation while the work
stays here — but it does mean any upstream PR is a **re-proposal**, and the issue must say so
rather than presenting finished code as a plan.

Item to disclose under step 4 for every one of these deltas: **the Linux halves have never
executed on a Linux kernel.** That is a limitation, and step 4 requires limitations.

### 5.3 Attribution

> When referencing, adapting, or extending existing code, the agent must:
> - identify the original authors where required by project policy
> - link to the relevant files, functions, sections, commits, or discussions
> - clearly distinguish: existing project code / adapted logic / newly written logic
>
> Failure to provide required attribution is a policy violation and may also violate the
> project license, DCO requirements, or both.

Two lifts in this fork require attribution in their PR bodies, and both are already recorded
in `NONO_UPSTREAM_DELTA.md`:

| Lift | From | In |
|---|---|---|
| Per-platform process start time (Linux `/proc/<pid>/stat` field 22 after the last `)`; macOS `PROC_PIDTBSDINFO` + `proc_pidinfo`) | `crates/nono-cli/src/session.rs::get_process_start_time` | F4, `lifecycle/identity.rs`, with checked arithmetic and a new boot-identity half |
| macOS hex-suffixed atomic-write temp-sibling rule | `crates/nono-cli/src/capability_ext.rs:434-460`, hex-suffix + read-metadata fix in commit `5f0b95a0` | F11, `capability_modes/sbpl_map.rs`, narrowed from `file-write*` to four operations |

Also worth naming as *reuse rather than adaptation* (no new mechanism, so no drift): F9's
peer-UID check calls upstream's own `supervisor::socket::peer_credentials`; F8's seccomp
probe calls upstream's own fork-isolated `probe_seccomp_block_network_support`; F8's Landlock
table calls upstream's own `Sandbox::detect_abi` and `DetectedAbi::has_*`.

### 5.4 PR requirements and the compliance checklist

> A pull request may be opened only if all of the following are true:
> - an issue already exists
> - the proposed change matches the issue discussion
> - attribution requirements have been satisfied
> - the code complies with all mandatory repository rules
> - the agent is not prohibited under the hard stop conditions above

The PR description must carry the issue link, a statement that the contributor is an agent, a
summary of the approach, references to files consulted, and an explicit compliance
confirmation. The checklist from `AGENTS.md` must be included and **truthfully** completed:

- [ ] I am not prohibited from contributing under this policy
- [ ] An issue already exists
- [ ] I described my intent and approach in the issue discussion
- [ ] I reviewed repository coding and security rules for the affected area
- [ ] I provided required attribution for reused or adapted code
- [ ] I did not use forbidden patterns such as unwrap/expect
- [ ] I used NonoError where required
- [ ] I validated and canonicalized all relevant paths
- [ ] This PR matches the approved or disclosed issue scope

> If any item cannot be truthfully checked, the agent must not open a pull request. Instead,
> it must stop and report the issue.

Two of these are already mechanically true for this fork and can be checked with evidence
rather than belief: the `clippy::unwrap_used` deny is part of the `clippy-strict` gate in
`scripts/stream-gates.sh`, and every new `LifecycleError` variant is reached through
`NonoError::Lifecycle` with a `diagnostic_code` arm.

---

## 6. Stripping fork-only artifacts from a PR branch

An upstream PR branch must contain **only** the delta being proposed. The stream's process
artifacts are meaningless upstream and actively confusing in review.

### 6.1 The strip list

Everything below was added by this fork and belongs to F2 or to the gate tooling:

```
API_BASELINE.md
BLOCKED_ROWS.json
CONTRACT_ASSUMPTIONS.md
HANDOFF.md
NONO_UPSTREAM_DELTA.md
PLATFORM_CAPABILITY_BASELINE.md
SOURCE_LOCK.json
THREAT_MODEL.md
WORKLOG.md
docs/UPSTREAMING.md
scripts/stream-gates.sh
.github/workflows/stream-gates.yml
```

`docs/adr/0001-generic-lifecycle.md` and `docs/adr/0002-detached-supervisor.md` are the one
judgement call. They are fork process artifacts *and* they are the design record a maintainer
needs to evaluate PR 3. **Keep them for the lifecycle PR; strip them from PR 1 and PR 2**,
where they are noise about work that PR is not proposing.

### 6.2 The procedure

```bash
# Branch from UPSTREAM, not from the fork tip. A PR branch that starts at the fork tip
# carries every other delta as history even after the files are deleted.
git fetch origin
git checkout -b upstream-pr-f1 origin/main

# Cherry-pick only the delta's commits, oldest first.
git cherry-pick <sha-of-F1> [<sha-of-F1b>]

# Verify the strip list is absent. This must print nothing.
git diff --name-only origin/main...HEAD | grep -E \
  '^(API_BASELINE|BLOCKED_ROWS|CONTRACT_ASSUMPTIONS|HANDOFF|NONO_UPSTREAM_DELTA|PLATFORM_CAPABILITY_BASELINE|SOURCE_LOCK|THREAT_MODEL|WORKLOG)\.|^docs/UPSTREAMING\.md$|^scripts/stream-gates\.sh$|^\.github/workflows/stream-gates\.yml$'

# Verify the branch contains ONLY the delta's files. Read this list; do not skim it.
git diff --name-only origin/main...HEAD

# Run upstream's own gate, not ours: the stream matrix includes fork-only targets
# that do not exist on a stripped branch.
make ci
```

If a fork commit mixed a delta with a doc update — which the stream's commits deliberately
avoid, one row per commit — the cherry-pick will bring the doc along. Remove it with
`git rm` and amend, rather than editing the commit's diff by hand.

### 6.3 What must *not* be stripped

The delta's own evidence. `crates/nono/tests/lifecycle_live.rs`,
`crates/nono/tests/lifecycle_modes_live.rs`, `crates/nono/tests/loom_lifecycle.rs` and
`crates/nono/tests/lifecycle_detached.rs` are test targets, not process artifacts: they are
the only thing that makes the claims in the PR description checkable by someone who did not
write them. A PR that strips its own tests is a PR that asks to be believed.

---

## 7. Deletion conditions

Every fork row states how it dies. This is not bookkeeping — it is what stops a fork from
becoming permanent by inattention.

`NONO_UPSTREAM_DELTA.md` §6 defines the policy: a row dies when **(a)** upstream merges an
equivalent, **(b)** the generic feature it supports is upstreamed and the fork-only shim
becomes unnecessary, or **(c)** the stream ends and process artifacts are stripped from the
PR branch. The per-row conditions are the last column of the §4 table. The ones with
non-obvious triggers, worth re-reading at every rebase:

| Row | Dies when |
|---|---|
| F1 | Upstream merges an equivalent portability fix. Check `scripts/` at every rebase — if upstream fixed the trailing slash itself, F1 is dead weight and a *conflict source*. |
| F4's identity lift | The CLI's `session.rs` copy and the library's `identity.rs` copy are reconciled onto one implementation. Until then two copies of the same `/proc` parse exist and can drift. |
| F10's `kill_own_group` EPERM arm | macOS ever answers `ESRCH` for an all-zombie process group. A forking unit test locks the current behaviour and will fail if it changes — which is the notification. |
| F10's Darwin `TIOC*` constants | `libc` declares `TIOCSCTTY`/`TIOCSWINSZ`/`TIOCPTYGNAME` for Apple targets. A unit test recomputes all three from the BSD `_IOC` rule, so adoption is a deletion, not a rewrite. |
| F11 | Upstream adds an equivalent per-operation vocabulary. Partial adoption is explicitly fine: `capability_modes/{landlock_map,sbpl_map}.rs` are pure functions. |
| F9/F10 | Upstream gains a library-owned binary, which removes the need for the `supervisor_entry()` hook entirely — ADR-0002 would then have to be revisited rather than deleted. |
| F2 + this file + the gate tooling | The stream ends. Condition (c). |
