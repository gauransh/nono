#!/usr/bin/env bash
#
# stream-gates.sh — the full gate matrix for the Crystal Nono substrate fork,
# with three outcomes per gate and no fourth.
#
#   PASS     the gate ran here, now, and was green
#   FAIL     the gate ran here, now, and was red
#   NOT_RUN  the gate did not run, and the line says which concrete capability
#            this host is missing to run it
#
# NOT_RUN is never PASS (stream contract §12). A gate that could not run is an
# unanswered question, and the summary counts it separately from both answers.
# The exit status is nonzero if and only if at least one gate FAILed, so a host
# that cannot run half the matrix still reports honestly on the half it can.
#
# Every gate writes its full output to a log directory printed at the end, so a
# FAIL line can be traced back to the transcript that produced it.
#
# Usage:
#   scripts/stream-gates.sh            # run everything this host can run
#   scripts/stream-gates.sh --list     # print the gate names and exit
#
# Environment:
#   STREAM_GATES_LOG_DIR   where to write per-gate logs (default: mktemp -d)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

HOST_OS="$(uname -s)"
LOG_DIR="${STREAM_GATES_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/stream-gates.XXXXXX")}"
mkdir -p "$LOG_DIR"

PASS_COUNT=0
FAIL_COUNT=0
NOT_RUN_COUNT=0
FAILED_GATES=""
NOT_RUN_GATES=""

GATE_NAMES=(
  workspace-tests
  nono-crate-tests
  lifecycle-live
  lifecycle-modes-live
  lifecycle-detached
  loom-lifecycle
  clippy-strict
  clippy-loom
  fmt-check
  lint-docs
  lint-aliases
  doc-tests
  miri-pure-lifecycle
  linux-landlock-live
  linux-lifecycle-live
)

if [[ "${1:-}" == "--list" ]]; then
  printf '%s\n' "${GATE_NAMES[@]}"
  exit 0
fi

# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

emit() {
  # emit <status> <gate> <detail>
  printf '%-8s %-22s %s\n' "$1" "$2" "$3"
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  emit PASS "$1" "$2"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  FAILED_GATES="$FAILED_GATES $1"
  emit FAIL "$1" "$2"
}

not_run() {
  # A NOT_RUN reason must name the capability this host lacks, not the fact
  # that it lacks one. "unavailable" is not a reason; "docker daemon down" is.
  NOT_RUN_COUNT=$((NOT_RUN_COUNT + 1))
  NOT_RUN_GATES="$NOT_RUN_GATES $1"
  emit NOT_RUN "$1" "$2"
}

# Summarize a libtest-shaped log: every `test result:` line aggregated, so a
# multi-suite run reports one set of totals plus the suite count.
test_summary() {
  local log="$1"
  awk '
    /^test result:/ {
      suites++
      for (i = 1; i <= NF; i++) {
        if ($(i+1) ~ /^passed/)  p += $i
        if ($(i+1) ~ /^failed/)  f += $i
        if ($(i+1) ~ /^ignored/) g += $i
      }
    }
    END {
      if (suites == 0) { print "no test-result line in log"; exit }
      printf "%d passed / %d failed / %d ignored (%d suites)", p, f, g, suites
    }
  ' "$log"
}

# Last lines of a failing log, for the operator who is about to open it.
failure_tail() {
  local log="$1"
  local line
  line="$(grep -E '^(error|test result: FAILED|failures:|thread .* panicked)' "$log" | head -1)"
  if [[ -z "$line" ]]; then
    line="$(grep -v '^[[:space:]]*$' "$log" | tail -1)"
  fi
  printf '%s' "${line:0:140}"
}

# run_gate <name> <summary-kind: tests|plain> <command...>
run_gate() {
  local name="$1" kind="$2"
  shift 2
  local log="$LOG_DIR/$name.log"
  if "$@" >"$log" 2>&1; then
    if [[ "$kind" == tests ]]; then
      pass "$name" "$(test_summary "$log")"
    else
      pass "$name" "clean"
    fi
  else
    if [[ "$kind" == tests ]]; then
      fail "$name" "$(test_summary "$log") — $(failure_tail "$log")"
    else
      fail "$name" "$(failure_tail "$log")"
    fi
  fi
}

# ---------------------------------------------------------------------------
# capability probes
# ---------------------------------------------------------------------------

# Why the Linux gates are not running here, in the operator's terms. The
# reason is probed rather than assumed, so a host that has since started
# Docker gets a different line.
linux_absent_reason() {
  if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
      printf 'Linux execution environment available but not wired: run this script inside a container built from docker/Dockerfile-CI'
    else
      printf 'Linux execution environment unavailable: docker daemon down (open Docker Desktop once and accept the first-run prompt)'
    fi
  else
    printf 'Linux execution environment unavailable: no docker binary on PATH (install Docker Desktop, then open it once and accept the first-run prompt)'
  fi
}

# Miri runs on nightly only, and only with the component installed. Both halves
# are probed, because "no nightly" and "nightly without miri" are different
# operator actions.
miri_absent_reason() {
  if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    printf 'nightly toolchain not installed: rustup toolchain install nightly --component miri'
    return
  fi
  printf 'miri component not installed: rustup +nightly component add miri'
}

miri_available() {
  rustup toolchain list 2>/dev/null | grep -q '^nightly' || return 1
  rustup +nightly component list --installed 2>/dev/null | grep -q '^miri' || return 1
  return 0
}

# ---------------------------------------------------------------------------
# the matrix
# ---------------------------------------------------------------------------

echo "stream-gates: host $HOST_OS $(uname -m), logs in $LOG_DIR"
echo

run_gate workspace-tests tests \
  cargo test --workspace --no-fail-fast

run_gate nono-crate-tests tests \
  cargo test -p nono --no-fail-fast

# `--nocapture` so a test that decided it could not answer says so in the log.
# Several tests here report INCONCLUSIVE or NOT_APPLICABLE on a host that
# cannot give them what they need -- an unprivileged runner has no writable
# cgroup2 mount -- and libtest swallows the stdout of a *passing* test. Without
# this the log cannot distinguish a gate that proved something from one that
# skipped, which is the whole difference between evidence and a green tick.
run_gate lifecycle-live tests \
  cargo test -p nono --test lifecycle_live -- --nocapture

# The mode matrix asserts Seatbelt behaviour and is `#![cfg(target_os =
# "macos")]`; on Linux it compiles to zero tests, and zero tests passing is not
# a pass. The Linux half of the same vocabulary is linux-landlock-live.
if [[ "$HOST_OS" == "Darwin" ]]; then
  run_gate lifecycle-modes-live tests \
    cargo test -p nono --test lifecycle_modes_live
else
  not_run lifecycle-modes-live \
    "macOS-only target (#![cfg(target_os = \"macos\")]): needs a Seatbelt host; the Linux half is linux-landlock-live"
fi

run_gate lifecycle-detached tests \
  cargo test -p nono --test lifecycle_detached

run_gate loom-lifecycle tests \
  env RUSTFLAGS='--cfg nono_loom' cargo test -p nono --test loom_lifecycle --release

run_gate clippy-strict plain \
  cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used

run_gate clippy-loom plain \
  env RUSTFLAGS='--cfg nono_loom' cargo clippy -p nono --all-targets -- -D warnings -D clippy::unwrap_used

run_gate fmt-check plain \
  cargo fmt --all -- --check

run_gate lint-docs plain \
  bash scripts/lint-docs.sh

run_gate lint-aliases plain \
  bash scripts/test-list-aliases.sh

run_gate doc-tests tests \
  cargo test --doc -p nono

# Miri over the PURE half of the lifecycle only: the state machine, plan
# validation, the gate's constant-time classification, and the recovery
# decision table. Everything else in this module forks, execs, opens sockets or
# writes files, none of which miri can interpret — so the filter is a
# deliberate subset and not a whole-crate claim.
#
# `--lib` is part of the gate, not a convenience: the crate's integration
# targets spawn processes and re-exec themselves, so building or running any of
# them under miri can only ever produce "unsupported operation". If a
# `Running tests/...` line ever appears in this gate's log, the target selection
# below has stopped working and the gate is measuring something else.
MIRI_FILTERS=(
  lifecycle::state::
  lifecycle::gate::
  lifecycle::plan::
  a_verified_record_is_never_re_adopted_whatever_the_probe_says
  a_live_supervisor_outranks_every_probe_of_the_child
  a_supervisor_that_is_gone_falls_back_to_the_slice_a_table
  every_verdict_maps_to_exactly_one_decision
)

# Miri's sandbox refuses `clock_gettime(CLOCK_REALTIME)` — a host clock read is
# not something it can interpret deterministically — and the plan tests take
# timestamps for their event ring. Disabling isolation is the documented way to
# let interpreted code read the real clock; it does not weaken any check miri
# makes about the code itself, which is what this gate is for.
MIRI_ENV=(MIRIFLAGS="${MIRIFLAGS:-} -Zmiri-disable-isolation")

# How many tests a libtest log says actually ran.
test_ran_count() {
  awk '
    /^test result:/ {
      for (i = 1; i <= NF; i++) {
        if ($(i+1) ~ /^passed/) p += $i
        if ($(i+1) ~ /^failed/) f += $i
      }
    }
    END { print p + f + 0 }
  ' "$1"
}

if miri_available; then
  MIRI_LOG="$LOG_DIR/miri-pure-lifecycle.log"
  if env "${MIRI_ENV[@]}" \
      cargo +nightly miri test -p nono --lib -- "${MIRI_FILTERS[@]}" \
      >"$MIRI_LOG" 2>&1; then
    # A filter that matches nothing exits zero, and a gate that reports PASS for
    # zero tests is the exact shape of a check that has quietly stopped
    # checking. Zero is NOT_RUN, with the reason named.
    if [[ "$(test_ran_count "$MIRI_LOG")" -gt 0 ]]; then
      pass miri-pure-lifecycle "$(test_summary "$MIRI_LOG")"
    else
      not_run miri-pure-lifecycle \
        "miri ran zero tests: the filters in MIRI_FILTERS match no test in the library target (a green run of nothing is not a pass)"
    fi
  else
    fail miri-pure-lifecycle "$(test_summary "$MIRI_LOG") — $(failure_tail "$MIRI_LOG")"
  fi
else
  not_run miri-pure-lifecycle "$(miri_absent_reason)"
fi

# The two Linux halves. On a Linux host they are ordinary gates; on macOS they
# are the stream's one standing external blocker. Cross-compilation is not a
# workaround (the crate pulls sigstore-verify -> aws-lc-sys, which wants
# x86_64-linux-gnu-gcc), which is why the reason names a runner and not a
# target triple.
if [[ "$HOST_OS" == "Linux" ]]; then
  run_gate linux-landlock-live tests \
    cargo test -p nono --lib -- sandbox::linux:: capability_modes::
  run_gate linux-lifecycle-live tests \
    cargo test -p nono --test lifecycle_live --test lifecycle_detached
else
  LINUX_REASON="$(linux_absent_reason)"
  not_run linux-landlock-live "$LINUX_REASON"
  not_run linux-lifecycle-live "$LINUX_REASON"
fi

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

echo
echo "----------------------------------------------------------------------"
printf 'gates: %d PASS  %d FAIL  %d NOT_RUN  (of %d)\n' \
  "$PASS_COUNT" "$FAIL_COUNT" "$NOT_RUN_COUNT" "${#GATE_NAMES[@]}"
[[ -n "$FAILED_GATES" ]] && echo "failed:  $FAILED_GATES"
[[ -n "$NOT_RUN_GATES" ]] && echo "not run: $NOT_RUN_GATES"
echo "logs:    $LOG_DIR"
echo "NOT_RUN is not PASS: each line above names the capability this host lacks."
echo "----------------------------------------------------------------------"

[[ "$FAIL_COUNT" -eq 0 ]]
