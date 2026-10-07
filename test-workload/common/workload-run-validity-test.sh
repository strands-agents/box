#!/bin/bash
# common/workload-run-validity-test.sh — pin the per-agent run-validity proof.
#
# The gate decides whether a case FAILS with `run-invalid` or is scored against
# the oracle, so each agent's proof needs a test beside it. This script writes
# synthetic transcripts and checks the gate's answer. It runs on the operator's
# own host and needs no instance, no box, and no model.
#
# Usage: workload-run-validity-test.sh     (exit 0 all pinned, 1 a failure)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/workload-run-validity.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAILURES=0

check() {   # check <label> <expected> <agent> <turns> [last]
  local label="$1" want="$2"; shift 2
  local got
  got="$(bash "$GATE" "$@" 2>/dev/null)"
  if [ "$got" = "$want" ]; then
    echo "ok   $label"
  else
    echo "FAIL $label: want [$want] got [$got]"
    FAILURES=$((FAILURES + 1))
  fi
}

check_refusal() {   # check_refusal <label> <agent>
  local label="$1" agent="$2" out code
  out="$(bash "$GATE" "$agent" "$WORK/empty.jsonl" 2>&1)"; code=$?
  if [ "$code" -eq 3 ] && case "$out" in *"$agent"*) true ;; *) false ;; esac; then
    echo "ok   $label"
  else
    echo "FAIL $label: exit $code, message [$out]"
    FAILURES=$((FAILURES + 1))
  fi
}

: > "$WORK/empty.jsonl"
: > "$WORK/empty.txt"
printf 'answer\n' > "$WORK/last.txt"

printf '%s\n' '{"type":"system"}' '{"type":"tool_use","name":"Bash"}' \
  '{"type":"result"}' > "$WORK/claude-valid.jsonl"
printf '%s\n' '{"type":"system"}' '{"type":"result"}' > "$WORK/claude-notools.jsonl"
printf '%s\n' '{"id":"1"}' '{"id":"2"}' '{"id":"3"}' > "$WORK/codex-events.jsonl"
printf '%s\n' '{"kind":"strands.start"}' \
  '{"kind":"strands.tool_invocation","tool":"run_command","seq":1}' \
  '{"kind":"strands.tool_result","seq":1}' \
  '{"kind":"strands.tool_invocation","tool":"write_file","seq":2}' \
  '{"kind":"strands.end","tool_invocations":2}' > "$WORK/strands-valid.jsonl"
printf '%s\n' '{"kind":"strands.start"}' \
  '{"kind":"strands.error","error":"could not reach the model"}' \
  > "$WORK/strands-notools.jsonl"
printf '%s\n' '{"kind":"strands.start"}' \
  '{"kind":"strands.tool_invocation","tool":"run_command","seq":1}' \
  > "$WORK/strands-killed.jsonl"
# One transcript comes from the agent's own emit(), so the gate's pattern is
# checked against the bytes the agent writes and not against a hand-written line.
python3 - "$HERE/workload-strands-agent.py" > "$WORK/strands-emitted.jsonl" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("agent", sys.argv[1])
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
agent.emit("strands.tool_invocation", tool="run_command", seq=1)
PY

# Claude Code proves the model answered with a tool_use event.
check "claude with a tool_use is VALID"  "VALID 1 3"   claude "$WORK/claude-valid.jsonl" ""
check "claude without one is INVALID"    "INVALID 0 2" claude "$WORK/claude-notools.jsonl" ""

# Codex proves it with a final message, or with more than two events.
check "codex with a last message is VALID" "VALID 0 0" codex "$WORK/empty.jsonl" "$WORK/last.txt"
check "codex with three events is VALID"   "VALID 0 3" codex "$WORK/codex-events.jsonl" "$WORK/empty.txt"
check "codex with neither is INVALID"      "INVALID 0 0" codex "$WORK/empty.jsonl" "$WORK/empty.txt"

# The Strands agent proves it with its own tool_invocation event, and counts
# those events as the row's tool_uses.
check "strands with two invocations is VALID" "VALID 2 5"   strands "$WORK/strands-valid.jsonl" ""
check "strands that only errored is INVALID"  "INVALID 0 2" strands "$WORK/strands-notools.jsonl" ""
# The proof is flushed before the tool runs, so a killed run stays VALID and
# agent B reports `case-timeout` rather than `run-invalid`.
check "strands killed after one call is VALID" "VALID 1 2" strands "$WORK/strands-killed.jsonl" ""
check "the agent's own emit() is counted"       "VALID 1 1" strands "$WORK/strands-emitted.jsonl" ""
# Claude's rule scores only a Claude transcript; a Strands transcript under it
# is INVALID.
check "strands is not scored by claude's rule" "INVALID 0 5" claude "$WORK/strands-valid.jsonl" ""

# An unknown agent name fails with the name in the message.
check_refusal "an unknown name is refused by name" nobody
check_refusal "a second unknown name is refused by name" gemini
check_refusal "an empty name is refused"                 ""

if [ "$FAILURES" -eq 0 ]; then
  echo "run-validity: all checks pinned"
else
  echo "run-validity: $FAILURES check(s) failed"
fi
[ "$FAILURES" -eq 0 ]
