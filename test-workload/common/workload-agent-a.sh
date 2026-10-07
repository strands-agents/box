#!/bin/bash
# common/workload-agent-a.sh — run ONE workload case's agent inside the box.
#
# This is the workload counterpart of common/agent-a-runner.sh: same position in
# the ordering contract (oracle start -> HERE -> oracle stop -> agent B), same
# refusal to trust the agent's own account of what happened. It prepares the
# project, generates the box.toml + policy.dw pair for this (dimension, agent,
# platform) cell, starts the box, and captures the transcript. It decides no
# verdict — the oracle does that from the files on disk.
#
# A dimension whose manifest says `runs=2` is a two-run cell: the project and the
# box directory are kept, the box starts twice, and the dimension supplies run
# two's goal and its trailing agent arguments from run one's artefacts. Run one
# may end by SIGKILL (`run1_stop=kill`, taken once `run1_stop_when` exists).
#
# Usage: workload-agent-a.sh <run-dir> <case-dir>
# Env (exported by workload-bootstrap.sh): WL_AGENT, WL_DIMENSION, WL_SRC,
#   AWS_REGION, plus the WL_* paths from workload-lib.sh.
set -uo pipefail

RUN_DIR="${1:?Usage: $0 <run-dir> <case-dir>}"
CASE_DIR="${2:?Usage: $0 <run-dir> <case-dir>}"
AGENT="${WL_AGENT:?}"
DIM="${WL_DIMENSION:?}"
COMMON="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$COMMON/workload-lib.sh"
wl_resolve_paths
# shellcheck disable=SC1090
source "$CASE_DIR/case.sh"

PROJECT="$RUN_DIR/project"
CFG="$RUN_DIR/.strands-box"          # outside the project: a write grant on the
BOX="$RUN_DIR/box"                   # project may not enclose the box's policy
JOURNAL="$RUN_DIR/decisions.jsonl"
LOG="$RUN_DIR/agent-a.log"
TURNS="$RUN_DIR/turns.jsonl"
log() { echo "[agent-a $DIM/$AGENT $(date -u +%H:%M:%SZ)] $*" | tee -a "$LOG"; }

# A cell that cannot run must FAIL with a named cause, never be skipped, so a
# refusal still writes the result agent B reads. An agent name this script does
# not know lands here instead of in a default that runs another agent's command.
refuse_agent() {
  log "ERROR: $1"
  python3 - "$RUN_DIR/agent-a.json" "$1" <<'PY'
import json, sys
out, err = sys.argv[1:3]
json.dump({"run_status": "INVALID", "exit_code": 3, "duration_s": 0,
           "tool_uses": 0, "events": 0, "first_error": err}, open(out, "w"))
PY
  exit 3
}

# Once per cell. A two-run cell keeps all three across its runs: that is what it
# measures.
rm -rf "$PROJECT" "$CFG" "$BOX"
mkdir -p "$PROJECT/.tmp" "$CFG" "$BOX" "$RUN_DIR"
chmod 700 "$BOX"
: > "$LOG"; : > "$TURNS"

# The final message each agent leaves behind. Claude Code writes none, so an
# empty path means the run-validity gate has no file to read.
case "$AGENT" in
  claude)  LAST="" ;;
  codex)   LAST="$PROJECT/.codex-last-message.txt" ;;
  strands) LAST="$PROJECT/.strands-last-message.txt" ;;
  *) refuse_agent "unknown agent name: $AGENT (known: claude, codex, strands)" ;;
esac
if [ -n "$LAST" ]; then : > "$LAST"; fi

# The suite runs without `set -e`, so a refusal here is only a refusal when the
# status is read. The function returns 1 on an agent it does not know, and a cell
# that seeds no agent configuration must not continue to the box.
wl_seed_agent_config "$PROJECT" >>"$LOG" 2>&1 \
  || refuse_agent "wl_seed_agent_config refused agent $AGENT"

# 1. The dimension seeds its project and any fixture its pair names (a hook
#    settings file, an MCP server, a virtualenv the table's command must already
#    exist for).
wl_prepare "$PROJECT" >>"$LOG" 2>&1 || log "WARN: wl_prepare returned $?"

# 2. Generate the pair. The manifest is the dimension's declaration of which tool
#    tables it needs and which permits it adds; boxgen.py owns every spelling rule.
MANIFEST="$RUN_DIR/manifest.conf"
{ echo "dimension=$DIM"; echo "name=wl-$DIM-$AGENT"; wl_manifest; } > "$MANIFEST"
PATHS="$RUN_DIR/paths.json"
wl_paths_json > "$PATHS"
GEN="$(python3 "$COMMON/boxgen.py" "$MANIFEST" "$PATHS" "$AGENT" "$PROJECT" "$CFG" "$JOURNAL" "$BOX" 2>>"$LOG")"
if [ -z "$GEN" ]; then
  log "ERROR: boxgen failed — no pair written"
  echo "BOXGEN_FAILED" > "$RUN_DIR/run_status.txt"
  exit 3
fi
echo "$GEN" > "$RUN_DIR/generated.json"
TIMEOUT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["timeout"])' "$RUN_DIR/generated.json")"
log "pair written: $CFG/box.toml (timeout ${TIMEOUT}s)"

# The driver's own keys. boxgen.py ignores them; the generated pair is the same
# with or without them.
RUNS="$(wl_manifest_value "$MANIFEST" runs 1)"
RUN1_STOP="$(wl_manifest_value "$MANIFEST" run1_stop exit)"
RUN1_STOP_WHEN="$(wl_manifest_value "$MANIFEST" run1_stop_when "")"
RUN1_STOP_WHEN="${RUN1_STOP_WHEN//\{\{PROJECT\}\}/$PROJECT}"
case "$RUNS" in 1|2) ;; *) refuse_agent "manifest runs=$RUNS: a cell runs once or twice" ;; esac
case "$RUN1_STOP" in
  exit) ;;
  kill) [ -n "$RUN1_STOP_WHEN" ] || refuse_agent "run1_stop=kill needs run1_stop_when" ;;
  *) refuse_agent "manifest run1_stop=$RUN1_STOP: exit or kill" ;;
esac

# 3. Build the prompt from a goal file. The placeholders carry this host's real
#    spellings, because a workload that must name an absolute interpreter or
#    `node --jitless <npm-cli.js>` cannot be told to guess it. A two-run dimension
#    may add its own values for one run through `wl_goal_vars <run>`.
build_prompt() {   # build_prompt <goal-file> <vars-file>
  python3 - "$1" "$PATHS" "$PROJECT" "$2" <<'PY'
import json, sys
goal, paths, project, vars_file = sys.argv[1:5]
P = json.load(open(paths))
s = open(goal).read()
jit = (" " + P["NODE_JITLESS"]) if P["NODE_JITLESS"] else ""
if P["PLATFORM"] == "macos":
    py = project + "/.venv/bin/python3"
    # macOS framework CPython confirms a certificate through the Security
    # framework, not the CA bundle the box injects, so pip cannot reach PyPI
    # without these; the reference pair measured the same residual.
    # NOTE: no apostrophes in this heredoc. It sits inside a command
    # substitution, and the bash 3.2 that macOS ships tracks quotes even inside a
    # quoted heredoc, so one apostrophe swallows the rest of the substitution and
    # the whole script stops parsing on that platform alone.
    trusted = "--trusted-host pypi.org --trusted-host files.pythonhosted.org"
    pip = py + " -m pip install " + trusted + " pytest"
    pytest = "%s -m pytest -q > pytest-out.txt 2>&1" % py
else:
    py = P["PYTHON"]
    pip = "%s -m pip install --target %s/.pylibs pytest" % (py, project)
    pytest = "PYTHONPATH=%s/.pylibs %s -m pytest -q > pytest-out.txt 2>&1" % (project, py)
P = dict(P, NPM_CMD="%s%s %s" % (P["NODE"], jit, P["NPM_CLI"]),
         NODE_CMD="%s%s" % (P["NODE"], jit), PY_CMD=py,
         PIP_INSTALL=pip, PYTEST_RUN=pytest, PROJECT=project)
try:
    for line in open(vars_file):
        if "=" in line:
            k, v = line.rstrip("\n").split("=", 1)
            P[k] = v
except OSError:
    pass
for k, v in P.items():
    s = s.replace("{{%s}}" % k, v)
print(s)
PY
}

# The goal for one run: `goal.md`, then `goal.<n>.md`, unless the dimension names
# another file through `wl_goal <run>`.
goal_for_run() {
  if declare -F wl_goal >/dev/null; then wl_goal "$1"; return; fi
  if [ "$1" = 1 ]; then echo "$CASE_DIR/goal.md"; else echo "$CASE_DIR/goal.$1.md"; fi
}

export PATH="$WL_SRC/target/release:/usr/local/bin:/opt/homebrew/bin:$PATH"
export HOME="$WL_HOME"        # the operator home the `~/...` spellings assume
cd "$PROJECT" || exit 3

RUN_STATUS=VALID; TOOL_USES=0; EVENTS=0; DURATION=0; EXIT_CODE=0
RUNS_JSON="[]"
n=1
while [ "$n" -le "$RUNS" ]; do
  # 4. Run the agent inside the box. `command` in the generated box.toml already
  #    carries the program and its fixed arguments; the appended arguments are the
  #    non-interactive flags, a second run's arguments from the dimension, and
  #    the prompt. A single run keeps the one-file names; a two-run cell numbers
  #    each run's artefacts and also accumulates them under the one-file names.
  if [ "$RUNS" = 1 ]; then
    TURNS_N="$TURNS"; ERR_N="$LOG"; LAST_N="$LAST"
  else
    TURNS_N="$RUN_DIR/turns.$n.jsonl"; ERR_N="$RUN_DIR/stderr.$n.log"
    LAST_N="${LAST:+${LAST%.txt}.$n.txt}"
    : > "$TURNS_N"; : > "$ERR_N"
    if [ -n "$LAST_N" ]; then : > "$LAST_N"; fi
  fi
  VARS_N="$RUN_DIR/goal-vars.$n"
  if declare -F wl_goal_vars >/dev/null; then wl_goal_vars "$n" > "$VARS_N"; else : > "$VARS_N"; fi
  GOAL_N="$(goal_for_run "$n")"
  [ -f "$GOAL_N" ] || refuse_agent "run $n: goal file $GOAL_N is absent"
  PROMPT="$(build_prompt "$GOAL_N" "$VARS_N")"
  ARGS_N="$RUN_DIR/run-args.$n"
  : > "$ARGS_N"
  if [ "$n" -gt 1 ]; then
    # The dimension reads run one's stream and names what run two appends: for a
    # resume, the session it must continue. A dimension that cannot name it
    # refuses, and the cell fails with that cause rather than start a fresh run.
    PREV=$((n - 1))
    if declare -F wl_run_args >/dev/null; then
      wl_run_args "$n" "$RUN_DIR/turns.$PREV.jsonl" "$RUN_DIR/stderr.$PREV.log" > "$ARGS_N" 2>>"$LOG" \
        || refuse_agent "run $n: wl_run_args refused (see $LOG)"
    fi
  fi
  EXTRA=()
  while IFS= read -r -d '' word; do EXTRA+=("$word"); done \
    < <(wl_agent_arguments "$AGENT" "$LAST_N" "$ARGS_N" "$PROMPT" 2>>"$LOG")
  [ "${#EXTRA[@]}" -gt 0 ] || refuse_agent "unknown agent name: $AGENT (known: claude, codex, strands)"
  [ "$RUNS" = 1 ] || log "run $n of $RUNS: $(tr -d '\n' < "$ARGS_N" | cut -c1-120)"

  START=$(date +%s)
  STOPPED=exit
  # Portable hard stop: macOS ships no `timeout`. Run the box in the background,
  # poll, and kill the process group if the case overruns its budget.
  strands-box run --config "$CFG/box.toml" -- "${EXTRA[@]}" >"$TURNS_N" 2>>"$ERR_N" &
  BOX_PID=$!
  ELAPSED=0
  while kill -0 "$BOX_PID" 2>/dev/null; do
    if [ "$n" = 1 ] && [ "$RUN1_STOP" = kill ]; then
      # The stop file can appear and the run end inside one five-second tick, so
      # the kill variant watches for it ten times a tick.
      tick=0
      while [ "$tick" -lt 10 ] && [ ! -e "$RUN1_STOP_WHEN" ] && kill -0 "$BOX_PID" 2>/dev/null; do
        sleep 0.5; tick=$((tick + 1))
      done
    else
      sleep 5
    fi
    ELAPSED=$((ELAPSED + 5))
    if [ "$n" = 1 ] && [ "$RUN1_STOP" = kill ] && [ -e "$RUN1_STOP_WHEN" ]; then
      # The variant that measures recovery: the box dies with no chance to
      # shut down, the way a crashed terminal or a host reboot ends it.
      log "run 1: $RUN1_STOP_WHEN exists — SIGKILL to the box and everything beneath it"
      wl_kill_tree "$BOX_PID"
      STOPPED=kill
      echo kill > "$RUN_DIR/run1-killed"
      break
    fi
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      log "TIMEOUT after ${TIMEOUT}s — killing the box"
      kill -TERM "$BOX_PID" 2>/dev/null; sleep 5; kill -KILL "$BOX_PID" 2>/dev/null
      echo timeout > "$RUN_DIR/timed_out"
      break
    fi
  done
  wait "$BOX_PID" 2>/dev/null; EXIT_CODE=$?
  DURATION_N=$(( $(date +%s) - START ))
  DURATION=$((DURATION + DURATION_N))
  if [ "$RUNS" = 1 ]; then
    log "box exited $EXIT_CODE after ${DURATION_N}s"
  else
    log "box exited $EXIT_CODE after ${DURATION_N}s (run $n of $RUNS, stopped by $STOPPED)"
  fi

  if [ "$RUNS" != 1 ]; then
    cat "$ERR_N" >> "$LOG"
    cat "$TURNS_N" >> "$TURNS"
    # What the oracle compares across the runs: the box's identity and the
    # journal as it stood when this run ended.
    wl_box_state "$BOX" "$RUN_DIR/box-state.$n.json"
    cp "$JOURNAL" "$RUN_DIR/decisions.$n.jsonl" 2>/dev/null || : > "$RUN_DIR/decisions.$n.jsonl"
    if [ "$n" -lt "$RUNS" ] && declare -F wl_between_runs >/dev/null; then
      wl_between_runs "$n" "$PROJECT" >>"$LOG" 2>&1 || log "WARN: wl_between_runs $n returned $?"
    fi
  fi

  # 5. Run-validity gate. common/workload-run-validity.sh holds each agent's proof
  #    that the run reached the model, and refuses an agent name it does not know.
  VALIDITY="$(bash "$COMMON/workload-run-validity.sh" "$AGENT" "$TURNS_N" "$LAST_N" 2>>"$LOG")"
  if [ -z "$VALIDITY" ]; then
    refuse_agent "the run-validity gate refused agent $AGENT"
  fi
  read -r STATUS_N TOOL_USES_N EVENTS_N <<<"$VALIDITY"
  [ "$STATUS_N" = VALID ] || RUN_STATUS=INVALID
  TOOL_USES=$((TOOL_USES + TOOL_USES_N)); EVENTS=$((EVENTS + EVENTS_N))
  RUNS_JSON="$(python3 - "$RUNS_JSON" "$n" "$STATUS_N" "$EXIT_CODE" "$DURATION_N" "$TOOL_USES_N" "$EVENTS_N" "$STOPPED" <<'PY'
import json, sys
runs = json.loads(sys.argv[1])
index, status, code, dur, tu, ev, stopped = sys.argv[2:9]
runs.append({"index": int(index), "run_status": status, "exit_code": int(code), "duration_s": int(dur),
             "tool_uses": int(tu), "events": int(ev), "stopped": stopped})
print(json.dumps(runs))
PY
)"
  [ "$RUNS" = 1 ] || log "run $n: run_status=$STATUS_N tool_uses=$TOOL_USES_N events=$EVENTS_N"
  [ -e "$RUN_DIR/timed_out" ] && break
  n=$((n + 1))
done

# The first error the run produced, so a case that cannot run FAILS with a named
# cause instead of being skipped.
FIRST_ERR="$(grep -m1 -aiE 'error|refus|denied|EPERM|ENOENT|not permitted|abort' "$LOG" "$TURNS" 2>/dev/null | head -1 | cut -c1-300)"

python3 - "$RUN_DIR/agent-a.json" "$RUN_STATUS" "$EXIT_CODE" "$DURATION" "$TOOL_USES" "$EVENTS" "$FIRST_ERR" "$RUNS" "$RUNS_JSON" <<'PY'
import json, sys
out, status, code, dur, tu, ev, err, runs, runs_json = sys.argv[1:10]
row = {"run_status": status, "exit_code": int(code), "duration_s": int(dur),
       "tool_uses": int(tu), "events": int(ev), "first_error": err}
if runs != "1":
    row["runs"] = json.loads(runs_json)
json.dump(row, open(out, "w"))
PY
log "run_status=$RUN_STATUS tool_uses=$TOOL_USES events=$EVENTS"
