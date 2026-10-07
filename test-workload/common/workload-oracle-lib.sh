#!/bin/bash
# common/workload-oracle-lib.sh — HOST-side oracle engine for workload cases.
#
# The network-egress oracle watches packets; a workload oracle watches outcomes.
# Both are the trust anchor for the same reason: the thing being tested must not
# be the thing that reports whether it worked. So every assertion here reads the
# host filesystem and the box's own decision journal — build artefacts, test
# output, commits, a hook's log line, an MCP reply, a bound socket — and never the
# agent's transcript or its closing summary.
#
# A dimension's oracle.sh sources this file and calls `wl_oracle_main "$@"`; the
# assertions themselves live in the dimension's case.sh as `wl_checks`.
#
#   start — truncate the journal and record the pre-state. Nothing is judged yet.
#   stop  — run wl_checks, write verdict.json (one row per check + a summary).
set -uo pipefail

WL_ORACLE_DIR="${WL_RUN_DIR:?}/oracle"
WL_ORACLE_VERDICT="$WL_ORACLE_DIR/verdict.json"
WL_JOURNAL="${WL_RUN_DIR}/decisions.jsonl"
WL_CHECKS_FILE="$WL_ORACLE_DIR/checks.jsonl"
WL_COMMON="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

wl_ologe(){ mkdir -p "$WL_ORACLE_DIR"; echo "  $*" >> "$WL_ORACLE_DIR/oracle.log"; }
wl_olog(){ wl_ologe "$*"; echo "[oracle ${WL_DIMENSION:-?}/${WL_AGENT:-?} $(date -u +%H:%M:%SZ)] $*"; }

# --- assertion primitives ---------------------------------------------------
# wl_check <id> <ok:0|1> <evidence>  — record one host-observed fact.
wl_check() {
  python3 - "$WL_CHECKS_FILE" "$1" "$2" "$3" <<'PY'
import json, sys
path, cid, ok, ev = sys.argv[1:5]
with open(path, "a") as f:
    f.write(json.dumps({"id": cid, "ok": ok == "1", "evidence": ev[:400]}) + "\n")
PY
  [ "$2" = 1 ] && wl_ologe "PASS $1 — $3" || wl_ologe "FAIL $1 — $3"
}
# wl_assert_file <id> <path> [substring] — the file exists (and contains it).
wl_assert_file() {
  local id="$1" f="$2" sub="${3:-}"
  if [ ! -e "$f" ]; then wl_check "$id" 0 "absent: $f"; return; fi
  if [ -n "$sub" ]; then
    if grep -Fqa -- "$sub" "$f" 2>/dev/null; then wl_check "$id" 1 "$f contains '$sub'"
    else wl_check "$id" 0 "$f lacks '$sub': $(head -c 200 "$f" | tr '\n' ' ')"; fi
  else
    wl_check "$id" 1 "present: $f"
  fi
}

# wl_assert_any <id> <file> <substring>... — the file contains ANY of them. For an
# outcome one tool spells more than one way (a TAP summary is `# pass 1`, a plain
# runner prints `ok 1`), asserting one spelling fails on a true green.
wl_assert_any() {
  local id="$1" f="$2"; shift 2
  if [ ! -e "$f" ]; then wl_check "$id" 0 "absent: $f"; return; fi
  local sub
  for sub in "$@"; do
    if grep -Fqa -- "$sub" "$f" 2>/dev/null; then
      wl_check "$id" 1 "$f contains '$sub'"; return
    fi
  done
  wl_check "$id" 0 "$f has none of [$*]: $(head -c 200 "$f" | tr '\n' ' ')"
}

# wl_assert_glob <id> <pattern> — at least one path matches (build artefacts).
wl_assert_glob() {
  local id="$1" pat="$2" n
  # shellcheck disable=SC2086
  n=$(ls -d $pat 2>/dev/null | wc -l | tr -d ' ')
  [ "${n:-0}" -gt 0 ] && wl_check "$id" 1 "$n match(es) for $pat" || wl_check "$id" 0 "no match for $pat"
}

# wl_assert_commits <id> <project> <min> — the workload really committed. Host git
# reads the repository; the agent's claim about committing is not consulted.
wl_assert_commits() {
  local id="$1" proj="$2" min="$3" n
  n=$(git -c safe.directory='*' -C "$proj" --no-pager log --oneline 2>/dev/null | wc -l | tr -d ' ')
  n=${n:-0}
  [ "$n" -ge "$min" ] && wl_check "$id" 1 "$n commit(s)" || wl_check "$id" 0 "$n commit(s), wanted >= $min"
}

# --- the decision journal ---------------------------------------------------
# [telemetry.decisions] writes OTLP JSON: one object per flush, each carrying
# resourceLogs -> scopeLogs -> logRecords, and each decision's verdict, action
# and resource in its `strands.box.policy.*` attributes. So the journal is
# queried structurally rather than grepped.
#
# wl_journal_find <permit|deny> <action-substring> [resource-substring]
#   -> prints the first matching record as `action resource`, exit 0 if found.
wl_journal_find() {
  python3 "$WL_COMMON/journal_find.py" "$WL_JOURNAL" "$1" "$2" "${3:-}"
}

# wl_assert_journal <id> <permit|deny> <action-substring> [resource-substring]
# The box's own record that it judged this. Half the ground truth: a file on disk
# says the work happened, the journal says the box permitted it.
wl_assert_journal() {
  local id="$1" want="$2" act="$3" res="${4:-}" hit
  if [ ! -s "$WL_JOURNAL" ]; then wl_check "$id" 0 "journal empty or absent: $WL_JOURNAL"; return; fi
  hit="$(wl_journal_find "$want" "$act" "$res")"
  if [ -n "$hit" ]; then
    wl_check "$id" 1 "journal $want: $hit"
  else
    wl_check "$id" 0 "journal has no $want for '$act' ${res:+on '"'"'$res'"'"'}"
  fi
}

# wl_assert_no_denial <id> <resource-substring> — nothing the workload needed was
# refused. Scoped to a resource, because a run legitimately produces unrelated
# denials (an agent probing an endpoint its own policy does not name).
wl_assert_no_denial() {
  local id="$1" res="$2" hit
  hit="$(wl_journal_find deny "" "$res")"
  [ -z "$hit" ] && wl_check "$id" 1 "no denial on '$res'" || wl_check "$id" 0 "denied: $hit"
}

# wl_journal_count <journal> <permit|deny> <action-substring> [resource-substring]
#                  [--attr KEY=SUBSTRING]...
#   -> prints how many records match. The journal is an argument because a two-run
#      cell keeps a copy taken between its runs beside the whole.
wl_journal_count() {
  python3 "$WL_COMMON/journal_find.py" --count "$@"
}

# --- two-run cells ----------------------------------------------------------
# wl_assert_same_box <before.json> <after.json> — the identity facts wl_box_state
# records are equal and present: one check per fact.
wl_assert_same_box() {
  python3 - "$WL_CHECKS_FILE" "$1" "$2" <<'PY'
import json, sys
checks, before, after = sys.argv[1:4]
def load(p):
    try:
        return json.load(open(p))
    except Exception as exc:
        return {"_error": str(exc)}
a, b = load(before), load(after)
with open(checks, "a") as f:
    for key, cid in [("box_id", "same-box-id"), ("record_inode", "same-box-record"),
                     ("configured", "same-box-configured"), ("history_inode", "same-box-history")]:
        ok = a.get(key) is not None and a.get(key) == b.get(key)
        ev = "%s: before=%s after=%s" % (key, a.get(key, a.get("_error")), b.get(key, b.get("_error")))
        f.write(json.dumps({"id": cid, "ok": ok, "evidence": ev[:400]}) + "\n")
PY
}

# wl_assert_no_line <id> <file> <extended-regex> — no line of the file matches.
wl_assert_no_line() {
  local id="$1" f="$2" re="$3" hit
  if [ ! -e "$f" ]; then wl_check "$id" 0 "absent: $f"; return; fi
  hit="$(grep -Ea -- "$re" "$f" 2>/dev/null | head -1 | cut -c1-200)"
  [ -z "$hit" ] && wl_check "$id" 1 "no line in $f matches /$re/" || wl_check "$id" 0 "$f has: $hit"
}

# wl_disclosure <stderr-file> — the startup disclosure, from its first line to its
# HOME line, and nothing else the box or the agent wrote to stderr.
wl_disclosure() {
  python3 - "$1" <<'PY'
import sys
inside = False
for line in open(sys.argv[1], errors="replace"):
    if line.startswith("strands-box: [agent] runs "):
        inside = True
    if inside:
        sys.stdout.write(line)
        if line.startswith("strands-box: [agent] HOME="):
            break
PY
}

# wl_assert_disclosure_stable <id> <stderr-1> <stderr-2> — run two disclosed what
# run one disclosed, byte for byte.
wl_assert_disclosure_stable() {
  local id="$1" one two
  one="$(wl_disclosure "$2")"; two="$(wl_disclosure "$3")"
  if [ -z "$one" ]; then wl_check "$id" 0 "no disclosure in $2"; return; fi
  if [ "$one" = "$two" ]; then
    wl_check "$id" 1 "$(printf '%s\n' "$one" | wc -l | tr -d ' ') disclosure lines equal across runs"
  else
    wl_check "$id" 0 "disclosure differs: $(diff <(printf '%s\n' "$one") <(printf '%s\n' "$two") | head -3 | tr '\n' ' ')"
  fi
}

# wl_tree_listing <dir>... — every entry beneath the directories that exist, with
# its size and modification time, sorted. Two listings compare as text.
wl_tree_listing() {
  python3 - "$@" <<'PY'
import os, sys
rows = []
for top in sys.argv[1:]:
    for root, dirs, files in os.walk(top):
        for name in sorted(dirs + files):
            path = os.path.join(root, name)
            try:
                st = os.lstat(path)
                rows.append("%s %d %d" % (path, st.st_size, st.st_mtime_ns))
            except OSError:
                rows.append("%s ? ?" % path)
print("\n".join(sorted(rows)))
PY
}

# wl_assert_tree_unchanged <id> <before-listing> <dir>... — the listing taken at
# oracle start equals one taken now.
wl_assert_tree_unchanged() {
  local id="$1" before="$2"; shift 2
  local now
  now="$(wl_tree_listing "$@")"
  if [ "$(cat "$before" 2>/dev/null)" = "$now" ]; then
    wl_check "$id" 1 "unchanged: $*"
  else
    wl_check "$id" 0 "changed: $(diff "$before" <(printf '%s\n' "$now") 2>/dev/null | head -3 | tr '\n' ' ')"
  fi
}

# wl_assert_budget_carried <id-prefix> <rule-id> <action> <command> <budget> [<run-one-spend>]
# Three checks over the journal copy taken after run one and the whole journal:
#   <prefix>-unspent-in-run-one   run one met no refusal by the budget rule
#   <prefix>-refused-in-run-two   run two met at least one
#   <prefix>-carried-over         run two was permitted exactly <budget> minus what
#                                 run one spent, which only holds when run one's
#                                 spend still counted. Attempts are the `shell:exec`
#                                 permits for <command>; permitted = attempts - refusals.
#                                 A retried refusal adds one to each and leaves the
#                                 difference intact.
# <run-one-spend> is what run one spent, from durable evidence such as the
# directories a `mkdir` left behind; absent, the journal copy's permitted attempts.
wl_assert_budget_carried() {
  local prefix="$1" rule="$2" action="$3" command="$4" budget="$5" spent1="${6:-}"
  local first="$WL_RUN_DIR/decisions.1.jsonl"
  if [ ! -s "$first" ]; then
    wl_check "$prefix-unspent-in-run-one" 0 "no journal copy after run one: $first"
    return
  fi
  local d1 dall a1 aall d2 a2 permitted2
  d1="$(wl_journal_count "$first" deny "$action" --attr "strands.box.policy.rule=$rule")"
  dall="$(wl_journal_count "$WL_JOURNAL" deny "$action" --attr "strands.box.policy.rule=$rule")"
  a1="$(wl_journal_count "$first" permit "shell:exec" --attr "process.command=$command")"
  aall="$(wl_journal_count "$WL_JOURNAL" permit "shell:exec" --attr "process.command=$command")"
  d2=$((dall - d1)); a2=$((aall - a1)); permitted2=$((a2 - d2))
  [ -n "$spent1" ] || spent1=$((a1 - d1))
  local ev="rule=$rule budget=$budget run1: $command=$a1 refused=$d1 spent=$spent1; run2: $command=$a2 refused=$d2 permitted=$permitted2"
  [ "$d1" -eq 0 ] && wl_check "$prefix-unspent-in-run-one" 1 "$ev" || wl_check "$prefix-unspent-in-run-one" 0 "$ev"
  [ "$d2" -ge 1 ] && wl_check "$prefix-refused-in-run-two" 1 "$ev" || wl_check "$prefix-refused-in-run-two" 0 "$ev"
  [ "$d2" -ge 1 ] && [ "$permitted2" -eq $((budget - spent1)) ] \
    && wl_check "$prefix-carried-over" 1 "$ev (permitted = budget - run one's spend)" \
    || wl_check "$prefix-carried-over" 0 "$ev (wanted permitted = $((budget - spent1)))"
}

# wl_assert_runs_valid <id> — every run of a two-run cell reached the model, as
# agent A recorded it.
wl_assert_runs_valid() {
  python3 - "$WL_CHECKS_FILE" "$WL_RUN_DIR/agent-a.json" "$1" <<'PY'
import json, sys
checks, result, cid = sys.argv[1:4]
try:
    runs = json.load(open(result)).get("runs", [])
except Exception:
    runs = []
ok = bool(runs) and all(r.get("run_status") == "VALID" for r in runs)
ev = ", ".join("run %s %s (%s tool uses)" % (r.get("index"), r.get("run_status"), r.get("tool_uses")) for r in runs) or "no runs recorded"
with open(checks, "a") as f:
    f.write(json.dumps({"id": cid, "ok": ok, "evidence": ev[:400]}) + "\n")
PY
}

# wl_note_codex_arg0 <file> — record whether Codex staged the helper it runs host
# binaries through. The failure is intermittent, its mechanism is not identified,
# and it can land on any Linux Codex cell, so what happened is recorded wherever it
# appears rather than asserted in one place. Never fails a cell: it is evidence,
# not a verdict. The guard is positive and names the one agent the defect belongs
# to, so any other agent records nothing here by intent; the agent name itself is
# refused once, in wl_oracle_start.
wl_note_codex_arg0() {
  local f="$1"
  [ "${WL_AGENT:-}" = codex ] && [ "${WL_PLATFORM:-}" = linux ] || return 0
  if grep -Fqa "Could not find" "$f" 2>/dev/null; then
    local line
    line="$(grep -ao 'Could not find.\{0,80\}' "$f" | head -1)"
    wl_check codex-arg0-staging 1 "codex-arg0-staging-intermittent: helper did NOT stage: $line"
  else
    wl_check codex-arg0-staging 1 "codex-arg0-staging-intermittent not hit: helper staged, or this step ran no host binary"
  fi
}

# --- lifecycle --------------------------------------------------------------
# The oracle runs first in every cell, so it is where an agent name this suite
# does not know must stop the cell. A failed check is recorded as well as the
# refusal on stderr: if the caller ignores the status, `wl_oracle_stop` still
# reads that row and the cell gets FAIL with the name in its evidence, rather
# than a PASS composed from another agent's assertions.
wl_oracle_start() {
  mkdir -p "$WL_ORACLE_DIR"
  : > "$WL_CHECKS_FILE"; : > "$WL_ORACLE_VERDICT"; : > "$WL_ORACLE_DIR/oracle.log"
  : > "$WL_JOURNAL"
  if ! wl_agent_known "${WL_AGENT:-}"; then
    wl_check agent-name-known 0 "unknown agent '${WL_AGENT:-}' (known: ${WL_AGENTS:-})"
    wl_olog "start REFUSED — unknown agent '${WL_AGENT:-}'"
    return 1
  fi
  # A dimension that must compare host state across the run records it here.
  if declare -F wl_prestate >/dev/null; then wl_prestate; fi
  wl_olog "start — journal truncated, pre-state recorded"
}

wl_oracle_stop() {
  mkdir -p "$WL_ORACLE_DIR"
  wl_olog "running host checks"
  wl_checks "${WL_RUN_DIR}/project"
  python3 - "$WL_CHECKS_FILE" "$WL_ORACLE_VERDICT" "${WL_DIMENSION:-?}" "${WL_AGENT:-?}" "${WL_PLATFORM:-?}" <<'PY'
import json, sys
checks_path, out, dim, agent, plat = sys.argv[1:6]
rows = []
try:
    for line in open(checks_path):
        line = line.strip()
        if line:
            rows.append(json.loads(line))
except FileNotFoundError:
    pass
failed = [r["id"] for r in rows if not r["ok"]]
json.dump({"dimension": dim, "agent": agent, "platform": plat,
           "checks": rows, "failed": failed,
           "verdict": "PASS" if rows and not failed else ("FAIL" if rows else "ERROR")},
          open(out, "w"), indent=1)
PY
  wl_olog "stop — $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["verdict"], d["failed"])' "$WL_ORACLE_VERDICT" 2>/dev/null)"
}

wl_oracle_main() {
  case "${1:-status}" in
    start) wl_oracle_start ;;
    stop)  wl_oracle_stop ;;
    *)     cat "$WL_ORACLE_VERDICT" 2>/dev/null ;;
  esac
}
