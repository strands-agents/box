#!/bin/bash
# common/workload-two-run-test.sh — pin the two-run path with no instance, no box,
# and no model.
#
# A two-run cell cannot run on a host without containment, so each piece the
# driver and the oracle rely on is checked here against synthetic artefacts: the
# session id each agent's stream names, the argument placement for a second run,
# the journal counts the budget assertions read, the box-identity snapshot, the
# disclosure comparison, the dimension-to-agent filter, and the policy a budget
# dimension appends to the generated pair.
#
# Usage: workload-two-run-test.sh     (exit 0 all pinned, 1 a failure)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TW="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAILURES=0

ok()   { echo "ok   $1"; }
fail() { echo "FAIL $1: $2"; FAILURES=$((FAILURES + 1)); }
expect() {   # expect <label> <want> <got>
  if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "want [$2] got [$3]"; fi
}

export WL_HOME_DIR="$WORK/home"
mkdir -p "$WL_HOME_DIR"
export AWS_REGION=us-west-2 WL_STRANDS_MODEL=us.anthropic.claude-opus-5
# shellcheck disable=SC1091
source "$HERE/workload-lib.sh"
wl_resolve_paths

# --- the session id each agent names in its own stream ------------------------
printf '%s\n' '{"type":"system","subtype":"init","session_id":"sess-claude-1","tools":["Bash"]}' \
  '{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash"}]}}' \
  '{"type":"result","session_id":"sess-claude-1"}' > "$WORK/claude.jsonl"
printf '%s\n' '{"type":"thread.started","thread_id":"thr-codex-1"}' \
  '{"type":"turn.started"}' '{"type":"item.completed","item":{"type":"command_execution"}}' > "$WORK/codex.jsonl"
printf '%s\n' '{"type":"system","subtype":"hook","session_id":"not-init"}' > "$WORK/claude-noinit.jsonl"
: > "$WORK/empty.jsonl"
expect "claude session id from the init event" "sess-claude-1" "$(wl_session_id claude "$WORK/claude.jsonl")"
expect "codex thread id from thread.started"   "thr-codex-1"   "$(wl_session_id codex "$WORK/codex.jsonl")"
wl_session_id claude "$WORK/claude-noinit.jsonl" >/dev/null 2>&1; expect "a system event that is not init names no session" 1 "$?"
wl_session_id codex "$WORK/empty.jsonl" >/dev/null 2>&1;        expect "an empty stream names no session" 1 "$?"
wl_session_id strands "$WORK/claude.jsonl" >/dev/null 2>&1;     expect "strands has no session to resume (refused by name)" 3 "$?"
wl_session_id gemini "$WORK/claude.jsonl" >/dev/null 2>&1;      expect "an unknown agent is refused" 3 "$?"

# --- where run two's arguments go, per agent ---------------------------------
argv_of() {   # argv_of <agent> <last> <args-file> <prompt> -> one argument per line
  wl_agent_arguments "$@" | tr '\0' '\n'
}
: > "$WORK/no-args"
printf '%s\n' --resume sess-claude-1 > "$WORK/claude-args"
printf '%s\n' resume thr-codex-1 > "$WORK/codex-args"
expect "claude run one appends its flags then the prompt" \
  "$(printf '%s\n' --print --output-format stream-json --verbose --dangerously-skip-permissions 'do it')" \
  "$(argv_of claude "" "$WORK/no-args" "do it")"
expect "claude run two puts --resume after its flags" \
  "$(printf '%s\n' --print --output-format stream-json --verbose --dangerously-skip-permissions --resume sess-claude-1 'go on')" \
  "$(argv_of claude "" "$WORK/claude-args" "go on")"
expect "codex run two puts resume <id> before --json" \
  "$(printf '%s\n' resume thr-codex-1 --json --output-last-message /p/last.2.txt 'go on')" \
  "$(argv_of codex /p/last.2.txt "$WORK/codex-args" "go on")"
expect "strands run two has no resume and keeps its flags" \
  "$(printf '%s\n' --json --last-message /p/last.2.txt 'go on')" \
  "$(argv_of strands /p/last.2.txt "$WORK/no-args" "go on")"
expect "a prompt with newlines is one argument" "6" \
  "$(wl_agent_arguments claude "" "$WORK/no-args" "$(printf 'line one\nline two')" | tr -cd '\0' | wc -c | tr -d ' ')"
argv_of nobody "" "$WORK/no-args" x >/dev/null 2>&1; expect "an unknown agent gets no arguments" 1 "$?"

# --- journal counts the budget assertions read --------------------------------
export WL_RUN_DIR="$WORK/run" WL_DIMENSION=test WL_AGENT=claude
mkdir -p "$WL_RUN_DIR/oracle"
# shellcheck disable=SC1091
source "$HERE/workload-oracle-lib.sh"
record() {   # record <verdict> <action> <resource> <rule> [command]
  python3 - "$@" <<'PY'
import json, sys
verdict, action, resource, rule = sys.argv[1:5]
attrs = [("strands.box.policy.verdict", verdict), ("strands.box.policy.action", action),
         ("strands.box.policy.resource", resource), ("strands.box.policy.rule", rule)]
if len(sys.argv) > 5:
    attrs.append(("process.command", sys.argv[5]))
rec = {"attributes": [{"key": k, "value": {"stringValue": v}} for k, v in attrs]}
rec["attributes"].append({"key": "process.command_args",
                          "value": {"arrayValue": {"values": [{"stringValue": "d1"}, {"stringValue": "d2"}]}}})
print(json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": [rec]}]}]}))
PY
}
J="$WORK/decisions.jsonl"
{ record permit shell:exec mkdir shell_commands mkdir; record permit fs:write "~/p/d1" workspace_write
  record permit shell:exec mkdir shell_commands mkdir; record permit fs:write "~/p/d2" workspace_write
  record permit shell:exec mkdir shell_commands mkdir; record deny fs:write "~/p/d3" mkdir_budget
  record permit shell:exec ls shell_commands ls;       record permit fs:read "~/p/d1" workspace_read
  record deny fs:write "~/p/.tmp/x" "<default-deny>"
} > "$J"
expect "count permits of one command"       3 "$(wl_journal_count "$J" permit shell:exec --attr process.command=mkdir)"
expect "count denies by one rule"           1 "$(wl_journal_count "$J" deny fs:write --attr strands.box.policy.rule=mkdir_budget)"
expect "count honours the resource filter"  2 "$(wl_journal_count "$J" permit fs:write "~/p/d")"
expect "an array attribute matches joined"  1 "$(wl_journal_count "$J" permit shell:exec --attr "process.command_args=d1 d2" --attr process.command=ls)"
expect "a count over an absent journal is 0" 0 "$(wl_journal_count "$WORK/none.jsonl" permit fs:write)"
python3 "$HERE/journal_find.py" "$J" permit fs:write --attr >/dev/null 2>&1; expect "a bare --attr is a usage error" 2 "$?"
expect "the first match still prints action and resource" "fs:write ~/p/d1" "$(wl_journal_find permit fs:write "~/p/d" 2>/dev/null || python3 "$HERE/journal_find.py" "$J" permit fs:write "~/p/d")"

# --- wl_assert_budget_carried over a run-one copy and the whole -----------------
budget_case() {   # budget_case <label> <run1-records...> -- <run2-records...> -> the three verdicts
  local label="$1"; shift
  : > "$WL_CHECKS_FILE"; : > "$WL_RUN_DIR/decisions.1.jsonl"; : > "$WL_JOURNAL"
  local target="$WL_RUN_DIR/decisions.1.jsonl"
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--" ]; then target="$WL_JOURNAL"; shift; continue; fi
    case "$1" in
      mkdir-ok)   { record permit shell:exec mkdir r mkdir; record permit fs:write "~/p/d" workspace_write; } >> "$target" ;;
      mkdir-deny) { record permit shell:exec mkdir r mkdir; record deny fs:write "~/p/d" mkdir_budget; } >> "$target" ;;
    esac
    shift
  done
  cat "$WL_RUN_DIR/decisions.1.jsonl" >> "$WL_JOURNAL"
  wl_assert_budget_carried budget mkdir_budget fs:write mkdir 8
  python3 -c 'import json,sys; print(" ".join(("1" if json.loads(l)["ok"] else "0") for l in open(sys.argv[1]) if l.strip()))' "$WL_CHECKS_FILE"
}
expect "history carried: 3 then 5 permitted and 3 refused passes all three" "1 1 1" \
  "$(budget_case carried mkdir-ok mkdir-ok mkdir-ok -- mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-deny mkdir-deny mkdir-deny)"
expect "history reset: 8 permitted in run two fails carried-over and refused" "1 0 0" \
  "$(budget_case reset mkdir-ok mkdir-ok mkdir-ok -- mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok)"
expect "a refusal in run one fails unspent-in-run-one and the conservation check" "0 1 0" \
  "$(budget_case early mkdir-ok mkdir-deny -- mkdir-ok mkdir-deny)"
expect "history reset plus one extra attempt: 8 permitted then refused fails carried-over" "1 1 0" \
  "$(budget_case reset-extra mkdir-ok mkdir-ok mkdir-ok -- mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-deny)"
expect "a retried refusal in run two leaves carried-over intact" "1 1 1" \
  "$(budget_case retried mkdir-ok mkdir-ok mkdir-ok -- mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-deny mkdir-deny mkdir-deny mkdir-deny mkdir-deny)"
expect "a kill cut the run-one copy to 2 of 3: with no stated spend carried-over fails" "1 1 0" \
  "$(budget_case cut mkdir-ok mkdir-ok -- mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-deny mkdir-deny mkdir-deny)"
expect "the same cut copy with the stated spend of 3 passes all three" "1 1 1" \
  "$(budget_case cut mkdir-ok mkdir-ok -- mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-deny mkdir-deny mkdir-deny >/dev/null; : > "$WL_CHECKS_FILE"; wl_assert_budget_carried budget mkdir_budget fs:write mkdir 8 3; python3 -c 'import json,sys; print(" ".join(("1" if json.loads(l)["ok"] else "0") for l in open(sys.argv[1]) if l.strip()))' "$WL_CHECKS_FILE")"
expect "a refusal in run one spent nothing: 8 permitted then refused, run two refused once passes carried-over" "0 1 1" \
  "$(budget_case spent-is-permitted mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-ok mkdir-deny -- mkdir-deny)"
expect "no run-one journal copy fails with a named cause" "0" \
  "$(: > "$WL_CHECKS_FILE"; rm -f "$WL_RUN_DIR/decisions.1.jsonl"; wl_assert_budget_carried budget mkdir_budget fs:write mkdir 8; python3 -c 'import json,sys; print(" ".join(("1" if json.loads(l)["ok"] else "0") for l in open(sys.argv[1]) if l.strip()))' "$WL_CHECKS_FILE")"

# --- the box identity snapshot and its comparison -----------------------------
BOXD="$WORK/box"; mkdir -p "$BOXD/private"
printf 'name = "wl"\nbox_id = "box-0123456789abcdef"\n' > "$BOXD/private/box.toml"
printf 'commit-bytes' > "$BOXD/private/configured"
printf 'db' > "$BOXD/private/dogwood.redb"
wl_box_state "$BOXD" "$WORK/state1.json"
expect "the snapshot reads the box id" "box-0123456789abcdef" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["box_id"])' "$WORK/state1.json")"
wl_box_state "$BOXD" "$WORK/state2.json"
: > "$WL_CHECKS_FILE"; wl_assert_same_box "$WORK/state1.json" "$WORK/state2.json"
expect "an unchanged box passes all four identity checks" "4 0" \
  "$(python3 -c 'import json,sys; rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]; print(sum(r["ok"] for r in rows), sum(not r["ok"] for r in rows))' "$WL_CHECKS_FILE")"
printf 'name = "wl"\nbox_id = "box-fedcba9876543210"\n' > "$BOXD/private/box.toml"
printf 'other-bytes' > "$BOXD/private/configured"
wl_box_state "$BOXD" "$WORK/state3.json"
: > "$WL_CHECKS_FILE"; wl_assert_same_box "$WORK/state1.json" "$WORK/state3.json"
expect "a rewritten id and commit fail their two checks" "same-box-id same-box-configured" \
  "$(python3 -c 'import json,sys; print(" ".join(r["id"] for r in (json.loads(l) for l in open(sys.argv[1]) if l.strip()) if not r["ok"]))' "$WL_CHECKS_FILE")"
wl_box_state "$WORK/nowhere" "$WORK/state4.json"
: > "$WL_CHECKS_FILE"; wl_assert_same_box "$WORK/state4.json" "$WORK/state4.json"
expect "an absent box passes nothing" "0" \
  "$(python3 -c 'import json,sys; print(sum(json.loads(l)["ok"] for l in open(sys.argv[1]) if l.strip()))' "$WL_CHECKS_FILE")"

# --- the disclosure block, out of everything else on stderr -------------------
cat > "$WORK/stderr.1.log" <<'EOF'
strands-box: box box-0123456789abcdef created · config /r/.strands-box/box.toml
strands-box: [agent] runs /opt/claude with no policy decision over these paths:
  read        /r/project
  write       /r/project
strands-box: [agent] runtime minimum, added by Core:
  /dev/null
strands-box: [agent] HOME=/var/tmp/wl-home PATH=/r/box/bin:/usr/bin:/bin
agent noise line
EOF
sed -e '/created/d' -e 's/agent noise line/other noise/' "$WORK/stderr.1.log" > "$WORK/stderr.2.log"
expect "the disclosure starts at its first line and ends at HOME" 6 "$(wl_disclosure "$WORK/stderr.1.log" | wc -l | tr -d ' ')"
: > "$WL_CHECKS_FILE"; wl_assert_disclosure_stable disclosure-stable "$WORK/stderr.1.log" "$WORK/stderr.2.log"
expect "noise around the block does not break stability" 1 "$(python3 -c 'import json,sys; print(int(json.loads(open(sys.argv[1]).readline())["ok"]))' "$WL_CHECKS_FILE")"
sed -e 's#write       /r/project#write       /r/project /r/other#' "$WORK/stderr.1.log" > "$WORK/stderr.3.log"
: > "$WL_CHECKS_FILE"; wl_assert_disclosure_stable disclosure-stable "$WORK/stderr.1.log" "$WORK/stderr.3.log"
expect "a changed grant line fails stability" 0 "$(python3 -c 'import json,sys; print(int(json.loads(open(sys.argv[1]).readline())["ok"]))' "$WL_CHECKS_FILE")"
: > "$WL_CHECKS_FILE"; wl_assert_no_line box-not-recreated "$WORK/stderr.2.log" 'strands-box: box .* (created|updated)'
expect "run two with no created line passes" 1 "$(python3 -c 'import json,sys; print(int(json.loads(open(sys.argv[1]).readline())["ok"]))' "$WL_CHECKS_FILE")"
: > "$WL_CHECKS_FILE"; wl_assert_no_line box-not-recreated "$WORK/stderr.1.log" 'strands-box: box .* (created|updated)'
expect "a created line fails it" 0 "$(python3 -c 'import json,sys; print(int(json.loads(open(sys.argv[1]).readline())["ok"]))' "$WL_CHECKS_FILE")"

# --- which agents a dimension runs for --------------------------------------
for agent in claude codex strands; do
  wl_dimension_applies "$TW/workload-baseline" "$agent"; expect "baseline applies to $agent" 0 "$?"
done
wl_dimension_applies "$TW/workload-resume-claude" claude;        expect "resume-claude applies to claude" 0 "$?"
wl_dimension_applies "$TW/workload-resume-claude" codex;         expect "resume-claude does not apply to codex" 1 "$?"
wl_dimension_applies "$TW/workload-kill-codex" codex;     expect "kill-codex applies to codex" 0 "$?"
wl_dimension_applies "$TW/workload-kill-codex" strands;   expect "kill-codex does not apply to strands" 1 "$?"
wl_dimension_applies "$TW/workload-budget" strands;      expect "budget applies to strands" 0 "$?"
mkdir -p "$WORK/typo-dim"; printf 'wl_agents="cluade"\nwl_manifest() { :; }\n' > "$WORK/typo-dim/case.sh"
wl_dimension_agents_known "$WORK/typo-dim" 2>/dev/null;     expect "a dimension naming an unknown agent is refused" 1 "$?"
wl_dimension_agents_known "$TW/workload-resume-codex";       expect "a dimension naming a known agent passes" 0 "$?"
wl_dimension_agents_known "$TW/workload-baseline";           expect "a dimension naming no agent passes" 0 "$?"

# --- the manifest keys the driver reads, and the kill variants ----------------
printf 'tools=\nruns=2\nrun1_stop=kill\n' > "$WORK/manifest.conf"
expect "a manifest value is read"            2    "$(wl_manifest_value "$WORK/manifest.conf" runs 1)"
expect "an absent key takes its default"     exit "$(wl_manifest_value "$WORK/manifest.conf" run1_stop_missing exit)"
expect "an empty value takes its default"    1    "$(wl_manifest_value "$WORK/manifest.conf" tools 1)"
for variant in claude codex; do
  mf="$(export WL_RUN_DIR="$WORK/run" WL_AGENT=$variant; cd "$TW/workload-kill-$variant" && source ./case.sh && wl_manifest)"
  expect "kill-$variant declares the SIGKILL stop" "kill" "$(printf '%s\n' "$mf" | sed -n 's/^run1_stop=//p')"
  expect "kill-$variant stops once d3 exists"      "{{PROJECT}}/d3" "$(printf '%s\n' "$mf" | sed -n 's/^run1_stop_when=//p')"
  g1="$(cd "$TW/workload-kill-$variant" && source ./case.sh && wl_goal 1)"
  g2="$(cd "$TW/workload-kill-$variant" && source ./case.sh && wl_goal 2)"
  [ -f "$g1" ] && [ -f "$g2" ] && ok "kill-$variant names the sibling's two goal files" || fail "kill-$variant goal files" "$g1 $g2"
  mf="$(export WL_RUN_DIR="$WORK/run" WL_AGENT=$variant; cd "$TW/workload-resume-$variant" && source ./case.sh && wl_manifest)"
  expect "resume-$variant stops by exit" "exit" "$(printf '%s\n' "$mf" | sed -n 's/^run1_stop=//p')"
done

# --- the budget rule reaches the generated policy, and only when asked ---------
gen() {   # gen <dimension> <agent> <out-dir>
  local dim="$1" agent="$2" out="$3"
  mkdir -p "$out/project/.tmp" "$out/.strands-box" "$out/box"
  (
    export WL_PLATFORM_OVERRIDE=linux WL_AGENT="$agent" WL_DIMENSION="$dim" WL_RUN_DIR="$out"
    # shellcheck disable=SC1090
    source "$TW/$dim/case.sh"
    wl_prepare "$out/project" >/dev/null 2>&1
    { echo "dimension=$dim"; echo "name=wl-$dim-$agent"; wl_manifest; } > "$out/manifest.conf"
    wl_paths_json > "$out/paths.json"
    python3 "$HERE/boxgen.py" "$out/manifest.conf" "$out/paths.json" "$agent" "$out/project" "$out/.strands-box" "$out/decisions.jsonl" "$out/box" > "$out/generated.json" 2>"$out/boxgen.err"
  )
}
gen workload-resume-claude claude "$WORK/gen-resume"
expect "the resume pair carries the mkdir budget" 1 "$(grep -c '@id("mkdir_budget") forbid' "$WORK/gen-resume/.strands-box/policy.dw")"
expect "the budget counts create_dir within one hour" 1 "$(grep -c 'formerly within 1h' "$WORK/gen-resume/.strands-box/policy.dw")"
expect "the budget file carries no unexpanded placeholder" 0 "$(grep -c '{{' "$WORK/gen-resume/.strands-box/policy.dw")"
gen workload-budget codex "$WORK/gen-budget"
expect "the budget pair carries the listing budget on enumerate" 1 \
  "$(grep -c 'Box::FsReadOperation::"enumerate" } && tp(t)' "$WORK/gen-budget/.strands-box/policy.dw")"
expect "codex budget carries no Claude tool flag" 0 "$(grep -c disallowedTools "$WORK/gen-budget/.strands-box/box.toml")"
gen workload-budget claude "$WORK/gen-budget-claude"
expect "claude budget disallows its own listing tools" 1 "$(grep -c -- '--disallowedTools' "$WORK/gen-budget-claude/.strands-box/box.toml")"
gen workload-baseline claude "$WORK/gen-baseline"
expect "a dimension without policy_file appends nothing" 0 "$(grep -c 'forbid' "$WORK/gen-baseline/.strands-box/policy.dw")"
expect "every pair permits reading /dev/null, which a stdin redirect raises" 1 \
  "$(grep -cF '@id("dev_null_read") permit (principal, action == Box::Action::"fs:read", resource) when { context.input.path == "/dev/null" };' "$WORK/gen-baseline/.strands-box/policy.dw")"

if [ "$FAILURES" -eq 0 ]; then
  echo "two-run: all checks pinned"
else
  echo "two-run: $FAILURES check(s) failed"
fi
[ "$FAILURES" -eq 0 ]
