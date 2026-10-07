#!/bin/bash
# workload-resume-claude — one box, two runs: Claude Code resumes its conversation
# with `--resume <session-id>`, recalls a token it never wrote to disk, and the box
# keeps its identity, its disclosure, and a temporal budget it started to spend in
# run one. Plan scenario S-53. `WL_RESUME_STOP=kill` is the SIGKILL variant.
#
# The budget counts directory creation (`mkdir`), not content writes: Claude
# Code's Bash tool writes a working-directory file and sources a snapshot on
# every call, so a `write_content` or `read_content` count would carry per-call
# noise that no goal can hold still. Run one creates three directories; run two
# attempts eight against a budget of eight, so run two is refused only when run
# one's three still count.

wl_agents="claude"
: "${WL_RESUME_STOP:=exit}"
WL_RESUME_BUDGET=8
WL_RESUME_RULE=mkdir_budget

wl_manifest() {
  cat <<EOF
tools=
timeout=600
enumerate=1
runs=2
run1_stop=$WL_RESUME_STOP
run1_stop_when={{PROJECT}}/d3
policy_file=$WL_RUN_DIR/budget.dw
EOF
}

wl_prepare() {
  # The token lives in the run directory, outside the project, and reaches the
  # agent only through run one's prompt. The only way it can appear in
  # resumed.txt is through the resumed conversation.
  printf 'resume-%s-%s%s\n' "$(date +%s)" "$RANDOM" "$RANDOM" > "$WL_RUN_DIR/nonce.txt"
  wl_write_budget "$WL_RUN_DIR/budget.dw" "$WL_RESUME_RULE" fs:write FsWriteOperation create_dir "$WL_RESUME_BUDGET"
}

wl_goal_vars() {
  [ "$1" = 1 ] && echo "NONCE=$(tr -d '[:space:]' < "$WL_RUN_DIR/nonce.txt")"
  return 0
}

# Run two continues the session run one started. The id comes from the agent's
# own stream; without it the cell refuses rather than start a fresh conversation.
wl_run_args() {
  local sid
  [ "$1" = 2 ] || return 0
  sid="$(wl_session_id claude "$2")" || { echo "workload-resume-claude: no session_id in $2" >&2; return 1; }
  printf '%s\n' --resume "$sid"
}

# Where the session file stood when run one ended, so run two's write shows.
wl_between_runs() {
  local sid file
  sid="$(wl_session_id claude "$WL_RUN_DIR/turns.1.jsonl")" || return 1
  file="$(wl_session_file claude "$2" "$sid")"
  printf '%s %s\n' "$file" "$(wl_mtime "$file")" > "$WL_RUN_DIR/session-file.1"
}

wl_prestate() {
  wl_tree_listing "$WL_HOME/.claude" > "$WL_ORACLE_DIR/home-config.before"
}

wl_checks() {
  local proj="$1" run="$WL_RUN_DIR" nonce sid file before
  nonce="$(tr -d '[:space:]' < "$run/nonce.txt" 2>/dev/null)"
  if [ -z "$nonce" ]; then
    wl_check resume-recall 0 "no token recorded: wl_prepare did not run"
  else
    wl_assert_file resume-recall "$proj/resumed.txt" "$nonce"
  fi
  wl_assert_file resume-report "$proj/budget-report.txt" "REFUSED d"
  sid="$(wl_session_id claude "$run/turns.1.jsonl" 2>/dev/null)"
  if [ -z "$sid" ]; then
    wl_check session-file-in-grant 0 "run one's stream names no session_id"
  else
    file="$(wl_session_file claude "$proj" "$sid")"
    before="$(cut -d' ' -f2 "$run/session-file.1" 2>/dev/null)"
    if [ -z "$file" ]; then
      wl_check session-file-in-grant 0 "no $sid.jsonl under $proj/.claude-config/projects"
    elif [ -z "$before" ]; then
      wl_check session-file-in-grant 0 "wl_between_runs recorded no session file after run one; now: $file"
    elif [ "$(wl_mtime "$file")" -gt "$before" ]; then
      wl_check session-file-in-grant 1 "$file written again by run two"
    else
      wl_check session-file-in-grant 0 "$file not written by run two (before=$before now=$(wl_mtime "$file"))"
    fi
  fi
  wl_assert_no_denial resume-no-config-denial "project/.claude-config"
  wl_assert_tree_unchanged home-config-untouched "$WL_ORACLE_DIR/home-config.before" "$WL_HOME/.claude"
  wl_assert_same_box "$run/box-state.1.json" "$run/box-state.2.json"
  wl_assert_no_line box-not-recreated "$run/stderr.2.log" 'strands-box: box .* (created|updated)'
  wl_assert_disclosure_stable disclosure-stable "$run/stderr.1.log" "$run/stderr.2.log"
  # Run one's spend is the directories it left behind.
  wl_assert_budget_carried budget "$WL_RESUME_RULE" fs:write mkdir "$WL_RESUME_BUDGET" \
    "$(find "$proj" -maxdepth 1 -type d -name 'd[1-3]' | wc -l | tr -d ' ')"
  wl_assert_runs_valid run-valid-each
  if [ "$WL_RESUME_STOP" = kill ]; then
    wl_assert_file kill-happened "$run/run1-killed" kill
    wl_assert_no_line kill-no-stale-state "$run/stderr.2.log" 'stale|live\.json|box\.sock|already running|AlreadyRunning'
  fi
}
