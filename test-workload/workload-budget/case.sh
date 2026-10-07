#!/bin/bash
# workload-budget — one box, two runs, and one temporal budget across both:
# the agent lists three directories in run one and twelve in run two against a
# budget of twelve listings per hour. Run two is refused only when run one's
# three still count, the refusal reaches the agent through its shell tool, and
# the agent reports it rather than loop on it. Plan scenario S-50; runs for every
# agent, because no run resumes a conversation.
#
# The budget counts `enumerate` (`ls <dir>`), not content reads: Claude Code's
# Bash tool sources a snapshot on every call, so a `read_content` count would
# carry per-call noise. Claude Code's own file tools are disallowed here so a
# listing can only happen through the shell the box mediates.

WL_BUDGET=12
WL_BUDGET_RULE=listing_budget

wl_manifest() {
  cat <<EOF
tools=
timeout=600
enumerate=1
runs=2
policy_file=$WL_RUN_DIR/budget.dw
EOF
  case "${WL_AGENT:-}" in
    claude) echo "agent_args=--disallowedTools Glob,Grep,Read,Task" ;;
    codex|strands) ;; # neither has a native listing tool the prompt must steer away from
    *)
      echo "workload-budget: wl_manifest has no arm for agent '${WL_AGENT:-}'" >&2
      return 1 ;;
  esac
}

wl_prepare() {
  local proj="$1" n
  for n in $(seq 1 15); do
    mkdir -p "$proj/dir$n"
    printf 'entry %s\n' "$n" > "$proj/dir$n/file$n.txt"
  done
  wl_write_budget "$WL_RUN_DIR/budget.dw" "$WL_BUDGET_RULE" fs:read FsReadOperation enumerate "$WL_BUDGET"
}

wl_checks() {
  local proj="$1" run="$WL_RUN_DIR" refusals
  wl_assert_file budget-run-one-listing "$proj/listing-1.txt" "dir1:"
  wl_assert_file budget-report "$proj/budget-report.txt" "REFUSED dir"
  wl_assert_budget_carried budget "$WL_BUDGET_RULE" fs:read ls "$WL_BUDGET"
  # Reported, not looped: twelve listings against nine remaining gives three
  # refusals, and an agent that retried each one a few times stays under this.
  refusals="$(wl_journal_count "$WL_JOURNAL" deny fs:read --attr "strands.box.policy.rule=$WL_BUDGET_RULE")"
  if [ "${refusals:-0}" -ge 1 ] && [ "$refusals" -le 9 ]; then
    wl_check budget-no-loop 1 "$refusals refusal(s) by $WL_BUDGET_RULE"
  else
    wl_check budget-no-loop 0 "$refusals refusal(s) by $WL_BUDGET_RULE, wanted 1 to 9"
  fi
  wl_assert_same_box "$run/box-state.1.json" "$run/box-state.2.json"
  wl_assert_no_line box-not-recreated "$run/stderr.2.log" 'strands-box: box .* (created|updated)'
  wl_assert_disclosure_stable disclosure-stable "$run/stderr.1.log" "$run/stderr.2.log"
  wl_assert_runs_valid run-valid-each
  wl_note_codex_arg0 "$run/turns.jsonl"
}
