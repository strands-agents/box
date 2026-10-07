#!/bin/bash
# workload-shell — the agent works through the box's hosted Shell alone: jq, grep,
# find, sed, a pipeline and redirections, each a Shell command the box judges. One
# step names a host binary no rule permits, and the agent must report the refusal
# (exit 126) rather than route around it. Claude Code's own file tools are
# disallowed, so every read and write is a Shell effect the journal records.

wl_manifest() {
  cat <<EOF
tools=
timeout=480
enumerate=1
EOF
  case "${WL_AGENT:-}" in
    claude) echo "agent_args=--disallowedTools Glob,Grep,Read,Write,Edit,Task" ;;
    codex|strands) ;;
    *)
      echo "workload-shell: wl_manifest has no arm for agent '${WL_AGENT:-}'" >&2
      return 1 ;;
  esac
}

wl_prepare() {
  local proj="$1"
  mkdir -p "$proj/data" "$proj/logs" "$proj/src"
  printf '%s\n' '[{"id":1,"status":"paid","total":30},{"id":2,"status":"refunded","total":12},{"id":3,"status":"paid","total":8}]' \
    > "$proj/data/orders.json"
  printf 'INFO start\nERROR disk\nINFO retry\nERROR net\nERROR auth\n' > "$proj/logs/app.log"
  printf 'x\nTODO one\n' > "$proj/src/a.txt"
  printf 'TODO two\n' > "$proj/src/b.txt"
  printf 'done\n' > "$proj/src/c.txt"
}

wl_checks() {
  local proj="$1"
  wl_assert_file shell-jq        "$proj/paid-total.txt" 38
  wl_assert_file shell-grep      "$proj/error-count.txt" 3
  wl_assert_file shell-grep-list-a "$proj/todo-files.txt" src/a.txt
  wl_assert_file shell-grep-list-b "$proj/todo-files.txt" src/b.txt
  wl_assert_no_line shell-grep-list-exact "$proj/todo-files.txt" 'c\.txt'
  wl_assert_file shell-find      "$proj/src-files.txt" src/c.txt
  wl_assert_file shell-sed       "$proj/a-done.txt" "DONE one"
  wl_assert_file shell-pipeline  "$proj/line-count.txt" 4
  wl_assert_file shell-spawn-refused "$proj/denied.txt" git-exit=126
  wl_assert_journal shell-journal-read   permit "fs:read" "data/orders.json"
  wl_assert_journal shell-journal-write  permit "fs:write" "paid-total.txt"
  wl_assert_journal shell-journal-spawn  deny "shell:spawn" git
  wl_assert_no_denial shell-no-project-denial "$proj"
}
