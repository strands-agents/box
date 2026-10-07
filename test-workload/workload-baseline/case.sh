#!/bin/bash
# workload-baseline — the shipped example's shape: one agent, one project, the
# mediated Shell, one model round trip, and no host binary at all. This is the
# floor every other dimension builds on: if this cell fails, nothing downstream
# is meaningful.
#
# Reference: artifact section 1 (Claude Code) and section 7 (Codex CLI). Both
# shipped pairs grant the project and permit shell:exec with no shell:spawn rule,
# so the two agents differ here only in which model host is bound.

wl_manifest() {
  cat <<EOF
tools=
timeout=480
enumerate=1
EOF
}

wl_prepare() {
  local proj="$1"
  printf 'notes for the workload\n' > "$proj/notes.md"
}

wl_checks() {
  local proj="$1"
  wl_assert_file baseline-edit  "$proj/notes.md" WORKLOAD_BASELINE_OK
  wl_assert_file baseline-shell "$proj/shell.txt" baseline-shell-ran
  wl_assert_journal baseline-journal-model permit "http:request"
  wl_assert_no_denial baseline-no-project-denial "$proj"
}
