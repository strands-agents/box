#!/bin/bash
# workload-git — a real git workflow (branch, conflict, rebase --continue without
# a terminal) plus the tool-coverage gate: a program no [tool.*] table covers is
# refused by name before it runs, and the refusal is recorded in the journal.
#
# Reference: artifact section 5. `fs:delete` is permitted inside the project
# because a rebase removes files there; macOS also needs `fs:move`.

wl_manifest() {
  cat <<EOF
tools=git
fs=delete
fs_macos=move
timeout=900
EOF
}

wl_prepare() { :; }

wl_checks() {
  local proj="$1"
  wl_assert_file git-repo "$proj/.git/HEAD"
  wl_assert_commits git-commits "$proj" 3
  wl_assert_file git-resolved "$proj/story.txt" resolved
  wl_assert_file git-log "$proj/gitlog.txt" "feature commit"
  # The rebase finished rather than being left in progress.
  if [ -d "$proj/.git/rebase-merge" ] || [ -d "$proj/.git/rebase-apply" ]; then
    wl_check git-rebase-complete 0 "rebase still in progress"
  else
    wl_check git-rebase-complete 1 "no rebase state left behind"
  fi
  wl_assert_journal git-journal-spawn permit "shell:spawn" git
  # The gate: the unauthorized interpreter was refused, and the box says so.
  wl_assert_journal git-gate-denied deny "shell:spawn" python
}
