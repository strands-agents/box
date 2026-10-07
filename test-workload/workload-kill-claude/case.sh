#!/bin/bash
# workload-kill-claude — workload-resume-claude, with run one ended by
# SIGKILL to the box the moment its third directory exists. Run two must resume
# the same conversation in the same box, and its stderr must name no stale lock,
# socket, or live record. The goals are the sibling's; only the stop differs.
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../workload-resume-claude/case.sh"
WL_RESUME_STOP=kill

wl_goal() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ "$1" = 1 ]; then echo "$here/../workload-resume-claude/goal.md"; else echo "$here/../workload-resume-claude/goal.$1.md"; fi
}
