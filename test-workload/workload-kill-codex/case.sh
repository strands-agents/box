#!/bin/bash
# workload-kill-codex — workload-resume-codex, with run one ended by
# SIGKILL to the box the moment its third directory exists. Run two must resume
# the same thread in the same box, and its stderr must name no stale lock, socket,
# or live record. The goals are the sibling's; only the stop differs.
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../workload-resume-codex/case.sh"
WL_RESUME_STOP=kill

wl_goal() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ "$1" = 1 ]; then echo "$here/../workload-resume-codex/goal.md"; else echo "$here/../workload-resume-codex/goal.$1.md"; fi
}
