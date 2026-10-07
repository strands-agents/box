#!/bin/bash
# deterministic/tools/mac-diagnostics.sh — entry point bootstrap.sh calls in diagnostic mode.
#
# The capture itself is tools/mac_diagnostics.py (stdlib Python): every external command runs in
# its own process group under a watchdog that terminates and reaps the group at the earlier of its
# per-command timeout and one global deadline, with byte caps on command output and on copied
# reports. This wrapper only finds python3 and, when there is none, writes the same file set with
# a grep-derived killed-pid list and a summary that says exactly what could not be done — valid
# JSON, no fabricated facts. It never changes a test outcome and always exits 0.
#
# Usage: mac-diagnostics.sh <results-dir with verdict.json> <output-dir> [run-start-epoch]
set -uo pipefail
RESULTS="${1:?results dir}"
OUT="${2:?output dir}"
RUN_START="${3:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_TIMEOUT="${DIAG_TOTAL_TIMEOUT:-600}"
mkdir -p "$OUT"

if command -v python3 >/dev/null 2>&1; then
  # Outer backstop on the whole capture, in its own session so it can be reaped as a group: the
  # helper enforces the same deadline itself; this only guards a helper that stopped responding.
  if command -v setsid >/dev/null 2>&1; then
    setsid python3 "$HERE/mac_diagnostics.py" "$RESULTS" "$OUT" "$RUN_START" &
  else
    python3 "$HERE/mac_diagnostics.py" "$RESULTS" "$OUT" "$RUN_START" &
  fi
  helper=$!
  deadline=$(( $(date +%s) + TOTAL_TIMEOUT + 30 ))
  while kill -0 "$helper" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      kill -TERM -- "-$helper" 2>/dev/null || kill -TERM "$helper" 2>/dev/null
      sleep 2
      kill -KILL -- "-$helper" 2>/dev/null || kill -KILL "$helper" 2>/dev/null
      wait "$helper" 2>/dev/null
      printf '{"applicable":false,"helper_error":"helper exceeded the outer deadline of %ss and was terminated","diagnostic_errors":1,"incomplete":true}\n' "$((TOTAL_TIMEOUT + 30))" > "$OUT/summary.json"
      exit 0
    fi
    sleep 0.2
  done
  wait "$helper" 2>/dev/null
  exit 0
fi

# No python3: record that, extract killed pids with grep (integers only, so the JSON stays valid),
# and stop. Failed case ids and every macOS record need python3 and are reported as not captured.
printf 'python3 unavailable: only killed pids were extracted (grep); no crash reports, logs or image identity captured\n' > "$OUT/errors.txt"
pids=""
if [ -f "$RESULTS/verdict.json" ]; then
  pids=$(grep -oE 'bash: line [0-9]+:[[:space:]]+[0-9]+ Killed: 9' "$RESULTS/verdict.json" 2>/dev/null | grep -oE '[0-9]+ Killed' | grep -oE '^[0-9]+' | sort -un | paste -sd, -)
else
  printf 'no verdict.json at %s\n' "$RESULTS/verdict.json" >> "$OUT/errors.txt"
fi
printf '{"verdict_present":%s,"fallback":"grep","failed_cases":[],"killed_pids":[%s],"killed":[]}\n' \
  "$([ -f "$RESULTS/verdict.json" ] && echo true || echo false)" "${pids:-}" > "$OUT/cases.json"
errors=$(wc -l < "$OUT/errors.txt" | tr -d ' ')
printf '{"applicable":false,"helper_error":"python3 unavailable","killed_pids":[%s],"crash_reports":{"matched":0,"conclusion":"not captured: python3 unavailable"},"diagnostic_errors":%s,"incomplete":true}\n' \
  "${pids:-}" "${errors:-1}" > "$OUT/summary.json"
exit 0
