#!/bin/bash
# common/workload-run-validity.sh — decide whether ONE workload run reached the
# model.
#
# A case where the agent never reached the model executed zero attempts; that is
# not a workload pass, and the oracle must not read an empty project as a clean
# refusal. Each agent proves the model answered through the artefact it actually
# writes, so the proof is per agent, and an unknown agent name is refused by
# name rather than scored by another agent's rule.
#
#   claude   one `"type":"tool_use"` event in the stream-json transcript
#   codex    a non-empty `--output-last-message` file, or more than two events,
#            because its event stream is not a stable contract across versions
#   strands  one `"kind":"strands.tool_invocation"` event, which the agent
#            flushes before it runs the tool, so a killed run keeps the proof it
#            already earned and agent B still reads it as `case-timeout`
#
# Usage: workload-run-validity.sh <agent> <turns-file> [last-message-file]
# Prints "<VALID|INVALID> <tool_uses> <events>"; exit 3 for an unknown agent.
set -uo pipefail
AGENT="${1-}"
TURNS="${2:?Usage: $0 <agent> <turns-file> [last-message-file]}"
LAST="${3-}"

count_matches() {      # a portable integer, 0 when the file is absent
  local found
  found=$(grep -c "$1" "$TURNS" 2>/dev/null || true)
  found=${found//[^0-9]/}
  echo "${found:-0}"
}

EVENTS=$(wc -l < "$TURNS" 2>/dev/null | tr -d ' '); EVENTS=${EVENTS:-0}

case "$AGENT" in
  claude)
    TOOL_USES=$(count_matches '"type":"tool_use"')
    if [ "$TOOL_USES" -gt 0 ]; then STATUS=VALID; else STATUS=INVALID; fi
    ;;
  codex)
    TOOL_USES=$(count_matches '"type":"tool_use"')
    if [ -n "$LAST" ] && [ -s "$LAST" ]; then STATUS=VALID
    elif [ "$EVENTS" -gt 2 ]; then STATUS=VALID
    else STATUS=INVALID; fi
    ;;
  strands)
    TOOL_USES=$(count_matches '"kind":"strands.tool_invocation"')
    if [ "$TOOL_USES" -gt 0 ]; then STATUS=VALID; else STATUS=INVALID; fi
    ;;
  *)
    echo "run-validity: unknown agent name: $AGENT (known: claude, codex, strands)" >&2
    exit 3
    ;;
esac

echo "$STATUS $TOOL_USES $EVENTS"
