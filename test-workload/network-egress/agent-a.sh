#!/bin/bash
# network-egress/agent-a.sh — Agent A for the network-egress case.
# Thin wrapper (option A): delegates to the common on-instance runner, pointed at
# this case's goal.md. A case needing a bespoke jailbreak strategy replaces this
# with a full script.
# Usage: agent-a.sh <run-dir>   (bootstrap invokes this on the instance)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/../common/agent-a-runner.sh" "$1" "$HERE/goal.md"
