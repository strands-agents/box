#!/bin/bash
# manual/macos/run-harness.sh
# Laptop (SSH) launcher for the jailbreak harness on a Mac instance.
#
# The on-instance orchestration lives in ONE place — common/bootstrap.sh, which
# builds the box and starts the Rust harness (creds -> canaries -> agent -> verdict
# -> upload). This driver ships the harness tree to the instance, runs bootstrap.sh
# there, and fetches the verdict (common/lib.sh: run_harness), so the manual path and
# the pipeline path run identical code. It exits 0 only when the verdict is PASS.
#
# Prereqs: the instance is provisioned + `install.sh` has built strands-box and
# Claude Code (bootstrap reuses an already-built box; it does not rebuild).
#
# Usage: ./manual/macos/run-harness.sh <instance-id> [case]   (case: network-egress, workloads)
set -euo pipefail
source "$(dirname "$0")/../../common/lib.sh"

INSTANCE_ID="${1:?Usage: $0 <instance-id> [case]}"
run_harness macos "$INSTANCE_ID" ec2-user "${2:-network-egress}"
