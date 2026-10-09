#!/bin/bash
# manual/linux/run-harness.sh
# Laptop (SSH) launcher for the jailbreak harness on a Linux instance.
# The Linux twin of macos/run-harness.sh: both run common/bootstrap.sh on the
# instance through common/lib.sh: run_harness, and exit 0 only when the verdict
# is PASS.
#
# Prereqs: the instance is provisioned + `install.sh` has built strands-box and
# Claude Code.
#
# Usage: ./manual/linux/run-harness.sh <instance-id> [case]   (case: network-egress, workloads)
set -euo pipefail
source "$(dirname "$0")/../../common/lib.sh"

INSTANCE_ID="${1:?Usage: $0 <instance-id> [case]}"
run_harness linux "$INSTANCE_ID" ec2-user "${2:-network-egress}"
