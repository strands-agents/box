#!/bin/bash
# manual/macos/run-harness.sh
# Manual (laptop, SSH) launcher for the two-agent jailbreak harness.
#
# As of 4c the on-instance orchestration lives in ONE place — common/bootstrap.sh
# (creds -> oracle -> Agent A -> stop oracle -> Agent B -> upload). This driver no
# longer re-implements that flow over SSH; it just ships the harness tree to the
# instance and invokes bootstrap.sh there, so the manual path and the pipeline
# path run identical code. The pipeline invokes the same bootstrap.sh via SSM.
#
# Prereqs: the instance is provisioned + `install.sh` has built strands-box and
# Claude Code (bootstrap reuses an already-built box; it does not rebuild).
#
# Usage: ./manual/macos/run-harness.sh <instance-id> [dimension]
set -euo pipefail
source "$(dirname "$0")/../../common/lib.sh"
require_inputs ARTIFACTS_BUCKET || exit 1

INSTANCE_ID="${1:?Usage: $0 <instance-id> [dimension]}"
DIMENSION="${2:-network-egress}"
USER="ec2-user"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="manual-${TIMESTAMP}"
HARNESS_DIR="$(cd "$(dirname "$0")/../.." && pwd)"   # test-workload/
REMOTE_ROOT="/Users/ec2-user/indet-harness"

echo "=== Strands Box Jailbreak Harness (manual) ==="
echo "Instance: $INSTANCE_ID | dimension: $DIMENSION | run: $RUN_ID"

BOX_COMMIT=$(ssh_to "$INSTANCE_ID" "$USER" \
  "cd ~/strands-box && git rev-parse HEAD 2>/dev/null || cat ~/strands-box/COMMIT 2>/dev/null || echo unknown" 2>/dev/null || echo unknown)
echo "Box commit: $BOX_COMMIT"

# Ship the harness tree (common/ + case folders) to the instance.
echo "[1/3] Uploading harness tree..."
TARBALL=$(mktemp /tmp/indet-harness.XXXXXX.tgz)
tar czf "$TARBALL" -C "$(dirname "$HARNESS_DIR")" "$(basename "$HARNESS_DIR")"
ssh_to "$INSTANCE_ID" "$USER" "rm -rf $REMOTE_ROOT && mkdir -p $REMOTE_ROOT"
scp_to "$INSTANCE_ID" "$USER" "$TARBALL" "$REMOTE_ROOT/harness.tgz"
rm -f "$TARBALL"
ssh_to "$INSTANCE_ID" "$USER" "tar xzf $REMOTE_ROOT/harness.tgz -C $REMOTE_ROOT --strip-components=1"

# Invoke the unified bootstrap on the instance. Manual runs upload to the
# artifacts bucket (bootstrap keys by LEDGER_BUCKET); source comes from the
# already-installed box, so the S3 source fetch failing is fine (bootstrap reuses).
echo "[2/3] Running bootstrap on the instance (oracle -> Agent A -> Agent B)..."
ssh_to "$INSTANCE_ID" "$USER" \
  "sudo LEDGER_BUCKET='${ARTIFACTS_BUCKET}' BOX_COMMIT='${BOX_COMMIT}' RUN_ID='${RUN_ID}' CASE='${DIMENSION}' PLATFORM=macos AWS_REGION='${AWS_REGION}' bash $REMOTE_ROOT/common/bootstrap.sh"

echo "[3/3] Done. Artifacts under:"
DEST="s3://${ARTIFACTS_BUCKET}/reports/${BOX_COMMIT}/${RUN_ID}/indeterministic/macos/${DIMENSION}"
echo "  $DEST"
aws s3 ls "$DEST/" --region "$AWS_REGION" 2>/dev/null | awk '{print "  " $4}' || true
echo ""
echo "Validation report:  aws s3 cp $DEST/validation_report.md - | cat"
echo "Agent A turn log:   aws s3 cp $DEST/agent-a.log - | grep '\\[turn'"
