#!/bin/bash
# manual/teardown.sh — Stop or terminate all test resources
# Usage:
#   ./teardown.sh          # Stop instances (preserves state, avoids Mac 24h wait)
#   ./teardown.sh --full   # Terminate instances + release Dedicated Host
set -euo pipefail
source "$(dirname "$0")/../common/lib.sh"

refresh_credentials

MODE="${1:-stop}"

echo "=== Strands Box Containment Tests — Teardown ==="

# Find all project instances
INSTANCES=$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=instance-state-name,Values=running,stopped" \
  --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name]' --output text)

if [ -z "$INSTANCES" ]; then
  echo "No active instances found."
else
  echo "Instances:"
  echo "$INSTANCES" | while read -r id type state; do
    echo "  $id ($type) — $state"
  done
  
  INSTANCE_IDS=$(echo "$INSTANCES" | awk '{print $1}' | tr '\n' ' ')
  
  if [ "$MODE" = "--full" ]; then
    echo ""
    echo "Terminating instances: $INSTANCE_IDS"
    aws ec2 terminate-instances --region "$AWS_REGION" --instance-ids $INSTANCE_IDS --output text
    
    echo "Waiting for instances to terminate..."
    # A host still holding an instance is refused as `InvalidHost.Occupied`, so this
    # waits rather than sleeping a fixed minute. Polled rather than `aws ec2 wait`,
    # whose 40x15s ceiling is under ten minutes and which a Mac routinely exceeds;
    # 100x15s gives it twenty-five. A failed describe leaves the loop and lets the
    # release below report the real state, which it now reads from `Unsuccessful`.
    LEFT=""
    for _ in $(seq 1 100); do
      LEFT=$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids $INSTANCE_IDS \
        --query 'Reservations[].Instances[?State.Name!=`terminated`].InstanceId' \
        --output text 2>/dev/null) || break
      [ -z "$LEFT" ] && break
      sleep 15
    done
    [ -z "$LEFT" ] || echo "  WARNING: still not terminated after 25 minutes: $LEFT"

    # Release Dedicated Hosts
    HOSTS=$(aws ec2 describe-hosts --region "$AWS_REGION" \
      --filter "Name=tag:Project,Values=$PROJECT_TAG" \
      --query 'Hosts[?State!=`released`].HostId' --output text)
    if [ -n "$HOSTS" ]; then
      echo "Releasing Dedicated Hosts: $HOSTS"
      # `release-hosts` is a partial-success API: it exits 0 and reports refusals in
      # `Unsuccessful`, so the exit status alone says nothing. Read that array and
      # print the real reason rather than guessing one.
      FAILED=$(aws ec2 release-hosts --region "$AWS_REGION" --host-ids $HOSTS \
        --query 'Unsuccessful[].[ResourceId,Error.Code,Error.Message]' --output text 2>&1) || \
        FAILED="release-hosts call failed: $FAILED"
      if [ -n "$FAILED" ]; then
        echo "  WARNING: a Dedicated Host was NOT released and keeps billing:"
        echo "$FAILED" | sed 's/^/    /'
        echo "    An occupied host is still terminating an instance or scrubbing;"
        echo "    a Mac host also cannot be released within 24h of allocation."
        echo "    Re-run './teardown.sh --full' once it reaches 'available'."
      fi
    fi
  else
    echo ""
    echo "Stopping instances: $INSTANCE_IDS"
    aws ec2 stop-instances --region "$AWS_REGION" --instance-ids $INSTANCE_IDS --output text
    echo "  Stopped. Use --full to terminate and release Dedicated Host."
  fi
fi

echo ""
echo "Done."
