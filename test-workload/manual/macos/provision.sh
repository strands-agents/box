#!/bin/bash
# macos/provision.sh — Allocate a Dedicated Host and launch a Mac instance
# Note: 24-hour minimum allocation applies to the Dedicated Host.
set -euo pipefail
source "$(dirname "$0")/../../common/lib.sh"
require_inputs KEY_PAIR VPC_ID SECURITY_GROUP INSTANCE_PROFILE MACOS_AMI || exit 1

refresh_credentials

echo "=== macOS Containment Test — Provision ==="

# Check if instance already exists
EXISTING=$(aws ec2 describe-instances --region "$AWS_REGION" \
  --filters "Name=tag:Name,Values=strands-box-poc-macos" \
            "Name=tag:Project,Values=$PROJECT_TAG" \
            "Name=instance-state-name,Values=running,stopped" \
  --query 'Reservations[].Instances[].InstanceId' --output text)

if [ -n "$EXISTING" ]; then
  echo "Instance already exists: $EXISTING"
  STATE=$(aws ec2 describe-instances --region "$AWS_REGION" \
    --instance-ids "$EXISTING" --query 'Reservations[].Instances[].State.Name' --output text)
  if [ "$STATE" = "stopped" ]; then
    echo "Starting stopped instance..."
    aws ec2 start-instances --region "$AWS_REGION" --instance-ids "$EXISTING" --output text
    wait_for_instance "$EXISTING"
  fi
  wait_for_ssm "$EXISTING"
  echo "$EXISTING"
  exit 0
fi

# Reuse a host this project already owns before allocating another. A Dedicated
# Host bills a 24-hour minimum and cannot be released before it expires, so
# allocating per run both pays twice and exhausts the account's host quota.
# The tag filter is what keeps this off the CloudFormation-managed hosts, which
# carry no Project tag; `length(Instances)==0` is what keeps it off a busy one.
HOST_ID=$(aws ec2 describe-hosts --region "$AWS_REGION" \
  --filter "Name=tag:Project,Values=$PROJECT_TAG" \
           "Name=instance-type,Values=$MACOS_INSTANCE_TYPE" \
           "Name=state,Values=available" \
  --query 'Hosts[?length(Instances)==`0`]|[0].HostId' --output text)

if [ -n "$HOST_ID" ] && [ "$HOST_ID" != "None" ]; then
  MAC_AZ=$(aws ec2 describe-hosts --region "$AWS_REGION" --host-ids "$HOST_ID" \
    --query 'Hosts[0].AvailabilityZone' --output text)
  echo "Reusing Dedicated Host $HOST_ID in $MAC_AZ (already allocated, already billed)"
else
  # Find AZ with availability for this instance type
  MAC_AZ=$(aws ec2 describe-instance-type-offerings --region "$AWS_REGION" \
    --location-type availability-zone \
    --filters "Name=instance-type,Values=$MACOS_INSTANCE_TYPE" \
    --query 'InstanceTypeOfferings[0].Location' --output text)
  if [ -z "$MAC_AZ" ] || [ "$MAC_AZ" = "None" ]; then
    echo "ERROR: $MACOS_INSTANCE_TYPE is not offered in $AWS_REGION" >&2
    exit 1
  fi
  echo "$MACOS_INSTANCE_TYPE available in: $MAC_AZ"

  echo "Allocating Dedicated Host (24h minimum)..."
  HOST_ID=$(aws ec2 allocate-hosts --region "$AWS_REGION" \
    --instance-type "$MACOS_INSTANCE_TYPE" \
    --availability-zone "$MAC_AZ" \
    --auto-placement off \
    --quantity 1 \
    --tag-specifications "ResourceType=dedicated-host,Tags=[{Key=Name,Value=strands-box-poc-mac},{Key=Project,Value=$PROJECT_TAG}]" \
    --query 'HostIds[0]' --output text)
  echo "Dedicated Host: $HOST_ID"
fi

# Get subnet in that AZ
MAC_SUBNET=$(aws ec2 describe-subnets --region "$AWS_REGION" \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=availability-zone,Values=$MAC_AZ" \
  --query 'Subnets[0].SubnetId' --output text)

# Launch instance
echo "Launching $MACOS_INSTANCE_TYPE on $HOST_ID..."
INSTANCE_ID=$(aws ec2 run-instances --region "$AWS_REGION" \
  --image-id "$MACOS_AMI" \
  --instance-type "$MACOS_INSTANCE_TYPE" \
  --key-name "$KEY_PAIR" \
  --security-group-ids "$SECURITY_GROUP" \
  --subnet-id "$MAC_SUBNET" \
  --iam-instance-profile "Name=$INSTANCE_PROFILE" \
  --placement "HostId=$HOST_ID" \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":200,"VolumeType":"gp3"}}]' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=strands-box-poc-macos},{Key=Project,Value=$PROJECT_TAG}]" \
  --query 'Instances[0].InstanceId' --output text)

echo "Instance: $INSTANCE_ID"
wait_for_instance "$INSTANCE_ID"
wait_for_ssm "$INSTANCE_ID"
echo ""
echo "Next: ./macos/install.sh $INSTANCE_ID"
# Last line, bare: setup.sh reads the id with `grep -E '^i-' | tail -1`. The reuse
# branch above already ends this way, and the launch path has to match it.
echo "$INSTANCE_ID"
