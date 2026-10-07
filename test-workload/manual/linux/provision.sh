#!/bin/bash
# linux/provision.sh — Launch an AL2023 arm64 instance for containment testing
# Outputs the instance ID on success.
set -euo pipefail
source "$(dirname "$0")/../../common/lib.sh"
require_inputs KEY_PAIR VPC_ID SECURITY_GROUP INSTANCE_PROFILE LINUX_AMI || exit 1

refresh_credentials

echo "=== Linux Containment Test — Provision ==="

# Check if instance already exists
EXISTING=$(aws ec2 describe-instances --region "$AWS_REGION" \
  --filters "Name=tag:Name,Values=strands-box-poc-linux-al2023" \
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

# Pick a subnet in the default VPC
SUBNET_ID=$(aws ec2 describe-subnets --region "$AWS_REGION" \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=default-for-az,Values=true" \
  --query 'Subnets[0].SubnetId' --output text)

echo "Launching $LINUX_INSTANCE_TYPE in $SUBNET_ID..."

INSTANCE_ID=$(aws ec2 run-instances \
  --region "$AWS_REGION" \
  --image-id "$LINUX_AMI" \
  --instance-type "$LINUX_INSTANCE_TYPE" \
  --key-name "$KEY_PAIR" \
  --security-group-ids "$SECURITY_GROUP" \
  --subnet-id "$SUBNET_ID" \
  --iam-instance-profile "Name=$INSTANCE_PROFILE" \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":50,"VolumeType":"gp3"}}]' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=strands-box-poc-linux-al2023},{Key=Project,Value=$PROJECT_TAG}]" \
  --query 'Instances[0].InstanceId' --output text)

echo "Instance: $INSTANCE_ID"
wait_for_instance "$INSTANCE_ID"
wait_for_ssm "$INSTANCE_ID"
echo ""
echo "Next: ./linux/install.sh $INSTANCE_ID"
# Last line, bare: setup.sh reads the id with `grep -E '^i-' | tail -1`. The reuse
# branch above already ends this way, and the launch path has to match it.
echo "$INSTANCE_ID"
