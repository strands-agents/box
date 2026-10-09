#!/bin/bash
# setup.sh — One-click setup for Strands Box Containment Tests
#
# Usage:
#   ./setup.sh              # Provision + install BOTH platforms
#   ./setup.sh linux        # Linux only
#   ./setup.sh macos        # macOS only
#   ./setup.sh --run        # Provision + install + run the harness on both
#   ./setup.sh linux --run  # Linux only, including the harness run
#
# --run runs the case named by CASE (default network-egress; `workloads` runs the
# workload suite) through <platform>/run-harness.sh, and the script exits non-zero
# unless every platform's verdict is PASS.
#
# Prerequisites:
#   - AWS CLI v2 with credentials on the default chain, or AWS_CREDENTIAL_REFRESH set
#   - strands-box source tarball at /tmp/strands-box-src.tar.gz
#     (generate with: cd <box repository root> && \
#      tar czf /tmp/strands-box-src.tar.gz --exclude='.git' --exclude='target' \
#      --exclude='build' --exclude='rust-toolchain.toml' --exclude='.cargo' .)
#
# What this does:
#   1. Provisions EC2 instances (AL2023 arm64 + mac-m4.metal Dedicated Host)
#   2. Uploads the strands-box source and builds strands-box on each
#   3. Installs Claude Code + configures box for Bedrock via aws://default
#   4. Optionally runs the harness: canaries, the agent against the case's goal.md, and
#      the verdict rule.
#
# Cost:
#   - Linux: ~$0.07/hr (t4g.large)
#   - macOS: a Dedicated Host bills a 24-hour minimum from allocation, and keeps
#     billing while allocated even with no instance on it. See EC2 Mac pricing.
#
# Teardown:
#   ./teardown.sh          # Stop (preserves state)
#   ./teardown.sh --full   # Terminate + release Dedicated Host

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

source ../common/lib.sh

# Parse arguments
PLATFORM="${1:-both}"
[ "$PLATFORM" = "--run" ] && PLATFORM=both
RUN_HARNESS=false
for arg in "$@"; do
  if [ "$arg" = "--run" ]; then
    RUN_HARNESS=true
  fi
done
CASE="${CASE:-network-egress}"
# One platform's failing verdict must not skip the other's run, so each records its
# status here and the script exits on it at the end.
FAILED=""

# Validate source tarball exists
if [ ! -f "$SOURCE_TARBALL" ]; then
  echo "ERROR: Source tarball not found at $SOURCE_TARBALL"
  echo ""
  echo "Generate it with:"
  echo "  cd <box repository root>"
  echo "  tar czf /tmp/strands-box-src.tar.gz --exclude='.git' --exclude='target' \\"
  echo "    --exclude='build' --exclude='rust-toolchain.toml' --exclude='.cargo' ."
  exit 1
fi

refresh_credentials

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Strands Box Containment Tests — One-Click Setup          ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Account:  ${AWS_ACCOUNT:-<default credential chain>}    ║"
echo "║  Region:   $AWS_REGION                              ║"
echo "║  Platform: $PLATFORM                                       ║"
echo "║  Run:      $RUN_HARNESS                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# --- Linux ---
if [ "$PLATFORM" = "both" ] || [ "$PLATFORM" = "linux" ]; then
  echo "━━━ Linux (AL2023, kernel 6.1, arm64) ━━━"
  LINUX_ID=$(bash linux/provision.sh | grep -E '^i-' | tail -1)
  echo "Provisioned: $LINUX_ID"
  
  bash linux/install.sh "$LINUX_ID"
  
  if [ "$RUN_HARNESS" = "true" ]; then
    echo ""
    echo "Running $CASE on Linux..."
    bash linux/run-harness.sh "$LINUX_ID" "$CASE" || FAILED="$FAILED linux"
  fi
  echo ""
fi

# --- macOS ---
if [ "$PLATFORM" = "both" ] || [ "$PLATFORM" = "macos" ]; then
  echo "━━━ macOS (macOS 26, Seatbelt, Apple Silicon mac-m4.metal) ━━━"
  MACOS_ID=$(bash macos/provision.sh | grep -E '^i-' | tail -1)
  echo "Provisioned: $MACOS_ID"
  
  bash macos/install.sh "$MACOS_ID"
  
  if [ "$RUN_HARNESS" = "true" ]; then
    echo ""
    echo "Running $CASE on macOS..."
    bash macos/run-harness.sh "$MACOS_ID" "$CASE" || FAILED="$FAILED macos"
  fi
  echo ""
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Setup Complete                                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Run the harness individually:"
echo "  ./linux/run-harness.sh <instance-id> [case]"
echo "  ./macos/run-harness.sh <instance-id> [case]"
echo ""
echo "Teardown:"
echo "  ./teardown.sh          # Stop instances"
echo "  ./teardown.sh --full   # Terminate + release host"

if [ -n "$FAILED" ]; then
  echo ""
  echo "Verdict not PASS on:$FAILED (case $CASE). Reports: $REPORT_DIR"
  exit 1
fi
