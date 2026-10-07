#!/bin/bash
# setup.sh — One-click setup for Strands Box Containment Tests
#
# Usage:
#   ./setup.sh              # Provision + install BOTH platforms
#   ./setup.sh linux        # Linux only
#   ./setup.sh macos        # macOS only
#   ./setup.sh --run        # Provision + install + run jailbreak on both
#   ./setup.sh linux --run  # Linux only, including jailbreak run
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
#   4. Optionally runs the jailbreak probe
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
RUN_JAILBREAK=false
for arg in "$@"; do
  if [ "$arg" = "--run" ]; then
    RUN_JAILBREAK=true
  fi
done

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
echo "║  Run:      $RUN_JAILBREAK                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# --- Linux ---
if [ "$PLATFORM" = "both" ] || [ "$PLATFORM" = "linux" ]; then
  echo "━━━ Linux (AL2023, kernel 6.1, arm64) ━━━"
  LINUX_ID=$(bash linux/provision.sh | grep -E '^i-' | tail -1)
  echo "Provisioned: $LINUX_ID"
  
  bash linux/install.sh "$LINUX_ID"
  
  if [ "$RUN_JAILBREAK" = "true" ]; then
    echo ""
    echo "Running jailbreak on Linux..."
    bash linux/run-jailbreak.sh "$LINUX_ID"
  fi
  echo ""
fi

# --- macOS ---
if [ "$PLATFORM" = "both" ] || [ "$PLATFORM" = "macos" ]; then
  echo "━━━ macOS (macOS 26, Seatbelt, Apple Silicon mac-m4.metal) ━━━"
  MACOS_ID=$(bash macos/provision.sh | grep -E '^i-' | tail -1)
  echo "Provisioned: $MACOS_ID"
  
  bash macos/install.sh "$MACOS_ID"
  
  if [ "$RUN_JAILBREAK" = "true" ]; then
    echo ""
    echo "Running jailbreak on macOS..."
    bash macos/run-jailbreak.sh "$MACOS_ID"
  fi
  echo ""
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Setup Complete                                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Run jailbreaks individually:"
echo "  ./linux/run-jailbreak.sh <instance-id> [custom-prompt]"
echo "  ./macos/run-jailbreak.sh <instance-id> [custom-prompt]"
echo ""
echo "Teardown:"
echo "  ./teardown.sh          # Stop instances"
echo "  ./teardown.sh --full   # Terminate + release host"
