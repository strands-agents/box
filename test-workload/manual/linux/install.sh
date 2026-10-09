#!/bin/bash
# linux/install.sh — Install strands-box + Claude Code on an AL2023 instance
# Usage: ./linux/install.sh <instance-id>
# Requires: source tarball at $SOURCE_TARBALL (default: /tmp/strands-box-src.tar.gz)
set -euo pipefail
source "$(dirname "$0")/../../common/lib.sh"

INSTANCE_ID="${1:?Usage: $0 <instance-id>}"
USER="ec2-user"

echo "=== Linux Install — $INSTANCE_ID ==="

# Upload source tarball
echo "[1/3] Uploading source tarball..."
scp_to "$INSTANCE_ID" "$USER" "$SOURCE_TARBALL" "/tmp/strands-box-src.tar.gz"

# Upload the install payload. The version pin is emitted ahead of the quoted
# heredoc: the heredoc itself expands nothing, so a value from this side must be
# written into the script rather than referenced from it.
INSTALL_PAYLOAD=$(mktemp)
printf '#!/bin/bash\nCLAUDE_SPEC=%q\n' "${WL_CLAUDE_VERSION:+@${WL_CLAUDE_VERSION}}" > "$INSTALL_PAYLOAD"
cat >> "$INSTALL_PAYLOAD" << 'REMOTE_SCRIPT'
set -ex

# System deps (AL2023)
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y --allowerasing openssl-devel pkg-config git curl

# Rust
if ! command -v rustc &>/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
source "$HOME/.cargo/env"
rustc --version

# Build strands-box
rm -rf ~/strands-box
mkdir ~/strands-box
tar xzf /tmp/strands-box-src.tar.gz -C ~/strands-box
cd ~/strands-box
cargo build --workspace --release 2>&1 | tail -5
export PATH="$HOME/strands-box/target/release:$PATH"
echo 'export PATH="$HOME/strands-box/target/release:$PATH"' >> ~/.bashrc

# Node.js + Claude Code
sudo dnf install -y nodejs20 npm
sudo npm install -g "@anthropic-ai/claude-code${CLAUDE_SPEC}" 2>&1 | tail -3

echo "=== INSTALL COMPLETE ==="
uname -r
# Verify, do not narrate — see the note in macos/install.sh. This leg happened to
# install cleanly, but the pattern asserted success on failure here too.
strands-box --version
claude --version
REMOTE_SCRIPT

echo "[2/3] Uploading install script..."
scp_to "$INSTANCE_ID" "$USER" "$INSTALL_PAYLOAD" "~/install.sh"
rm -f "$INSTALL_PAYLOAD"

echo "[3/3] Running install (this takes ~5-8 minutes for Rust build)..."
ssh_to "$INSTANCE_ID" "$USER" "chmod +x ~/install.sh && bash ~/install.sh" 2>&1 | tail -20

echo ""
echo "=== Linux instance $INSTANCE_ID ready ==="
echo "Next: ./linux/run-harness.sh $INSTANCE_ID [case]"
