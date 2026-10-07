#!/bin/bash
# macos/install.sh — Install strands-box + Claude Code on a Mac instance
# Usage: ./macos/install.sh <instance-id>
set -euo pipefail
source "$(dirname "$0")/../../common/lib.sh"

INSTANCE_ID="${1:?Usage: $0 <instance-id>}"
USER="ec2-user"

echo "=== macOS Install — $INSTANCE_ID ==="

# Upload source tarball
echo "[1/4] Uploading source tarball..."
scp_to "$INSTANCE_ID" "$USER" "$SOURCE_TARBALL" "/tmp/strands-box-src.tar.gz"

# Upload the install payload. The version pin is emitted ahead of the quoted
# heredoc: the heredoc itself expands nothing, so a value from this side must be
# written into the script rather than referenced from it.
INSTALL_PAYLOAD=$(mktemp)
printf '#!/bin/bash\nCLAUDE_SPEC=%q\n' "${WL_CLAUDE_VERSION:+@${WL_CLAUDE_VERSION}}" > "$INSTALL_PAYLOAD"
cat >> "$INSTALL_PAYLOAD" << 'REMOTE_SCRIPT'
set -ex
# Homebrew's prefix is architecture-dependent: /opt/homebrew on Apple Silicon and
# /usr/local on Intel. The default macOS PATH carries neither, and the mac-m4 default
# made the Intel-only spelling below a silent no-op, so brew is located rather than
# assumed -- without this, node never installs and the box starts with no agent.
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
find_brew() {
  for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [ -x "$candidate" ]; then echo "$candidate"; return 0; fi
  done
  return 1
}
if ! BREW="$(find_brew)"; then
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" < /dev/null
  BREW="$(find_brew)" || {
    echo "FATAL: brew is on neither prefix after running the Homebrew installer" >&2
    exit 1
  }
fi
eval "$("$BREW" shellenv)"
echo "eval \"\$($BREW shellenv)\"" >> ~/.zprofile
brew --version | head -1

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
echo 'export PATH="$HOME/strands-box/target/release:$PATH"' >> ~/.zprofile

# Node.js + Claude Code. `node@22` is keg-only: brew does not link its bin into
# PATH, so `npm` is not found unless the keg's own bin is added. The guard is what
# turns a missing npm into a failed install rather than a box that starts without
# an agent.
brew install node@22 2>&1 | tail -3
NODE_BIN="$(brew --prefix node@22)/bin"
export PATH="$NODE_BIN:$PATH"
echo "export PATH=\"$NODE_BIN:\$PATH\"" >> ~/.zprofile
command -v npm >/dev/null || {
  echo "FATAL: npm is not on PATH after installing node@22 (looked in $NODE_BIN)" >&2
  exit 1
}
npm install -g "@anthropic-ai/claude-code${CLAUDE_SPEC}" 2>&1 | tail -3

# The workspace and the private box directory the pair names. `run --config`
# reads box.toml alone and performs no discovery, so both exist before the box
# starts, and the box directory is empty and mode 0700. `.tmp` and
# `.claude-config` are where box.toml points Claude Code's scratch and
# configuration, inside the workspace.
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
mkdir -p ~/jailbreak-harness/.strands-box ~/jailbreak-harness/.tmp ~/jailbreak-harness/.claude-config
rm -rf ~/jailbreak-box && mkdir -p ~/jailbreak-box && chmod 700 ~/jailbreak-box

echo "=== INSTALL COMPLETE ==="
sw_vers
# Verify, do not narrate. `claude --version || echo "claude installed"` asserted
# success on failure, so an install with no agent reported a clean finish and the
# box was asked to exec a binary that did not exist. Under `set -e` these two
# lines fail the install instead.
strands-box --version
claude --version
REMOTE_SCRIPT

echo "[2/4] Uploading install script..."
scp_to "$INSTANCE_ID" "$USER" "$INSTALL_PAYLOAD" "~/install.sh"
rm -f "$INSTALL_PAYLOAD"

echo "[3/4] Running install (Rust build, several minutes)..."
ssh_to "$INSTANCE_ID" "$USER" "chmod +x ~/install.sh && bash ~/install.sh" 2>&1 | tail -20

# Write the box pair here and upload it. The box has no verb that writes one, so
# the driver renders both files from the same two sources common/bootstrap.sh
# uses, against the canonical paths the remote payload created above.
echo "[4/4] Applying box configuration..."
# The box compares canonical spellings, so the instance resolves its own home and
# this side never assumes that /Users/ec2-user is not a symbolic link. One value
# crosses, and the last line of it: an ssh banner would otherwise be read as a
# path. The two directories below it were made by mkdir under that home, so they
# are real and need no second round trip.
HOME_ON_INSTANCE=$(ssh_to "$INSTANCE_ID" "$USER" 'cd ~ && pwd -P' | tr -d '\r' | tail -n 1)
case "$HOME_ON_INSTANCE" in
  /*) ;;
  *) echo "ERROR: $INSTANCE_ID did not report an absolute home (got '${HOME_ON_INSTANCE}')" >&2; exit 1 ;;
esac
WORKSPACE="$HOME_ON_INSTANCE/jailbreak-harness"
BOX_DIR="$HOME_ON_INSTANCE/jailbreak-box"
# box.toml's `command` must be the agent's absolute real path: the box resolves a
# bare name against the box PATH, which does not carry npm's global bin on macOS.
AGENT_COMMAND=$(agent_command_on_instance "$INSTANCE_ID" "$USER") || exit 1
echo "agent command on instance: $AGENT_COMMAND"
BOX_TOML=$(mktemp); BOX_POLICY=$(mktemp)
if ! render_box_pair "$HOME_ON_INSTANCE" "$WORKSPACE" "$BOX_DIR" \
       "$AGENT_COMMAND" "$BOX_TOML" "$BOX_POLICY"; then
  rm -f "$BOX_TOML" "$BOX_POLICY"; exit 1
fi
echo "box_dir on instance: $BOX_DIR"
scp_to "$INSTANCE_ID" "$USER" "$BOX_TOML"   "~/jailbreak-harness/.strands-box/box.toml"
scp_to "$INSTANCE_ID" "$USER" "$BOX_POLICY" "~/jailbreak-harness/.strands-box/policy.dw"
rm -f "$BOX_TOML" "$BOX_POLICY"

echo ""
echo "=== macOS instance $INSTANCE_ID ready ==="
echo "Next: ./macos/run-jailbreak.sh $INSTANCE_ID"
