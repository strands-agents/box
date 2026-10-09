#!/bin/bash
# Install the on-instance tools, build the box and harness, then enter Rust.
# Env: LEDGER_BUCKET, BOX_COMMIT, RUN_ID; optional PLATFORM, CASE, AWS_REGION.
set -uo pipefail
: "${LEDGER_BUCKET:?}"; : "${BOX_COMMIT:?}"; : "${RUN_ID:?}"
export AWS_REGION="${AWS_REGION:-us-west-2}"
CASE="${CASE:-network-egress}"

# `CASE=workloads` selects the workload suite instead of one jailbreak dimension.
# That suite runs every (dimension x agent) cell in this one invocation and
# aggregates their rows, so the pipeline passes a case name and the harness owns
# the choice of engine.
if [ "$CASE" = workloads ]; then
  exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/workload-bootstrap.sh"
fi

case "$(uname -s)" in Darwin) DEF_PLAT=macos ;; *) DEF_PLAT=linux ;; esac
PLATFORM="${PLATFORM:-$DEF_PLAT}"

# Guaranteed-writable work root (SSM leaves HOME empty on macOS; /root absent there).
# Not under /tmp: on macOS that is /private/tmp, which the box floor grants
# recursively, and a floor grant that encloses the operator home is refused.
if [ -z "${HOME:-}" ] || [ ! -d "${HOME:-/nonexistent}" ] || [ ! -w "${HOME:-/nonexistent}" ]; then
  export HOME=/var/tmp/indet-home
fi
mkdir -p "$HOME"

# Homebrew puts the AWS CLI under /opt/homebrew on Apple Silicon and /usr/local on Intel;
# the SSM shell has neither on PATH.
export PATH="$PATH:/usr/local/bin:/opt/homebrew/bin"
AWS="$(command -v aws || echo /usr/local/bin/aws)"
BOOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"      # test-workload/common
HARNESS_ROOT="$(dirname "$BOOT_DIR")"                          # test-workload/
SRC="$HOME/strands-box"
log() { echo "[indet-bootstrap] $*"; }

log "platform=$PLATFORM case=$CASE run=$RUN_ID"

# 1. Fetch + unpack the box source (commit-keyed, latest fallback); recover commit.
# Only replace an existing tree when a tarball actually downloaded — a manual run
# with a pre-built box (no S3 source) must not be wiped.
# INDET_REUSE_SRC=1 (manual/run_harness) skips the fetch entirely: install.sh built the
# box under test in $SRC, and the latest.tar.gz fallback would silently swap in
# whatever box was last staged there instead.
rm -f /tmp/src.tgz
PFX="${STAGE_PREFIX:+${STAGE_PREFIX%/}/}"   # optional staging prefix (from send step); empty = bucket root
if [ "${INDET_REUSE_SRC:-0}" = 1 ] && [ -d "$SRC" ]; then
  log "INDET_REUSE_SRC=1 — using the installed source at $SRC, no S3 fetch"
else
  "$AWS" s3 cp "s3://$LEDGER_BUCKET/${PFX}box-src/$BOX_COMMIT.tar.gz" /tmp/src.tgz 2>/dev/null \
    || "$AWS" s3 cp "s3://$LEDGER_BUCKET/${PFX}box-src/latest.tar.gz" /tmp/src.tgz 2>/dev/null || log "source download FAILED"
fi
if [ -s /tmp/src.tgz ]; then
  rm -rf "$SRC"; mkdir -p "$SRC"
  tar xzf /tmp/src.tgz -C "$SRC" 2>/dev/null || log "source extract FAILED"
elif [ -d "$SRC" ]; then
  log "no S3 source tarball — reusing existing $SRC"
else
  log "WARN: no S3 source and no existing tree at $SRC"
fi
EFFECTIVE_COMMIT="$BOX_COMMIT"
for c in "$SRC/COMMIT"; do
  [ -f "$c" ] && { EFFECTIVE_COMMIT="$(tr -d '[:space:]' < "$c")"; break; }
done
log "effective box commit: $EFFECTIVE_COMMIT"

# Upload a verdict when failure prevents the Rust harness from starting.
bootstrap_failure() {
  local destination="s3://$LEDGER_BUCKET/reports/$EFFECTIVE_COMMIT/$RUN_ID/indeterministic/$PLATFORM/$CASE"
  local placeholder
  placeholder=$(mktemp) || return 1
  printf '{"mode":"indeterministic","platform":"%s","dimension":"%s","verdict":"UNCERTAIN","risk_score":0,"run_status":"INVALID","note":"harness could not start; see box-build.log"}\n' "$PLATFORM" "$CASE" > "$placeholder"
  "$AWS" s3 cp "$placeholder" "$destination/verdict.json" || true
  rm -f "$placeholder"
  [ ! -f /tmp/box-build.log ] || "$AWS" s3 cp /tmp/box-build.log "$destination/box-build.log" || true
}
trap bootstrap_failure EXIT

# 2. Toolchain + build strands-box (reuse if the deterministic stage already built it).
if [ ! -x "$SRC/target/release/strands-box" ]; then
  if [ "$PLATFORM" = "linux" ]; then
    sudo dnf groupinstall -y "Development Tools" >/tmp/toolchain.log 2>&1 || true
    sudo dnf install -y --allowerasing openssl-devel pkg-config git curl python3 nodejs20 npm >>/tmp/toolchain.log 2>&1 || true
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || log "rustup install FAILED"
  fi
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env" 2>/dev/null || true
  ( cd "$SRC" && cargo build -p strands-box -p strands-box-containment --release ) \
    >/tmp/box-build.log 2>&1 || log "box build FAILED (see /tmp/box-build.log)"
else
  log "strands-box already built — reusing"
fi
# Build the harness from the source under test, including when the box is reused.
VERDICT_BIN="$HARNESS_ROOT/verdict/target/release"
if [ -d "$HARNESS_ROOT/verdict" ]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env" 2>/dev/null || true
  ( cd "$HARNESS_ROOT/verdict" && cargo build --locked --release --all-features --bin workload-oracle ) \
    >>/tmp/box-build.log 2>&1 || { log "workload-oracle build FAILED (see /tmp/box-build.log)"; exit 1; }
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env" 2>/dev/null || true
export PATH="$SRC/target/release:$VERDICT_BIN:$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

# 3. Claude Code via the official standalone installer (cross-platform, no npm/node
#    dependency). It drops a self-contained binary at ~/.local/bin/claude on BOTH
#    macOS and Linux, so `command -v claude` resolves without a global npm prefix on
#    PATH. The prior npm-only path installed claude on Linux (node came from dnf) but
#    never on macOS (no node/npm), leaving claude unresolvable there -> the box's
#    "cannot resolve bare workload executable claude" error.
# WL_CLAUDE_VERSION names one released version, and unset installs the latest, so
# this stage measures the box against the current agent. A plain version, not a
# `latest` or `stable` keyword: it must also be a valid npm spec for the second
# route below, and npm has no `stable` tag.
WL_CLAUDE_VERSION="${WL_CLAUDE_VERSION:-}"
if ! command -v claude >/dev/null 2>&1; then
  if curl -fsSL https://claude.ai/install.sh -o /tmp/claude-install.sh 2>/tmp/claude-install.log; then
    bash /tmp/claude-install.sh ${WL_CLAUDE_VERSION:+"$WL_CLAUDE_VERSION"} >>/tmp/claude-install.log 2>&1 \
      || log "claude standalone install FAILED (see /tmp/claude-install.log)"
  else
    log "claude installer download FAILED (see /tmp/claude-install.log)"
  fi
fi
# Fallback: if the standalone installer didn't land claude but npm is present (Linux).
if ! command -v claude >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  npm install -g "@anthropic-ai/claude-code${WL_CLAUDE_VERSION:+@$WL_CLAUDE_VERSION}" >>/tmp/claude-install.log 2>&1 \
    || log "claude npm fallback FAILED"
fi

# 4. The Rust harness owns setup, observation, execution, validity, and upload.
export INDET_SRC="$SRC"
exec workload-oracle jailbreak run --case "$CASE" --platform "$PLATFORM" \
  --box-commit "$EFFECTIVE_COMMIT" --run-id "$RUN_ID"
