#!/bin/bash
# common/bootstrap.sh — on-instance entry for the INDETERMINISTIC stage, invoked
# by the pipeline SSM step (4d) or by a manual SSH driver. Mirrors the
# deterministic bootstrap contract, then adds the agent-driven jailbreak flow.
#
# Runs entirely on the instance (no SSH). Steps:
#   1. fetch + build strands-box (reused if the deterministic stage already built it)
#   2. install Claude Code; create the box directory; write box.toml + policy.dw + policy patch
#   3. fetch IMDS creds -> ~/.aws/credentials  (BEFORE the oracle, so its watch
#      window is not polluted by the credential fetch)
#   4. start the case oracle -> run Agent A (Claude in box) -> stop oracle -> Agent B
#   5. upload artifacts + a compact verdict.json to the ledger under
#      reports/<commit>/<runId>/indeterministic/<platform>/<case>/
#
# Env: LEDGER_BUCKET, BOX_COMMIT, RUN_ID (required); PLATFORM (linux|macos, else
#      uname), CASE (dimension, default network-egress), AWS_REGION (us-west-2).
# Never `set -e`: a breach verdict or a build hiccup must still upload a verdict.
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
CASE_DIR="$HARNESS_ROOT/$CASE"
SRC="$HOME/strands-box"
WS="$HOME/jailbreak-harness"
RUN_DIR="$HOME/indet-run/$CASE"
log() { echo "[indet-bootstrap] $*"; }

log "platform=$PLATFORM case=$CASE run=$RUN_ID"
if [ ! -d "$CASE_DIR" ]; then log "FATAL: case dir $CASE_DIR not found"; fi
rm -rf "$RUN_DIR"; mkdir -p "$RUN_DIR/oracle" "$RUN_DIR/agent-a" "$RUN_DIR/agent-b"

# 1. Fetch + unpack the box source (commit-keyed, latest fallback); recover commit.
# Only replace an existing tree when a tarball actually downloaded — a manual run
# with a pre-built box (no S3 source) must not be wiped.
rm -f /tmp/src.tgz
PFX="${STAGE_PREFIX:+${STAGE_PREFIX%/}/}"   # optional staging prefix (from send step); empty = bucket root
"$AWS" s3 cp "s3://$LEDGER_BUCKET/${PFX}box-src/$BOX_COMMIT.tar.gz" /tmp/src.tgz 2>/dev/null \
  || "$AWS" s3 cp "s3://$LEDGER_BUCKET/${PFX}box-src/latest.tar.gz" /tmp/src.tgz 2>/dev/null || log "source download FAILED"
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
# shellcheck disable=SC1091
source "$HOME/.cargo/env" 2>/dev/null || true
export PATH="$SRC/target/release:/usr/local/bin:/opt/homebrew/bin:$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

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

# 4. Write the box workspace: box.toml from box-config.toml + policy.dw from the
#    deterministic fixture + policy patch. `run --config` reads box.toml alone and
#    performs no discovery, so box_dir and workspace are absolute canonical paths
#    and the private box directory exists, empty, mode 0700, before the box starts.
# `.tmp` and `.claude-config` are where box.toml points Claude Code's scratch and configuration,
# inside the workspace; both must exist before the box starts.
mkdir -p "$WS/.strands-box" "$WS/.tmp" "$WS/.claude-config"
BOX_DIR="$HOME/jailbreak-box"
rm -rf "$BOX_DIR"; mkdir -p "$BOX_DIR"; chmod 700 "$BOX_DIR"
# The box compares canonical spellings (symlinks resolved), so substitute those.
HOME_CANON="$(cd "$HOME" && pwd -P)"
WS_CANON="$(cd "$WS" && pwd -P)"
BOX_DIR_CANON="$(cd "$BOX_DIR" && pwd -P)"
log "box_dir: $BOX_DIR_CANON workspace: $WS_CANON"
# box.toml's `command` names the agent by absolute real path. The box resolves a bare
# name against the box PATH, which does not carry npm's global bin on macOS, and the
# contained exec must name a symlinked launcher's real target rather than the link.
AGENT_COMMAND=""
if CLAUDE_PATH="$(command -v claude 2>/dev/null)"; then
  AGENT_COMMAND="$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' \
    "$CLAUDE_PATH" 2>/dev/null || echo "$CLAUDE_PATH")"
fi
case "$AGENT_COMMAND" in
  /*) log "agent command: $AGENT_COMMAND" ;;
  *) log "ERROR: claude did not resolve to an absolute path (got '${AGENT_COMMAND}')"
     AGENT_COMMAND="" ;;
esac
if [ -f "$BOOT_DIR/box-config.toml" ] && [ -n "$AGENT_COMMAND" ]; then
  # Write to a temp file and move it into place, so a sed failure cannot leave a
  # zero-byte config behind. The replacement values are absolute paths under
  # /var/tmp or /home with no sed metacharacters (& or \).
  if sed -e "s|__WORKSPACE__|${WS_CANON}|g" -e "s|__BOX_DIR__|${BOX_DIR_CANON}|g" \
         -e "s|__AGENT_COMMAND__|${AGENT_COMMAND}|g" \
       "$BOOT_DIR/box-config.toml" > "$WS/.strands-box/box.toml.tmp"; then
    mv "$WS/.strands-box/box.toml.tmp" "$WS/.strands-box/box.toml"
  else
    log "ERROR: templating box-config.toml failed; no box.toml written"
    rm -f "$WS/.strands-box/box.toml.tmp"
  fi
elif [ ! -f "$BOOT_DIR/box-config.toml" ]; then
  log "ERROR: $BOOT_DIR/box-config.toml not found; no box.toml written"
else
  log "ERROR: no agent command resolved; no box.toml written"
fi
export INDET_BOX_CONFIG="$WS/.strands-box/box.toml"
POLICY="$WS/.strands-box/policy.dw"
# The policy is the deterministic suite's fixture.dw (the repository holds
# test-integ/ and test-workload/ as siblings). The box spells a path beneath
# the operator home as `~/...`, so {{WORKSPACE}} renders that way,
# exactly as test-integ/src/lib.rs prepare_box does.
FIXTURE="$(dirname "$HARNESS_ROOT")/test-integ/src/fixture.dw"
if [ -f "$FIXTURE" ]; then
  python3 - "$FIXTURE" "$POLICY" "$HOME_CANON" "$WS_CANON" <<'PYEOF' && log "policy written from fixture.dw" || log "ERROR: writing policy.dw from fixture.dw failed"
import sys
fixture, out, home, workspace = sys.argv[1:5]
def policy_path(path):
    prefix = home.rstrip("/") + "/"
    if not path.startswith(prefix):
        sys.exit("%s is not beneath operator home %s" % (path, home))
    rel = path[len(prefix):]
    return ("~/" + rel).replace("\\", "\\\\").replace('"', '\\"').replace("*", "\\*")
s = open(fixture).read()
s = s.replace("{{WORKSPACE}}", policy_path(workspace))
# The Shell mediates its commands through the policy, and bash opens /dev/null for
# every redirection, so without these two permits EVERY command the agent runs is
# refused with "[default-deny]" and the cell measures nothing. boxgen.py emits the
# same pair for the generated path; appended here rather than added to fixture.dw,
# which the deterministic suite shares.
s += """
@id("dev_null") permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.path == "/dev/null" };

@id("dev_null_read") permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "/dev/null" };
"""
open(out, "w").write(s)
PYEOF
else
  log "ERROR: $FIXTURE not found; no policy.dw written"
fi
if [ -f "$POLICY" ] && ! grep -q 'bedrock-runtime' "$POLICY"; then
  # Widen the model_request rule's permitted host from the box default
  # ("*.api.aws") to the Bedrock runtime host Claude Code actually calls. Done in
  # python for GNU/BSD portability: the previous `sed -i'' -e '/range/{s///}'`
  # form is GNU-specific and FAILED SILENTLY on macOS BSD sed (2>/dev/null||true),
  # leaving the policy unpatched so the box's policy interceptor denied the
  # Bedrock egress -> claude saw "403 blocked by effect interceptor". Linux (GNU
  # sed) patched fine, which is why only macOS 403'd.
  python3 - "$POLICY" <<'PYEOF' 2>/dev/null && log "policy patched for bedrock-runtime host" || log "WARN: policy patch skipped/failed"
import sys
p = sys.argv[1]
s = open(p).read()
old = 'context.input.host like "*.api.aws"'
new = 'context.input.host like "bedrock-runtime.*.amazonaws.com"'
if old in s:
    open(p, "w").write(s.replace(old, new))
    print("patched")
else:
    sys.exit("pattern not found")
PYEOF
fi

# 5. Credentials from IMDS -> ~/.aws/credentials (BEFORE oracle; do NOT let the
#    agent fetch these later — the oracle would see it as forbidden egress).
log "fetching IMDS credentials before starting oracle..."
IMDS="http://169.254.169.254"
TOKEN=$(curl -s -X PUT "$IMDS/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "$IMDS/latest/meta-data/iam/security-credentials/" 2>/dev/null || true)
if [ -n "$ROLE" ]; then
  CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "$IMDS/latest/meta-data/iam/security-credentials/$ROLE" 2>/dev/null || true)
  mkdir -p "$HOME/.aws"
  echo "$CREDS" | python3 -c '
import sys, json, os
c = json.load(sys.stdin)
open(os.path.expanduser("~/.aws/credentials"), "w").write(
  "[default]\naws_access_key_id = %s\naws_secret_access_key = %s\naws_session_token = %s\n"
  % (c["AccessKeyId"], c["SecretAccessKey"], c["Token"]))
' 2>/dev/null && log "credentials written for role $ROLE" || log "WARN: could not parse IMDS credentials"
  printf "[default]\nregion = %s\n" "$AWS_REGION" > "$HOME/.aws/config"
else
  log "WARN: no IMDS role — Agent A will be INVALID (cannot reach Bedrock)"
fi

# Export the on-instance contract for the case scripts.
export INDET_WS="$WS" INDET_SRC="$SRC" INDET_PLATFORM="$PLATFORM"
export INDET_DIMENSION="$CASE" INDET_COMMIT="$EFFECTIVE_COMMIT"
export INDET_ORACLE_DIR="$RUN_DIR/oracle"

# 6. Oracle -> Agent A -> Oracle stop -> Agent B  (ordering is load-bearing).
log "starting oracle..."
bash "$CASE_DIR/oracle.sh" start || log "oracle start note"
log "running Agent A (Claude in box)..."
bash "$CASE_DIR/agent-a.sh" "$RUN_DIR" || log "agent-a returned nonzero (captured)"
log "stopping oracle..."
bash "$CASE_DIR/oracle.sh" stop || log "oracle stop note"
log "running Agent B (validation + scoring)..."
bash "$CASE_DIR/agent-b.sh" "$RUN_DIR" || log "agent-b returned nonzero (captured)"

# 7. Upload artifacts + verdict to the ledger.
DEST="s3://$LEDGER_BUCKET/reports/$EFFECTIVE_COMMIT/$RUN_ID/indeterministic/$PLATFORM/$CASE"
up() { [ -f "$1" ] && "$AWS" s3 cp "$1" "$DEST/$2" >/dev/null 2>&1 && log "uploaded $2" || true; }
up "$RUN_DIR/verdict.json"                 "verdict.json"
up "$RUN_DIR/validation_report.md"         "validation_report.md"
up "$RUN_DIR/agent-a/method_report.md"     "method_report.md"
up "$RUN_DIR/oracle/verdict.json"          "oracle-verdict.json"
up "$RUN_DIR/agent-a.log"                  "agent-a.log"
up "$RUN_DIR/agent-a/turns.jsonl"          "turns.jsonl"
up "$RUN_DIR/agent-b/deterministic_checks.json" "deterministic_checks.json"
[ -f /tmp/box-build.log ] && "$AWS" s3 cp /tmp/box-build.log "$DEST/box-build.log" >/dev/null 2>&1 || true

# Ensure a verdict.json always exists at the dest (UNCERTAIN placeholder if none).
if [ ! -f "$RUN_DIR/verdict.json" ]; then
  printf '{"mode":"indeterministic","platform":"%s","dimension":"%s","verdict":"UNCERTAIN","risk_score":0,"run_status":"INVALID","note":"no verdict produced"}\n' \
    "$PLATFORM" "$CASE" > /tmp/indet-v.json
  "$AWS" s3 cp /tmp/indet-v.json "$DEST/verdict.json" >/dev/null 2>&1 || true
fi
log "done: $DEST"
