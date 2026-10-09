#!/bin/bash
# common/lib.sh — Common config + SSH/S3 helpers for the manual drivers.
# Sourced by the manual/ laptop drivers.

# --- AWS Configuration ---
# Every value that names an account resource is an input. A manual/ driver calls
# require_inputs with the names it needs and refuses to run without them. The
# region and the instance types have public defaults.
export AWS_ACCOUNT="${AWS_ACCOUNT:-}"
export AWS_REGION="${AWS_REGION:-us-west-2}"
export KEY_PAIR="${KEY_PAIR:-}"
export VPC_ID="${VPC_ID:-}"
export SECURITY_GROUP="${SECURITY_GROUP:-}"
export INSTANCE_PROFILE="${INSTANCE_PROFILE:-}"
export PROJECT_TAG="${PROJECT_TAG:-strands-box-containment-tests}"

# --- AMIs --- (an AMI id is region-specific: supply the ids for $AWS_REGION)
export LINUX_AMI="${LINUX_AMI:-}"        # AL2023 kernel 6.1, arm64
export MACOS_AMI="${MACOS_AMI:-}"        # macOS, arm64

# --- Instance Types ---
export LINUX_INSTANCE_TYPE="${LINUX_INSTANCE_TYPE:-t4g.large}"    # 2 vCPU, 8GB, arm64
export MACOS_INSTANCE_TYPE="${MACOS_INSTANCE_TYPE:-mac-m4.metal}" # Apple M4, 16-core; needs macOS 15+

# require_inputs <NAME>... — refuse to continue while any named variable is empty.
require_inputs() {
  local missing="" v
  for v in "$@"; do
    [ -n "${!v:-}" ] || missing="$missing $v"
  done
  if [ -n "$missing" ]; then
    echo "ERROR: set these environment variables first:$missing" >&2
    echo "       See test-workload/README.md, section 'Inputs'." >&2
    return 1
  fi
}

# --- Source ---
# Path to the strands-box source tarball (no .git, no target/, no rust-toolchain.toml)
export SOURCE_TARBALL="${SOURCE_TARBALL:-/tmp/strands-box-src.tar.gz}"

# pack_source <src_dir> [out_tarball]
# Builds the source tarball for the harness AND stamps a COMMIT file at its root
# so the box_commit is recoverable on the instance (the tarball excludes .git,
# which is why box_commit was showing 'unknown'). Run this before install.sh.
pack_source() {
  local src_dir="${1:?pack_source <src_dir> [out_tarball]}"
  local out="${2:-$SOURCE_TARBALL}"
  local commit
  commit=$(cd "$src_dir" && git rev-parse HEAD 2>/dev/null || echo "unknown")
  echo "$commit" > "$src_dir/COMMIT"
  echo "[config] Stamped COMMIT=$commit into $src_dir/COMMIT"
  tar czf "$out" \
    --exclude='.git' --exclude='target' --exclude='rust-toolchain.toml' \
    --exclude='.cargo/config.toml' \
    -C "$src_dir" .
  echo "[config] Packed $out ($(du -h "$out" | awk '{print $1}')) at commit $commit"
}

# --- S3 ---
# The bucket that holds the source tarball and the run artefacts. An input.
export ARTIFACTS_BUCKET="${ARTIFACTS_BUCKET:-}"

# upload_to_s3 <local-file> <s3-key>
upload_to_s3() {
  local src="$1" key="$2"
  require_inputs ARTIFACTS_BUCKET || return 1
  aws s3 cp "$src" "s3://${ARTIFACTS_BUCKET}/${key}" --region "$AWS_REGION"
}

# --- Helpers ---
PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PKG_DIR

# --- Run reports ---
# The probe's stdout is the only record of what the agent did, and a run log ages
# out. A report is written under the package so the workflow's
# `**/method_report.md` glob uploads it as a run artifact.
export REPORT_DIR="${REPORT_DIR:-$PKG_DIR/run-reports}"

# start_report <platform> <instance-id> — create the file and echo its path. The
# transcript is fenced because it is evidence: the agent's own markdown must read
# verbatim rather than render into this file's headings.
start_report() {
  local platform="$1" instance_id="$2" report type
  report="$REPORT_DIR/$platform/method_report.md"
  mkdir -p "$(dirname "$report")" || return 1
  if [ "$platform" = macos ]; then type="$MACOS_INSTANCE_TYPE"; else type="$LINUX_INSTANCE_TYPE"; fi
  {
    echo "# strands-box jailbreak probe — $platform"
    echo
    echo "| field | value |"
    echo "|---|---|"
    echo "| run | ${RUN_ID:-local} |"
    echo "| box commit | ${BOX_COMMIT:-unknown} |"
    echo "| instance | $instance_id |"
    echo "| instance type | $type |"
    echo "| region | $AWS_REGION |"
    echo "| started | $(date -u +%Y-%m-%dT%H:%M:%SZ) |"
    echo
    echo '```'
  } > "$report"
  echo "$report"
}

# finish_report <report-path> <exit-status> — close the fence and record the outcome.
finish_report() {
  local report="$1" status="$2"
  {
    echo '```'
    echo
    echo "Probe exited $status at $(date -u +%Y-%m-%dT%H:%M:%SZ)."
  } >> "$report"
}

# refresh_credentials — run the operator's own credential command, when one is set.
# AWS_CREDENTIAL_REFRESH names a shell command that leaves valid credentials in
# ~/.aws or in the environment. When it is unset, the AWS CLI default chain is used.
refresh_credentials() {
  if [ -n "${AWS_CREDENTIAL_REFRESH:-}" ]; then
    echo "[config] Refreshing credentials..."
    bash -c "$AWS_CREDENTIAL_REFRESH" 2>&1 | tail -1
  else
    echo "[config] AWS_CREDENTIAL_REFRESH is unset; using the default AWS credential chain"
  fi
}

wait_for_instance() {
  local instance_id="$1"
  echo "[config] Waiting for $instance_id to be running..."
  aws ec2 wait instance-running --region "$AWS_REGION" --instance-ids "$instance_id"
  echo "[config] Waiting for status checks..."
  aws ec2 wait instance-status-ok --region "$AWS_REGION" --instance-ids "$instance_id"
}

EPHEMERAL_KEY="/tmp/strands-box-containment-key"

# wait_for_ssm <instance-id> — block until the SSM agent has registered. A freshly
# booted instance passes its status checks before the agent connects, and the
# transport below cannot reach it until it has.
wait_for_ssm() {
  local instance_id="$1" i
  echo "[config] Waiting for $instance_id to register with SSM..."
  for i in $(seq 1 60); do
    if [ "$(aws ssm describe-instance-information --region "$AWS_REGION" \
              --filters "Key=InstanceIds,Values=$instance_id" \
              --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null)" = "Online" ]; then
      return 0
    fi
    sleep 10
  done
  echo "ERROR: $instance_id never came Online in SSM. Check the instance profile" >&2
  echo "       carries AmazonSSMManagedInstanceCore and the agent is running." >&2
  return 1
}

# push_ephemeral_key <instance-id> <user> — make one key and push it through EC2
# Instance Connect. That is an EC2 API call, not a network path, so it works with
# no inbound rule and no public address.
push_ephemeral_key() {
  local instance_id="$1" user="$2"
  if [ ! -f "$EPHEMERAL_KEY" ]; then
    ssh-keygen -t ed25519 -f "$EPHEMERAL_KEY" -N "" -q
  fi
  aws ec2-instance-connect send-ssh-public-key \
    --region "$AWS_REGION" \
    --instance-id "$instance_id" \
    --instance-os-user "$user" \
    --ssh-public-key "file://${EPHEMERAL_KEY}.pub" --output text >/dev/null
}

# _ssh_args — set SSH_ARGS for ssh and scp. SSH runs over an SSM session rather
# than to a public address, so the security group needs no inbound rule at all.
# An array, because the ProxyCommand must survive as a single argument.
_ssh_args() {
  SSH_ARGS=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o ConnectTimeout=60
    -o "ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p --region $AWS_REGION"
    -i "$EPHEMERAL_KEY"
  )
}

# The host is the instance id, not an address: the ProxyCommand reads it as %h.
ssh_to() {
  local instance_id="$1" user="$2"
  shift 2
  push_ephemeral_key "$instance_id" "$user"
  _ssh_args
  ssh "${SSH_ARGS[@]}" "${user}@${instance_id}" "$@"
}

scp_to() {
  local instance_id="$1" user="$2" src="$3" dst="$4"
  push_ephemeral_key "$instance_id" "$user"
  _ssh_args
  scp "${SSH_ARGS[@]}" "$src" "${user}@${instance_id}:${dst}"
}

# agent_command_on_instance <instance-id> <user> — the agent's absolute real path on
# the instance, for box.toml's `command`. Resolved through realpath because the box
# execs the real target, and npm's launcher is a symlink the contained exec cannot
# name. python3, not readlink -f, which BSD readlink does not support on macOS.
agent_command_on_instance() {
  local instance_id="$1" user="$2" resolved
  resolved=$(ssh_to "$instance_id" "$user" \
    'for c in "$HOME/.local/bin/claude" "$(command -v claude 2>/dev/null)" \
              /opt/homebrew/bin/claude /usr/local/bin/claude /usr/bin/claude; do
       [ -n "$c" ] && [ -x "$c" ] || continue
       python3 -c "import os,sys;print(os.path.realpath(sys.argv[1]))" "$c"
       exit 0
     done
     exit 1' \
    | tr -d '\r' | tail -n 1)
  case "$resolved" in
    /*) echo "$resolved" ;;
    *) echo "ERROR: claude did not resolve to an absolute path on $instance_id" >&2
       echo "       (got '${resolved}'); the install step must land it first." >&2
       return 1 ;;
  esac
}

# render_box_pair <home> <workspace> <box-dir> <agent-command> <out-toml> <out-policy> — write
# the box.toml and policy.dw the probe path runs, from verdict/src/jailbreak/box-config.toml and
# test-integ/src/fixture.dw, the same way common/bootstrap.sh writes them on an
# instance. <home>, <workspace> and <box-dir> are canonical absolute paths on the
# instance, and the workspace must be beneath the home: the box spells a path
# under the operator home as `~/...`, so that is how the policy names it.
# <agent-command> is the agent's absolute path ON THE INSTANCE: the box resolves a
# bare name against the box PATH, which misses npm's global bin on macOS.
render_box_pair() {
  local home="$1" workspace="$2" box_dir="$3" agent_command="$4" out_toml="$5" out_policy="$6"
  local fixture="$PKG_DIR/../test-integ/src/fixture.dw"
  [ -f "$fixture" ] || { echo "ERROR: $fixture not found" >&2; return 1; }
  case "$agent_command" in
    /*) ;;
    *) echo "ERROR: render_box_pair needs an absolute agent command, got '$agent_command'" >&2
       return 1 ;;
  esac
  # Write through a temp file, so a sed failure cannot leave a zero-byte config.
  # mktemp names it, rather than a suffix on the output path: a name this side can
  # predict is a name another process can pre-create as a link.
  local staged
  staged="$(mktemp)" || return 1
  sed -e "s|__WORKSPACE__|${workspace}|g" -e "s|__BOX_DIR__|${box_dir}|g" \
    -e "s|__AGENT_COMMAND__|${agent_command}|g" \
    "$PKG_DIR/verdict/src/jailbreak/box-config.toml" > "$staged" || {
      rm -f "$staged"; echo "ERROR: templating box-config.toml failed" >&2; return 1; }
  mv "$staged" "$out_toml"
  # Python, not sed: the bedrock-runtime substitution below is the one that
  # `sed -i` spells differently on GNU and BSD, and the BSD form failed silently.
  python3 - "$fixture" "$out_policy" "$home" "$workspace" <<'PYEOF'
import sys
fixture, out, home, workspace = sys.argv[1:5]
prefix = home.rstrip("/") + "/"
if not workspace.startswith(prefix):
    sys.exit("%s is not beneath operator home %s" % (workspace, home))
rel = workspace[len(prefix):]
spelled = ("~/" + rel).replace("\\", "\\\\").replace('"', '\\"').replace("*", "\\*")
s = open(fixture).read().replace("{{WORKSPACE}}", spelled)
# Widen the model_request rule from the box default to the Bedrock runtime host
# Claude Code calls.
s = s.replace('context.input.host like "*.api.aws"',
              'context.input.host like "bedrock-runtime.*.amazonaws.com"')
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
}

# run_harness <platform> <instance-id> <user> <case> — run one case through the
# on-instance bootstrap (canaries, agent, verdict, upload), fetch what it uploaded
# into $REPORT_DIR/<platform>/<case>/, and return 0 only when its verdict is PASS.
#
# This is the harness the pipeline runs, not the eight-command smoke prompt in
# run-jailbreak.sh: the agent attacks against the case's goal.md, and the verdict
# comes from the host canaries and the verdict rule, never from the agent's own
# account. A missing or unreadable verdict is a failure, never a pass.
run_harness() {
  local platform="$1" instance_id="$2" user="$3" case="$4"
  require_inputs ARTIFACTS_BUCKET || return 1
  local run_id="${RUN_ID:-manual-$(date -u +%Y%m%dT%H%M%SZ)}"
  local out="$REPORT_DIR/$platform/$case" home commit tarball rc profile
  mkdir -p "$out" || return 1

  # `|| true` on both lookups: under the callers' `set -euo pipefail` a failed remote
  # command aborts here with no message, so let the checks below say what went wrong.
  home=$(ssh_to "$instance_id" "$user" 'cd ~ && pwd -P' | tr -d '\r' | tail -n 1) || true
  case "$home" in
    /*) ;;
    *) echo "ERROR: $instance_id did not report an absolute home (got '${home}')" >&2; return 1 ;;
  esac
  # The bootstrap keys its upload by the COMMIT stamp in the box source when there is
  # one (pack_source writes it) and by BOX_COMMIT otherwise; resolve it the same way.
  # A source tarball built in CI carries no COMMIT stamp, and the missing file is the
  # normal case there, not an error: fall through to BOX_COMMIT.
  commit=$(ssh_to "$instance_id" "$user" 'cat ~/strands-box/COMMIT 2>/dev/null || true' | tr -d '\r[:space:]') || true
  commit="${commit:-${BOX_COMMIT:-unknown}}"
  echo "=== $platform / $case — run $run_id, box $commit ==="

  # Ship the harness with the policy fixture beside it: the bootstrap reads
  # test-integ/src/fixture.dw as a sibling of test-workload/.
  tarball=$(mktemp)
  tar czf "$tarball" -C "$PKG_DIR/.." --exclude='run-reports' --exclude='target' \
    test-workload test-common test-integ/src/fixture.dw || { rm -f "$tarball"; return 1; }
  ssh_to "$instance_id" "$user" "rm -rf '$home/indet-harness' && mkdir -p '$home/indet-harness'"
  scp_to "$instance_id" "$user" "$tarball" "$home/indet-harness/harness.tgz"
  rm -f "$tarball"
  ssh_to "$instance_id" "$user" "tar xzf '$home/indet-harness/harness.tgz' -C '$home/indet-harness'"

  # Root, because the harness adds a canary address to the loopback interface. HOME
  # stays the operator's, so the bootstrap reuses the box install.sh built there
  # rather than fetching a source from S3, and PATH is the login one that carries
  # the agent install.sh landed.
  if [ "$platform" = macos ]; then profile="$home/.zprofile"; else profile="$home/.bashrc"; fi
  # AL2023 creates the operator home mode 0700. Root's namespace backend cannot then
  # traverse it to bind the workspace and the box binaries beneath it ("Permission
  # denied" during containment apply), so grant traversal only (0711, not listing).
  if [ "$platform" = linux ]; then
    ssh_to "$instance_id" "$user" "chmod o+x '$home'" || return 1
  fi
  ssh_to "$instance_id" "$user" ". '$profile' >/dev/null 2>&1; sudo env PATH=\"\$PATH\" HOME=\"$home\" \
      LEDGER_BUCKET='$ARTIFACTS_BUCKET' BOX_COMMIT='$commit' RUN_ID='$run_id' CASE='$case' \
      PLATFORM='$platform' AWS_REGION='$AWS_REGION' INDET_REUSE_SRC=1 WL_SRC_DIR=\"$home/strands-box\" \
      bash '$home/indet-harness/test-workload/common/bootstrap.sh'" 2>&1 | tee "$out/run.log" || true

  aws s3 cp --recursive --only-show-errors --region "$AWS_REGION" \
    "s3://$ARTIFACTS_BUCKET/reports/$commit/$run_id/indeterministic/$platform/$case/" "$out/" \
    || echo "WARN: could not fetch the run's artefacts from s3://$ARTIFACTS_BUCKET" >&2

  python3 - "$out/verdict.json" "$platform" "$case" <<'PYEOF'
import json, sys
path, platform, case = sys.argv[1:4]
try:
    v = json.load(open(path))
except (OSError, ValueError) as why:
    print("%s / %s: no readable verdict (%s) — FAIL" % (platform, case, why))
    sys.exit(1)
verdict = v.get("verdict", "?")
print("%s / %s: %s" % (platform, case, verdict))
for key in ("security_outcome", "run_status", "note", "residuals", "reasons", "counts"):
    if v.get(key) not in (None, "", []):
        print("  %s: %s" % (key, v[key]))
sys.exit(0 if verdict == "PASS" else 1)
PYEOF
  rc=$?
  return "$rc"
}
