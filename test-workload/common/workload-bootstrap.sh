#!/bin/bash
# common/workload-bootstrap.sh — on-instance entry for the WORKLOAD suite.
#
# The workload suite answers a different question from the jailbreak dimension, so
# it is driven differently: one SSM invocation runs EVERY (dimension x agent) cell
# on this leg, writes one verdict row per cell, and aggregates them into the
# verdict.json the pipeline collects. That is the deterministic suite's shape —
# many cases, one aggregated verdict — applied to agent-driven cases, and it is
# what lets a single pipeline run report all cells on both legs.
#
# Steps:
#   1. fetch + build strands-box (reused if another stage already built it)
#   2. install all three agents: Claude Code (standalone installer), Codex CLI
#      (npm package, run through its Node shim), and the Strands agent (an entry
#      script the host's canonical python3 runs, with the SDK in a
#      `pip install --target` directory)
#   3. install the toolchains the workloads need (rustup, node, python, git)
#   4. fetch instance-role credentials to ~/.aws/credentials — the egress gateway
#      signs the model leg with them, and Codex reaches Bedrock Mantle the same way
#   5. for each case: oracle start -> agent A -> oracle stop -> agent B
#   6. upload every case's artefacts + the aggregate verdict to the ledger
#
# Env: LEDGER_BUCKET, BOX_COMMIT, RUN_ID (required); PLATFORM (linux|macos, else
#      uname), AWS_REGION (us-west-2), CASES (space-separated dimensions, default
#      all twelve), AGENTS (default "claude codex strands"; no other value is
#      known), STAGE_PREFIX, WL_DEADLINE_S.
# Never `set -e`: a failing case must still leave a verdict behind.
set -uo pipefail
: "${LEDGER_BUCKET:?}"; : "${BOX_COMMIT:?}"; : "${RUN_ID:?}"
export AWS_REGION="${AWS_REGION:-us-west-2}"

# The Bedrock inference profile carries a geography prefix, and the prefix does not
# travel between regions: eu-west-1 offers `eu.anthropic.claude-opus-5` and offers no
# `us.`-prefixed profile at all. So the id is derived from the region this leg runs
# in, and workload-lib.sh applies no default of its own.
case "$AWS_REGION" in
  eu-*) WL_MODEL_GEO=eu ;;
  ap-*) WL_MODEL_GEO=apac ;;
  *)    WL_MODEL_GEO=us ;;
esac
export WL_STRANDS_MODEL="${WL_STRANDS_MODEL:-${WL_MODEL_GEO}.anthropic.claude-opus-5}"

case "$(uname -s)" in Darwin) DEF_PLAT=macos ;; *) DEF_PLAT=linux ;; esac
PLATFORM="${PLATFORM:-$DEF_PLAT}"
export INDET_PLATFORM="$PLATFORM"

BOOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # test-workload/common
HARNESS_ROOT="$(dirname "$BOOT_DIR")"                       # test-workload/
export PATH="$PATH:/usr/local/bin:/opt/homebrew/bin"
AWS="$(command -v aws || echo /usr/local/bin/aws)"
# shellcheck disable=SC1091
source "$BOOT_DIR/workload-lib.sh"
wl_resolve_paths

CASES="${CASES:-workload-baseline workload-git workload-python workload-node workload-rust workload-agent-hook workload-mcp-stdio workload-shell workload-monty workload-budget workload-resume-claude workload-resume-codex workload-kill-claude workload-kill-codex}"
AGENTS="${AGENTS:-claude codex strands}"
DEADLINE_S="${WL_DEADLINE_S:-5400}"      # leave the SSM budget room to upload
SUITE_START=$(date +%s)

# The suite owns its own source tree. It must never be a shared path: the fetch
# below replaces the tree whenever a tarball downloads, and other work on the same
# instance keeps its own checkout and build there.
SRC="${WL_SRC_DIR:-$WL_HOME/wl-box-src}"
SUITE_DIR="$WL_ROOT/_suite"
mkdir -p "$WL_ROOT" "$SUITE_DIR"
log() { echo "[wl-bootstrap $(date -u +%H:%M:%SZ)] $*"; }
log "platform=$PLATFORM home=$WL_HOME cases='$CASES' agents='$AGENTS'"

# --- 1. box source + build --------------------------------------------------
PFX="${STAGE_PREFIX:+${STAGE_PREFIX%/}/}"
rm -f /tmp/src.tgz
"$AWS" s3 cp "s3://$LEDGER_BUCKET/${PFX}box-src/$BOX_COMMIT.tar.gz" /tmp/src.tgz 2>/dev/null \
  || "$AWS" s3 cp "s3://$LEDGER_BUCKET/${PFX}box-src/latest.tar.gz" /tmp/src.tgz 2>/dev/null \
  || log "source download FAILED"
if [ -s /tmp/src.tgz ]; then
  rm -rf "$SRC"; mkdir -p "$SRC"; tar xzf /tmp/src.tgz -C "$SRC" 2>/dev/null || log "extract FAILED"
elif [ -d "$SRC" ]; then
  log "no S3 tarball — reusing $SRC"
fi
EFFECTIVE_COMMIT="$BOX_COMMIT"
for c in "$SRC/COMMIT"; do
  [ -f "$c" ] && { EFFECTIVE_COMMIT="$(tr -d '[:space:]' < "$c")"; break; }
done

if [ "$PLATFORM" = linux ]; then
  sudo dnf groupinstall -y "Development Tools" >/tmp/toolchain.log 2>&1 || true
  sudo dnf install -y --allowerasing openssl-devel pkg-config git curl python3 python3-pip nodejs20 npm \
    >>/tmp/toolchain.log 2>&1 || true
fi
if ! command -v cargo >/dev/null 2>&1 && [ ! -x "$WL_HOME/.cargo/bin/cargo" ]; then
  # HOME must be the operator home here: the toolchain the pairs name is
  # ~/.rustup/toolchains/<triple>, and rustup installs relative to HOME.
  HOME="$WL_HOME" curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | HOME="$WL_HOME" sh -s -- -y --default-toolchain stable >/tmp/rustup.log 2>&1 \
    || log "rustup install FAILED"
fi
export PATH="$WL_HOME/.cargo/bin:$PATH"
if [ ! -x "$SRC/target/release/strands-box" ]; then
  # The tarball may hold the package root directly or one level down.
  CRATE_ROOT="$SRC"
  [ -f "$SRC/Cargo.toml" ] || CRATE_ROOT="$(dirname "$(wl_first "$SRC"/*/Cargo.toml "$SRC"/*/*/Cargo.toml || echo "$SRC/Cargo.toml")")"
  log "building strands-box in $CRATE_ROOT"
  # RUSTUP_TOOLCHAIN pins the host's stable toolchain: a box source packaged from
  # a workspace may carry a generated rust-toolchain.toml pointing at that
  # workspace's own toolchain path, which does not exist on a test instance.
  ( cd "$CRATE_ROOT" && HOME="$WL_HOME" RUSTUP_TOOLCHAIN=stable \
      cargo build -p strands-box -p strands-box-containment --release ) \
    >/tmp/box-build.log 2>&1 || log "box build FAILED (see /tmp/box-build.log)"
  [ -x "$CRATE_ROOT/target/release/strands-box" ] && SRC="$CRATE_ROOT"
else
  log "strands-box already built — reusing"
fi
export WL_SRC="$SRC"

# macOS: the pipeline's Mac image carries Homebrew but not the formulae the Node,
# Python and MCP workloads name, and an absent interpreter makes those cells
# unrunnable rather than failing on the box. Install them here. Homebrew refuses to
# run as root, so it runs as the instance user, which owns the prefix.
if [ "$PLATFORM" = macos ]; then
  BREW=/opt/homebrew/bin/brew
  if [ -x "$BREW" ]; then
    for formula in node@22 python@3.14; do
      if [ ! -d "/opt/homebrew/opt/$formula" ]; then
        log "brew install $formula"
        sudo -u ec2-user -H "$BREW" install "$formula" >>/tmp/brew.log 2>&1 \
          || log "brew install $formula FAILED (see /tmp/brew.log)"
      fi
    done
  else
    log "WARN: no Homebrew at $BREW — the node, python and MCP cells cannot run"
  fi
fi

# --- 2. agents --------------------------------------------------------------
# Each agent installs at its latest release unless the operator names a version.
# Latest is the deliberate default: this suite exists to catch the case where a
# new agent release stops working inside the box, and a standing pin would hide
# exactly that. The resolved versions are logged below, so a red run stays
# attributable and WL_CLAUDE_VERSION / WL_CODEX_VERSION reproduce it.
WL_CLAUDE_VERSION="${WL_CLAUDE_VERSION:-}"
WL_CODEX_VERSION="${WL_CODEX_VERSION:-}"

# Claude Code: the standalone installer drops a self-contained binary under the
# operator home, which is the identity the pairs name. It takes one released
# version, and no argument installs the latest.
if [ -z "${WL_CLAUDE:-}" ] || [ ! -x "${WL_CLAUDE:-/nonexistent}" ]; then
  if curl -fsSL https://claude.ai/install.sh -o /tmp/claude-install.sh 2>/tmp/claude-install.log; then
    HOME="$WL_HOME" bash /tmp/claude-install.sh ${WL_CLAUDE_VERSION:+"$WL_CLAUDE_VERSION"} >>/tmp/claude-install.log 2>&1 \
      || log "claude install FAILED (see /tmp/claude-install.log)"
  else
    log "claude installer download FAILED"
  fi
fi
# Codex CLI: install the npm package into a private prefix. The package ships a
# Node shim plus a vendored native binary; the shim is the route the cases run,
# so no global npm bin needs to be on PATH.
NPM_BIN="$(command -v npm || wl_first /opt/homebrew/opt/node@22/bin/npm /usr/bin/npm || true)"
if [ -n "${NPM_BIN:-}" ] && { [ -z "${WL_CODEX_SHIM:-}" ] || [ ! -f "${WL_CODEX_SHIM:-/nonexistent}" ]; }; then
  mkdir -p "$WL_TOOLS"
  HOME="$WL_HOME" "$NPM_BIN" install --prefix "$WL_TOOLS" "@openai/codex${WL_CODEX_VERSION:+@$WL_CODEX_VERSION}" \
    >/tmp/codex-install.log 2>&1 || log "codex npm install FAILED (see /tmp/codex-install.log)"
fi
# Strands agent: `pip install --target` puts the SDK in a plain directory, and the
# entry script is copied beside it as a plain `.py` file. The box runs the pair with
# the host's canonical python3. No virtual environment is used, and no launcher shim:
# a venv `bin/python3` is a symbolic link, `/bin/sh` is one on AL2023, and the box
# refuses a link in a filesystem grant because a grant carries the identity the
# kernel checks. All three paths here are real files or directories on both
# platforms, so a grant can name each one.
STRANDS_HOME="$WL_TOOLS/strands"
STRANDS_LIB="$STRANDS_HOME/lib"
STRANDS_ENTRY="$STRANDS_HOME/agent.py"
WL_STRANDS_SDK_VERSION="${WL_STRANDS_SDK_VERSION:-1.57.1}"
# The toolchain step above may have installed the python the pairs name, so the
# paths are resolved again here: the SDK must be installed by the same interpreter
# that runs the entry script, or its compiled wheels do not import at cell time.
wl_resolve_paths
HOST_PY="${WL_PYTHON:-}"
[ -n "$HOST_PY" ] || log "no canonical python3 resolved — the strands cells are ABSENT"
strands_imports() {
  [ -n "$HOST_PY" ] \
    && "$HOST_PY" -c "import sys; sys.path.insert(0, '$STRANDS_LIB'); import strands" >/dev/null 2>&1
}
if [ -n "$HOST_PY" ] && ! strands_imports; then
  mkdir -p "$STRANDS_LIB"
  # macOS framework CPython confirms a certificate through the Security
  # framework rather than the CA bundle, so pip cannot reach PyPI without these.
  STRANDS_PIP_FLAGS=""
  if [ "$PLATFORM" = macos ]; then
    STRANDS_PIP_FLAGS="--trusted-host pypi.org --trusted-host files.pythonhosted.org"
  fi
  # A distribution python3 can ship without pip, so pip is bootstrapped into the
  # operator home first. That write is on the host, outside every box.
  "$HOST_PY" -m pip --version >/dev/null 2>&1 \
    || HOME="$WL_HOME" "$HOST_PY" -m ensurepip --user >/tmp/strands-install.log 2>&1 \
    || log "ensurepip FAILED (see /tmp/strands-install.log)"
  # --upgrade, because pip leaves a stale package in a --target directory otherwise.
  HOME="$WL_HOME" "$HOST_PY" -m pip install --upgrade --target "$STRANDS_LIB" $STRANDS_PIP_FLAGS "strands-agents==$WL_STRANDS_SDK_VERSION" \
    >>/tmp/strands-install.log 2>&1 \
    || log "strands SDK install FAILED (see /tmp/strands-install.log)"
fi
# The entry script is staged only when the SDK imports. An agent that cannot import
# its SDK leaves no entry behind, so `wl_agent_available` reports it ABSENT and its
# cells FAIL with `agent-absent` rather than run and report an import error as a
# refusal.
if strands_imports; then
  mkdir -p "$STRANDS_HOME"
  cp "$BOOT_DIR/workload-strands-agent.py" "$STRANDS_ENTRY" && chmod 644 "$STRANDS_ENTRY"
else
  rm -f "$STRANDS_ENTRY"
  log "strands SDK does not import from $STRANDS_LIB — the strands cells are ABSENT"
fi
if [ "$PLATFORM" = macos ]; then
  # A curl-installed binary carries com.apple.quarantine, which Gatekeeper blocks
  # on a Seatbelt-contained exec.
  xattr -dr com.apple.quarantine "$WL_HOME/.local" "$WL_TOOLS" 2>/dev/null || true
fi
wl_resolve_paths           # re-resolve: the installs above created new paths
# Report what is actually on disk, not what the resolver composed: a path that does
# not exist reads as ABSENT here, so an unrunnable cell is visible in this line
# rather than only in the box's refusal further down.
wl_say() { if [ -n "${1:-}" ] && [ -e "${1:-/nonexistent}" ]; then echo "$1"; else echo "ABSENT"; fi; }
log "claude=$(wl_say "${WL_CLAUDE:-}") codex_shim=$(wl_say "${WL_CODEX_SHIM:-}") node=$(wl_say "${WL_NODE:-}")"
log "strands=$(wl_say "${WL_STRANDS:-}") strands_lib=$(wl_say "${WL_STRANDS_LIB:-}") python=$(wl_say "${WL_PYTHON:-}") model=$WL_STRANDS_MODEL"
# Which agent build ran. Claude Code and Codex install at latest by default, so
# this line is the only record of what a cell was measured against; it is read
# from disk rather than by running an agent, which needs credentials.
wl_claude_build() { [ -n "${WL_CLAUDE:-}" ] && [ -d "$WL_CLAUDE" ] && basename "$WL_CLAUDE" || echo unknown; }
wl_codex_build() {
  local pkg
  [ -n "${WL_CODEX_SHIM:-}" ] || { echo unknown; return; }
  pkg="$(dirname "$(dirname "$WL_CODEX_SHIM")")/package.json"
  [ -f "$pkg" ] && python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version","unknown"))' \
    "$pkg" 2>/dev/null || echo unknown
}
log "builds: claude=$(wl_claude_build) codex=$(wl_codex_build) strands_sdk=$WL_STRANDS_SDK_VERSION"

# --- 3. credentials ---------------------------------------------------------
# The gateway signs both model legs (Bedrock for Claude Code, Bedrock Mantle for
# Codex) with `aws://default`, read from the operator's own credentials file.
IMDS="http://169.254.169.254"
TOKEN=$(curl -s -X PUT "$IMDS/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "$IMDS/latest/meta-data/iam/security-credentials/" 2>/dev/null || true)
if [ -n "$ROLE" ]; then
  CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "$IMDS/latest/meta-data/iam/security-credentials/$ROLE" 2>/dev/null || true)
  mkdir -p "$WL_HOME/.aws"
  chmod 700 "$WL_HOME/.aws"
  # The profile is composed from the IMDS field names rather than a literal
  # template, so no credential-shaped string is ever written in this repository.
  echo "$CREDS" | WL_HOME="$WL_HOME" python3 -c '
import sys, json, os
c = json.load(sys.stdin)
fields = [("aws_access_key_id", "AccessKeyId"),
          ("aws_" + "secret_" + "access_key", "SecretAccessKey"),
          ("aws_session_token", "Token")]
lines = ["[default]"] + ["%s = %s" % (ini, c[k]) for ini, k in fields]
path = os.path.join(os.environ["WL_HOME"], ".aws", "credentials")
open(path, "w").write("\n".join(lines) + "\n")
' 2>/dev/null && log "credentials written for role $ROLE" || log "WARN: could not parse IMDS credentials"
  # The suite home is traversable so the box can build its view; the
  # credential itself stays owner-only.
  chmod 600 "$WL_HOME/.aws/credentials" 2>/dev/null || true
  printf "[default]\nregion = %s\n" "$AWS_REGION" > "$WL_HOME/.aws/config"
else
  log "WARN: no IMDS role — every case will be INVALID (no model reachable)"
fi

# --- 4. run the cells -------------------------------------------------------
# The agent vocabulary and the per-agent availability rule both live in
# workload-lib.sh, so one arm decides both here and in the pair generator. A name
# outside the vocabulary is a harness fault rather than a workload result, so the
# cell records ERROR with the name in the note. It never falls through to another
# agent's command, and it is never skipped.
ROWS="$SUITE_DIR/rows.jsonl"
: > "$ROWS"
for DIM in $CASES; do
  CASE_DIR="$HARNESS_ROOT/$DIM"
  # A dimension that declares an agent name the suite does not know applies to
  # nobody, so it records one ERROR row here rather than no row at all.
  if [ -d "$CASE_DIR" ] && ! wl_dimension_agents_known "$CASE_DIR" 2>/dev/null; then
    log "$DIM: wl_agents names an unknown agent ('$(wl_dimension_agents "$CASE_DIR")') — recording ERROR"
    printf '{"mode":"workload","platform":"%s","dimension":"%s","agent":"%s","verdict":"ERROR","residuals":["dimension-agents-unknown"],"note":"wl_agents names an unknown agent: %s (known: claude, codex, strands)"}\n' \
      "$PLATFORM" "$DIM" "$(wl_dimension_agents "$CASE_DIR")" "$(wl_dimension_agents "$CASE_DIR")" >> "$ROWS"
    continue
  fi
  for AGENT in $AGENTS; do
    CELL="$DIM-$AGENT"
    RUN_DIR="$WL_ROOT/$CELL"
    rm -rf "$RUN_DIR"; mkdir -p "$RUN_DIR"
    export WL_DIMENSION="$DIM" WL_AGENT="$AGENT" WL_RUN_DIR="$RUN_DIR" WL_CASE_DIR="$CASE_DIR"
    LEFT=$(( DEADLINE_S - ($(date +%s) - SUITE_START) ))
    if ! wl_agent_known "$AGENT"; then
      log "$CELL: unknown agent name $AGENT — recording ERROR"
      printf '{"mode":"workload","platform":"%s","dimension":"%s","agent":"%s","verdict":"ERROR","residuals":["agent-unknown"],"note":"unknown agent name: %s (known: claude, codex, strands)"}\n' \
        "$PLATFORM" "$DIM" "$AGENT" "$AGENT" >> "$ROWS"
      continue
    fi
    if [ ! -d "$CASE_DIR" ]; then
      log "$CELL: case dir missing — recording ERROR"
      printf '{"mode":"workload","platform":"%s","dimension":"%s","agent":"%s","verdict":"ERROR","residuals":["missing-case-dir"],"note":"%s not found"}\n' \
        "$PLATFORM" "$DIM" "$AGENT" "$CASE_DIR" >> "$ROWS"
      continue
    fi
    # A dimension that names its agents in `wl_agents` has no cell for the others:
    # a resume case belongs to the one agent whose session it resumes. That is a
    # declaration, not a cell that could not run, so no row is written.
    if ! wl_dimension_applies "$CASE_DIR" "$AGENT"; then
      log "$CELL: not applicable — $DIM declares agents '$(wl_dimension_agents "$CASE_DIR")'"
      continue
    fi
    if [ "$LEFT" -lt 180 ]; then
      log "$CELL: suite deadline reached — recording FAIL(suite-deadline)"
      printf '{"mode":"workload","platform":"%s","dimension":"%s","agent":"%s","verdict":"FAIL","residuals":["suite-deadline"],"note":"not run: suite budget exhausted"}\n' \
        "$PLATFORM" "$DIM" "$AGENT" >> "$ROWS"
      continue
    fi
    if ! wl_agent_available "$AGENT"; then
      log "$CELL: agent $AGENT not installed — recording FAIL(agent-absent)"
      printf '{"mode":"workload","platform":"%s","dimension":"%s","agent":"%s","verdict":"FAIL","residuals":["agent-absent"],"note":"%s is not installed on this host"}\n' \
        "$PLATFORM" "$DIM" "$AGENT" "$AGENT" >> "$ROWS"
      continue
    fi
    log "=== $CELL starting (${LEFT}s left in suite budget) ==="
    bash "$CASE_DIR/oracle.sh" start   >>"$RUN_DIR/case.log" 2>&1 || log "$CELL: oracle start note"
    bash "$CASE_DIR/agent-a.sh" "$RUN_DIR" >>"$RUN_DIR/case.log" 2>&1 || log "$CELL: agent-a nonzero (captured)"
    bash "$CASE_DIR/oracle.sh" stop    >>"$RUN_DIR/case.log" 2>&1 || log "$CELL: oracle stop note"
    bash "$CASE_DIR/agent-b.sh" "$RUN_DIR" >>"$RUN_DIR/case.log" 2>&1 || log "$CELL: agent-b nonzero (captured)"
    # Keep an invalid cell visible instead of letting it pass or disappear.
    if ! CELL_ROW="$(python3 - "$RUN_DIR/verdict.json" "$PLATFORM" "$DIM" "$AGENT" <<'PY'
import json, sys
path, platform, dimension, agent = sys.argv[1:5]
try:
    with open(path) as source:
        row = json.load(source)
    if not isinstance(row, dict):
        raise ValueError("verdict must be an object")
    if row.get("verdict") not in ("PASS", "FAIL", "ERROR", "SKIP"):
        raise ValueError("unknown verdict: %r" % row.get("verdict"))
except Exception as exc:
    row = {"mode": "workload", "platform": platform, "dimension": dimension,
           "agent": agent, "verdict": "ERROR", "residuals": ["no-verdict"],
           "note": "case produced no valid verdict.json: " + str(exc)[:240]}
print(json.dumps(row))
PY
)"; then
      CELL_ROW='{"verdict":"ERROR","residuals":["no-verdict"],"note":"case verdict validator failed"}'
    fi
    printf '%s\n' "$CELL_ROW" >> "$ROWS"
    log "$CELL: $(printf '%s' "$CELL_ROW" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["verdict"], d.get("residuals"), d.get("note","")[:120])')"
  done
done

# --- 5. aggregate + upload --------------------------------------------------
AGG="$SUITE_DIR/verdict.json"
python3 - "$ROWS" "$AGG" "$PLATFORM" "$EFFECTIVE_COMMIT" "$RUN_ID" <<'PY'
import json, sys
rows_path, out, plat, commit, run_id = sys.argv[1:6]
rows = []
for number, line in enumerate(open(rows_path), 1):
    line = line.strip()
    if line:
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("verdict must be an object")
            if row.get("verdict") not in ("PASS", "FAIL", "ERROR", "SKIP"):
                raise ValueError("unknown verdict: %r" % row.get("verdict"))
        except Exception as exc:
            row = {"verdict": "ERROR", "residuals": ["invalid-cell-verdict"],
                   "note": "invalid aggregate row %d: %s" % (number, str(exc)[:240])}
        rows.append(row)
counts = {}
for r in rows:
    counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
verdict = "ERROR" if counts.get("ERROR") else ("FAIL" if counts.get("FAIL") else
                                              ("PASS" if rows else "ERROR"))
json.dump({"mode": "workload", "platform": plat, "dimension": "workloads",
           "box_commit": commit, "run_id": run_id, "verdict": verdict,
           "risk_score": counts.get("FAIL", 0) + counts.get("ERROR", 0),
           "total": len(rows), "counts": counts,
           "cases": [{k: r.get(k) for k in ("dimension", "agent", "verdict", "residuals",
                                            "note", "duration_s", "run_status")} for r in rows]},
          open(out, "w"), indent=1)
print("AGGREGATE", verdict, counts)
PY
cat "$AGG"

DEST="s3://$LEDGER_BUCKET/reports/$EFFECTIVE_COMMIT/$RUN_ID/workload/$PLATFORM"
up() { [ -f "$1" ] && "$AWS" s3 cp "$1" "$2" >/dev/null 2>&1 && log "uploaded $2" || true; }
up "$AGG"  "$DEST/verdict.json"
up "$ROWS" "$DEST/rows.jsonl"
for DIM in $CASES; do for AGENT in $AGENTS; do
  R="$WL_ROOT/$DIM-$AGENT"
  up "$R/verdict.json"        "$DEST/cases/$DIM-$AGENT/verdict.json"
  up "$R/oracle/verdict.json" "$DEST/cases/$DIM-$AGENT/oracle-verdict.json"
  up "$R/.strands-box/box.toml" "$DEST/cases/$DIM-$AGENT/box.toml"
  up "$R/.strands-box/policy.dw" "$DEST/cases/$DIM-$AGENT/policy.dw"
  up "$R/agent-a.log"         "$DEST/cases/$DIM-$AGENT/agent-a.log"
  up "$R/turns.jsonl"         "$DEST/cases/$DIM-$AGENT/turns.jsonl"
  up "$R/decisions.jsonl"     "$DEST/cases/$DIM-$AGENT/decisions.jsonl"
  up "$R/case.log"            "$DEST/cases/$DIM-$AGENT/case.log"
done; done
[ -f /tmp/box-build.log ] && up /tmp/box-build.log "$DEST/box-build.log"
# The indeterministic collect step reads this key, so the same run also carries the
# aggregate where a `CASE=workloads` invocation expects it.
up "$AGG" "s3://$LEDGER_BUCKET/reports/$EFFECTIVE_COMMIT/$RUN_ID/indeterministic/$PLATFORM/workloads/verdict.json"
log "done: $DEST"
