#!/bin/bash
# common/workload-lib.sh — shared engine for the WORKLOAD dimensions.
#
# A workload dimension asks a different question from network-egress: not "can a
# capable adversary escape?" but "does a real coding workload actually run to
# completion inside the box, and does the box's own journal agree?". The shape is
# the same four files per dimension (goal.md, agent-a.sh, agent-b.sh, oracle.sh)
# and the same ordering contract (oracle start -> agent A -> oracle stop -> agent
# B), so common/bootstrap.sh drives both kinds unchanged.
#
# What is dimension-specific lives in the dimension's `case.sh`, which defines
# three functions:
#   wl_manifest              — declares the tool tables, policy additions, the
#                              per-case timeout and the expected residuals
#   wl_prepare <project>     — seeds the project and any fixture the pair names
#   wl_checks <project>      — the HOST oracle's on-disk assertions
#
# Nothing here reads the agent's own claim about what it did. The verdict comes
# from wl_checks (files on disk) plus the box's decision journal.
#
# This file is sourced, not executed. It resolves the host's real paths once and
# exports them as WL_* so both the config generator and the checks name the same
# files the kernel checks.
set -uo pipefail

# --- Platform ---------------------------------------------------------------
case "$(uname -s)" in Darwin) WL_PLATFORM=macos ;; *) WL_PLATFORM=linux ;; esac
WL_PLATFORM="${WL_PLATFORM_OVERRIDE:-${INDET_PLATFORM:-$WL_PLATFORM}}"
export WL_PLATFORM

wl_log() { echo "[workload $(date -u +%H:%M:%SZ)] $*"; }

# first_existing <path>... — echo the first path that exists, else nothing.
wl_first() { for p in "$@"; do [ -e "$p" ] && { echo "$p"; return 0; }; done; return 1; }

# wl_canon <path> — canonical spelling (symlinks resolved). The box matches a
# grant and a shell:spawn permit against the canonical file, and refuses a
# symbolic link by name, so every path a generated pair names goes through here.
wl_canon() { python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1" 2>/dev/null || echo "$1"; }

# --- Agent vocabulary -------------------------------------------------------
# The agents this suite runs. Every per-agent selector matches against this list
# and refuses a name that is not on it, so an unknown agent gives a failure that
# names itself instead of another agent's host, command and grants.
WL_AGENTS="claude codex strands"
export WL_AGENTS

# wl_agent_known <agent> — true for an agent this suite knows; else refuse by name.
wl_agent_known() {
  local known
  for known in $WL_AGENTS; do
    [ "$known" = "${1:-}" ] && return 0
  done
  echo "workload-lib: unknown agent '${1:-}' (known: $WL_AGENTS)" >&2
  return 1
}

# --- Operator home ----------------------------------------------------------
# The box spells a path beneath the operator's home as `~/...`, and the operator
# home is the HOME of the strands-box process. The suite gives itself one, rather
# than borrowing the instance user's:
#   * the instance user's home is mode 0700 and owned by that user, and the
#     namespace backend cannot traverse it when it builds the mount view — the
#     bind fails with EACCES before any workload starts;
#   * a shared home is also where other work on the same instance keeps its
#     checkouts, and this suite installs toolchains and agents into its home.
# Not under /tmp: on macOS that is /private/tmp, which the box floor grants
# recursively, and a floor grant enclosing the operator home is refused.
WL_HOME_DIR="${WL_HOME_DIR:-/var/tmp/wl-home}"
wl_resolve_home() {
  mkdir -p "$WL_HOME_DIR" 2>/dev/null
  chmod 755 "$WL_HOME_DIR" 2>/dev/null
  echo "$(cd "$WL_HOME_DIR" && pwd -P)"
}

# --- Host path resolution ---------------------------------------------------
# Every WL_* below names a real file on THIS host. A pair that names a path which
# does not exist is refused at load, so an unresolved tool is reported as a case
# failure with its own id rather than becoming a mystery load error.
wl_resolve_paths() {
  WL_HOME="$(wl_resolve_home)"
  WL_ROOT="$WL_HOME/workload-cases"          # per-case projects live under here
  WL_TOOLS="$WL_HOME/wl-tools"               # codex install prefix

  # Claude Code: the standalone installer drops a version directory; name the
  # directory itself (the launcher in ~/.local/bin is a symlink the box refuses).
  WL_CLAUDE=""
  if [ -d "$WL_HOME/.local/share/claude/versions" ]; then
    WL_CLAUDE="$(ls -dt "$WL_HOME/.local/share/claude/versions"/* 2>/dev/null | head -1)"
  fi

  # Codex: the npm package ships a Node shim plus a vendored native binary. The
  # shim is the route this suite measures (see docs in the dimension goals), so
  # the agent command is `node [--jitless] <shim.js> exec`.
  WL_CODEX_SHIM="$(wl_first "$WL_TOOLS/node_modules/@openai/codex/bin/codex.js" \
                            "$WL_TOOLS/lib/node_modules/@openai/codex/bin/codex.js" || true)"
  WL_CODEX_VENDOR="$(wl_first "$WL_TOOLS/node_modules/@openai/codex-linux-arm64/vendor" \
                              "$WL_TOOLS/node_modules/@openai/codex-darwin-arm64/vendor" || true)"

  # Strands SDK agent: an entry script the box runs with the host's canonical
  # python3, plus a `pip install --target` directory that holds the SDK. Neither
  # is a symbolic link on either platform, so a grant can name all three, and no
  # virtual environment is needed (a venv `bin/python3` is a link the box refuses).
  WL_STRANDS_HOME="$WL_TOOLS/strands"
  WL_STRANDS="$(wl_first "$WL_STRANDS_HOME/agent.py" || true)"
  WL_STRANDS_LIB="$(wl_first "$WL_STRANDS_HOME/lib" || true)"

  # git: on macOS /usr/bin/git is Apple's shim; the tool is under the Command
  # Line Tools, and both it and the helper directory must be exec.
  WL_GIT=/usr/bin/git
  WL_TRUE=/usr/bin/true
  if [ "$WL_PLATFORM" = macos ]; then
    WL_CLT=/Library/Developer/CommandLineTools
    WL_GIT_EXEC="$WL_CLT/usr/bin/git"
    WL_GIT_HELPERS="$WL_CLT/usr/libexec/git-core"
    WL_SH=/bin/sh
    WL_BASH=/bin/bash
  else
    WL_CLT=""
    WL_GIT_EXEC=/usr/bin/git
    WL_GIT_HELPERS=/usr/libexec/git-core
    WL_SH=/bin/sh                 # a symlink on AL2023: never granted by name
    WL_BASH=/usr/bin/bash         # the canonical file a grant may name
  fi

  # Python: a bare `python3` is the Shell's own interpreter (Monty), which has no
  # -m, so every pair names the interpreter absolutely.
  if [ "$WL_PLATFORM" = macos ]; then
    WL_PY_KEG="$(ls -dt /opt/homebrew/Cellar/python@3.* 2>/dev/null | head -1)"
    if [ -n "${WL_PY_KEG:-}" ]; then
      WL_PY_VER="$(basename "$WL_PY_KEG" | sed 's/python@//')"
      # Canonical, not the Versions/Current spelling the glob also matches: the
      # box reports the path the kernel checks, and a permit naming the link
      # matches nothing (exit 126, default-deny).
      WL_PYTHON="$(wl_canon "$(ls -d "$WL_PY_KEG"/*/Frameworks/Python.framework/Versions/*/bin/python3.* 2>/dev/null \
                     | grep -E '/python3\.[0-9]+$' | tail -1)")"
    fi
    WL_PY_STDLIB=""
    # macOS has no /etc/ssl/cert.pem, and the runtime minimum grants /etc/ssl only
    # where it exists, so pip cannot confirm a certificate and PyPI is unreachable
    # ("problem confirming the ssl certificate: OSStatus"). Homebrew ships a bundle
    # under /opt/homebrew/etc, which the python table already reads.
    WL_CA_BUNDLE="$(wl_first /opt/homebrew/etc/ca-certificates/cert.pem \
                              /opt/homebrew/etc/openssl@3/cert.pem || true)"
  else
    WL_PYTHON="$(wl_canon "$(command -v python3 || echo /usr/bin/python3)")"
    WL_PY_VER="$(basename "$WL_PYTHON" | sed 's/python//')"
    WL_PY_STDLIB="/usr/lib/python$WL_PY_VER"
    WL_PY_STDLIB64="/usr/lib64/python$WL_PY_VER"
  fi

  # Node: the box refuses /usr/bin/node (a link) by name, so name the canonical
  # versioned binary; npm's identity is npm-cli.js inside the node tree.
  if [ "$WL_PLATFORM" = macos ]; then
    WL_BREW_READ="/opt/homebrew/Cellar /opt/homebrew/opt /opt/homebrew/etc /opt/homebrew/bin"
    # The pipeline's Mac image installs the Homebrew keg, so it wins and this
    # resolves exactly as it always has. A dev laptop often carries a version
    # manager's node instead, which suits the box just as well — its `bin/node` is
    # a real file rather than a link, and npm sits at the same relative path. Fall
    # back to it (newest first) rather than naming a keg that is not there: an
    # absent keg still `wl_canon`s to a plausible path, so without this the suite
    # reported a node it did not have and the cells failed inside the box.
    WL_NODE_KEG="$(wl_canon "$(wl_first /opt/homebrew/opt/node@22 \
      $(ls -d "$HOME"/.local/share/mise/installs/node/22.* 2>/dev/null | sort -rV) \
      $(ls -d "$HOME"/.nvm/versions/node/v22.* 2>/dev/null | sort -rV) \
      || echo /opt/homebrew/opt/node@22)")"
    WL_NODE="$WL_NODE_KEG/bin/node"
    WL_NPM_CLI="$WL_NODE_KEG/lib/node_modules/npm/bin/npm-cli.js"
    # The tree that must be readable and executable: the parent of the canonical
    # keg, which is `Cellar/node@22` for Homebrew (what this named literally
    # before) and the manager's `installs/node` otherwise.
    WL_NODE_FORMULA="$(dirname "$WL_NODE_KEG")"
    WL_NODE_TREE="$WL_NODE_FORMULA"
    WL_NODE_JITLESS=""            # macOS restricts no just-in-time compilation
    WL_SCRIPT_SHELL=/bin/bash
  else
    WL_BREW_READ=""
    WL_CA_BUNDLE=""
    WL_NODE="$(wl_canon "$(wl_first /usr/bin/node-20 /usr/bin/node || echo /usr/bin/node)")"
    WL_NODE_TREE="$(wl_first /usr/lib/nodejs20 /usr/lib/nodejs || echo /usr/lib/nodejs20)"
    WL_NPM_CLI="$WL_NODE_TREE/lib/node_modules/npm/bin/npm-cli.js"
    # F29/F64: the box refuses a memory permission change that adds execution and
    # NODE_OPTIONS is a refused name, so V8 needs the flag in `command` itself.
    WL_NODE_JITLESS="--jitless"
    WL_SCRIPT_SHELL="$WL_BASH"
  fi

  # Rust: the toolchain's own cargo, never the ~/.cargo/bin rustup proxy (which
  # is rustup and selects no table).
  case "$WL_PLATFORM" in
    macos) WL_RUST_TRIPLE=stable-aarch64-apple-darwin ;;
    *)     WL_RUST_TRIPLE=stable-aarch64-unknown-linux-gnu ;;
  esac
  WL_TOOLCHAIN="$WL_HOME/.rustup/toolchains/$WL_RUST_TRIPLE"
  WL_CARGO="$WL_TOOLCHAIN/bin/cargo"
  WL_RUSTC="$WL_TOOLCHAIN/bin/rustc"
  # The Linux linker chain: /usr/bin/cc and /usr/bin/ld are symbolic links and a
  # grant cannot name them, so RUSTFLAGS names gcc and the exec list names the
  # real programs gcc execs.
  WL_GCC=/usr/bin/gcc
  WL_GCC_LIBEXEC="$(ls -dt /usr/libexec/gcc/*/* 2>/dev/null | head -1)"

  export WL_HOME WL_ROOT WL_TOOLS WL_CLAUDE WL_CODEX_SHIM WL_CODEX_VENDOR
  export WL_STRANDS_HOME WL_STRANDS WL_STRANDS_LIB
  export WL_GIT WL_GIT_EXEC WL_GIT_HELPERS WL_TRUE WL_CLT WL_SH WL_BASH
  export WL_PYTHON WL_PY_VER WL_PY_KEG WL_PY_STDLIB WL_PY_STDLIB64
  export WL_BREW_READ WL_CA_BUNDLE
  export WL_NODE WL_NODE_TREE WL_NPM_CLI WL_NODE_KEG WL_NODE_FORMULA
  export WL_NODE_JITLESS WL_SCRIPT_SHELL
  export WL_TOOLCHAIN WL_CARGO WL_RUSTC WL_RUST_TRIPLE WL_GCC WL_GCC_LIBEXEC
}

# wl_paths_json — the resolved paths as JSON, for boxgen.py.
wl_paths_json() {
  python3 - <<'PY'
import json, os
keys = ["PLATFORM","HOME","ROOT","TOOLS","CLAUDE","CODEX_SHIM","CODEX_VENDOR",
        "STRANDS_HOME","STRANDS","STRANDS_LIB","STRANDS_MODEL","GIT","GIT_EXEC",
        "GIT_HELPERS","TRUE","CLT","SH","BASH","PYTHON","PY_VER","PY_KEG","PY_STDLIB","PY_STDLIB64",
        "NODE","NODE_TREE","NPM_CLI","NODE_KEG","NODE_FORMULA","NODE_JITLESS","SCRIPT_SHELL","BREW_READ","CA_BUNDLE",
        "TOOLCHAIN","CARGO",
        "RUSTC","RUST_TRIPLE","GCC","GCC_LIBEXEC"]
print(json.dumps({k: os.environ.get("WL_"+k, "") for k in keys}))
PY
}

# --- Per-agent adapter ------------------------------------------------------
# The three agents differ in three places only: the program the box runs, the
# environment that points it at its model, and the flags that make it
# non-interactive. Everything else — the grants, the policy, the checks — is the
# same case.
WL_BEDROCK_HOST="bedrock-runtime.${AWS_REGION:-us-west-2}.amazonaws.com"
WL_MANTLE_HOST="bedrock-mantle.${AWS_REGION:-us-west-2}.api.aws"
WL_CODEX_MODEL="${WL_CODEX_MODEL:-openai.gpt-5.6-terra}"
# The Strands agent calls Opus 5 on the Bedrock runtime host, which the gateway
# signs with the instance role. This is the Claude Code authorization path. The
# model id carries a geography prefix that differs by region, so this file holds
# no default for it: the caller sets WL_STRANDS_MODEL, and boxgen.py refuses a
# strands pair whose model id is empty.
export WL_STRANDS_MODEL="${WL_STRANDS_MODEL:-}"

# wl_agent_host <agent> — the model host the pair permits and binds.
wl_agent_host() {
  case "$1" in
    codex)          echo "$WL_MANTLE_HOST" ;;
    claude|strands) echo "$WL_BEDROCK_HOST" ;;
    *) wl_agent_known "$1"; return 1 ;;
  esac
}

# wl_agent_available <agent> — is this agent installed on this host?
wl_agent_available() {
  case "$1" in
    claude) [ -n "${WL_CLAUDE:-}" ] && [ -x "$WL_CLAUDE" ] ;;
    codex)  [ -n "${WL_CODEX_SHIM:-}" ] && [ -f "$WL_CODEX_SHIM" ] && [ -x "${WL_NODE:-/nonexistent}" ] ;;
    strands) [ -n "${WL_STRANDS:-}" ] && [ -f "$WL_STRANDS" ] \
               && [ -n "${WL_STRANDS_LIB:-}" ] && [ -d "$WL_STRANDS_LIB" ] \
               && [ -x "${WL_PYTHON:-/nonexistent}" ] ;;
    *) wl_agent_known "$1"; return 1 ;;
  esac
}

# wl_seed_agent_config <project> — the per-agent configuration every case needs
# inside the project, because HOME stays the operator's and no list names it.
# Called by workload-agent-a.sh before the dimension's own wl_prepare, so a
# dimension cannot forget it.
wl_seed_agent_config() {
  local proj="$1"
  mkdir -p "$proj/.tmp"
  wl_agent_known "${WL_AGENT:-}" || return 1
  if [ "${WL_AGENT:-}" = claude ]; then
    mkdir -p "$proj/.claude-config"
  elif [ "${WL_AGENT:-}" = strands ]; then
    # The Strands agent reads its model id and its region from the environment
    # the box composes, so this directory holds only what the entry script writes
    # while it runs. The agent's own reach to it comes from the project grants.
    mkdir -p "$proj/.strands"
  elif [ "${WL_AGENT:-}" = codex ]; then
    mkdir -p "$proj/.codex"
    # Codex's built-in `amazon-bedrock` provider signs SigV4 itself from the AWS
    # credential chain, which a contained process does not have: the environment
    # is literal and no list names ~/.aws. So the provider is declared explicitly
    # against the Mantle host and its key comes from a placeholder name; the real
    # authorization is the gateway's `aws://default` signature at the boundary.
    cat > "$proj/.codex/config.toml" <<EOF
model = "$WL_CODEX_MODEL"
model_provider = "boxmantle"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[model_providers.boxmantle]
name = "Bedrock Mantle through the box egress gateway"
base_url = "https://$WL_MANTLE_HOST/openai/v1"
wire_api = "responses"
env_key = "BOX_MANTLE_TOKEN"
EOF
  else
    echo "workload-lib: wl_seed_agent_config has no arm for agent '${WL_AGENT:-}'" >&2
    return 1
  fi
}

# --- Two-run cells ----------------------------------------------------------
# A dimension that declares `runs=2` keeps the project and the box directory and
# runs the agent twice in one box. What follows is what the driver, the
# dimensions, and the oracle share for that path.

# wl_manifest_value <manifest> <key> [default] — one `key=value` line, the last.
wl_manifest_value() {
  local value
  value="$(sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -1)"
  printf '%s' "${value:-${3:-}}"
}

# wl_dimension_agents <case-dir> — the agents a dimension declares in `wl_agents`,
# or nothing when it runs for every agent.
wl_dimension_agents() {
  # shellcheck disable=SC1090
  ( source "$1/case.sh" >/dev/null 2>&1; printf '%s' "${wl_agents:-}" )
}

# wl_dimension_agents_known <case-dir> — every agent a dimension declares is one
# this suite knows; a typo would otherwise make the dimension apply to nobody and
# vanish from the aggregate without a row.
wl_dimension_agents_known() {
  local declared known
  declared="$(wl_dimension_agents "$1")"
  for known in $declared; do
    wl_agent_known "$known" || return 1
  done
  return 0
}

# wl_dimension_applies <case-dir> <agent> — true unless the dimension names agents
# and this one is not among them.
wl_dimension_applies() {
  local declared known
  declared="$(wl_dimension_agents "$1")"
  [ -z "$declared" ] && return 0
  for known in $declared; do
    [ "$known" = "$2" ] && return 0
  done
  return 1
}

# wl_session_id <agent> <turns-file> — the session the agent started, read from
# its own event stream: Claude Code names it in the `system` `init` event, Codex in
# `thread.started`. Exit 1 when the stream holds none, 3 for an agent with no
# session to resume.
wl_session_id() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
agent, turns = sys.argv[1:3]
shapes = {"claude": ("system", "init", "session_id"),
          "codex": ("thread.started", None, "thread_id")}
if agent not in shapes:
    sys.stderr.write("workload-lib: wl_session_id has no arm for agent %r\n" % agent)
    sys.exit(3)
kind, subtype, field = shapes[agent]
try:
    lines = open(turns).read().splitlines()
except OSError:
    lines = []
for line in lines:
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("type") != kind or (subtype and event.get("subtype") != subtype):
        continue
    if event.get(field):
        print(event[field])
        sys.exit(0)
sys.exit(1)
PY
}

# wl_session_file <agent> <project> <session-id> — the file the agent keeps the
# session in, inside the project. Prints nothing when it is absent.
wl_session_file() {
  case "$1" in
    claude) ls "$2"/.claude-config/projects/*/"$3".jsonl 2>/dev/null | head -1 ;;
    codex)  ls "$2"/.codex/sessions/*/*/*/rollout-*-"$3".jsonl 2>/dev/null | head -1 ;;
    *) echo "workload-lib: wl_session_file has no arm for agent '$1'" >&2; return 3 ;;
  esac
}

# wl_mtime <path> — modification time in nanoseconds, or nothing.
wl_mtime() { python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_mtime_ns)' "$1" 2>/dev/null; }

# wl_box_state <box-dir> <out-json> — the identity facts a second run must keep:
# the box id, the record file's inode, the commit file's bytes, and the history
# database's inode.
wl_box_state() {
  python3 - "$1" "$2" <<'PY'
import hashlib
import json
import os
import re
import sys
box, out = sys.argv[1:3]
private = os.path.join(box, "private")


def inode(name):
    try:
        return os.stat(os.path.join(private, name)).st_ino
    except OSError:
        return None


def digest(name):
    try:
        return hashlib.sha256(open(os.path.join(private, name), "rb").read()).hexdigest()
    except OSError:
        return None


box_id = None
try:
    found = re.search(r'^box_id\s*=\s*"([^"]*)"', open(os.path.join(private, "box.toml")).read(), re.M)
    box_id = found.group(1) if found else None
except OSError:
    pass
json.dump({"box_id": box_id, "record_inode": inode("box.toml"),
           "configured": digest("configured"), "history_inode": inode("dogwood.redb")},
          open(out, "w"))
PY
}

# wl_descendants <pid> — every process beneath pid, depth first.
wl_descendants() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null); do
    printf '%s ' "$child"
    wl_descendants "$child"
  done
}

# wl_kill_tree <pid> — SIGKILL the process first, then everything beneath it.
wl_kill_tree() {
  local below
  below="$(wl_descendants "$1")"
  kill -KILL "$1" 2>/dev/null
  # shellcheck disable=SC2086
  [ -n "$below" ] && kill -KILL $below 2>/dev/null
  return 0
}

# wl_agent_arguments <agent> <last-message-file> <run-args-file> <prompt> — the
# arguments `run -- …` appends, NUL-separated. The run arguments a dimension
# supplies for a second run take the subcommand position for Codex and the Strands
# entry, which read `resume <id>` before their flags, and the flag position for
# Claude Code, which reads `--resume <id>` after its own.
wl_agent_arguments() {
  local agent="$1" last="$2" args_file="$3" prompt="$4" line
  local run_args=()
  if [ -s "$args_file" ]; then
    while IFS= read -r line; do run_args+=("$line"); done < "$args_file"
  fi
  case "$agent" in
    claude)
      printf '%s\0' --print --output-format stream-json --verbose --dangerously-skip-permissions
      [ "${#run_args[@]}" -gt 0 ] && printf '%s\0' "${run_args[@]}"
      ;;
    codex)
      [ "${#run_args[@]}" -gt 0 ] && printf '%s\0' "${run_args[@]}"
      printf '%s\0' --json --output-last-message "$last"
      ;;
    strands)
      [ "${#run_args[@]}" -gt 0 ] && printf '%s\0' "${run_args[@]}"
      printf '%s\0' --json --last-message "$last"
      ;;
    *) wl_agent_known "$agent"; return 1 ;;
  esac
  printf '%s\0' "$prompt"
}

# wl_write_budget <out> <rule-id> <action> <operation-type> <operation> <n> — a
# `forbid` that fires once <n> responses of that one operation lie within the last
# hour. The window is one hour because a two-run cell takes minutes, and run one's
# spend must still count in run two. A `::response` exists only for an effect that
# happened, so a refused attempt spends nothing.
wl_write_budget() {
  cat > "$1" <<EOF
@id("$2") forbid (principal, action == Box::Action::"$3", resource)
when { context.input.operation == Box::$4::"$5" }
when temporal {
  exists (spent: Long). (
    (count for (t: Timepoint). where (
      formerly within 1h (
        Box::Action::"$3"::response{ input.path: _, input.operation: Box::$4::"$5" } && tp(t)
      )
    )) == spent
    && spent >= $6
  )
};
EOF
}
