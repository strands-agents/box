#!/bin/bash
# workload-mcp-stdio — a stdio MCP server started by the agent, inside the agent's
# own boundary. The server is a Python script, so the agent's own lists must grant
# the interpreter and its standard library, and the policy permits that
# interpreter as the one host binary.
#
# Reference: artifact section 6 (the MCP half). Two things make this case
# measurable rather than assertable: the server appends every call it receives to
# mcp-calls.log inside the project, so the HOST oracle reads the server's own
# record rather than the agent's account; and on macOS a single-file exec grant on
# the interpreter is not enough, because CPython execs Python.app from beside
# itself, so the keg tree is exec (F50).
#
# Codex's stdio MCP route is unmeasured before this suite — it is the coverage this
# dimension exists to add — so a Codex failure here is recorded with its first
# error, not skipped.
#
# The Strands entry takes its server from `.strands/mcp.json` under
# STRANDS_STATE_DIR, in Claude Code's `mcpServers` shape; a server the entry does
# not start FAILS `mcp-call-recorded` by measurement. Every fork below names its
# agent, and an unknown name fails with that name.

wl_manifest() {
  cat <<EOF
tools=
timeout=600
tools_allow=Glob,Grep,Read,Write,Edit,Bash,Task
agent_read_linux={{PY_STDLIB}} {{PY_STDLIB64}}
agent_exec_linux={{PYTHON}} {{PY_STDLIB64}}
agent_read_macos={{BREW_READ}}
agent_exec_macos={{PY_KEG}}
spawn={{PYTHON}}
EOF
  case "${WL_AGENT:-}" in
    claude) echo "agent_args=--mcp-config {{PROJECT}}/mcp.json --strict-mcp-config" ;;
    codex|strands) ;; # each reads its server from a file wl_prepare writes
    *)
      echo "workload-mcp-stdio: wl_manifest has no arm for agent '${WL_AGENT:-}'" >&2
      return 1 ;;
  esac
}

wl_prepare() {
  local proj="$1"
  # The server: one tool, and a line in mcp-calls.log for every call it answers.
  cat > "$proj/mcp-server.py" <<'SRV'
#!/usr/bin/env python3
"""A minimal stdio MCP server: one `echo` tool, and a host-readable call log.

The log is the oracle's ground truth. An agent that writes the expected answer
without calling the tool leaves no line here, so the case cannot pass by
assertion alone.
"""
import json
import os
import sys

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp-calls.log")
TOOL = {"name": "echo", "description": "Echo text back, prefixed with MCP_ECHO:",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                        "required": ["text"]}}


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def note(line):
    with open(LOG, "a") as f:
        f.write(line + "\n")


for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    try:
        req = json.loads(raw)
    except ValueError:
        continue
    method, rid = req.get("method"), req.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
            "serverInfo": {"name": "demo", "version": "1.0.0"}}})
        note("initialize")
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": [TOOL]}})
        note("tools/list")
    elif method == "tools/call":
        args = (req.get("params") or {}).get("arguments") or {}
        text = str(args.get("text", ""))
        note("tools/call echo " + text)
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": "MCP_ECHO:" + text}]}})
    elif rid is not None:
        send({"jsonrpc": "2.0", "id": rid, "result": {}})
SRV
  case "${WL_AGENT:-}" in
    claude)  wl_write_mcp_json "$proj/mcp.json" "$proj/mcp-server.py" ;;
    strands) wl_write_mcp_json "$proj/.strands/mcp.json" "$proj/mcp-server.py" ;;
    codex)
      cat >> "$proj/.codex/config.toml" <<EOF

[mcp_servers.demo]
command = "$WL_PYTHON"
args = ["-u", "$proj/mcp-server.py"]
EOF
      ;;
    *)
      echo "workload-mcp-stdio: wl_prepare has no arm for agent '${WL_AGENT:-}'" >&2
      return 1 ;;
  esac
}

# wl_write_mcp_json <out> <server script> — one stdio server named `demo`, in the
# `mcpServers` shape Claude Code reads from --mcp-config and the Strands entry
# reads from its state directory.
wl_write_mcp_json() {
  # The interpreter is a resolved host path or nothing; an empty spelling would be
  # an unbound variable under set -u, which ends wl_prepare without a word.
  if [ -z "${WL_PYTHON:-}" ]; then
    echo "workload-mcp-stdio: WL_PYTHON is unresolved on this host, so the server's interpreter cannot be named" >&2
    return 1
  fi
  python3 - "$1" "$WL_PYTHON" "$2" <<'PY'
import json, sys
out, py, script = sys.argv[1:4]
json.dump({"mcpServers": {"demo": {"command": py, "args": ["-u", script]}}}, open(out, "w"))
PY
}

wl_checks() {
  local proj="$1"
  # The requirement wl_prepare had: a resolved interpreter to name in the server
  # entry. Asserted here so an unresolved one is a failed check in the verdict.
  if [ -n "${WL_PYTHON:-}" ]; then
    wl_check mcp-interpreter-resolved 1 "WL_PYTHON=$WL_PYTHON"
  else
    wl_check mcp-interpreter-resolved 0 "WL_PYTHON is unresolved: wl_prepare could not name the server's interpreter"
  fi
  # The server's own record: the call reached it.
  wl_assert_file mcp-call-recorded "$proj/mcp-calls.log" "tools/call echo hello-mcp"
  wl_assert_file mcp-reply-written "$proj/mcp-result.txt" "MCP_ECHO:hello-mcp"
  # Measured: an MCP server the agent starts itself runs in the AGENT's boundary
  # through the agent's own exec entry, so it raises no shell:spawn decision at
  # all — the journal's proof for this case is the model round trip plus the
  # absence of any refusal on the project. The spawn permit stays in the pair
  # because it is what authorizes the interpreter when the Shell starts it.
  wl_assert_journal mcp-journal-model permit "http:request"
  wl_assert_no_denial mcp-no-project-denial "$proj"
  case "${WL_AGENT:-}" in
    claude)
      # Claude Code's own AF_UNIX listener binds inside the project's .tmp, which the
      # write grant covers; the bound socket is host-visible proof it got that far.
      wl_assert_glob mcp-socket-bound "$proj/.tmp/*" ;;
    codex|strands) ;; # neither binds a listener the host can see
    *) wl_check mcp-agent-known 0 "wl_checks has no arm for agent '${WL_AGENT:-}'" ;;
  esac
}
