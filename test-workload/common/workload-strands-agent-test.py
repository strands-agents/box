#!/usr/bin/env python3
"""Pin what the Strands agent reads from STRANDS_STATE_DIR, with no model call.

Runs here, with no instance and no box:

  python3 test-workload/common/workload-strands-agent-test.py

The hook checks need only python3 and bash. The MCP checks start the real server
that workload-mcp-stdio/case.sh writes, through the SDK's own client, and need
the SDK: set STRANDS_LIB_DIR to a `pip install --target` directory, or they skip.
"""

import importlib.util
import json
import os
import re
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
FAILED = []


def load_agent():
    spec = importlib.util.spec_from_file_location(
        "workload_strands_agent", os.path.join(HERE, "workload-strands-agent.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, (" — " + detail) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def hook_checks(agent, work):
    state = os.path.join(work, ".strands")
    os.makedirs(state)
    check("no hooks.json configures nothing", agent.load_hooks(state) == {})

    # The shape workload-agent-hook/case.sh writes: one PostToolUse hook on Write.
    nonce = "hook-test-nonce-4711"
    marker = os.path.join(work, "hook.txt")
    command = "printf 'HOOK_FIRED %s' > %s" % (nonce, marker)
    json.dump({"hooks": {"PostToolUse": [{"matcher": "Write",
              "hooks": [{"type": "command", "command": command}]}]}},
              open(os.path.join(state, "hooks.json"), "w"))
    hooks = agent.load_hooks(state)
    check("hooks.json loads one PostToolUse hook on Write",
          hooks == {"PostToolUse": [("Write", [command])]}, repr(hooks))

    agent.run_hooks(hooks, "PostToolUse", "Bash", {"tool_input": {}})
    check("a Bash call does not fire the Write hook", not os.path.exists(marker))
    agent.run_hooks(hooks, "PreToolUse", "Write", {"tool_input": {}})
    check("a PreToolUse event does not fire a PostToolUse hook", not os.path.exists(marker))

    events = []
    agent.emit = lambda kind, **fields: events.append(dict(fields, kind=kind))
    fake = types.SimpleNamespace(
        tool_use={"toolUseId": "t1", "name": "write_file",
                  "input": {"path": "feature.txt", "content": "hook workload"}},
        result={"toolUseId": "t1", "status": "success",
                "content": [{"text": "wrote 13 bytes to feature.txt"}]})
    run = agent.RunEvents(hooks)
    run.before(fake)
    check("the invocation event is written before the tool runs, under Claude Code's name",
          [e["kind"] for e in events] == ["strands.tool_invocation"]
          and events[0]["tool"] == "Write" and events[0]["seq"] == 1, repr(events))
    check("before the tool runs, the PostToolUse hook has not fired", not os.path.exists(marker))
    run.after(fake)
    check("after a Write, the hook fires and the nonce lands in hook.txt",
          os.path.exists(marker) and open(marker).read() == "HOOK_FIRED " + nonce)
    kinds = [e["kind"] for e in events]
    check("the run writes tool_result and one hook event with exit 0",
          kinds == ["strands.tool_invocation", "strands.tool_result", "strands.hook"]
          and events[2]["exit_code"] == 0 and events[2]["event"] == "PostToolUse", repr(kinds))
    check("the invocation count is the run-validity proof",
          agent.TOOL_INVOCATIONS == 1)

    # The SDK's default executor runs tools concurrently: before(A), before(B),
    # after(A), after(B). Each result carries the seq of its own invocation.
    events.clear()
    second = types.SimpleNamespace(
        tool_use={"toolUseId": "t2", "name": "run_command", "input": {"command": "true"}},
        result={"toolUseId": "t2", "status": "success", "content": [{"text": "ok"}]})
    run.before(fake)
    run.before(second)
    run.after(fake)
    run.after(second)
    seqs = [(e["tool"], e["seq"]) for e in events if e["kind"] != "strands.hook"]
    check("two overlapping tool calls pair each result with its own invocation seq",
          seqs == [("Write", 2), ("Bash", 3), ("Write", 2), ("Bash", 3)], repr(seqs))

    agent.MCP_TOOL_SERVERS["echo"] = "demo"
    check("an MCP tool carries Claude Code's mcp__server__tool name",
          agent.claude_tool_name("echo") == "mcp__demo__echo")
    check("a regex matcher covers an MCP tool name",
          agent.hook_matches("mcp__demo__.*", "mcp__demo__echo")
          and not agent.hook_matches("mcp__demo__.*", "Write"))
    agent.MCP_TOOL_SERVERS.clear()


def server_source():
    case = open(os.path.join(HERE, "..", "workload-mcp-stdio", "case.sh")).read()
    match = re.search(r"<<'SRV'\n(.*?)\nSRV\n", case, re.S)
    return match.group(1) if match else None


def mcp_checks(agent, work):
    import contextlib
    try:
        import mcp  # noqa: F401
        import strands.tools.mcp  # noqa: F401
    except Exception as exc:
        print("skipping: strands SDK not importable at STRANDS_LIB_DIR (%s)" % exc)
        return
    source = server_source()
    check("workload-mcp-stdio/case.sh still carries its server", source is not None)
    if source is None:
        return
    project = os.path.join(work, "project")
    state = os.path.join(project, ".strands")
    os.makedirs(state)
    server = os.path.join(project, "mcp-server.py")
    open(server, "w").write(source)
    # The shape wl_write_mcp_json writes.
    json.dump({"mcpServers": {"demo": {"command": sys.executable, "args": ["-u", server]}}},
              open(os.path.join(state, "mcp.json"), "w"))

    events = []
    agent.emit = lambda kind, **fields: events.append(dict(fields, kind=kind))
    with contextlib.ExitStack() as stack:
        tools = agent.start_mcp_servers(state, stack)
        names = [t.tool_name for t in tools]
        check("the demo server starts and lists its echo tool", names == ["echo"], repr(names))
        started = [e for e in events if e["kind"] == "strands.mcp_server"]
        check("one mcp_server event, started, naming the tool",
              len(started) == 1 and started[0]["started"] and started[0]["tools"] == ["echo"],
              repr(started))
        result = agent.MCP_CLIENTS["demo"].call_tool_sync("t1", "echo", {"text": "hello-mcp"})
        text = agent.result_text(result)
        check("the echo tool answers through the SDK client",
              text == "MCP_ECHO:hello-mcp", repr(text))
    log = os.path.join(project, "mcp-calls.log")
    lines = open(log).read().splitlines() if os.path.exists(log) else []
    check("the server's log carries the line the oracle asserts",
          "tools/call echo hello-mcp" in lines, repr(lines))

    events.clear()
    agent.MCP_TOOL_SERVERS.clear()
    json.dump({"mcpServers": {"broken": {"command": os.path.join(work, "no-such-program")}}},
              open(os.path.join(state, "mcp.json"), "w"))
    with contextlib.ExitStack() as stack:
        tools = agent.start_mcp_servers(state, stack)
    failed = [e for e in events if e["kind"] == "strands.mcp_server"]
    check("a server that cannot start is reported by name and the run continues",
          tools == [] and len(failed) == 1 and not failed[0]["started"]
          and failed[0]["server"] == "broken", repr(failed))


def main():
    agent = load_agent()
    with tempfile.TemporaryDirectory() as work:
        hook_checks(agent, os.path.join(work, "hooks"))
    with tempfile.TemporaryDirectory() as work:
        mcp_checks(agent, os.path.join(work, "mcp"))
    if FAILED:
        print("strands-agent: %d check(s) FAILED: %s" % (len(FAILED), ", ".join(FAILED)))
        return 1
    print("strands-agent: all checks pinned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
