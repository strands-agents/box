#!/usr/bin/env python3
"""common/workload-strands-agent.py — the workload suite's Strands SDK agent.

The suite must exercise a third agent that is neither Claude Code nor Codex, so
the harness carries its own: an agent built on the Strands SDK, with two tools
and an event vocabulary of its own. Each event is one JSON object on stdout,
flushed when it happens, because agent A captures stdout as the transcript and a
run the box kills must keep the proof of what it already did.

  strands.start            the model, the region, the SDK directory, the state directory
  strands.mcp_server       one configured MCP server, started or not, with its tool names
  strands.tool_invocation  written BEFORE the tool runs; the run-validity proof
  strands.hook             one hook command ran, with its event and exit code
  strands.tool_result      the status the tool returned
  strands.end              the turn finished, with the invocation count
  strands.error            the run could not finish, with the cause

The box runs this file with the host's canonical python3 and composes the
environment it reads, so every name below is required and none is inherited.

STRANDS_STATE_DIR holds the per-run configuration, in Claude Code's vocabulary:
  hooks.json  {"hooks": {"PreToolUse"|"PostToolUse": [{"matcher": <regex over
              Claude Code's tool names>, "hooks": [{"type": "command",
              "command": <shell text>}]}]}}. A hook reads the event as JSON on
              stdin and runs through `bash -c`.
  mcp.json    {"mcpServers": {<name>: {"command", "args", "env"}}}, each a stdio
              server this program starts itself and whose tools the agent gets.
A file that is absent configures nothing. The agent's own tools carry Claude
Code's names for the matcher (`Write`, `Bash`), and an MCP tool carries
`mcp__<server>__<tool>`.

Usage: workload-strands-agent.py [--json] --last-message <path> <prompt>
Exit: 0 a finished turn, 3 a harness fault, 125 a boundary or transport failure,
126 a policy refusal.
"""

import contextlib
import errno
import json
import os
import re
import subprocess
import sys
import time

# The SDK sits in a `pip install --target` directory, which arrives as
# STRANDS_LIB_DIR, and this file puts it on the import path itself.
LIB_DIR = os.environ.get("STRANDS_LIB_DIR", "")
if LIB_DIR:
    sys.path.insert(0, LIB_DIR)

# A bare name resolves through the composed PATH, which starts with the box's own
# alias directory, so a command runs through the box rather than a host shell.
SHELL = "bash"
COMMAND_TIMEOUT = 300
HOOK_TIMEOUT = 60
MAX_OUTPUT = 8000
TOOL_INVOCATIONS = 0
REQUIRED_NAMES = ("STRANDS_LIB_DIR", "STRANDS_MODEL_ID", "STRANDS_STATE_DIR", "AWS_REGION")
HOOK_EVENTS = ("PreToolUse", "PostToolUse")
CLAUDE_TOOL_NAMES = {"write_file": "Write", "run_command": "Bash"}
MCP_TOOL_SERVERS = {}   # MCP tool name -> server name, filled as each server lists
MCP_CLIENTS = {}        # server name -> the client that holds its session

SYSTEM_PROMPT = (
    "You are a software engineer working in the current directory. "
    "Use run_command to run shell commands and write_file to write files. "
    "Other tools come from the MCP servers configured for this run; call one "
    "when the task names it. "
    "Run every command the task names, and report what each one returned. "
    "When a command is refused, say so and continue with the rest of the task."
)


def emit(kind, **fields):
    fields["kind"] = kind
    fields["t"] = round(time.time(), 3)
    sys.stdout.write(json.dumps(fields, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run_command(command: str) -> str:
    """Run one shell command in the current directory and return its output."""
    try:
        done = subprocess.run([SHELL, "-c", command], capture_output=True,
                              text=True, timeout=COMMAND_TIMEOUT)
    except Exception as exc:
        # A refusal reaches the workload as an OSError, and the agent reports it
        # to the model rather than exiting: the case is about what the box did.
        return "failed: %s" % exc
    out = (done.stdout + done.stderr)[:MAX_OUTPUT]
    return "exit=%d\n%s" % (done.returncode, out)


def write_file(path: str, content: str) -> str:
    """Write one file, and create the directories above it."""
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w") as handle:
            handle.write(content)
    except Exception as exc:
        return "failed: %s" % exc
    return "wrote %d bytes to %s" % (len(content), path)


def load_json(state_dir, name):
    path = os.path.join(state_dir, name)
    if not os.path.isfile(path):
        return None
    with open(path) as handle:
        return json.load(handle)


def load_hooks(state_dir):
    """Return {event: [(matcher, [command, ...]), ...]}; {} when hooks.json is absent."""
    table = (load_json(state_dir, "hooks.json") or {}).get("hooks") or {}
    hooks = {}
    for event in HOOK_EVENTS:
        for entry in table.get(event) or []:
            commands = [h["command"] for h in entry.get("hooks") or []
                        if h.get("type") == "command" and h.get("command")]
            if commands:
                hooks.setdefault(event, []).append((entry.get("matcher") or "", commands))
    return hooks


def claude_tool_name(name):
    if name in CLAUDE_TOOL_NAMES:
        return CLAUDE_TOOL_NAMES[name]
    server = MCP_TOOL_SERVERS.get(name)
    if server:
        return "mcp__%s__%s" % (server, name)
    return name


def hook_matches(matcher, tool_name):
    if matcher in ("", "*"):
        return True
    try:
        return re.fullmatch(matcher, tool_name) is not None
    except re.error:
        return matcher == tool_name


def run_hooks(hooks, event, tool_name, payload):
    payload = dict(payload, hook_event_name=event, tool_name=tool_name, cwd=os.getcwd())
    for matcher, commands in hooks.get(event, []):
        if not hook_matches(matcher, tool_name):
            continue
        for command in commands:
            try:
                done = subprocess.run([SHELL, "-c", command], input=json.dumps(payload),
                                      capture_output=True, text=True, timeout=HOOK_TIMEOUT)
                emit("strands.hook", event=event, tool=tool_name,
                     exit_code=done.returncode, command=command[:200])
            except Exception as exc:
                emit("strands.hook", event=event, tool=tool_name,
                     exit_code=-1, command=command[:200], error=str(exc)[:300])


def result_text(result):
    parts = []
    for item in (result or {}).get("content") or []:
        if "text" in item:
            parts.append(str(item["text"]))
        elif "json" in item:
            parts.append(json.dumps(item["json"]))
    return "\n".join(parts)


class RunEvents:
    """Emits the event vocabulary for every tool call and runs the hooks around it."""

    def __init__(self, hooks):
        self.hooks = hooks
        self.seq_by_use = {}

    def register_hooks(self, registry, **kwargs):
        from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent
        registry.add_callback(BeforeToolCallEvent, self.before)
        registry.add_callback(AfterToolCallEvent, self.after)

    def before(self, event):
        global TOOL_INVOCATIONS
        TOOL_INVOCATIONS += 1
        use = event.tool_use or {}
        seq = self.seq_by_use[use.get("toolUseId")] = TOOL_INVOCATIONS
        name = claude_tool_name(use.get("name", ""))
        tool_input = use.get("input")
        emit("strands.tool_invocation", tool=name, seq=seq,
             input=json.dumps(tool_input)[:400])
        run_hooks(self.hooks, "PreToolUse", name, {"tool_input": tool_input})

    def after(self, event):
        use = event.tool_use or {}
        name = claude_tool_name(use.get("name", ""))
        result = event.result if isinstance(event.result, dict) else {}
        text = result_text(result)
        seq = self.seq_by_use.pop(use.get("toolUseId"), TOOL_INVOCATIONS)
        emit("strands.tool_result", tool=name, seq=seq,
             status=result.get("status", "unknown"), bytes=len(text))
        run_hooks(self.hooks, "PostToolUse", name,
                  {"tool_input": use.get("input"), "tool_response": text[:MAX_OUTPUT]})


def start_mcp_servers(state_dir, stack):
    """Start every server mcp.json names and return the tools they list."""
    from mcp import StdioServerParameters, stdio_client
    from strands.tools.mcp import MCPClient

    servers = (load_json(state_dir, "mcp.json") or {}).get("mcpServers") or {}
    tools = []
    for name, spec in servers.items():
        command = (spec or {}).get("command")
        args = list((spec or {}).get("args") or [])
        # The child keeps the composed environment: the SDK's default is a short
        # allowlist, and a server inside the box needs what the box composed.
        env = dict(os.environ)
        env.update((spec or {}).get("env") or {})
        if not command:
            emit("strands.mcp_server", server=name, started=False, error="no command")
            continue
        try:
            client = MCPClient(lambda c=command, a=args, e=env: stdio_client(
                StdioServerParameters(command=c, args=a, env=e)))
            stack.enter_context(client)
            listed = client.list_tools_sync()
        except Exception as exc:
            emit("strands.mcp_server", server=name, started=False,
                 command=command, error=str(exc)[:300])
            continue
        names = [t.tool_name for t in listed]
        for tool_name in names:
            MCP_TOOL_SERVERS[tool_name] = name
        MCP_CLIENTS[name] = client
        emit("strands.mcp_server", server=name, started=True, command=command, tools=names)
        tools.extend(listed)
    return tools


def parse_args(argv):
    last_message = ""
    words = []
    index = 0
    while index < len(argv):
        if argv[index] == "--json":
            index += 1
        elif argv[index] == "--last-message" and index + 1 < len(argv):
            last_message = argv[index + 1]
            index += 2
        else:
            words.append(argv[index])
            index += 1
    return last_message, " ".join(words)


def exit_code_for(exc):
    # Exit 126 is a policy refusal and exit 125 is a boundary or transport
    # failure, so the two must not collapse into one code.
    if getattr(exc, "errno", None) in (errno.EPERM, errno.EACCES):
        return 126
    return 125


def main(argv):
    last_message, prompt = parse_args(argv)
    if not prompt:
        emit("strands.error", error="no prompt")
        return 3
    absent = [name for name in REQUIRED_NAMES if not os.environ.get(name)]
    if absent:
        emit("strands.error",
             error="the composed environment is missing %s" % ", ".join(absent))
        return 3
    try:
        from strands import Agent, tool
        from strands.models import BedrockModel
    except Exception as exc:
        emit("strands.error", error="strands SDK is not importable: %s" % exc)
        return 3

    region = os.environ["AWS_REGION"]
    model_id = os.environ["STRANDS_MODEL_ID"]
    state_dir = os.environ["STRANDS_STATE_DIR"]
    try:
        hooks = load_hooks(state_dir)
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        emit("strands.error", error="hooks.json: %s" % exc)
        return 3
    settings = {"region_name": region, "model_id": model_id}
    emit("strands.start", model=model_id, region=region, lib=LIB_DIR, state=state_dir,
         hooks={event: len(entries) for event, entries in hooks.items()})

    try:
        with contextlib.ExitStack() as stack:
            mcp_tools = start_mcp_servers(state_dir, stack)
            agent = Agent(model=BedrockModel(**settings),
                          tools=[tool(run_command), tool(write_file)] + mcp_tools,
                          system_prompt=SYSTEM_PROMPT,
                          callback_handler=None,
                          hooks=[RunEvents(hooks)])
            result = agent(prompt)
    except Exception as exc:
        emit("strands.error", error=str(exc)[:500], tool_invocations=TOOL_INVOCATIONS)
        return exit_code_for(exc)

    text = str(result)
    if last_message:
        try:
            with open(last_message, "w") as handle:
                handle.write(text)
        except OSError as exc:
            emit("strands.error", error="last message: %s" % exc)
    emit("strands.end", tool_invocations=TOOL_INVOCATIONS, chars=len(text))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
