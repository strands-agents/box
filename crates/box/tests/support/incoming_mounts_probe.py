"""Workload and local MCP fixture for the incoming-mount integration tests."""
import json
import mmap
import os
import pathlib
import subprocess
import sys

SELECTED = pathlib.Path(os.environ["FIXTURE_SELECTED"])
OTHER = pathlib.Path(os.environ["FIXTURE_OTHER"])
ROLE = os.environ["FIXTURE_ROLE"]


def snapshot(selected=SELECTED, other=OTHER):
    def content(path):
        try:
            return path.read_text()
        except FileNotFoundError:
            return None

    result = {
        "root": content(selected / "value"),
        "nested": content(selected / "nested/value"),
        "other_root": content(other / "value"),
        "other_nested": content(other / "nested/value"),
        "initial": content(selected / "initial"),
    }
    try:
        with (selected / "value").open("r+b") as output:
            output.write(b"a")
        result["write_errno"] = 0
    except OSError as error:
        result["write_errno"] = error.errno
    try:
        with (selected / "program").open("rb") as program:
            with mmap.mmap(program.fileno(), 4096, flags=mmap.MAP_PRIVATE,
                           prot=mmap.PROT_READ | mmap.PROT_EXEC):
                pass
        result["exec_errno"] = 0
    except OSError as error:
        result["exec_errno"] = error.errno
    return result


def emit(stage, result=None):
    frame = json.dumps({"stage": stage, "role": ROLE, "result": result})
    if os.environ["FIXTURE_MODE"] == "tool":
        with (pathlib.Path(os.environ["FIXTURE_CONTROL"]) / "events").open("w") as events:
            print(frame, file=events, flush=True)
    else:
        print(frame, flush=True)


def release():
    if os.environ["FIXTURE_MODE"] == "tool":
        with (pathlib.Path(os.environ["FIXTURE_CONTROL"]) / "release").open() as control:
            line = control.readline()
    else:
        line = sys.stdin.readline()
    assert line == "continue\n", "publisher closed the release pipe"


def receiver():
    emit("receiver-ready", snapshot())
    release()
    emit("receiver-done", snapshot())


def mcp_server():
    for line in sys.stdin:
        frame = json.loads(line)
        method = frame.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "incoming-mcp", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "observe", "description": "Read the fixture mounts",
                                  "inputSchema": {"type": "object", "properties": {}}}]}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": json.dumps(snapshot())}]}
        elif "id" not in frame:
            continue
        else:
            raise AssertionError("unexpected MCP method: " + str(method))
        print(json.dumps({"jsonrpc": "2.0", "id": frame["id"], "result": result}), flush=True)


def mcp_receiver():
    client = subprocess.Popen(["incoming-mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              text=True, bufsize=1)
    def call(identifier, method):
        params = {"name": "observe", "arguments": {}} if method == "tools/call" else {}
        if method == "initialize":
            params = {"protocolVersion": "2024-11-05", "capabilities": {},
                      "clientInfo": {"name": "incoming-mount-test", "version": "1"}}
        client.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identifier,
                                       "method": method, "params": params}) + "\n")
        client.stdin.flush()
        response = json.loads(client.stdout.readline())
        assert response.get("id") == identifier and "error" not in response, response
        return response["result"]
    try:
        call(1, "initialize")
        client.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        client.stdin.flush()
        assert call(2, "tools/list")["tools"][0]["name"] == "observe"
        before = call(3, "tools/call")
        emit("receiver-ready", json.loads(before["content"][0]["text"]))
        release()
        after = call(4, "tools/call")
        emit("receiver-done", json.loads(after["content"][0]["text"]))
    finally:
        client.stdin.close()
        assert client.wait(timeout=10) == 0


def agent():
    if ROLE == "agent":
        receiver()
        return
    emit("agent-ready", snapshot(OTHER, SELECTED))
    release()
    if ROLE == "tool":
        assert subprocess.run(["zsh", "-c", "incoming-tool"]).returncode == 0
    else:
        mcp_receiver()
    emit("agent-done", snapshot(OTHER, SELECTED))


status = pathlib.Path("/proc/self/status").read_text().splitlines()
assert all(int(line.split()[1], 16) == 0 for line in status
           if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:")))

mode = os.environ["FIXTURE_MODE"]
if mode == "mcp":
    mcp_server()
elif mode == "tool":
    receiver()
else:
    agent()
