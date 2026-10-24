"""Synthetic stdio MCP fixture; Box policy controls access to its tools."""
import json
import sys

DIRECTORY = sys.argv[1]
TOOLS = [
    {"name": "read_note", "description": "Read the synthetic MCP note.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "write_note", "description": "Write the synthetic MCP note.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                     "required": ["text"], "additionalProperties": False}},
    {"name": "delete_note", "description": "Delete the synthetic MCP note. Box policy refuses this tool.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
]

def reply(identity, result):
    print(json.dumps({"jsonrpc": "2.0", "id": identity, "result": result}), flush=True)

for line in sys.stdin:
    try:
        request = json.loads(line)
        if not isinstance(request, dict):
            continue
        identity = request.get("id")
        method = request.get("method")
        if identity is None:
            continue
        if method == "initialize":
            reply(identity, {"protocolVersion": request.get("params", {}).get("protocolVersion", "2024-11-05"),
                             "capabilities": {"tools": {}}, "serverInfo": {"name": "runtime_demo", "version": "1.0"}})
        elif method == "tools/list":
            reply(identity, {"tools": TOOLS})
        elif method == "tools/call":
            params = request.get("params", {})
            name = params.get("name")
            with open(DIRECTORY + "/calls.jsonl", "a") as log:
                log.write(json.dumps({"tool": name, "arguments": params.get("arguments", {})}) + "\n")
            if name == "read_note":
                with open(DIRECTORY + "/note.txt") as note:
                    text = note.read()
            elif name == "write_note":
                text = params.get("arguments", {}).get("text")
                if not isinstance(text, str) or len(text) > 4096:
                    raise ValueError("Expected text of at most 4096 characters")
                with open(DIRECTORY + "/note.txt", "w") as note:
                    note.write(text + "\n")
                text = "MCP note written"
            elif name == "delete_note":
                # A marker proves a policy failure without destroying the fixture.
                with open(DIRECTORY + "/delete-reached.txt", "w") as marker:
                    marker.write("The refused tool reached the server\n")
                text = "Unexpected: delete_note reached the server"
            else:
                raise ValueError("Unknown tool")
            reply(identity, {"content": [{"type": "text", "text": text}]})
        else:
            reply(identity, {})
    except (ValueError, TypeError, OSError) as error:
        if isinstance(locals().get("request"), dict) and request.get("id") is not None:
            reply(request["id"], {"isError": True, "content": [{"type": "text", "text": str(error)}]})
