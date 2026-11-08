"""Expose synthetic deployment tools whose HTTP requests pass through Box."""
import http.client
import json
import os
import re
import sys
from urllib.parse import urlsplit

HTTP_TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 65536
MAX_FRAME_CHARACTERS = 65536
OPERATIONS = {
    "deploy_checkout": ("POST", "/deployments/checkout"),
    "deployment_status": ("GET", "/deployments/checkout/status"),
}
TOOLS = [
    {"name": "deploy_checkout", "description": "Request a synthetic checkout deployment.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "deployment_status", "description": "Read synthetic checkout deployment diagnostics.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
]


def endpoint(value, hosts):
    parsed = urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname not in hosts
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or parsed.port is None or not 1 <= parsed.port <= 65535):
        raise ValueError("Expected an HTTP loopback endpoint with an explicit port")
    return parsed


def request(url, method, path):
    service = endpoint(url, {"127.0.0.1"})
    if not isinstance(method, str) or re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method) is None:
        raise ValueError("Expected an HTTP method token")
    if (not isinstance(path, str) or not path.startswith("/") or "#" in path
            or any(ord(character) <= 32 or ord(character) >= 127 for character in path)):
        raise ValueError("Expected an absolute HTTP request path")
    proxy_url = os.environ.get("HTTP_PROXY")
    if not proxy_url:
        raise ValueError("HTTP_PROXY is required for every deployment request")
    proxy = endpoint(proxy_url, {"127.0.0.1", "localhost"})
    connection = http.client.HTTPConnection(proxy.hostname, proxy.port,
                                            timeout=HTTP_TIMEOUT_SECONDS)
    try:
        headers = {"Host": service.netloc, "Connection": "close"}
        body = None
        if method == "POST":
            headers["Content-Type"] = "application/json"
            body = "{}"
        connection.request(method, "http://" + service.netloc + path,
                           body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("Deployment response exceeds the fixture limit")
        text = raw.decode("utf-8", errors="replace")
        try:
            result = json.loads(text)
        except ValueError:
            result = text
        return {"status": response.status,
                "box_refused": response.getheader("x-strands-box-egress") == "refused",
                "body": result}
    finally:
        connection.close()


def reply(identity, result):
    print(json.dumps({"jsonrpc": "2.0", "id": identity, "result": result}), flush=True)


def tool_result(value, failed=False):
    return {"isError": failed, "content": [{"type": "text", "text": json.dumps(value)}]}


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Provide the synthetic deployment service URL")
    url = sys.argv[1]
    endpoint(url, {"127.0.0.1"})
    while True:
        line = sys.stdin.readline(MAX_FRAME_CHARACTERS + 1)
        if not line:
            return
        if len(line) > MAX_FRAME_CHARACTERS:
            raise SystemExit("MCP request exceeds the fixture limit")
        identity = None
        try:
            message = json.loads(line)
            if not isinstance(message, dict):
                raise ValueError("Expected an MCP request object")
            identity = message.get("id")
            if identity is None:
                continue
            method = message.get("method")
            params = message.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("Expected MCP parameters")
            if method == "initialize":
                reply(identity, {"protocolVersion": params.get("protocolVersion", "2024-11-05"),
                                 "capabilities": {"tools": {}},
                                 "serverInfo": {"name": "deployment_tools", "version": "1.0"}})
            elif method == "tools/list":
                reply(identity, {"tools": TOOLS})
            elif method == "tools/call":
                name = params.get("name")
                if not isinstance(name, str) or name not in OPERATIONS:
                    raise ValueError("Unknown deployment tool")
                if params.get("arguments", {}) != {}:
                    raise ValueError("Deployment tools accept no arguments")
                result = request(url, *OPERATIONS[name])
                reply(identity, tool_result(result, result["status"] >= 400))
            else:
                print(json.dumps({"jsonrpc": "2.0", "id": identity,
                                  "error": {"code": -32601, "message": "Method not found"}}), flush=True)
        except (ValueError, TypeError, OSError, http.client.HTTPException) as error:
            if identity is not None:
                reply(identity, tool_result({"error": str(error)}, True))


if __name__ == "__main__":
    main()
