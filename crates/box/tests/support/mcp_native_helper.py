"""A stdio server that loads a selected native module and starts a helper."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlsplit


def load_extension(settings):
    spec = importlib.util.spec_from_file_location("_sqlite3", settings["extension"])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert str(Path(module.__file__).resolve()) == settings["extension"]
    with module.connect(":memory:") as connection:
        assert connection.execute("select 6 * 7").fetchone() == (42,)
    return module


def check_child(settings, host):
    load_extension(settings)
    assert Path(settings["readable"]).read_text() == "READABLE_CONTROL"
    refused = []
    for name, filename in settings["protected"].items():
        try:
            content = Path(filename).read_bytes()
        except OSError:
            assert not host, filename
        else:
            if host:
                assert content, filename
            else:
                assert not content, "protected content escaped: " + name
        if not host:
            try:
                with open(filename, "ab"):
                    pass
            except OSError:
                pass
            else:
                raise AssertionError("protected path is writable: " + name)
            refused.append(name)
    try:
        with open(settings["readable"], "ab"):
            pass
    except OSError:
        assert not host
    else:
        assert host, "read-only file is writable"
    try:
        with socket.create_connection(("127.0.0.1", settings["port"]), timeout=2):
            pass
    except OSError:
        assert not host
    else:
        assert host, "helper reached host loopback"
    if not host:
        proxy = urlsplit(os.environ["HTTPS_PROXY"])
        with socket.create_connection((proxy.hostname, proxy.port), timeout=5) as stream:
            stream.sendall(b"CONNECT helper-proof.invalid:443 HTTP/1.1\r\n"
                           b"Host: helper-proof.invalid:443\r\n\r\n")
            response = stream.makefile("rb").readline(4096)
        assert response.split()[1] == b"403", response
    return {"extension": settings["extension"], "sqlite_result": 42,
            "refused": refused, "host": host}


def serve(settings):
    try:
        module = load_extension(settings)
    except (ImportError, OSError) as error:
        native_error = "NATIVE_EXTENSION_UNAVAILABLE: " + str(error)
    else:
        native_error = None
    for line in sys.stdin:
        request = json.loads(line)
        method = request.get("method")
        if "id" not in request:
            continue
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "native-helper", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "verify", "description": "Check native helper access",
                                 "inputSchema": {"type": "object", "properties": {}}}]}
        elif method == "tools/call":
            failed = native_error is not None
            text = native_error
            if not failed:
                try:
                    # The Rust client bounds the complete exchange.
                    child = subprocess.run(
                        [settings["helper"], __file__, "--child", os.environ["PROBE_SETTINGS"]],
                        capture_output=True, text=True,
                    )
                except (FileNotFoundError, PermissionError) as error:
                    failed, text = True, "HELPER_UNAVAILABLE: " + str(error)
                else:
                    failed = child.returncode != 0
                    text = child.stderr if failed else json.dumps({
                        "server_extension": str(Path(module.__file__).resolve()),
                        "child": json.loads(child.stdout),
                    })
            result = {"content": [{"type": "text", "text": text}], "isError": failed}
        else:
            raise AssertionError("unexpected method: " + str(method))
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--child", "--host"):
        settings = json.loads(Path(sys.argv[2]).read_text())
        print(json.dumps(check_child(settings, sys.argv[1] == "--host")))
    else:
        serve(json.loads(Path(os.environ["PROBE_SETTINGS"]).read_text()))
