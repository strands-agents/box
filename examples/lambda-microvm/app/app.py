"""Serve the Box exercise and Lambda lifecycle hooks."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import platform
import threading
import uuid

import fixed
from interactive import ClaudeSession

HERE = Path(__file__).resolve().parent
CLAUDE = {}
LOCK = threading.Lock()
HOOKS = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, value):
        encoded = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.server.server_port != 8080:
            return self.reply(404, {})
        if self.path == "/info":
            return self.reply(200, {
                "manifest": json.loads((HERE / "manifest.json").read_text()),
                "package": json.loads((HERE / "box-package.json").read_text()),
                "box_sha256": hashlib.sha256(fixed.BOX.read_bytes()).hexdigest(),
                "architecture": platform.machine(), "uid": os.getuid(),
                "kernel": platform.release(), "hooks": list(HOOKS),
            })
        if self.path == "/demo":
            with fixed.LOCK:
                return self.reply(200, dict(fixed.STATE))
        return self.reply(404, {})

    def do_POST(self):
        if self.server.server_port == 9000:
            prefix = "/aws/lambda-microvms/runtime/v1/"
            hook = self.path.removeprefix(prefix)
            if not self.path.startswith(prefix) or hook not in (
                "ready", "validate", "run", "resume", "suspend", "terminate",
            ):
                return self.reply(404, {})
            HOOKS.append(hook)
            return self.reply(200, {})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16384:
                raise ValueError("Expected a JSON request of at most 16384 bytes")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("Expected a JSON object")
            if self.path == "/demo":
                if set(body) - {"negative"} or type(body.get("negative", False)) is not bool:
                    raise ValueError("Expected an optional negative boolean")
                with fixed.LOCK:
                    if fixed.STATE["status"] == "running":
                        return self.reply(409, {"error": "A fixed exercise is already running"})
                    fixed.STATE.clear()
                    fixed.STATE.update(status="running", job_id=uuid.uuid4().hex)
                threading.Thread(target=fixed.run_demo, args=(body.get("negative", False),), daemon=True).start()
                return self.reply(202, {"status": "running"})
            if self.path.startswith("/claude/"):
                key = self.path.removeprefix("/claude/")
                if str(uuid.UUID(key)) != key:
                    raise ValueError("Expected a canonical workload UUID")
                with LOCK:
                    if key not in CLAUDE:
                        if body.get("operation") != "start":
                            return self.reply(404, {"error": "Unknown Claude workload"})
                        if len(CLAUDE) >= 32:
                            return self.reply(409, {"error": "This instance retains 32 Claude workloads"})
                        CLAUDE[key] = ClaudeSession(fixed.BOX)
                    workload = CLAUDE[key]
                return self.reply(200, workload.handle(body))
            return self.reply(404, {})
        except (ValueError, TypeError) as error:
            return self.reply(400, {"error": str(error)})


if __name__ == "__main__":
    application = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    lifecycle = ThreadingHTTPServer(("0.0.0.0", 9000), Handler)
    threading.Thread(target=lifecycle.serve_forever, daemon=True).start()
    application.serve_forever()
