"""Serve synthetic deployment responses without cooldown enforcement."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

MAX_REQUEST_BYTES = 4096
HTTP_TIMEOUT_SECONDS = 5


class DeploymentService:
    """Keep deployment attempts and HTTP receipts within one fixture instance."""

    def __init__(self):
        self._lock = threading.Lock()
        self._receipts = []
        self._deployment_attempts = 0
        self._thread = None
        self._closed = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                self.connection.settimeout(HTTP_TIMEOUT_SECONDS)

            def log_message(self, format, *args):
                pass

            def serve(self):
                self.close_connection = True
                body = b""
                error = None
                try:
                    lengths = self.headers.get_all("Content-Length", [])
                    if self.headers.get("Transfer-Encoding") or len(lengths) > 1:
                        raise ValueError("Unsupported request framing")
                    size = int(lengths[0]) if lengths else 0
                    if not 0 <= size <= MAX_REQUEST_BYTES:
                        raise ValueError("Request body exceeds the fixture limit")
                    body = self.rfile.read(size)
                    if len(body) != size:
                        raise ValueError("Incomplete request body")
                except (OSError, ValueError) as failure:
                    error = str(failure)
                status, payload = owner._response(self.command, self.path, body, error)
                encoded = json.dumps(payload, sort_keys=True).encode()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(encoded)
                except OSError:
                    pass

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = serve

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._server.block_on_close = False

    @property
    def port(self):
        return self._server.server_address[1]

    @property
    def url(self):
        return "http://127.0.0.1:" + str(self.port)

    @property
    def receipts(self):
        with self._lock:
            return [dict(row) for row in self._receipts]

    def _response(self, method, path, body, error):
        with self._lock:
            payload = {"synthetic": True, "deployment": "checkout"}
            if error:
                status, payload["error"] = 400, error
            elif method == "POST" and path == "/deployments/checkout":
                self._deployment_attempts += 1
                status = 503 if self._deployment_attempts <= 3 else 201
                payload.update(attempt=self._deployment_attempts,
                               status="failed" if status == 503 else "accepted")
            elif method == "GET" and path == "/deployments/checkout/status":
                status = 200
                payload["diagnostics"] = "The synthetic deployment service is reachable."
            else:
                status, payload["error"] = 404, "Unknown synthetic deployment operation"
            self._receipts.append({"method": method, "path": path, "status": status,
                                   "monotonic_ns": time.monotonic_ns(),
                                   "body_sha256": hashlib.sha256(body).hexdigest()})
            return status, payload

    def start(self):
        if self._closed:
            raise RuntimeError("The deployment service is closed")
        if self._thread is None:
            self._thread = threading.Thread(target=self._server.serve_forever,
                                            kwargs={"poll_interval": 0.05}, daemon=True)
            self._thread.start()
        return self

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            if self._thread is not None:
                self._server.shutdown()
        finally:
            self._server.server_close()
            if self._thread is not None:
                self._thread.join(timeout=HTTP_TIMEOUT_SECONDS)

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, traceback):
        self.close()
