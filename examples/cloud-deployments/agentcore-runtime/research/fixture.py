"""Synthetic enrichment sources and a receiver ledger outside the workload."""

import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RECORDS = {
    "offline": {
        "source_id": "OFF-001",
        "title": "Offline behavior note",
        "finding": "Technicians can create and edit notes offline. Changes wait locally until a connection returns.",
    },
    "export": {
        "source_id": "EXP-002",
        "title": "Notebook export specification",
        "finding": "Teams can export selected notebooks as CSV files. Images remain separate attachments.",
    },
    "platforms": {
        "source_id": "PLT-003",
        "title": "Supported devices list",
        "finding": "The demo lists Android tablets and Linux desktops. It does not list iOS.",
    },
    "languages": {
        "source_id": "LANG-004",
        "title": "Interface language note",
        "finding": "The demo interface supports English and Spanish.",
    },
}


class ResearchFixture:
    def __init__(self):
        self._lock = threading.Lock()
        self._requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                pass

            def handle_request(self):
                topic = None
                status = 400
                data = {"error": "invalid_request", "synthetic": True}
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if self.headers.get("Transfer-Encoding") or size < 0 or size > 4096:
                        raise ValueError("invalid request body")
                    body = self.rfile.read(size)
                    payload = json.loads(body) if body else {}
                    if self.command == "POST" and self.path == "/research/enrich":
                        if isinstance(payload, dict) and set(payload) == {"topic"}:
                            topic = payload["topic"]
                            if isinstance(topic, str) and topic in RECORDS:
                                status = 200
                                data = dict(RECORDS[topic], topic=topic, synthetic=True)
                    else:
                        status = 404
                        data = {"error": "unknown_endpoint", "synthetic": True}
                except (ValueError, UnicodeDecodeError):
                    pass
                with owner._lock:
                    owner._requests.append({
                        "sequence": len(owner._requests) + 1,
                        "method": self.command,
                        "path": self.path,
                        "topic": topic,
                        "status": status,
                        "source_id": data.get("source_id"),
                    })
                encoded = json.dumps(data, sort_keys=True).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(encoded)
                self.close_connection = True

            do_POST = handle_request
            do_GET = handle_request
            do_PUT = handle_request
            do_DELETE = handle_request

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05}, daemon=True,
        )

    @property
    def port(self):
        return self._server.server_address[1]

    @property
    def base_url(self):
        return "http://127.0.0.1:" + str(self.port)

    def snapshot(self):
        with self._lock:
            return copy.deepcopy({"requests": self._requests})

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self._server.shutdown()
        self._thread.join(timeout=5)
        self._server.server_close()
