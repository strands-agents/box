#!/usr/bin/env python3
"""Save Box CLI telemetry HTTP payloads received on loopback for inspection."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import signal
import socket
import sys
import threading


BODY_LIMIT = 32 * 1024


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


class CaptureServer(ThreadingHTTPServer):
    daemon_threads = False

    def __init__(self, output, port=0):
        self.output = output
        self.failed = False
        self.lock = threading.Lock()
        self.request_count = 0
        super().__init__(("127.0.0.1", port), CaptureHandler)
        self.endpoint = f"http://127.0.0.1:{self.server_port}/box/ping"

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(2)
        try:
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        return connection, address


class CaptureHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        server = self.server
        try:
            if self.path != "/box/ping":
                raise ValueError(f"Unexpected request path: {self.path}")
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Expected a Content-Length request, not Transfer-Encoding.")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= BODY_LIMIT:
                raise ValueError(f"Expected 1–{BODY_LIMIT} body bytes, got {length}.")
            body = self.rfile.read(length)
            with server.lock:
                server.request_count += 1
                prefix = server.output / f"request-{server.request_count:04d}"
                prefix.with_suffix(".body").write_bytes(body)
                if len(body) != length:
                    raise ValueError("Request ended before Content-Length bytes arrived.")
                payload = json.loads(body)
                save_json(prefix.with_suffix(".json"), payload)
            self.send_response(204)
            self.end_headers()
        except (OSError, ValueError) as error:
            with server.lock:
                server.failed = True
            print(f"Telemetry capture: {error}", file=sys.stderr)
            try:
                self.send_error(400, "Telemetry capture failed")
            except OSError:
                pass

    def log_message(self, *_):
        pass


def stop(*_):
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Listen on loopback and save Box CLI telemetry HTTP payloads.",
        epilog="Point your Box CLI at the printed endpoint with BOX_TEST_TELEMETRY_ENDPOINT "
               "and BOX_TELEMETRY=1. Stop capture with Ctrl+C or SIGTERM.",
    )
    parser.add_argument("--output", type=Path, required=True, help="new directory for the capture")
    parser.add_argument("--port", type=int, default=0, help="loopback port (default: choose a free port)")
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535.")
    try:
        args.output.mkdir(parents=True, exist_ok=False)
        with CaptureServer(args.output, args.port) as server:
            previous = signal.signal(signal.SIGTERM, stop)
            try:
                print(server.endpoint, flush=True)
                server.serve_forever(poll_interval=0.05)
            except KeyboardInterrupt:
                pass
            finally:
                signal.signal(signal.SIGTERM, previous)
        return int(server.failed)
    except (OSError, ValueError) as error:
        print(f"Telemetry capture: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
