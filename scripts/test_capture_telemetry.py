"""Test local payload capture and the receiver CLI's shutdown and failure behavior."""

import http.client
import importlib.util
import json
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import urlsplit


SCRIPT = Path(__file__).with_name("capture_telemetry.py")
SPEC = importlib.util.spec_from_file_location("capture_telemetry", SCRIPT)
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


def post(endpoint, body, path="/box/ping"):
    parsed = urlsplit(endpoint)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        connection.request(
            "POST", path, body=body, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


class CaptureReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name)
        self.server = CAPTURE.CaptureServer(self.output)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())
        self.temporary.cleanup()

    def test_real_posts_preserve_raw_and_pretty_payloads_including_batches(self):
        payloads = [
            {"event": "run/1", "data": {"box_launched": True}},
            [{"event": "polling/1", "data": {}}, {"event": "shutdown/1", "data": {}}],
        ]
        self.assertEqual(urlsplit(self.server.endpoint).hostname, "127.0.0.1")
        for index, payload in enumerate(payloads, 1):
            body = json.dumps(payload, separators=(",", ":")).encode()
            self.assertEqual(post(self.server.endpoint, body), 204)
            self.assertEqual(
                (self.output / f"request-{index:04d}.body").read_bytes(), body
            )
            pretty = (self.output / f"request-{index:04d}.json").read_text(encoding="utf-8")
            self.assertEqual(json.loads(pretty), payload)
            self.assertIn("\n  ", pretty)
        self.assertEqual(self.server.request_count, 2)
        self.assertFalse(self.server.failed)

    def test_malformed_json_is_preserved_and_reported(self):
        body = b'{"event":'
        self.assertGreaterEqual(post(self.server.endpoint, body), 400)
        self.assertEqual((self.output / "request-0001.body").read_bytes(), body)
        self.assertFalse((self.output / "request-0001.json").exists())
        self.assertTrue(self.server.failed)

    def test_wrong_path_and_oversized_requests_are_not_accepted(self):
        self.assertGreaterEqual(post(self.server.endpoint, b"{}", path="/other"), 400)
        self.assertGreaterEqual(post(self.server.endpoint, b"x" * 32769), 400)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertTrue(self.server.failed)

    def test_accepted_socket_has_nodelay_enabled(self):
        observed = []
        original = self.server.get_request

        def get_request():
            connection, address = original()
            observed.append(connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
            return connection, address

        with mock.patch.object(self.server, "get_request", side_effect=get_request):
            self.assertEqual(post(self.server.endpoint, b"{}"), 204)
        self.assertEqual(len(observed), 1)
        self.assertNotEqual(observed[0], 0)

    def test_close_finishes_an_accepted_request_before_returning(self):
        body = b'{"event":"shutdown/1"}'
        accepted = threading.Event()
        closing = threading.Event()
        closed = threading.Event()
        original = CAPTURE.CaptureHandler.do_POST

        def handle_request(handler):
            accepted.set()
            original(handler)

        def close_server():
            closing.set()
            self.server.server_close()
            closed.set()

        with mock.patch.object(CAPTURE.CaptureHandler, "do_POST", handle_request):
            connection = socket.create_connection(self.server.server_address, timeout=5)
            closer = threading.Thread(target=close_server)
            try:
                connection.sendall(
                    b"POST /box/ping HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body[:1]
                )
                self.assertTrue(accepted.wait(timeout=1), "request was not accepted")
                self.server.shutdown()
                closer.start()
                self.assertTrue(closing.wait(timeout=1))
                self.assertFalse(closed.wait(timeout=0.05), "close discarded a pending request")
                connection.sendall(body[1:])
                response = http.client.HTTPResponse(connection)
                response.begin()
                self.assertEqual(response.status, 204)
                response.read()
                self.assertTrue(closed.wait(timeout=2), "close did not drain the request")
                self.assertEqual((self.output / "request-0001.body").read_bytes(), body)
                self.assertEqual(
                    json.loads((self.output / "request-0001.json").read_text()),
                    {"event": "shutdown/1"},
                )
                self.assertFalse(self.server.failed)
            finally:
                connection.close()
                if closer.ident is not None:
                    closer.join(timeout=3)
                    self.assertFalse(closer.is_alive())


class CaptureCommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name) / "capture"
        self.process = None

    def tearDown(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.kill()
            self.process.communicate(timeout=5)
        self.temporary.cleanup()

    def start(self):
        self.process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--output", str(self.output), "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ready, _, _ = select.select([self.process.stdout], [], [], 5)
        self.assertTrue(ready, "receiver did not print its endpoint")
        endpoint = self.process.stdout.readline().strip()
        self.assertEqual(urlsplit(endpoint).hostname, "127.0.0.1")
        self.assertEqual(urlsplit(endpoint).path, "/box/ping")
        return endpoint

    def test_command_captures_payload_and_exits_cleanly_on_sigterm(self):
        endpoint = self.start()
        body = b'{"event":"run/1","data":{"box_launched":true}}'
        self.assertEqual(post(endpoint, body), 204)
        self.process.terminate()
        _, stderr = self.process.communicate(timeout=5)
        self.assertEqual(self.process.returncode, 0, stderr)
        self.assertEqual((self.output / "request-0001.body").read_bytes(), body)
        self.assertEqual(
            json.loads((self.output / "request-0001.json").read_text()), json.loads(body)
        )

    def test_command_returns_failure_after_a_bad_request(self):
        endpoint = self.start()
        self.assertGreaterEqual(post(endpoint, b"not json"), 400)
        self.process.terminate()
        self.process.communicate(timeout=5)
        self.assertEqual(self.process.returncode, 1)
        self.assertEqual((self.output / "request-0001.body").read_bytes(), b"not json")

    def test_command_refuses_an_existing_output_directory(self):
        self.output.mkdir()
        sentinel = self.output / "keep.txt"
        sentinel.write_text("original")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--output", str(self.output)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(sentinel.read_text(), "original")
        self.assertEqual(list(self.output.iterdir()), [sentinel])


if __name__ == "__main__":
    unittest.main()
