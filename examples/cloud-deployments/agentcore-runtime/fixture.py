"""Synthetic shipment service with an independent request and effect ledger."""

from __future__ import annotations

import copy
import json
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional


class FixtureServer:
    """Serve one synthetic order; state lasts for this fixture instance only."""

    def __init__(
        self,
        eligibility_status: int = 200,
        drop_first_dispatch_response: bool = False,
    ) -> None:
        if eligibility_status not in (200, 409):
            raise ValueError("eligibility_status must be 200 or 409")
        self.eligibility_status = eligibility_status
        self.drop_first_dispatch_response = drop_first_dispatch_response
        self._dropped_dispatch_response = False
        self._lock = threading.Lock()
        self._requests: list[dict[str, Any]] = []
        self._effects: list[dict[str, Any]] = []
        self._resolution: Optional[dict[str, Any]] = None
        self._cached_reply: Optional[dict[str, Any]] = None
        self._thread: Optional[threading.Thread] = None
        self._closed = False
        self._order = {
            "synthetic": True,
            "order_id": 42,
            "customer_name": "Taylor (fictional)",
            "item": "Adjustable desk lamp",
            "quantity": 1,
            "as_of_date": "2026-11-02",
            "promised_delivery": "2026-10-29",
            "last_carrier_scan": {
                "date": "2026-10-26",
                "status": "Accepted by carrier",
            },
            "delivery_status": "delayed",
            "customer_preference": "replacement",
            "replacement_stock": 3,
            "replacement_estimated_delivery": "2026-11-05",
        }
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                pass

            def _serve(self) -> None:
                body = b""
                body_error = None
                try:
                    if self.headers.get("Transfer-Encoding"):
                        raise ValueError("transfer encoding is unsupported")
                    size = int(self.headers.get("Content-Length", "0"))
                    if size < 0 or size > 8192:
                        raise ValueError("invalid content length")
                    body = self.rfile.read(size)
                    if len(body) != size:
                        raise ValueError("incomplete request body")
                except ValueError:
                    body_error = "invalid_request_body"
                status, payload, replayed, drop = owner._handle(
                    self.command,
                    self.path,
                    body,
                    self.headers.get("Idempotency-Key"),
                    body_error,
                )
                self.close_connection = True
                if drop:
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    self.connection.close()
                    return
                encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Connection", "close")
                self.send_header("X-Synthetic-Fixture", "true")
                if replayed:
                    self.send_header("Idempotency-Replayed", "true")
                self.end_headers()
                if self.command != "HEAD":
                    try:
                        self.wfile.write(encoded)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            do_GET = _serve
            do_POST = _serve
            do_PUT = _serve
            do_PATCH = _serve
            do_DELETE = _serve
            do_HEAD = _serve
            do_OPTIONS = _serve

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def port(self) -> int:
        return self.address[1]

    @property
    def base_url(self) -> str:
        return "http://%s:%s" % self.address

    def start(self) -> "FixtureServer":
        if self._closed:
            raise RuntimeError("the fixture is closed")
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 0.05},
                name="shipment-fixture",
                daemon=True,
            )
            self._thread.start()
        return self

    def close(self) -> None:
        if self._closed:
            return
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=5)
        self._server.server_close()
        self._closed = True

    def __enter__(self) -> "FixtureServer":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def snapshot(self) -> dict[str, Any]:
        """Copy backend observations without an agent-accessible HTTP endpoint."""
        with self._lock:
            return copy.deepcopy({
                "requests": self._requests,
                "effects": self._effects,
                "resolution": self._resolution,
                "order": self._order,
                "effect_counts": {
                    kind: sum(effect["kind"] == kind for effect in self._effects)
                    for kind in ("dispatch", "refund")
                },
            })

    def _handle(
        self,
        method: str,
        path: str,
        body: bytes,
        key: Optional[str],
        body_error: Optional[str],
    ) -> tuple[int, dict[str, Any], bool, bool]:
        with self._lock:
            status, payload, replayed, new_effect = self._route(
                method, path, body, key, body_error
            )
            drop = bool(
                new_effect == "dispatch"
                and self.drop_first_dispatch_response
                and not self._dropped_dispatch_response
            )
            if drop:
                self._dropped_dispatch_response = True
            self._requests.append({
                "sequence": len(self._requests) + 1,
                "method": method,
                "path": path,
                "status": status,
                "idempotency_key": key,
                "replayed": replayed,
                "response_dropped": drop,
                "new_effect": new_effect,
            })
            return status, copy.deepcopy(payload), replayed, drop

    def _route(
        self,
        method: str,
        path: str,
        body: bytes,
        key: Optional[str],
        body_error: Optional[str],
    ) -> tuple[int, dict[str, Any], bool, Optional[str]]:
        def error(status: int, code: str):
            return status, {"synthetic": True, "error": code}, False, None

        if body_error:
            return error(400, body_error)
        if "?" in path or "#" in path:
            return error(400, "query_or_fragment_not_supported")
        if method not in ("GET", "POST"):
            return error(405, "method_not_allowed")
        if method == "GET":
            if body:
                return error(400, "get_body_not_supported")
            if path == "/orders/42":
                order = copy.deepcopy(self._order)
                order["resolution"] = copy.deepcopy(self._cached_reply)
                return 200, order, False, None
            if path in (
                "/orders/42/eligibility",
                "/orders/42/eligibility-failed",
                "/orders/43/eligibility",
            ):
                status = 200 if path == "/orders/43/eligibility" else self.eligibility_status
                if path == "/orders/42/eligibility-failed":
                    status = 409
                order_id = 43 if path == "/orders/43/eligibility" else 42
                return status, {
                    "synthetic": True,
                    "order_id": order_id,
                    "eligible": status == 200,
                    "reason": (
                        "Promised delivery missed; replacement stock is available."
                        if status == 200 else "Synthetic eligibility refusal control."
                    ),
                }, False, None
            return error(404, "unknown_endpoint")
        if path not in ("/orders/42/dispatch", "/orders/42/refund"):
            return error(404, "unknown_endpoint")
        try:
            payload = json.loads(body) if body else {}
        except (ValueError, UnicodeDecodeError):
            return error(400, "invalid_json")
        if payload != {}:
            return error(400, "body_must_be_empty_object")
        if not key or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", key):
            return error(400, "valid_idempotency_key_required")
        kind = path.rsplit("/", 1)[1]
        if self._resolution is not None:
            if self._resolution["kind"] == kind and self._resolution["idempotency_key"] == key:
                return 201, self._cached_reply, True, None
            return error(409, "order_already_resolved")
        effect_id = "%s-42-001" % kind
        self._resolution = {
            "order_id": 42,
            "kind": kind,
            "effect_id": effect_id,
            "idempotency_key": key,
        }
        self._effects.append(copy.deepcopy(self._resolution))
        self._cached_reply = {
            "synthetic": True,
            "order_id": 42,
            "resolution": kind,
            "effect_id": effect_id,
        }
        if kind == "dispatch":
            self._order["replacement_stock"] -= 1
            self._cached_reply.update({
                "item": self._order["item"],
                "quantity": self._order["quantity"],
                "estimated_delivery": self._order["replacement_estimated_delivery"],
            })
        return 201, self._cached_reply, False, kind
