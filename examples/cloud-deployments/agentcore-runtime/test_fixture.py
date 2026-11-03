"""Backend controls; these tests do not execute Box or an agent."""

import concurrent.futures
import http.client
import json
import unittest

from fixture import FixtureServer


def request(server, method, path, body=None, key="order-42-resolution"):
    conn = http.client.HTTPConnection(*server.address, timeout=3)
    headers = {}
    if key is not None:
        headers["Idempotency-Key"] = key
    if body is not None:
        body = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, json.loads(response.read()), dict(response.getheaders())
    finally:
        conn.close()


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = FixtureServer().start()
        self.addCleanup(self.fixture.close)

    def test_customer_story_and_eligibility_have_no_effects(self):
        status, order, _ = request(self.fixture, "GET", "/orders/42")
        self.assertEqual(status, 200)
        self.assertEqual(order["order_id"], 42)
        self.assertEqual(order["customer_preference"], "replacement")
        self.assertEqual(order["delivery_status"], "delayed")
        self.assertIsNone(order["resolution"])
        status, eligible, _ = request(self.fixture, "GET", "/orders/42/eligibility")
        self.assertEqual((status, eligible["eligible"]), (200, True))
        self.assertEqual(self.fixture.snapshot()["effects"], [])

    def test_failed_and_unrelated_eligibility_controls(self):
        status, failed, _ = request(self.fixture, "GET", "/orders/42/eligibility-failed")
        self.assertEqual((status, failed["eligible"]), (409, False))
        status, other, _ = request(self.fixture, "GET", "/orders/43/eligibility")
        self.assertEqual((status, other["order_id"], other["eligible"]), (200, 43, True))
        with FixtureServer(eligibility_status=409) as failed_fixture:
            status, failed, _ = request(failed_fixture, "GET", "/orders/42/eligibility")
            self.assertEqual((status, failed["eligible"]), (409, False))
            self.assertEqual(failed_fixture.snapshot()["effects"], [])

    def test_backend_does_not_duplicate_the_box_history_gate(self):
        status, reply, _ = request(self.fixture, "POST", "/orders/42/dispatch", {})
        self.assertEqual(status, 201)
        self.assertEqual(reply["effect_id"], "dispatch-42-001")
        snap = self.fixture.snapshot()
        self.assertEqual(snap["effect_counts"], {"dispatch": 1, "refund": 0})
        self.assertEqual(snap["order"]["replacement_stock"], 2)
        self.assertEqual(len(snap["requests"]), 1)

    def test_same_key_replays_the_original_receipt_without_an_effect(self):
        first = request(self.fixture, "POST", "/orders/42/dispatch", {})
        replay = request(self.fixture, "POST", "/orders/42/dispatch", {})
        self.assertEqual(first[:2], replay[:2])
        self.assertEqual(replay[2]["Idempotency-Replayed"], "true")
        status, _, _ = request(self.fixture, "POST", "/orders/42/dispatch", {}, key="new-key")
        self.assertEqual(status, 409)
        snap = self.fixture.snapshot()
        self.assertEqual(len(snap["effects"]), 1)
        self.assertEqual([r["new_effect"] for r in snap["requests"]], ["dispatch", None, None])

    def test_dispatch_and_refund_are_mutually_exclusive(self):
        for first, second in (("dispatch", "refund"), ("refund", "dispatch")):
            with self.subTest(first=first), FixtureServer() as server:
                status, _, _ = request(server, "POST", "/orders/42/" + first, {})
                self.assertEqual(status, 201)
                status, reply, _ = request(server, "POST", "/orders/42/" + second, {})
                self.assertEqual((status, reply["error"]), (409, "order_already_resolved"))
                self.assertEqual([e["kind"] for e in server.snapshot()["effects"]], [first])

    def test_lost_dispatch_response_keeps_one_effect_and_replays_receipt(self):
        with FixtureServer(drop_first_dispatch_response=True) as server:
            with self.assertRaises(http.client.RemoteDisconnected):
                request(server, "POST", "/orders/42/dispatch", {})
            snap = server.snapshot()
            self.assertEqual(len(snap["effects"]), 1)
            self.assertTrue(snap["requests"][0]["response_dropped"])
            status, replay, headers = request(server, "POST", "/orders/42/dispatch", {})
            self.assertEqual((status, replay["effect_id"]), (201, "dispatch-42-001"))
            self.assertEqual(headers["Idempotency-Replayed"], "true")
            status, _, _ = request(server, "POST", "/orders/42/refund", {})
            self.assertEqual(status, 409)
            self.assertEqual(server.snapshot()["effect_counts"], {"dispatch": 1, "refund": 0})
            _, order, _ = request(server, "GET", "/orders/42")
            self.assertEqual(order["resolution"], replay)

    def test_concurrent_replays_create_one_effect(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            replies = list(pool.map(
                lambda _: request(self.fixture, "POST", "/orders/42/dispatch", {}),
                range(8),
            ))
        self.assertTrue(all(reply[0] == 201 for reply in replies))
        self.assertEqual({reply[1]["effect_id"] for reply in replies}, {"dispatch-42-001"})
        snap = self.fixture.snapshot()
        self.assertEqual(len(snap["effects"]), 1)
        self.assertEqual(sum(r["replayed"] for r in snap["requests"]), 7)

    def test_unknown_queries_bodies_targets_and_methods_make_no_effects(self):
        cases = [
            ("GET", "/orders/42?other=43", None, 400),
            ("GET", "/orders/42", {"order_id": 43}, 400),
            ("POST", "/orders/42/dispatch?quantity=2", {}, 400),
            ("POST", "/orders/42/dispatch", {"quantity": 2}, 400),
            ("POST", "/orders/42/dispatch", [], 400),
            ("POST", "/orders/43/dispatch", {}, 404),
            ("POST", "/orders/42/%64ispatch", {}, 404),
            ("DELETE", "/orders/42", None, 405),
        ]
        for method, path, body, expected in cases:
            with self.subTest(method=method, path=path, body=body):
                status, _, _ = request(self.fixture, method, path, body)
                self.assertEqual(status, expected)
        self.assertEqual(self.fixture.snapshot()["effects"], [])

    def test_mutation_requires_an_idempotency_key(self):
        for key in (None, "bad key"):
            with self.subTest(key=key):
                status, _, _ = request(self.fixture, "POST", "/orders/42/dispatch", {}, key=key)
                self.assertEqual(status, 400)
        self.assertEqual(self.fixture.snapshot()["effects"], [])

    def test_snapshot_cannot_change_backend_state(self):
        snap = self.fixture.snapshot()
        snap["order"]["replacement_stock"] = 999
        snap["effects"].append({"kind": "refund"})
        self.assertEqual(self.fixture.snapshot()["order"]["replacement_stock"], 3)
        self.assertEqual(self.fixture.snapshot()["effects"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
