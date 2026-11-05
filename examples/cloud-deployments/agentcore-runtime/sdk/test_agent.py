"""Test HTTP routing, run bounds, and independent verification without AWS calls."""
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

agent = load("shipment_sdk_agent", "agent.py")
runner = load("shipment_sdk_runner", "run-demo.py")

class Response:
    status = 403
    data = b'{"error":"refused"}'
    header = "refused"
    def read(self, size): return self.data
    def getheader(self, name): return self.header

class Connection:
    def __init__(self, host, port, timeout):
        self.destination = (host, port, timeout)
        self.closed = False
        self.response = Response()
    def request(self, *args, **kwargs): self.sent = (args, kwargs)
    def getresponse(self): return self.response
    def close(self): self.closed = True

class ToolsTest(unittest.TestCase):
    def make(self):
        self.connection = Connection("127.0.0.1", 4567, 15)
        self.tools = agent.ShipmentTools("http://127.0.0.1:8910", "http://127.0.0.1:4567",
                                        lambda *args, **kwargs: self.connection)
        self.tools.phase = "premature"
        return self.tools

    def test_dispatch_reaches_proxy_without_local_eligibility_gate(self):
        result = json.loads(self.make().dispatch_replacement())
        self.assertEqual(self.connection.sent[0], ("POST", "http://127.0.0.1:8910/orders/42/replacement"))
        self.assertEqual(self.connection.sent[1]["headers"]["Idempotency-Key"], "replacement-42")
        self.assertEqual(result["status"], 403)
        self.assertTrue(result["box_refused"])
        self.assertTrue(self.connection.closed)

    def test_eligibility_and_dispatch_share_path_with_different_methods(self):
        tools = self.make()
        tools.check_eligibility()
        self.assertEqual(self.connection.sent[0], ("GET", "http://127.0.0.1:8910/orders/42/replacement"))
        tools.dispatch_replacement()
        self.assertEqual(self.connection.sent[0], ("POST", "http://127.0.0.1:8910/orders/42/replacement"))

    def test_backend_403_is_not_box_refusal(self):
        self.make()
        self.connection.response.header = None
        self.assertFalse(json.loads(self.tools.dispatch_replacement())["box_refused"])

    def test_reject_nonlocal_service(self):
        with self.assertRaises(ValueError):
            agent.ShipmentTools("http://example.com:80", "http://127.0.0.1:4567")

    def test_reject_absent_proxy(self):
        with self.assertRaises(ValueError):
            agent.ShipmentTools("http://127.0.0.1:8910", "")

    def test_tool_budget(self):
        self.make().attempts = 10
        with self.assertRaises(RuntimeError): self.tools.read_order()

    def test_failed_connections_consume_attempt_budget(self):
        def fail(*args, **kwargs):
            raise TimeoutError("synthetic connection failure")
        tools = agent.ShipmentTools("http://127.0.0.1:8910", "http://127.0.0.1:4567", fail)
        for _ in range(10):
            with self.assertRaises(TimeoutError): tools.read_order()
        with self.assertRaises(RuntimeError): tools.read_order()
        self.assertEqual(tools.attempts, 10)
        self.assertEqual(tools.events, [])

    def test_response_limit_closes_connection(self):
        self.make()
        self.connection.response.data = b"x" * 65537
        with self.assertRaises(ValueError): self.tools.read_order()
        self.assertTrue(self.connection.closed)

    def test_model_budget(self):
        budget = agent.ModelBudget()
        for _ in range(18): budget.before(None)
        with self.assertRaises(RuntimeError): budget.before(None)

    def test_tool_time_budget_prevents_new_requests(self):
        self.make().started = 0
        with patch.object(agent.time, "monotonic", return_value=201):
            with self.assertRaises(RuntimeError): self.tools.read_order()
        self.assertFalse(hasattr(self.connection, "sent"))

    def test_model_time_budget_prevents_new_calls(self):
        budget = agent.ModelBudget()
        budget.started = 0
        with patch.object(agent.time, "monotonic", return_value=201):
            with self.assertRaises(RuntimeError): budget.before(None)
        self.assertEqual(budget.calls, 0)

    def test_only_successful_model_responses_count(self):
        budget = agent.ModelBudget()
        budget.after(types.SimpleNamespace(exception=RuntimeError(), stop_response=None))
        self.assertEqual(budget.completed, 0)
        budget.after(types.SimpleNamespace(exception=None, stop_response=object()))
        self.assertEqual(budget.completed, 1)

class LibraryGrantTest(unittest.TestCase):
    def test_runtime_system_prefix_never_becomes_a_tree_grant(self):
        runtime = {"base": "/usr", "prefix": "/usr", "library_dirs": ["/usr/lib/python3.12", "/usr/lib64", "/usr/lib"]}
        grants = runner.read_grants(runtime, "/var/tmp/sdk/vendor", "/var/tmp/sdk/workspace")
        self.assertNotIn("/usr", grants)
        self.assertIn("/usr/lib", grants)
        self.assertTrue(any(Path(p) in Path("/usr/lib/python3.12/encodings").parents for p in grants))
        self.assertFalse(any(Path(p) in Path("/usr/bin/unrelated").parents for p in grants))

    def test_uv_python_grants_only_its_library_directory(self):
        base = "/opt/uv/cpython-3.12.16-linux-aarch64-gnu"
        runtime = {"base": base, "prefix": base, "library_dirs": [base + "/lib", base + "/lib/python3.12", "/usr/lib64"]}
        grants = runner.read_grants(runtime, "/var/tmp/sdk/vendor", "/var/tmp/sdk/workspace")
        self.assertNotIn(base, grants)
        self.assertIn(base + "/lib", grants)
        self.assertFalse(any(Path(p) in Path(base + "/bin/unrelated").parents for p in grants))

    def test_library_discovery_rejects_accidental_system_root(self):
        with self.assertRaises(ValueError):
            runner.read_grants({"library_dirs": ["/usr"]}, "/var/tmp/sdk/vendor", "/var/tmp/sdk/workspace")

class DiagnosticTest(unittest.TestCase):
    def test_known_credentials_and_bearer_values_are_redacted(self):
        value = "synthetic-test-secret"
        text = value + " Bearer synthetic-token ASIA" + "A" * 16
        output = runner.redact_diagnostic(text, [value])
        self.assertNotIn(value, output)
        self.assertNotIn("synthetic-token", output)
        self.assertNotIn("ASIA", output)

    def test_tails_are_bounded_after_redaction(self):
        value = "synthetic-test-secret"
        output = runner.diagnostic_tails("x" * 10000 + value, "e" * 20000 + value, [value])
        self.assertEqual(len(output["agent_stdout_tail"]), 6000)
        self.assertEqual(len(output["agent_stderr_tail"]), 12000)
        self.assertNotIn(value, json.dumps(output))
        self.assertTrue(output["agent_stderr_tail"].endswith("[REDACTED]"))

class VerifierTest(unittest.TestCase):
    def setUp(self):
        self.effect = {"order_id": 42, "kind": "dispatch", "effect_id": "dispatch-42-001", "idempotency_key": "replacement-42"}
        receipt = {"order_id": 42, "resolution": "dispatch", "effect_id": "dispatch-42-001",
                   "item": "Adjustable desk lamp", "quantity": 1, "estimated_delivery": "2026-11-05"}
        specs = [("premature", "read_order", 200, False), ("premature", "dispatch_replacement", 403, True),
                 ("recover", "check_eligibility", 200, False), ("recover", "dispatch_replacement", 201, False),
                 ("repeat", "dispatch_replacement", 403, True), ("refund", "request_refund", 403, True)]
        self.workload = {"same_process_finished": True, "strands_version": "1.63.0", "provider": "BedrockModel", "mode": runner.MODE,
                         "tool_executor": "SequentialToolExecutor", "tool_attempts": 6, "model_calls": 11, "model_responses": 11,
                         "phases": [{"phase": x, "usage": {"inputTokens": 50, "outputTokens": 10}} for x in ["premature", "recover", "repeat", "refund", "reply"]],
                         "steps": [{"phase": p, "operation": op, "status": status, "box_refused": refused,
                                    "body": receipt if p == "recover" and op == "dispatch_replacement" else {}} for p,op,status,refused in specs],
                         "customer_reply": "Your desk lamp replacement is confirmed by dispatch-42-001 for 2026-11-05."}
        self.service = {"requests": [{"method": m, "path": p, "status": s} for m,p,s in
                                    [("GET", "/orders/42", 200), ("GET", "/orders/42/replacement", 200), ("POST", "/orders/42/replacement", 201)]],
                        "effects": [self.effect], "effect_counts": {"dispatch": 1, "refund": 0}, "resolution": self.effect,
                        "order": {"item": "Adjustable desk lamp", "quantity": 1, "replacement_estimated_delivery": "2026-11-05"}}
        self.decisions = [{"strands.box.policy.action": "http:request", "strands.box.policy.verdict": "deny", "strands.box.policy.rule": rule}
                          for rule in ["dispatch_requires_eligibility", "dispatch_closes_mutations", "dispatch_closes_mutations"]]
        self.decisions.append({"strands.box.policy.action": "http:request", "strands.box.policy.verdict": "permit", "strands.box.policy.rule": "sdk_model_request"})

    def checks(self): return runner.verify(self.workload, self.service, self.decisions, 0, 30, False)
    def test_complete_evidence_passes(self): self.assertTrue(all(self.checks().values()))
    def test_empty_evidence_fails(self): self.assertFalse(all(runner.verify({}, {}, [], 0, 1, False).values()))
    def test_claimed_success_without_service_effect_fails(self):
        self.service["effects"] = []
        self.assertFalse(self.checks()["exact_expected_effect"])
    def test_backend_receiving_denied_request_fails(self):
        self.service["requests"].append({"method": "POST", "path": "/orders/42/refund", "status": 409})
        self.assertFalse(self.checks()["only_permitted_requests_reached_service"])
    def test_receiver_distinguishes_methods_on_the_replacement_path(self):
        self.service["requests"][1]["method"] = "POST"
        self.assertFalse(self.checks()["only_permitted_requests_reached_service"])

    def test_missing_policy_rule_fails(self):
        self.decisions.pop(0)
        self.assertFalse(self.checks()["expected_policy_refusals"])
    def test_scripted_provider_fails(self):
        self.workload["provider"] = "ScriptedModel"
        self.assertFalse(self.checks()["live_bedrock_provider"])
    def test_absent_usage_fails(self):
        for phase in self.workload["phases"]: phase["usage"] = {}
        self.assertFalse(self.checks()["model_usage_observed"])
    def test_unconfirmed_reply_fails(self):
        self.workload["customer_reply"] = "I dispatched it."
        self.assertFalse(self.checks()["reply_cites_confirmed_dispatch"])
    def test_expired_history_window_fails(self):
        self.assertFalse(runner.verify(self.workload, self.service, self.decisions, 0, 301, False)["finished_within_history_window"])

if __name__ == "__main__": unittest.main()
